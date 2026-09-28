import { checkFix, fixOutputSchema, type FixResult } from '@qualor/shared';
import { and, eq, inArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import type { Db } from '../db/client';
import { first } from '../db/rows';
import {
  analyses,
  branches,
  issues,
  jobs,
  llmRequests,
  projects,
  scmConnections,
  type LlmPost,
  type LlmRequestRow,
} from '../db/schema';
import { enqueue } from '../queue/queue';
import type { JobHandlers } from '../queue/worker';
import { gitlabClientFor } from '../scm/connections';
import { readScmContext } from '../scm/context';
import { BUSY_DEFER_SECONDS, type DecorationDeps } from '../scm/decorate';
import { issueUrl, linkOn, loadDecoration, type Loaded } from '../scm/decoration-data';
import { GITHUB_PR_NUMBER, type GitHubClient } from '../scm/github/client';
import { githubClientFor } from '../scm/github/connections';
import { MAX_FILE_PAGES } from '../scm/github/decorate';
import { githubWebBase, parseRepoRef, type GitHubRepoRef } from '../scm/github/url';
import { GITLAB_MR_IID, type GitLabClient } from '../scm/gitlab/client';
import { addedLineTexts, MAX_DIFF_PAGES, MAX_DISCUSSION_PAGES } from '../scm/inline';
import { ScmError } from '../scm/provider';
import { decorationRetryDelaySeconds, inSeconds, MAX_DECORATION_ATTEMPTS } from '../scm/queue';
import { aiResultSchema } from './dto';
import { buildIssueInput } from './input';
import { aiFixMarker, FIX_BODY_MAX_BYTES, fixSuggestionBody } from './render';
import {
  organizationSettings,
  pathExcluded,
  readLlmSettings,
  type StoredLlmSettings,
} from './settings';

/** llm.md §8.2: posting a fix suggestion is a job of its own, run by the `scm` worker. */
export const AI_FIX_QUEUE = 'scm-ai-fix';
/** llm.md §8.4: pages of review comments a GitHub post reads at most. */
export const MAX_REVIEW_COMMENT_PAGES = 30;

/**
 * llm.md §8.4: one post's own concurrency key. Not the branch's decoration key: a post retry
 * waiting out its backoff never delays the branch's decorations, and two jobs of one post never
 * run at once.
 */
export const aiFixKey = (requestId: string): string => `${AI_FIX_QUEUE}:${requestId}`;

export const aiFixPayload = z.strictObject({
  requestId: z.uuid(),
  /** Attempts made before this job's (0 for the first); 6 in all, as a decoration (§8.4). */
  attempt: z
    .number()
    .int()
    .min(0)
    .max(MAX_DECORATION_ATTEMPTS - 1),
});
type AiFixPayload = z.infer<typeof aiFixPayload>;

/** llm.md §8.4: why a queued post ended without a comment. */
export const POST_FAILURE_REASONS = [
  'not_head',
  'closed',
  'not_on_diff',
  'changed',
  'position_rejected',
  'refused',
  'unreachable',
  'not_understood',
  'not_possible',
] as const;
export type PostFailureReason = (typeof POST_FAILURE_REASONS)[number];

/** llm.md §8.2: why the route refuses to queue a post (the problem's `detail`). */
export const POST_REFUSALS = [
  'not_fix',
  'not_applicable',
  'not_open',
  'not_merge_request',
  'not_mapped',
  'not_latest',
  'no_scm_context',
  'already_posted',
] as const;
export type PostRefusal = (typeof POST_REFUSALS)[number];

type FixedResult = Extract<FixResult, { status: 'fixed' }>;

/**
 * llm.md §8.2: posting needs the AI assistant still on for the organisation, with the fix feature,
 * and neither the project nor the issue's path excluded (fail closed: an admin who turned it off
 * after the suggestion was made has the last word).
 */
function fixFeatureOn(
  settings: StoredLlmSettings,
  row: Pick<LlmRequestRow, 'organizationId' | 'projectId'>,
  path: string | null,
): boolean {
  const org = organizationSettings(settings, row.organizationId);
  return (
    settings.provider !== null &&
    org.enabled &&
    org.features.fix &&
    !org.excludedProjectIds.includes(row.projectId) &&
    !pathExcluded(settings, path)
  );
}

/** The stored answer as a fix result, or why it is none (it is never trusted as it is). */
function storedFix(row: LlmRequestRow): FixedResult | 'not_fix' | 'not_applicable' {
  if (row.feature !== 'fix' || row.status !== 'succeeded') return 'not_fix';
  const parsed = aiResultSchema.safeParse(row.result);
  if (!parsed.success || parsed.data.kind !== 'fix') return 'not_fix';
  if (parsed.data.status === 'not_applicable') return 'not_applicable';
  return parsed.data;
}

/**
 * llm.md §8.2: the checks of `POST /ai-requests/{id}/post`, in the order of the spec; the branch
 * whose decorations the post queues behind when it may be posted.
 */
async function postRefusal(
  db: Db,
  row: LlmRequestRow,
): Promise<{ refusal: PostRefusal | 'ai_disabled' } | { ok: true }> {
  const fix = storedFix(row);
  if (typeof fix === 'string') return { refusal: fix };
  const [found] =
    row.issueId === null
      ? []
      : await db
          .select({ issue: issues, branch: branches, project: projects })
          .from(issues)
          .innerJoin(branches, eq(branches.id, issues.branchId))
          .innerJoin(projects, eq(projects.id, issues.projectId))
          .where(eq(issues.id, row.issueId));
  if (!found || found.issue.status !== 'open' || found.issue.projectId !== row.projectId) {
    return { refusal: 'not_open' };
  }
  const { issue, branch, project } = found;
  if (!fixFeatureOn(await readLlmSettings(db), row, issue.path)) return { refusal: 'ai_disabled' };
  if (branch.kind !== 'merge_request') return { refusal: 'not_merge_request' };
  const [connection] =
    project.scmConnectionId === null || project.scmProjectRef === null
      ? []
      : await db
          .select()
          .from(scmConnections)
          .where(eq(scmConnections.id, project.scmConnectionId));
  if (!connection || (connection.provider !== 'gitlab' && connection.provider !== 'github')) {
    return { refusal: 'not_mapped' };
  }
  const number = connection.provider === 'gitlab' ? GITLAB_MR_IID : GITHUB_PR_NUMBER;
  if (!number.test(branch.name)) return { refusal: 'not_merge_request' };
  if (branch.lastAnalysisId === null || issue.lastSeenAnalysisId !== branch.lastAnalysisId) {
    return { refusal: 'not_latest' };
  }
  const [analysis] = await db
    .select({ scmContext: analyses.scmContext })
    .from(analyses)
    .where(eq(analyses.id, branch.lastAnalysisId));
  const stored = readScmContext(analysis?.scmContext);
  if (
    stored.kind !== 'ok' ||
    stored.context.provider !== connection.provider ||
    (connection.provider === 'github' && stored.context.github?.checkout !== 'head')
  ) {
    return { refusal: 'no_scm_context' };
  }
  return { ok: true };
}

/**
 * `POST /ai-requests/{id}/post` after the access check (llm.md §8.2): the request queued for
 * posting, or why it may not be. The row is locked while its post is decided, so concurrent
 * clicks queue one job: the others see it queued (or posted) and are refused `already_posted`.
 * A post left `queued` with no live job (its worker died) may be queued again; the job's marker
 * check keeps that from posting twice. `charge` (the G7 bound) runs only for a post that will be
 * queued, inside the transaction: when it throws, nothing is queued, and a refused post costs
 * the person nothing. With `audit`, a queued post records `ai.fix_posted` in the same
 * transaction (rbac-audit.md §8).
 */
export async function queueFixPost(
  db: Db,
  row: LlmRequestRow,
  charge: () => void = () => undefined,
  audit?: { recorder: AuditRecorder; context: AuditActorContext },
): Promise<{ ok: true; row: LlmRequestRow } | { ok: false; refusal: PostRefusal | 'ai_disabled' }> {
  const checked = await postRefusal(db, row);
  if ('refusal' in checked) return { ok: false, refusal: checked.refusal };
  return db.transaction(async (tx) => {
    const [locked] = await tx
      .select({ post: llmRequests.post })
      .from(llmRequests)
      .where(eq(llmRequests.id, row.id))
      .for('update');
    const status = locked?.post?.status;
    if (status === 'posted') return { ok: false, refusal: 'already_posted' as const };
    if (status === 'queued') {
      // A new statement after the lock: it sees the job of a click that committed meanwhile.
      const [live] = await tx
        .select({ id: jobs.id })
        .from(jobs)
        .where(
          and(
            eq(jobs.queue, AI_FIX_QUEUE),
            inArray(jobs.status, ['queued', 'running']),
            sql`${jobs.payload} ->> 'requestId' = ${row.id}`,
          ),
        )
        .limit(1);
      if (live) return { ok: false, refusal: 'already_posted' as const };
    }
    charge();
    const post: LlmPost = { status: 'queued', at: new Date().toISOString() };
    const updated = first(
      await tx
        .update(llmRequests)
        .set({ post, updatedAt: sql`now()` })
        .where(eq(llmRequests.id, row.id))
        .returning(),
    );
    await enqueue(tx, {
      queue: AI_FIX_QUEUE,
      payload: { requestId: row.id, attempt: 0 } satisfies AiFixPayload,
      concurrencyKey: aiFixKey(row.id),
      maxAttempts: 1,
    });
    if (audit?.recorder.active()) {
      const refs = await projectRefs(tx, row.projectId);
      await audit.recorder.record(tx, audit.context, [
        {
          action: 'ai.fix_posted',
          organization: refs.organization,
          project: refs.project,
          target: row.issueId === null ? null : { type: 'issue', id: row.issueId, label: null },
          details: { requestId: row.id },
        },
      ]);
    }
    return { ok: true, row: updated };
  });
}

// ─── The job ────────────────────────────────────────────────────────────────────────────────

type Outcome =
  { kind: 'posted'; url: string | null } | { kind: 'failed'; reason: PostFailureReason };

/** What one post needs, read again and checked again by the job. */
interface Target {
  row: LlmRequestRow;
  loaded: Loaded;
  path: string;
  fix: FixedResult;
  body: string;
  marker: string;
}

const failed = (reason: PostFailureReason): Outcome => ({ kind: 'failed', reason });

/**
 * llm.md §8.3: every line `startLine..endLine` is an added line of the file's diff, and its text
 * there is the line the model was shown, character for character.
 */
function placement(diff: string, fix: FixedResult): Outcome | null {
  const added = addedLineTexts(diff);
  for (let line = fix.startLine; line <= fix.endLine; line++) {
    if (!added.has(line)) return failed('not_on_diff');
  }
  for (const [i, text] of fix.original.entries()) {
    if (added.get(fix.startLine + i) !== text) return failed('changed');
  }
  return null;
}

const sameLines = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((line, i) => line === b[i]);

/**
 * Everything a post rests on, read from the database again and checked again: the stored answer
 * through the strict schema and `checkFix` against the issue's data as it is now (never the stored
 * JSON as it is), the issue open on the branch's latest analysis of a merge request, and the
 * comment's body within its bound. An `Outcome` when nothing may be posted.
 */
async function loadTarget(
  db: Db,
  row: LlmRequestRow,
  publicUrl: string | null,
): Promise<Target | Outcome> {
  const stored = storedFix(row);
  if (typeof stored === 'string' || row.issueId === null) return failed('not_possible');
  const built = await buildIssueInput(db, row.issueId, 'fix');
  if (!built || built.issue.status !== 'open' || built.issue.path === null) {
    return failed('not_possible');
  }
  // The issue's data (its snippet among it) is no longer what the model was given.
  if (built.inputSha256 !== row.inputSha256) return failed('changed');
  const answer = fixOutputSchema.safeParse({
    status: 'fixed',
    startLine: stored.startLine,
    endLine: stored.endLine,
    replacement: stored.replacement,
    explanation: stored.explanation,
  });
  if (!answer.success || answer.data.status !== 'fixed') return failed('not_possible');
  const checked = checkFix(answer.data, built.input);
  if (
    !checked.ok ||
    checked.value.status !== 'fixed' ||
    !sameLines(checked.value.original, stored.original)
  ) {
    return failed('not_possible');
  }
  const fix = checked.value;
  // The admin may have turned the assistant or its fix feature off, or excluded the project or
  // path, since the click (llm.md §8.2): nothing is posted then.
  if (!fixFeatureOn(await readLlmSettings(db), row, built.issue.path)) {
    return failed('not_possible');
  }
  const analysisId = built.issue.lastSeenAnalysisId;
  if (analysisId === null) return failed('not_possible');
  const loaded = await loadDecoration(db, analysisId);
  if (
    typeof loaded === 'string' ||
    loaded.branch.kind !== 'merge_request' ||
    loaded.branch.lastAnalysisId !== analysisId ||
    loaded.project.id !== row.projectId
  ) {
    return failed('not_possible');
  }
  const marker = aiFixMarker(built.issue.id, row.id);
  const body = fixSuggestionBody({
    provider: loaded.connection.provider === 'github' ? 'github' : 'gitlab',
    issueId: built.issue.id,
    requestId: row.id,
    model: row.model,
    ruleKey: built.rule.key,
    message: built.input.message,
    explanation: fix.explanation,
    startLine: fix.startLine,
    endLine: fix.endLine,
    replacement: fix.replacement,
    issueUrl: issueUrl(publicUrl, loaded.project.id, built.issue.id),
  });
  return { row, loaded, path: built.issue.path, fix, body, marker };
}

const firstLine = (body: string) => (body.split('\n', 1)[0] ?? '').replace(/\r$/, '');

/**
 * llm.md §8.3–§8.4 on GitLab: the comment found by its marker (posted already: a retry, or an
 * outcome that was lost) whatever else changed, else the merge request open at the analysed head,
 * the lines placed and unchanged, then one diff discussion on `startLine`.
 */
async function postToGitLab(client: GitLabClient, t: Target): Promise<Outcome> {
  const { connection, project, branch, revision, analysis } = t.loaded;
  const gitlabProject = await client.project(project.scmProjectRef ?? '');
  // As a decoration does (scm.md §4.2): the pipeline's GitLab project must be the mapped one.
  const stored = readScmContext(analysis.scmContext);
  const expected = stored.kind === 'ok' ? stored.context.gitlab?.projectId : undefined;
  if (expected !== undefined && String(gitlabProject.id) !== expected) return failed('refused');
  const ref = String(gitlabProject.id);
  const iid = branch.name;
  const mr = await client.mergeRequest(ref, iid);
  const noteUrl = (id: number) => linkOn(`${mr.web_url}#note_${id}`, connection.baseUrl);
  const me = await client.currentUser();
  const listed = await client.discussions(ref, iid, MAX_DISCUSSION_PAGES);
  for (const discussion of listed.items) {
    const note = discussion.notes[0];
    if (note && note.author.id === me.id && !note.system && firstLine(note.body) === t.marker) {
      return { kind: 'posted', url: noteUrl(note.id) };
    }
  }
  if (mr.state !== 'opened') return failed('closed');
  const refs = mr.diff_refs;
  if ((refs?.head_sha ?? mr.sha) !== revision) return failed('not_head');
  if (!refs?.base_sha || !refs.start_sha || !refs.head_sha) return failed('not_possible');
  // Beyond the page bound the comment may exist unseen: never post a second one.
  if (!listed.complete) return failed('not_possible');
  const diffs = await client.mergeRequestDiffs(ref, iid, MAX_DIFF_PAGES);
  const diff = diffs.items.find((d) => d.new_path === t.path && !d.deleted_file);
  if (!diff) return failed('not_on_diff');
  const misplaced = placement(diff.diff, t.fix);
  if (misplaced) return misplaced;
  const created = await client.createDiscussion(ref, iid, t.body, {
    baseSha: refs.base_sha,
    startSha: refs.start_sha,
    headSha: refs.head_sha,
    oldPath: diff.old_path,
    newPath: diff.new_path,
    newLine: t.fix.startLine,
  });
  if (created === 'position_rejected') return failed('position_rejected');
  const note = created.notes[0];
  return { kind: 'posted', url: note ? noteUrl(note.id) : null };
}

/**
 * llm.md §8.3–§8.4 on GitHub: as on GitLab, with a review comment by `<slug>[bot]` on the RIGHT
 * side of `startLine..endLine` at the analysed head.
 */
async function postToGitHub(
  client: GitHubClient,
  repoRef: GitHubRepoRef,
  t: Target,
): Promise<Outcome> {
  const { connection, branch, revision, analysis } = t.loaded;
  const app = await client.app();
  const repo = await client.useRepository(repoRef);
  const stored = readScmContext(analysis.scmContext);
  const github = stored.kind === 'ok' ? stored.context.github : undefined;
  // Fail closed (llm.md §8.2): without the repository the workflow ran in, the analysis cannot be
  // tied to this repository; and only a checkout of the head has the pull request's lines.
  if (github?.repositoryId === undefined || String(repo.id) !== github.repositoryId) {
    return failed('refused');
  }
  if (github.checkout !== 'head') return failed('not_possible');
  const number = branch.name;
  const webBase = githubWebBase(connection.baseUrl);
  const commentUrl = (url: string | undefined) => (url === undefined ? null : linkOn(url, webBase));
  const login = `${app.slug}[bot]`;
  const listed = await client.reviewComments(number, MAX_REVIEW_COMMENT_PAGES);
  const own = listed.items.find(
    (c) => c.user?.type === 'Bot' && c.user.login === login && firstLine(c.body) === t.marker,
  );
  if (own) return { kind: 'posted', url: commentUrl(own.html_url) };
  const pull = await client.pullRequest(number);
  if (pull.state !== 'open') return failed('closed');
  if (pull.head.sha !== revision) return failed('not_head');
  if (!listed.complete) return failed('not_possible');
  const files = await client.pullRequestFiles(number, MAX_FILE_PAGES);
  const file = files.items.find((f) => f.filename === t.path && f.status !== 'removed');
  if (file?.patch === undefined) return failed('not_on_diff');
  const misplaced = placement(file.patch, t.fix);
  if (misplaced) return misplaced;
  const created = await client.createReviewComment(number, {
    body: t.body,
    commitId: revision,
    path: t.path,
    line: t.fix.endLine,
    startLine: t.fix.startLine,
  });
  if (created === 'position_rejected') return failed('position_rejected');
  return { kind: 'posted', url: commentUrl(created.html_url) };
}

/**
 * The post for the target's connection, its client built (the key or token decrypted, the base
 * URL checked against the current rules) before anything is sent; null when it cannot be.
 */
function posterFor(deps: DecorationDeps, t: Target): (() => Promise<Outcome>) | null {
  const { connection, project } = t.loaded;
  if (connection.provider === 'github') {
    const found = githubClientFor(connection, deps.scm, deps.runtime);
    const repoRef = parseRepoRef(project.scmProjectRef ?? '');
    if ('problem' in found || repoRef === null) return null;
    return () => postToGitHub(found.client, repoRef, t);
  }
  const found = gitlabClientFor(connection, deps.scm);
  if ('problem' in found) return null;
  return () => postToGitLab(found.client, t);
}

/** Records the post's end, only while it is still the queued post this job was started for. */
async function record(db: Db, requestId: string, outcome: Outcome): Promise<void> {
  const at = new Date().toISOString();
  const post: LlmPost =
    outcome.kind === 'posted'
      ? { status: 'posted', ...(outcome.url === null ? {} : { url: outcome.url }), at }
      : { status: 'failed', reason: outcome.reason, at };
  await db
    .update(llmRequests)
    .set({ post, updatedAt: sql`now()` })
    .where(and(eq(llmRequests.id, requestId), sql`${llmRequests.post} ->> 'status' = 'queued'`));
}

const retryable = (error: ScmError) => error.kind === 'transient' || error.kind === 'rate_limited';

function reasonOf(error: ScmError): PostFailureReason {
  if (retryable(error)) return 'unreachable';
  if (error.kind === 'bad_answer' || error.kind === 'budget') return 'not_understood';
  return 'refused';
}

async function requeue(
  deps: DecorationDeps,
  target: Target,
  payload: AiFixPayload,
  delaySeconds: number,
): Promise<void> {
  await enqueue(deps.db, {
    queue: AI_FIX_QUEUE,
    payload,
    concurrencyKey: aiFixKey(target.row.id),
    runAt: inSeconds(delaySeconds),
    maxAttempts: 1,
  });
}

async function runPost(deps: DecorationDeps, payload: AiFixPayload): Promise<void> {
  const [row] = await deps.db
    .select()
    .from(llmRequests)
    .where(eq(llmRequests.id, payload.requestId));
  // Posted or failed meanwhile, or never queued: nothing to do.
  if (!row || row.feature !== 'fix' || row.post?.status !== 'queued') return;
  const log = (outcome: Outcome, connectionId: string | null, error: ScmError | null = null) => {
    const details = {
      requestId: row.id,
      connectionId,
      status: outcome.kind,
      reason: outcome.kind === 'failed' ? outcome.reason : null,
      // What the SCM said, never its message (which may quote what was sent).
      ...(error === null ? {} : { errorKind: error.kind, httpStatus: error.status }),
    };
    if (outcome.kind === 'posted') deps.logger?.info(details, 'AI fix suggestion posted');
    else deps.logger?.warn(details, 'AI fix suggestion not posted');
  };
  const target = await loadTarget(deps.db, row, deps.publicUrl);
  if (!('loaded' in target)) {
    await record(deps.db, row.id, target);
    return log(target, null);
  }
  const { connection, project } = target.loaded;
  if (Buffer.byteLength(target.body, 'utf8') > FIX_BODY_MAX_BYTES) {
    await record(deps.db, row.id, failed('not_possible'));
    return log(failed('not_possible'), connection.id);
  }
  const poster = posterFor(deps, target);
  if (poster === null) {
    await record(deps.db, row.id, failed('refused'));
    return log(failed('refused'), connection.id);
  }
  const { circuit, slots } = deps.runtime;
  if (!slots.tryTake(project.organizationId)) {
    // The organisation's slots are taken: the same attempt again shortly.
    return requeue(deps, target, payload, BUSY_DEFER_SECONDS);
  }
  let outcome: Outcome;
  let error: ScmError | null = null;
  try {
    if (!circuit.tryPass(connection.id)) {
      error = new ScmError('transient', 'The SCM circuit is open');
      outcome = failed('unreachable');
    } else {
      try {
        outcome = await poster();
        // Any answer, a refusal included: the SCM is up.
        circuit.success(connection.id);
      } catch (err) {
        if (!(err instanceof ScmError)) {
          circuit.release(connection.id);
          throw err;
        }
        error = err;
        if (retryable(err)) circuit.failure(connection.id);
        else if (err.status !== null) circuit.success(connection.id);
        else circuit.release(connection.id);
        outcome = failed(reasonOf(err));
      }
    }
  } finally {
    slots.release(project.organizationId);
  }
  if (error !== null && retryable(error)) {
    const next = payload.attempt + 1;
    if (next < MAX_DECORATION_ATTEMPTS) {
      const delay = Math.max(decorationRetryDelaySeconds(next), error.retryAfterSeconds ?? 0);
      await requeue(deps, target, { requestId: row.id, attempt: next }, delay);
      deps.logger?.info(
        { requestId: row.id, connectionId: connection.id, attempt: next, retryInSeconds: delay },
        'AI fix suggestion post retried',
      );
      return;
    }
  }
  await record(deps.db, row.id, outcome);
  log(outcome, connection.id, error);
}

/** The `scm-ai-fix` queue's handler, run by the `scm` worker (scm/decorate.ts `scmHandlers`). */
export function postFixHandler(deps: DecorationDeps): JobHandlers[string] {
  return async (job) => {
    const parsed = aiFixPayload.safeParse(job.payload);
    if (!parsed.success) {
      deps.logger?.warn({ jobId: job.id }, 'malformed AI fix post job payload; completing');
      return;
    }
    try {
      await runPost(deps, parsed.data);
    } catch (err) {
      // Never left queued by an error of Qualor's own: the person may post again (the marker
      // check keeps a comment that did reach the SCM from being posted twice).
      await record(deps.db, parsed.data.requestId, failed('not_possible'));
      throw err;
    }
  };
}

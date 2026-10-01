import type { FastifyBaseLogger } from 'fastify';
import type { Db } from '../db/client';
import { AI_FIX_QUEUE, postFixHandler } from '../llm/post';
import type { JobHandlers } from '../queue/worker';
import { gitlabClientFor, type ScmDeps } from './connections';
import {
  branchUrl,
  comparable,
  issueUrl,
  loadDecoration,
  recordMergeRequest,
  summaryData,
  type Loaded,
} from './decoration-data';
import { decorateGitHub } from './github/decorate';
import {
  GITLAB_MR_IID,
  GitLabError,
  type GitLabClient,
  type GitLabCommitStatus,
  type GitLabDiscussion,
  type GitLabNote,
} from './gitlab/client';
import { MAX_DISCUSSION_PAGES, reconcileInline } from './inline';
import { markerOf } from './markdown';
import { ScmError } from './provider';
import {
  decorationPayload,
  decorationRetryDelaySeconds,
  inSeconds,
  MAX_DECORATION_ATTEMPTS,
  requeueDecoration,
  SCM_QUEUE,
  type DecorationPayload,
} from './queue';
import { commitStatusFor, statusName, summaryBody, type SummaryInput } from './render';
import type { ScmRuntime } from './runtime';

/** A job whose organisation's slots are taken runs again this much later, without an attempt. */
export const BUSY_DEFER_SECONDS = 2;

export interface DecorationDeps {
  db: Db;
  scm: ScmDeps;
  runtime: ScmRuntime;
  /** `QUALOR_PUBLIC_URL`, for links (scm.md §2.3). */
  publicUrl: string | null;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
  /** Threads one job resolves or reopens (scm.md §5.4); tests set a smaller bound. */
  maxThreadUpdates?: number;
}

export type DecorationOutcome =
  | { kind: 'done'; connectionId: string }
  | { kind: 'nothing'; reason: string }
  | { kind: 'busy'; branchId: string }
  | {
      kind: 'failed';
      /** Whose decoration failed, for the log lines. */
      provider: 'GitLab' | 'GitHub';
      connectionId: string;
      branchId: string;
      error: ScmError;
      /** Retried with backoff (a transient failure, a rate limit or an open circuit). */
      retry: boolean;
      /** Counts towards the connection's circuit (not a refusal by the open circuit itself). */
      countsForCircuit: boolean;
    };

/**
 * The summary notes of this project among the discussions, by marker (§5.3): `own` is the token
 * user's, the one Qualor edits; `foreign` are top-level notes with the marker by other users, such
 * as the summary an earlier token's user posted before the token was replaced. GitLab lets only a
 * note's author edit it, so those are never edited, only removed.
 */
function summaryNotes(discussions: readonly GitLabDiscussion[], botId: number, projectId: string) {
  let own: GitLabNote | null = null;
  const foreign: GitLabNote[] = [];
  for (const discussion of discussions) {
    for (const note of discussion.notes) {
      if (note.system) continue;
      const marker = markerOf(note.body);
      if (marker?.kind !== 'summary' || marker.projectId !== projectId) continue;
      if (note.author.id === botId) own ??= note;
      else if (discussion.individual_note) foreign.push(note);
    }
  }
  return { own, foreign };
}

/**
 * The newest of our statuses that a post would replace: our name, and the pipeline we would post
 * to (or, without one, the ref we would send), as far as GitLab's answer says. With `pipelineId`
 * null and `ref` set, a status on any pipeline of that ref counts: it is what a post with the ref
 * only replaces (GitLab attaches it to the newest pipeline of the sha and ref).
 */
function currentStatus(
  listed: readonly GitLabCommitStatus[],
  name: string,
  pipelineId: string | null,
  ref: string | null,
): GitLabCommitStatus | null {
  let newest: GitLabCommitStatus | null = null;
  for (const s of listed) {
    if (s.name !== name) continue;
    if (pipelineId !== null && typeof s.pipeline_id === 'number') {
      if (String(s.pipeline_id) !== pipelineId) continue;
    } else if (pipelineId === null && ref !== null && typeof s.ref === 'string' && s.ref !== ref) {
      continue;
    }
    if (newest === null || s.id > newest.id) newest = s;
  }
  return newest;
}

/**
 * scm.md §5.1: the commit status of the analysed revision, posted only when it differs from the
 * current one. GitLab reuses only a pending or running status: a final state posted again adds a
 * row (and an entry in the pipeline's list), so re-running a decoration must read before it
 * writes to change nothing (§11.1).
 */
async function reconcileCommitStatus(
  deps: DecorationDeps,
  client: GitLabClient,
  ref: string,
  loaded: Loaded,
  payload: DecorationPayload,
): Promise<void> {
  const { state, description } = commitStatusFor(loaded.gate);
  const targetUrl = branchUrl(deps.publicUrl, loaded);
  const pipelineId = payload.gitlab?.pipelineId ?? null;
  // A merge request's status belongs to its source branch; a merge-result commit is on no branch,
  // so GitLab needs the ref when no pipeline gives it one.
  const gitRef =
    loaded.branch.kind === 'merge_request' ? loaded.branch.mrSourceBranch : loaded.branch.name;
  const name = statusName(loaded.project.key);
  const listed = await client.commitStatuses(ref, loaded.revision, name);
  const says = (current: GitLabCommitStatus | null) =>
    current !== null &&
    current.status === state &&
    (current.description ?? '') === description &&
    (current.target_url ?? null) === targetUrl;
  if (says(currentStatus(listed, name, pipelineId, gitRef))) return;
  await client.setCommitStatus(ref, loaded.revision, {
    state,
    description,
    name,
    targetUrl,
    pipelineId,
    ref: gitRef,
    // A refused pipeline makes the client post with the ref only: compare with what that
    // replaces first (§5.1), so a rerun adds no row.
    unchangedWithoutPipeline:
      pipelineId !== null && says(currentStatus(listed, name, null, gitRef)),
  });
}

/**
 * The merge request part of a decoration (scm.md §5.2–§5.5): inline discussions, then the
 * summary.
 */
async function decorateMergeRequest(
  deps: DecorationDeps,
  client: GitLabClient,
  ref: string,
  loaded: Loaded,
  payload: DecorationPayload,
): Promise<void> {
  const iid = loaded.branch.name;
  const mr = await client.mergeRequest(ref, iid);
  await recordMergeRequest(
    deps.db,
    loaded,
    { title: mr.title, url: mr.web_url },
    loaded.connection.baseUrl,
  );
  if (mr.state !== 'opened') return;
  const revision = loaded.revision;
  const head = mr.diff_refs?.head_sha ?? mr.sha;
  const me = await client.currentUser();
  const listed = await client.discussions(ref, iid, MAX_DISCUSSION_PAGES);
  const skipped: SummaryInput['inline']['skipped'] =
    payload.gitlab?.mergeRequestEventType === 'merged_result' ||
    payload.gitlab?.mergeRequestEventType === 'merge_train'
      ? 'merged_result'
      : head !== revision
        ? 'stale'
        : null;
  // §5.4: only when the report's line numbers are the merge request's (merged results win over
  // stale: a merge commit is never the head).
  const inline =
    skipped === null
      ? await reconcileInline({
          db: deps.db,
          client,
          ref,
          iid,
          projectId: loaded.project.id,
          branchId: loaded.branch.id,
          mr,
          discussions: listed.items,
          discussionsComplete: listed.complete,
          botId: me.id,
          issueUrl: (issueId) => issueUrl(deps.publicUrl, loaded.project.id, issueId),
          ...(deps.maxThreadUpdates === undefined
            ? {}
            : { maxThreadUpdates: deps.maxThreadUpdates }),
        })
      : { commented: 0, unplaced: 0 };
  const { top, total, newIssues, smallChangesetLines } = await summaryData(
    deps.db,
    loaded,
    deps.publicUrl,
  );
  const body = summaryBody({
    projectId: loaded.project.id,
    revision,
    gate: loaded.gate,
    newIssues,
    topIssues: top,
    topIssuesTotal: total,
    inline: { ...inline, skipped },
    branchUrl: branchUrl(deps.publicUrl, loaded),
    mergeRequestHead: head !== null && head !== revision ? head : null,
    smallChangesetLines,
  });
  const { own, foreign } = summaryNotes(listed.items, me.id, loaded.project.id);
  if (own) {
    if (comparable(own.body) !== comparable(body)) {
      await client.updateNote(ref, iid, own.id, body);
    }
  } else if (listed.complete) {
    await client.createNote(ref, iid, body);
  } else {
    // Beyond the page bound the summary may exist unseen: never post a second one.
    deps.logger?.warn(
      { analysisId: loaded.analysis.id, connectionId: loaded.connection.id },
      'GitLab merge request has too many discussions to find the Qualor summary; not posting one',
    );
    return;
  }
  await removeForeignSummaries(client, ref, iid, foreign);
}

/**
 * Summaries of this project by another user (the token was replaced by one of another user) go
 * once this token's own is in place, so the merge request shows one verdict. GitLab lets a
 * Maintainer delete any note; with a lower role the old note stays (a 403, or a 404 when it is
 * already gone, is not a failure of the job). Other failures are, so a retry removes it.
 */
async function removeForeignSummaries(
  client: GitLabClient,
  ref: string,
  iid: string,
  foreign: readonly GitLabNote[],
): Promise<void> {
  for (const note of foreign) {
    try {
      await client.deleteNote(ref, iid, note.id);
    } catch (err) {
      if (err instanceof GitLabError && err.status === 404) continue;
      // Refused once, refused for the others too.
      if (err instanceof GitLabError && err.status === 403) return;
      throw err;
    }
  }
}

const retryable = (error: ScmError) => error.kind === 'transient' || error.kind === 'rate_limited';

/**
 * The error a job ends with when its parts failed: an exhausted budget stops the job (§4.3);
 * otherwise a retryable failure wins, so a part that can still succeed is tried again (a run
 * repeated converges on the same state), else the first failure.
 */
function decisiveError(errors: readonly ScmError[]): ScmError | null {
  return errors.find((e) => e.kind === 'budget') ?? errors.find(retryable) ?? errors[0] ?? null;
}

/**
 * One decoration (scm.md §4.2): the commit status of the analysis's revision and, for the
 * branch's latest analysis of an open merge request, the inline discussions and the summary. A
 * failed status does not stop the merge request part (§4.3), unless GitLab rate-limited it or the
 * budget ran out; the job then fails with it and is retried as it says. Idempotent: running it
 * again converges on the same state in GitLab and, once there, changes nothing.
 */
export async function decorateAnalysis(
  deps: DecorationDeps,
  payload: DecorationPayload,
): Promise<DecorationOutcome> {
  const loaded = await loadDecoration(deps.db, payload.analysisId);
  if (typeof loaded === 'string') return { kind: 'nothing', reason: loaded };
  const { connection, branch } = loaded;
  const provider = connection.provider === 'github' ? 'GitHub' : 'GitLab';
  const failed = (error: ScmError, circuit = false): DecorationOutcome => ({
    kind: 'failed',
    provider,
    connectionId: connection.id,
    branchId: branch.id,
    error,
    retry: circuit || retryable(error),
    countsForCircuit: !circuit && retryable(error),
  });
  const { circuit } = deps.runtime;
  if (!circuit.tryPass(connection.id)) {
    const openUntil = circuit.openUntil(connection.id);
    const text =
      openUntil === null
        ? `${provider} unreachable (circuit half-open, another job is probing)`
        : `${provider} unreachable (circuit open until ${new Date(openUntil).toISOString()})`;
    return failed(
      provider === 'GitLab' ? new GitLabError('transient', text) : new ScmError('transient', text),
      true,
    );
  }
  let outcome: DecorationOutcome | undefined;
  try {
    outcome = await decorateThroughCircuit(deps, payload, loaded, failed);
    return outcome;
  } finally {
    settleCircuit(deps.runtime, connection.id, outcome);
  }
}

/**
 * scm.md §4.2: what a job that passed the circuit tells it. A transient failure counts; any answer
 * from GitLab (a success, or a refusal such as 401 or 404: GitLab is up) closes the circuit and
 * starts the count again; a job that ended without an answer (its organisation's slots were
 * taken, a token that no longer decrypts, an error of Qualor's own) only hands a probe on.
 */
function settleCircuit(
  runtime: ScmRuntime,
  connectionId: string,
  outcome: DecorationOutcome | undefined,
): void {
  if (outcome?.kind === 'done') runtime.circuit.success(connectionId);
  else if (outcome?.kind === 'failed' && outcome.countsForCircuit) {
    runtime.circuit.failure(connectionId);
  } else if (outcome?.kind === 'failed' && outcome.error.status !== null) {
    runtime.circuit.success(connectionId);
  } else runtime.circuit.release(connectionId);
}

async function decorateThroughCircuit(
  deps: DecorationDeps,
  payload: DecorationPayload,
  loaded: Loaded,
  failed: (error: ScmError) => DecorationOutcome,
): Promise<DecorationOutcome> {
  const { branch, project } = loaded;
  if (!deps.runtime.slots.tryTake(project.organizationId)) {
    return { kind: 'busy', branchId: branch.id };
  }
  try {
    return loaded.connection.provider === 'github'
      ? await decorateGitHub(deps, payload, loaded, failed)
      : await decorateGitLab(deps, payload, loaded, failed);
  } finally {
    deps.runtime.slots.release(project.organizationId);
  }
}

/**
 * One GitLab decoration (scm.md §4.2): the project, the commit status, then the merge request
 * part.
 */
async function decorateGitLab(
  deps: DecorationDeps,
  payload: DecorationPayload,
  loaded: Loaded,
  failed: (error: ScmError) => DecorationOutcome,
): Promise<DecorationOutcome> {
  const { connection, branch, project } = loaded;
  try {
    const found = gitlabClientFor(connection, deps.scm);
    if ('problem' in found) return failed(new GitLabError('refused', found.problem));
    const client = found.client;
    const gitlabProject = await client.project(project.scmProjectRef ?? '');
    const expected = payload.gitlab?.projectId;
    if (expected !== undefined && String(gitlabProject.id) !== expected) {
      return failed(
        new GitLabError(
          'refused',
          "The pipeline's GitLab project is not the project Qualor is mapped to",
        ),
      );
    }
    const ref = String(gitlabProject.id);
    const errors: ScmError[] = [];
    try {
      await reconcileCommitStatus(deps, client, ref, loaded, payload);
    } catch (err) {
      if (!(err instanceof ScmError)) throw err;
      // An exhausted budget stops the job (§4.3), and so does a rate limit: more requests now
      // would only be refused too, and the retry waits for GitLab's Retry-After.
      if (err.kind === 'budget' || err.kind === 'rate_limited') return failed(err);
      errors.push(err);
    }
    if (
      branch.kind === 'merge_request' &&
      GITLAB_MR_IID.test(branch.name) &&
      branch.lastAnalysisId === loaded.analysis.id
    ) {
      try {
        await decorateMergeRequest(deps, client, ref, loaded, payload);
      } catch (err) {
        if (!(err instanceof ScmError)) throw err;
        errors.push(err);
      }
    }
    const error = decisiveError(errors);
    return error === null ? { kind: 'done', connectionId: connection.id } : failed(error);
  } catch (err) {
    if (err instanceof ScmError) return failed(err);
    throw err;
  }
}

/**
 * The `scm` worker's handlers (main.ts): the `scm` queue's decorations (scm.md §4.2–§4.3), and the
 * posts of AI fix suggestions (llm.md §8.2) with the same runtime (circuit, slots, GitHub pacing).
 */
export function scmHandlers(deps: DecorationDeps): JobHandlers {
  return {
    [SCM_QUEUE]: async (job) => {
      const parsed = decorationPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed decoration job payload; completing');
        return;
      }
      const payload = parsed.data;
      const outcome = await decorateAnalysis(deps, payload);
      switch (outcome.kind) {
        case 'nothing':
          return;
        case 'done':
          return;
        case 'busy':
          await requeueDecoration(
            deps.db,
            outcome.branchId,
            payload,
            inSeconds(BUSY_DEFER_SECONDS),
          );
          return;
        case 'failed': {
          const { error } = outcome;
          const next = payload.attempt + 1;
          const details = {
            analysisId: payload.analysisId,
            connectionId: outcome.connectionId,
            attempt: next,
            status: error.status,
            reason: error.message,
          };
          if (outcome.retry && next < MAX_DECORATION_ATTEMPTS) {
            const delay = Math.max(decorationRetryDelaySeconds(next), error.retryAfterSeconds ?? 0);
            const queued = await requeueDecoration(
              deps.db,
              outcome.branchId,
              { ...payload, attempt: next },
              inSeconds(delay),
            );
            if (queued) {
              deps.logger?.info(
                { ...details, retryInSeconds: delay },
                `${outcome.provider} decoration retried`,
              );
            } else {
              deps.logger?.info(
                details,
                `${outcome.provider} decoration superseded: a newer decoration of the branch is queued`,
              );
            }
          } else {
            deps.logger?.warn(details, `${outcome.provider} decoration stopped`);
          }
        }
      }
    },
    [AI_FIX_QUEUE]: postFixHandler(deps),
  };
}

import type { Quality, Severity } from '@qualor/shared';
import { and, eq, inArray } from 'drizzle-orm';
import type { Db } from '../../db/client';
import { issues, rules } from '../../db/schema';
import { AI_ENGINE } from '../../rules/server-engines';
import type { DecorationDeps } from '../decorate';
import {
  closingRevisions,
  desiredInlineIssues,
  issueUrl,
  type DesiredAiIssue,
  type Loaded,
} from '../decoration-data';
import type { Failures } from '../failures';
import {
  aiFindingNote,
  aiThreads,
  liveSuggestion,
  MAX_FIXED_NOTES,
  MAX_INLINE_THREADS,
  postsAiThread,
  type InlineReconciled,
} from '../inline';
import { isFullSha, markerOf, notedFixes } from '../markdown';
import { ScmError } from '../provider';
import { AI_THREAD_SEVERITIES } from '../../review/rules';
import { fixedNote, inlineBody, reopenedNote, resolvedNote } from '../render';
import { azureAddedLines } from './added-lines';
import {
  azureThreadOpen,
  machineMadeComment as machineMade,
  sameAzureIdentity as sameId,
  type AzureDevOpsClient,
  type AzureIteration,
  type AzureThread,
} from './client';

export { MAX_AZURE_DIFF_FILES } from './added-lines';

/**
 * Ruling P2: at most this many threads are resolved, reopened or given a lost reopened comment by
 * one job; the rest wait for the branch's next decoration. An update is at most a status PATCH and
 * one comment: two requests.
 */
export const MAX_AZURE_THREAD_UPDATES = 100;
/** Pages of the analysed iteration's changes one job reads (100 files each). */
export const MAX_AZURE_CHANGE_PAGES = 10;
/**
 * The requests of a pull request's decoration that no bound above covers: the identity, the pull
 * request, its iterations, the pages of changes, the thread listing, the status's read and write,
 * the summary's listing and its one write, and a branch analysis' commit status.
 */
export const AZURE_REQUESTS_OUTSIDE_THREADS = 1 + 1 + 1 + MAX_AZURE_CHANGE_PAGES + 1 + 2 + 2 + 1;

/** What the thread reconciliation is given: everything the decoration has read so far. */
export interface AzureThreadsContext {
  deps: Pick<DecorationDeps, 'db' | 'publicUrl'>;
  client: AzureDevOpsClient;
  loaded: Loaded;
  repositoryId: string;
  prId: number;
  /** The iteration holding the analysed commit (the pull request's newest). */
  analysed: AzureIteration;
  /** The pull request's head commit now: the AI review's threads are posted only while it is the reviewed one. */
  liveHead: string | null;
  /**
   * Whether the analyzers' issues are Qualor's to comment: false when the pipeline did not check
   * out the head, so their line numbers are not the pull request's. The AI review's threads do
   * not depend on it: they are placed on the live diff at the reviewed head.
   */
  analyzers: boolean;
  /** Qualor's identity in Azure DevOps (the author of its threads). */
  identityId: string;
  /** Where the failures of single writes are kept: the job goes on, or stops on a rate limit. */
  failures: Failures;
}

/** One of Qualor's threads for an issue, as the listing shows it. */
interface OwnThread {
  thread: AzureThread;
  /** Qualor's `qualor:fixed` comment for the issue is the last non-system comment. */
  fixedLast: boolean;
  /** Resolved by Qualor: not open (neither active nor pending), {@link fixedLast}, no person replied. */
  resolvedByQualor: boolean;
  /** Someone but Qualor commented after its first comment. */
  humanReplied: boolean;
  /** The revisions Qualor's comments in the thread say its issue was fixed at. */
  notedFixes: ReadonlySet<string>;
}

/**
 * Qualor's threads by issue id: a thread whose first comment is by the identity and starts with an
 * issue marker. A marker in anyone else's comment is ignored; of two threads for one issue the
 * first (the older) is the issue's; a system thread has no status and is never one.
 */
function ownThreads(threads: readonly AzureThread[], identityId: string): Map<string, OwnThread> {
  const own = new Map<string, OwnThread>();
  for (const thread of threads) {
    const comments = thread.comments.filter((c) => !machineMade(c.commentType));
    const first = comments[0];
    if (thread.status === null || first === undefined || !sameId(first.authorId, identityId)) {
      continue;
    }
    const marker = markerOf(first.content);
    if (marker?.kind !== 'issue' || own.has(marker.issueId)) continue;
    const replies = comments.slice(1);
    const last = comments[comments.length - 1];
    const lastMarker =
      last !== undefined && sameId(last.authorId, identityId) ? markerOf(last.content) : null;
    const fixedLast = lastMarker?.kind === 'fixed' && lastMarker.issueId === marker.issueId;
    const humanReplied = replies.some((c) => !sameId(c.authorId, identityId));
    own.set(marker.issueId, {
      thread,
      fixedLast,
      resolvedByQualor: !azureThreadOpen(thread.status) && fixedLast && !humanReplied,
      humanReplied,
      notedFixes: notedFixes(
        replies.filter((c) => sameId(c.authorId, identityId)).map((c) => c.content),
        marker.issueId,
      ),
    });
  }
  return own;
}

/** The issues of this project that Qualor's threads are for, by id (another project's are left out). */
async function threadIssues(db: Db, projectId: string, ids: string[]) {
  const rows =
    ids.length === 0
      ? []
      : await db
          .select({
            id: issues.id,
            branchId: issues.branchId,
            status: issues.status,
            duplicateOf: issues.duplicateOfIssueId,
            engineId: rules.engineId,
          })
          .from(issues)
          .innerJoin(rules, eq(rules.id, issues.ruleId))
          .where(and(inArray(issues.id, ids), eq(issues.projectId, projectId)));
  return new Map(rows.map((row) => [row.id, row]));
}

/** What one of Qualor's threads needs from this job. */
type ThreadUpdate = 'resolve' | 'reopen' | 'note';

/**
 * What a thread of Qualor's needs: resolving, reopening, its lost reopened comment alone (`note`),
 * or nothing (null). A thread is resolved by Qualor exactly when it is not open (neither `active` nor `pending`: a
 * pending thread is under review, so Qualor never reopens it and never resolves it), Qualor's
 * `qualor:fixed` comment is its last non-system comment, and no person replied in it (Qualor never
 * resolves a thread anyone replied in, so a resolved one with a reply was resolved by a person).
 * Only that is Qualor's to undo (ruling G3); any other resolution stays, and its issue still counts.
 *
 * An active thread of an open issue that still ends with Qualor's `qualor:fixed` comment lost a
 * write: a reopening whose comment failed, or a resolution whose status change failed. It gets the
 * `qualor:reopened` comment and no status change; were it left so, a person's later silent
 * resolution would look like Qualor's, and Qualor would undo it.
 */
function threadUpdate(own: OwnThread, open: boolean): ThreadUpdate | null {
  if (open && own.resolvedByQualor) return 'reopen';
  if (open && own.thread.status === 'active' && own.fixedLast && !own.humanReplied) return 'note';
  if (!open && own.thread.status === 'active' && !own.humanReplied) return 'resolve';
  return null;
}

/**
 * One write of the job: its failure is kept (a rate limit or the request budget stops the job),
 * except a thread that is gone (a person deleted it after the listing). True when it was done.
 */
async function write(failures: Failures, part: () => Promise<unknown>): Promise<boolean> {
  try {
    await part();
    return true;
  } catch (err) {
    if (!(err instanceof ScmError && err.kind === 'not_found')) failures.add(err);
    return false;
  }
}

/** What the thread reconciliation worked out about the existing threads. */
interface Plan {
  updates: {
    issueId: string;
    thread: AzureThread;
    action: ThreadUpdate;
    fixedLast: boolean;
    /** An AI review thread: never counted in `commented`, so never taken off it either. */
    reviewed: boolean;
  }[];
  /** The fixed issues whose open threads someone replied in, the oldest thread first. */
  fixed: string[];
  /** The analyzers' open issues with a thread (the AI review's are not counted). */
  commented: number;
}

async function planUpdates(
  ctx: AzureThreadsContext,
  own: ReadonlyMap<string, OwnThread>,
): Promise<Plan> {
  const known = await threadIssues(ctx.deps.db, ctx.loaded.project.id, [...own.keys()]);
  const plan: Plan = { updates: [], fixed: [], commented: 0 };
  // In the order of the listing, the oldest first: what the bound leaves for the next job is the
  // same on every run.
  for (const [issueId, mine] of own) {
    const issue = known.get(issueId);
    if (issue === undefined) continue;
    // Without `analyzers` their threads are left as they are.
    if (!ctx.analyzers && issue.engineId !== AI_ENGINE) continue;
    // The AI review's threads are reconciled like the analyzers' but not counted: the summary's
    // count is the analyzers' (GitLab's `reviewed` rule).
    const reviewed = issue.engineId === AI_ENGINE;
    const onBranch = issue.branchId === ctx.loaded.branch.id;
    const open = onBranch && issue.status === 'open' && issue.duplicateOf === null;
    if (open && !reviewed) plan.commented += 1;
    const action = threadUpdate(mine, open);
    if (action !== null && plan.updates.length < MAX_AZURE_THREAD_UPDATES) {
      plan.updates.push({
        issueId,
        thread: mine.thread,
        action,
        fixedLast: mine.fixedLast,
        reviewed,
      });
    }
    if (
      onBranch &&
      issue.status === 'closed' &&
      azureThreadOpen(mine.thread.status) &&
      mine.humanReplied
    ) {
      plan.fixed.push(issueId);
    }
  }
  return plan;
}

/**
 * The resolutions, reopenings and lost reopened comments. A resolution writes its comment first,
 * so a failure between the two leaves an active thread that the next job resolves again, never a
 * resolved thread that looks like a person's; a reopening changes the status first, so a failure
 * between them leaves an active thread with Qualor's fixed comment last, which the next job gives
 * its reopened comment alone (`note`). Returns how many issues that count (the analyzers', not the
 * AI review's) are left without an active thread: their reopening's status change failed.
 */
async function applyUpdates(
  ctx: AzureThreadsContext,
  plan: Plan,
  revisions: ReadonlyMap<string, string>,
): Promise<number> {
  const { client, repositoryId, prId, failures } = ctx;
  const revision = ctx.loaded.revision.toLowerCase();
  const reopenedComment = (update: Plan['updates'][number]) =>
    write(failures, () =>
      client.addComment(
        repositoryId,
        prId,
        update.thread.id,
        reopenedNote(update.issueId, revision),
      ),
    );
  let lost = 0;
  for (const update of plan.updates) {
    if (failures.stop !== null) break;
    const id = update.thread.id;
    if (update.action === 'resolve') {
      const sha = revisions.get(update.issueId) ?? revision;
      // No full revision to name (a marker holds one only): the thread waits.
      if (!update.fixedLast && !isFullSha(sha)) continue;
      // Qualor's fixed comment is already the last (an earlier job's status change failed, or a
      // person reopened the thread without a word): only the status is sent, one note a time.
      const noted =
        update.fixedLast ||
        (await write(failures, () =>
          client.addComment(repositoryId, prId, id, resolvedNote(update.issueId, sha)),
        ));
      if (noted) {
        await write(failures, () => client.setThreadStatus(repositoryId, prId, id, 'fixed'));
      }
    } else if (update.action === 'reopen') {
      if (await write(failures, () => client.setThreadStatus(repositoryId, prId, id, 'active'))) {
        await reopenedComment(update);
      } else if (!update.reviewed) {
        lost += 1;
      }
    } else {
      // The thread is active already: its issue counts, whether or not the comment is written.
      await reopenedComment(update);
    }
  }
  return lost;
}

/** The notes of fixed issues in the open threads a person replied in, one per revision. */
async function applyFixedNotes(
  ctx: AzureThreadsContext,
  own: ReadonlyMap<string, OwnThread>,
  fixed: readonly string[],
  revisions: ReadonlyMap<string, string>,
): Promise<void> {
  let written = 0;
  for (const issueId of fixed) {
    const mine = own.get(issueId);
    const sha = revisions.get(issueId);
    if (mine === undefined || sha === undefined || mine.notedFixes.has(sha)) continue;
    if (written === MAX_FIXED_NOTES || ctx.failures.stop !== null) break;
    written += 1;
    await write(ctx.failures, () =>
      ctx.client.addComment(ctx.repositoryId, ctx.prId, mine.thread.id, fixedNote(issueId, sha)),
    );
  }
}

/** What the creations of one job made. */
interface Creations {
  created: number;
  unplaced: number;
  /** The AI findings with no thread that the summary lists instead. */
  aiNotPosted: DesiredAiIssue[];
}

const NOTHING: Creations = { created: 0, unplaced: 0, aiNotPosted: [] };

/** The AI findings that got no thread this time and are listed: low ones are counted, never listed. */
const listedAiFindings = (
  waiting: readonly DesiredAiIssue[],
  posted: ReadonlySet<DesiredAiIssue>,
): DesiredAiIssue[] =>
  waiting.filter((issue) => !posted.has(issue) && AI_THREAD_SEVERITIES.has(issue.severity));

/**
 * The new threads of the most severe open new issues without one, each on an added line of the
 * pull request's iteration; the issues with no place are counted as unplaced. Then the AI review's:
 * the findings of the branch's newest finished review that have no thread (at most
 * `MAX_AI_THREADS`, the most severe first, only while the pull request is at the head that
 * review read) get one on their anchor, an added line. A suggestion is kept only when it still
 * applies to the diff, and its thread selects the lines it replaces whole; a low finding is posted for
 * its suggestion only. The findings with no thread this time are returned for the summary. Nothing
 * is created when the changes are cut by their page bound. A thread is created once: a failed
 * creation is not made again in this job.
 */
async function createThreads(
  ctx: AzureThreadsContext,
  own: ReadonlyMap<string, OwnThread>,
): Promise<Creations> {
  const { client, repositoryId, prId, analysed, failures } = ctx;
  const desired = ctx.analyzers
    ? await desiredInlineIssues(ctx.deps.db, ctx.loaded.branch.id, MAX_INLINE_THREADS)
    : [];
  const fresh = desired.filter((issue) => !own.has(issue.id));
  const ai = await aiThreads(ctx.deps.db, ctx.loaded.branch.id, ctx.liveHead, (id) => own.has(id));
  const aiCreate = ai?.create ?? [];
  const posted = new Set<DesiredAiIssue>();
  // Nothing is created, so the findings that wait are listed instead.
  const unlisted: Creations = {
    ...NOTHING,
    aiNotPosted: listedAiFindings(ai?.waiting ?? [], posted),
  };
  if (fresh.length === 0 && aiCreate.length === 0) {
    return { ...NOTHING, aiNotPosted: listedAiFindings(ai?.waiting ?? [], posted) };
  }
  let places: Map<string, ReadonlyMap<number, string>>;
  try {
    const listed = await client.iterationChanges(
      repositoryId,
      prId,
      analysed.id,
      MAX_AZURE_CHANGE_PAGES,
    );
    // The files past the page bound may hold the issues' files: place none rather than some.
    if (!listed.complete) return unlisted;
    const paths = [
      ...new Set([
        ...fresh.flatMap((issue) => (issue.path === null ? [] : [issue.path])),
        ...aiCreate.map((issue) => issue.path),
      ]),
    ];
    places = await azureAddedLines(client, repositoryId, analysed, listed.changes, paths);
  } catch (err) {
    failures.add(err);
    return unlisted;
  }
  let created = 0;
  let unplaced = 0;
  for (const issue of fresh) {
    const text =
      issue.path === null || issue.line === null
        ? undefined
        : places.get(issue.path)?.get(issue.line);
    if (issue.path === null || issue.line === null || text === undefined) {
      unplaced += 1;
      continue;
    }
    if (failures.stop !== null) break;
    const { path, line } = issue;
    const body = inlineBody({
      issueId: issue.id,
      severity: issue.severity as Severity,
      quality: issue.quality as Quality,
      ruleKey: issue.ruleKey,
      helpUri: issue.helpUri,
      message: issue.message,
      confidence: issue.confidence,
      url: issueUrl(ctx.deps.publicUrl, ctx.loaded.project.id, issue.id),
    });
    const made = await write(failures, () =>
      client.createThread(repositoryId, prId, {
        content: body,
        status: 'active',
        anchor: { filePath: path, startLine: line, endLine: line, endLineLength: text.length },
      }),
    );
    if (made) created += 1;
  }
  if (ai !== null) {
    for (const issue of aiCreate) {
      if (failures.stop !== null) break;
      const place = places.get(issue.path);
      const text = place?.get(issue.anchorLine);
      if (place === undefined || text === undefined) continue;
      const found = await liveSuggestion(ctx.deps.db, ctx.loaded.branch.id, ai.head, issue, place);
      const note = aiFindingNote(
        'azure',
        issue,
        found,
        issueUrl(ctx.deps.publicUrl, ctx.loaded.project.id, issue.id),
      );
      // The thread selects what the note kept: a suggestion's lines whole (all are added lines,
      // `liveSuggestion`), or the anchor alone when the note left it out.
      const kept = note.suggestion;
      const range =
        kept === null
          ? { startLine: issue.anchorLine, endLine: issue.anchorLine, endLineLength: text.length }
          : {
              startLine: kept.startLine,
              endLine: kept.endLine,
              endLineLength: (place.get(kept.endLine) ?? text).length,
            };
      if (!postsAiThread(issue, note)) continue;
      try {
        await client.createThread(repositoryId, prId, {
          content: note.body,
          status: 'active',
          anchor: { filePath: issue.path, ...range },
        });
        posted.add(issue);
      } catch (err) {
        // Azure DevOps refused the position (a 400): the summary lists the finding, the job goes on.
        if (err instanceof ScmError && err.kind === 'refused' && err.status === 400) continue;
        if (!(err instanceof ScmError && err.kind === 'not_found')) failures.add(err);
      }
    }
  }
  // An AI thread is not counted in `created`: the summary's count is the analyzers'.
  return {
    created,
    unplaced,
    aiNotPosted: listedAiFindings(ai?.waiting ?? [], posted),
  };
}

/** The AI findings that wait for a thread when the job stopped before creating any: all are listed. */
async function stoppedAiFindings(
  ctx: AzureThreadsContext,
  own: ReadonlyMap<string, OwnThread>,
): Promise<DesiredAiIssue[]> {
  const ai = await aiThreads(ctx.deps.db, ctx.loaded.branch.id, ctx.liveHead, (id) => own.has(id));
  return listedAiFindings(ai?.waiting ?? [], new Set());
}

/**
 * Qualor's inline threads on an open pull request whose newest iteration was analysed at its head.
 * For the threads of this project's analyzer issues (design §7.4, thread properties cannot be
 * changed, so Qualor's comments carry the state):
 * - an open issue whose thread Qualor resolved gets it reopened, with a `qualor:reopened` comment.
 *   The rule for "resolved by Qualor" is {@link threadUpdate}'s; a resolution of a person's
 *   stays, and its issue still counts (ruling G3). An active thread of an open issue that still
 *   ends with Qualor's `qualor:fixed` comment (a write of an earlier job failed) gets the
 *   `qualor:reopened` comment alone;
 * - an issue that is no longer open gets its thread resolved, with a `qualor:fixed` comment, unless
 *   someone but Qualor commented in it. Its comment is skipped when Qualor's `qualor:fixed` comment
 *   for the issue is already the last (a retry, or a person reopened it silently): one note a time;
 * - a fixed issue whose open thread someone replied in gets one note per revision
 *   ({@link MAX_FIXED_NOTES} a job);
 * - then each of the (at most {@link MAX_INLINE_THREADS}) most severe open new issues without a
 *   thread gets one on an added line, or counts as unplaced.
 * At most {@link MAX_AZURE_THREAD_UPDATES} threads are changed a job. A thread is never deleted and
 * its first comment never edited. A failure to list the threads throws; a failed write is kept in
 * `failures` and the job goes on, unless it is a rate limit or the request budget.
 */
export async function reconcileAzureThreads(ctx: AzureThreadsContext): Promise<InlineReconciled> {
  const listed = await ctx.client.threads(ctx.repositoryId, ctx.prId);
  const own = ownThreads(listed, ctx.identityId);
  const plan = await planUpdates(ctx, own);
  const revisions = await closingRevisions(ctx.deps.db, [
    ...plan.fixed,
    ...plan.updates.filter((u) => u.action === 'resolve').map((u) => u.issueId),
  ]);
  const lost = await applyUpdates(ctx, plan, revisions);
  await applyFixedNotes(ctx, own, plan.fixed, revisions);
  const creations =
    ctx.failures.stop === null
      ? await createThreads(ctx, own)
      : { created: 0, unplaced: 0, aiNotPosted: await stoppedAiFindings(ctx, own) };
  return {
    commented: plan.commented - lost + creations.created,
    unplaced: creations.unplaced,
    aiNotPosted: creations.aiNotPosted,
  };
}

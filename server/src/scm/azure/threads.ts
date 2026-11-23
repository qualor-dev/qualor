import type { Quality, Severity } from '@qualor/shared';
import { and, eq, inArray } from 'drizzle-orm';
import type { Db } from '../../db/client';
import { issues, rules } from '../../db/schema';
import { AI_ENGINE } from '../../rules/server-engines';
import type { DecorationDeps } from '../decorate';
import { closingRevisions, desiredInlineIssues, issueUrl, type Loaded } from '../decoration-data';
import type { Failures } from '../failures';
import { MAX_FIXED_NOTES, MAX_INLINE_THREADS, type InlineResult } from '../inline';
import { addedLines } from '../line-diff';
import { fixedMarker, isFullSha, markerOf, notedFixes, reopenedMarker } from '../markdown';
import { ScmError } from '../provider';
import { fixedNote, inlineBody } from '../render';
import type { AzureChange, AzureDevOpsClient, AzureIteration, AzureThread } from './client';

/**
 * Ruling P2: at most this many threads are resolved, reopened or given a lost reopened comment by
 * one job; the rest wait for the branch's next decoration. An update is at most a status PATCH and
 * one comment: two requests.
 */
export const MAX_AZURE_THREAD_UPDATES = 100;
/** Files whose two versions one job reads to find the added lines: the rest are unplaced. */
export const MAX_AZURE_DIFF_FILES = 40;
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
  /** Resolved by Qualor: not active, {@link fixedLast}, and no person replied in it. */
  resolvedByQualor: boolean;
  /** Someone but Qualor commented after its first comment. */
  humanReplied: boolean;
  /** The revisions Qualor's comments in the thread say its issue was fixed at. */
  notedFixes: ReadonlySet<string>;
}

const sameId = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/** Comments the server writes itself (a push, a changed file) are nobody's reply. */
const machineMade = (commentType: string): boolean =>
  commentType === 'system' || commentType === 'codeChange';

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
      resolvedByQualor: thread.status !== 'active' && fixedLast && !humanReplied,
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
 * or nothing (null). A thread is resolved by Qualor exactly when it is not active, Qualor's
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

/** Fixed text of the comment that goes with a resolution: its marker, and the revision it was found at. */
function resolvedNote(issueId: string, sha: string): string {
  return [
    fixedMarker(issueId, sha),
    `Fixed in \`${sha.slice(0, 7)}\`. Qualor resolved this thread because the issue is gone.`,
  ].join('\n');
}

/** Fixed text of the comment that goes with a reopening. */
function reopenedNote(issueId: string): string {
  return [reopenedMarker(issueId), 'The issue is back, so Qualor reopened this thread.'].join('\n');
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
  }[];
  /** The fixed issues whose open threads someone replied in, the oldest thread first. */
  fixed: string[];
  /** The analyzers' open issues with a thread. */
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
    // The AI review's threads are not Azure DevOps' yet: none is Qualor's to touch.
    if (issue === undefined || issue.engineId === AI_ENGINE) continue;
    const onBranch = issue.branchId === ctx.loaded.branch.id;
    const open = onBranch && issue.status === 'open' && issue.duplicateOf === null;
    if (open) plan.commented += 1;
    const action = threadUpdate(mine, open);
    if (action !== null && plan.updates.length < MAX_AZURE_THREAD_UPDATES) {
      plan.updates.push({ issueId, thread: mine.thread, action, fixedLast: mine.fixedLast });
    }
    if (
      onBranch &&
      issue.status === 'closed' &&
      mine.thread.status === 'active' &&
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
 * its reopened comment alone (`note`). Returns how many issues that count are left without an
 * active thread: their reopening's status change failed.
 */
async function applyUpdates(
  ctx: AzureThreadsContext,
  plan: Plan,
  revisions: ReadonlyMap<string, string>,
): Promise<number> {
  const { client, repositoryId, prId, failures } = ctx;
  const reopenedComment = (update: Plan['updates'][number]) =>
    write(failures, () =>
      client.addComment(repositoryId, prId, update.thread.id, reopenedNote(update.issueId)),
    );
  let lost = 0;
  for (const update of plan.updates) {
    if (failures.stop !== null) break;
    const id = update.thread.id;
    if (update.action === 'resolve') {
      const sha = revisions.get(update.issueId) ?? ctx.loaded.revision.toLowerCase();
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
      } else {
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

/** The change that holds `path`, unless the file was deleted. */
const changeOf = (changes: readonly AzureChange[], path: string): AzureChange | null => {
  const change = changes.find((c) => c.path === path);
  return change === undefined || change.changeType.toLowerCase().includes('delete') ? null : change;
};

/**
 * The added lines (line number to text) of each of `paths` that the pull request changed, at most
 * {@link MAX_AZURE_DIFF_FILES} files: the file at the head against the file at the common commit
 * (the original path of a renamed one; none for an added file). A path missing from the result has
 * no place for a comment: deleted, binary, too large or missing, not in the changes, too different
 * to diff, or beyond the bound.
 */
async function placesOf(
  ctx: AzureThreadsContext,
  paths: readonly string[],
  changes: readonly AzureChange[],
): Promise<Map<string, ReadonlyMap<number, string>>> {
  const places = new Map<string, ReadonlyMap<number, string>>();
  for (const path of paths.slice(0, MAX_AZURE_DIFF_FILES)) {
    const change = changeOf(changes, path);
    if (change === null) continue;
    const head = await ctx.client.fileText(ctx.repositoryId, path, ctx.analysed.sourceRefCommit);
    if ('skipped' in head) continue;
    let base: string | null = null;
    if (!change.changeType.toLowerCase().includes('add')) {
      const original = await ctx.client.fileText(
        ctx.repositoryId,
        change.originalPath ?? path,
        ctx.analysed.commonRefCommit,
      );
      if ('skipped' in original) continue;
      base = original.text;
    }
    const added = addedLines(base, head.text);
    if (added !== null) places.set(path, added);
  }
  return places;
}

/**
 * The new threads of the most severe open new issues without one, each on an added line of the
 * pull request's iteration; the issues with no place are counted as unplaced. Nothing is created
 * when the changes are cut by their page bound. A thread is created once: a failed creation is not
 * made again in this job.
 */
async function createThreads(
  ctx: AzureThreadsContext,
  own: ReadonlyMap<string, OwnThread>,
): Promise<{ created: number; unplaced: number }> {
  const desired = await desiredInlineIssues(ctx.deps.db, ctx.loaded.branch.id, MAX_INLINE_THREADS);
  const fresh = desired.filter((issue) => !own.has(issue.id));
  if (fresh.length === 0) return { created: 0, unplaced: 0 };
  const { client, repositoryId, prId, analysed, failures } = ctx;
  let places: Map<string, ReadonlyMap<number, string>>;
  try {
    const listed = await client.iterationChanges(
      repositoryId,
      prId,
      analysed.id,
      MAX_AZURE_CHANGE_PAGES,
    );
    // The files past the page bound may hold the issues' files: place none rather than some.
    if (!listed.complete) return { created: 0, unplaced: 0 };
    const paths = [...new Set(fresh.flatMap((issue) => (issue.path === null ? [] : [issue.path])))];
    places = await placesOf(ctx, paths, listed.changes);
  } catch (err) {
    failures.add(err);
    return { created: 0, unplaced: 0 };
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
        filePath: path,
        line,
        lineLength: text.length,
      }),
    );
    if (made) created += 1;
  }
  return { created, unplaced };
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
export async function reconcileAzureThreads(ctx: AzureThreadsContext): Promise<InlineResult> {
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
    ctx.failures.stop === null ? await createThreads(ctx, own) : { created: 0, unplaced: 0 };
  return { commented: plan.commented - lost + creations.created, unplaced: creations.unplaced };
}

import type { Quality, Severity } from '@qualor/shared';
import { and, eq, inArray } from 'drizzle-orm';
import type { Db } from '../db/client';
import { issues } from '../db/schema';
import { desiredInlineIssues } from './decoration-data';
import {
  GitLabError,
  type GitLabClient,
  type GitLabDiff,
  type GitLabDiscussion,
  type GitLabMergeRequest,
} from './gitlab/client';
import { markerOf } from './markdown';
import { inlineBody } from './render';

/** scm.md §4.3: pages of discussions one job reads at most ... */
export const MAX_DISCUSSION_PAGES = 50;
/** ... and pages of the merge request's diffs. */
export const MAX_DIFF_PAGES = 30;
/** scm.md §5.4: at most this many issues are commented inline per merge request ... */
export const MAX_INLINE_THREADS = 50;
/**
 * ... and at most this many threads are resolved or reopened by one job; the rest wait for the
 * branch's next decoration. With {@link REQUESTS_OUTSIDE_INLINE} and the creations this keeps a
 * job within its 400 requests (scm.md §4.3), so the summary is always written.
 */
export const MAX_THREAD_UPDATES = 200;
/**
 * The most requests a job makes besides creating, resolving and reopening threads: the project,
 * the user, the merge request, the commit status (a read, a post and its retry without the
 * pipeline), the summary, and every page of discussions and diffs it may read.
 */
export const REQUESTS_OUTSIDE_INLINE = 7 + MAX_DISCUSSION_PAGES + MAX_DIFF_PAGES;

export interface InlineContext {
  db: Db;
  client: GitLabClient;
  /** The GitLab project id. */
  ref: string;
  iid: string;
  /** The Qualor project: only threads of its own issues are touched (a monorepo, §5.3). */
  projectId: string;
  branchId: string;
  mr: GitLabMergeRequest;
  discussions: readonly GitLabDiscussion[];
  /** False when the page bound cut the discussions: a thread may exist unseen (§4.3). */
  discussionsComplete: boolean;
  botId: number;
  issueUrl: (issueId: string) => string | null;
  /** {@link MAX_THREAD_UPDATES} unless a test sets a smaller one. */
  maxThreadUpdates?: number;
}

export interface InlineResult {
  /** Open issues with a Qualor discussion after this run. */
  commented: number;
  /** Desired issues the diff has no place for. */
  unplaced: number;
}

/** The added lines of a unified diff (`+` lines of its hunks), by line number in the new file. */
export function addedLines(diff: string): Set<number> {
  return new Set(addedLineTexts(diff).keys());
}

/**
 * The added lines of a unified diff (GitLab's `diff`, GitHub's `patch`): new line number → text
 * without the `+` (and without a `\r` the diff kept). Context lines (a space, or an empty line)
 * count in the new file; removed lines and `\ No newline at end of file` do not.
 */
export function addedLineTexts(diff: string): Map<number, string> {
  const added = new Map<number, string>();
  let line = 0;
  for (const raw of diff.split('\n')) {
    const text = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
    if (hunk) {
      line = Number(hunk[1]);
      continue;
    }
    if (line === 0 || text.startsWith('\\')) continue;
    if (text.startsWith('+')) {
      added.set(line, text.slice(1));
      line += 1;
    } else if (text.startsWith(' ') || text === '') {
      line += 1;
    }
  }
  return added;
}

interface OwnThread {
  id: string;
  /** Every resolvable note is resolved (GitLab's `resolved` of the discussion). */
  resolved: boolean;
  /** Resolved, and every resolvable note by Qualor's own user (ruling G3). */
  resolvedByQualor: boolean;
  /** A person (not Qualor's user, not GitLab) wrote in the thread after Qualor's note. */
  humanReplied: boolean;
}

/**
 * Qualor's inline discussions by issue id (scm.md §5.3): the first note is by the token's user and
 * starts with an issue marker. A second thread of one issue (never created by Qualor) is ignored.
 */
function ownThreads(discussions: readonly GitLabDiscussion[], botId: number) {
  const threads = new Map<string, OwnThread>();
  for (const discussion of discussions) {
    const [first, ...replies] = discussion.notes;
    if (!first || first.author.id !== botId || first.system) continue;
    const marker = markerOf(first.body);
    if (marker?.kind !== 'issue' || threads.has(marker.issueId)) continue;
    const resolvable = discussion.notes.filter((n) => n.resolvable === true);
    const resolved = resolvable.length > 0 && resolvable.every((n) => n.resolved === true);
    threads.set(marker.issueId, {
      id: discussion.id,
      resolved,
      resolvedByQualor: resolved && resolvable.every((n) => n.resolved_by?.id === botId),
      humanReplied: replies.some((n) => !n.system && n.author.id !== botId),
    });
  }
  return threads;
}

/**
 * Resolves or reopens one thread; false when GitLab no longer has it (a person deleted it after
 * the listing): like a rejected position, that thread is skipped and the job goes on.
 */
async function setResolved(ctx: InlineContext, id: string, resolved: boolean): Promise<boolean> {
  try {
    await ctx.client.resolveDiscussion(ctx.ref, ctx.iid, id, resolved);
    return true;
  } catch (err) {
    if (err instanceof GitLabError && err.kind === 'not_found') return false;
    throw err;
  }
}

/**
 * scm.md §5.4: reconciles Qualor's inline discussions with the branch's open new issues. Called
 * only when the merge request's head is the analysed revision and the pipeline was not a
 * merged-results one. For the threads of this project's issues:
 * - an open issue whose thread Qualor resolved gets it reopened; one a person resolved stays so;
 * - an issue that is no longer open gets its thread resolved, unless a person replied in it;
 * - a thread of an issue this project does not have (another Qualor project of a monorepo, or an
 *   issue since deleted) is left alone.
 * Then each of the (at most {@link MAX_INLINE_THREADS}) most severe open new issues without a
 * thread gets one when the diff has a place for it, unless the discussions were cut by the page
 * bound. Threads are never deleted, and notes written by anyone else are never touched.
 */
export async function reconcileInline(ctx: InlineContext): Promise<InlineResult> {
  const threads = ownThreads(ctx.discussions, ctx.botId);
  const threadIssues = [...threads.keys()];
  const known =
    threadIssues.length === 0
      ? []
      : await ctx.db
          .select({
            id: issues.id,
            branchId: issues.branchId,
            status: issues.status,
            duplicateOf: issues.duplicateOfIssueId,
          })
          .from(issues)
          .where(and(inArray(issues.id, threadIssues), eq(issues.projectId, ctx.projectId)));
  const maxUpdates = ctx.maxThreadUpdates ?? MAX_THREAD_UPDATES;
  let commented = 0;
  let updates = 0;
  for (const issue of known) {
    const thread = threads.get(issue.id);
    if (!thread) continue;
    const open =
      issue.branchId === ctx.branchId && issue.status === 'open' && issue.duplicateOf === null;
    let resolve: boolean | null = null;
    if (open && thread.resolvedByQualor) resolve = false;
    else if (!open && !thread.resolved && !thread.humanReplied) resolve = true;
    let exists = true;
    if (resolve !== null && updates < maxUpdates) {
      updates += 1;
      exists = await setResolved(ctx, thread.id, resolve);
    }
    if (open && exists) commented += 1;
  }

  // Beyond the page bound a thread may exist unseen: never create a second one (scm.md §4.3).
  if (!ctx.discussionsComplete) return { commented, unplaced: 0 };
  const desired = await desiredInlineIssues(ctx.db, ctx.branchId, MAX_INLINE_THREADS);
  const missing = desired.filter((issue) => !threads.has(issue.id));
  if (missing.length === 0) return { commented, unplaced: 0 };
  // The position's SHAs are the merge request's own: a stale diff never gets a thread.
  const refs = ctx.mr.diff_refs;
  if (!refs?.base_sha || !refs.head_sha || !refs.start_sha) {
    return { commented, unplaced: missing.length };
  }
  // The diffs are read after the merge request: a push in between can make them newer than
  // `diff_refs`. GitLab then refuses the position (usually a 400), counted as not placed.
  const diffs = await ctx.client.mergeRequestDiffs(ctx.ref, ctx.iid, MAX_DIFF_PAGES);
  const byPath = new Map<string, { diff: GitLabDiff; added: Set<number> }>();
  for (const diff of diffs.items) {
    if (diff.deleted_file) continue;
    byPath.set(diff.new_path, { diff, added: addedLines(diff.diff) });
  }
  let unplaced = 0;
  for (const issue of missing) {
    const place = byPath.get(issue.path ?? '');
    if (!place || issue.line === null || !place.added.has(issue.line)) {
      unplaced += 1;
      continue;
    }
    const created = await ctx.client.createDiscussion(
      ctx.ref,
      ctx.iid,
      inlineBody({
        issueId: issue.id,
        severity: issue.severity as Severity,
        quality: issue.quality as Quality,
        ruleKey: issue.ruleKey,
        message: issue.message,
        url: ctx.issueUrl(issue.id),
      }),
      {
        baseSha: refs.base_sha,
        startSha: refs.start_sha,
        headSha: refs.head_sha,
        oldPath: place.diff.old_path,
        newPath: place.diff.new_path,
        newLine: issue.line,
      },
    );
    if (created === 'position_rejected') unplaced += 1;
    else commented += 1;
  }
  return { commented, unplaced };
}

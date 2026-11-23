import { deleteBranchSnapshots } from '../../review/lifecycle';
import { queueGitHubAnswers, replyWindow, type ReplyWindow } from '../../review/reply-queue';
import {
  withMergeRequestHead,
  withUnplacedFindings,
  type ReviewSummaryState,
} from '../../review/render';
import type { DecorationDeps, DecorationOutcome } from '../decorate';
import {
  branchUrl,
  comparable,
  issueUrl,
  loadReviewSummary,
  newestReviewedHead,
  recordMergeRequest,
  summaryData,
  unplacedFinding,
  type DesiredAiIssue,
  type Loaded,
  type SummaryData,
} from '../decoration-data';
import { attempt, Failures } from '../failures';
import { markerOf } from '../markdown';
import { ScmError } from '../provider';
import type { DecorationPayload } from '../queue';
import { statusName, summaryBody, type SummaryInput } from '../render';
import { installationSlotKey } from '../runtime';
import {
  GITHUB_PR_NUMBER,
  GITHUB_TEXT,
  MAX_THREAD_PAGES,
  type CheckRunUpdate,
  type GitHubCheckRun,
  type GitHubClient,
  type GitHubComment,
  type GitHubPullRequest,
} from './client';
import { githubClientFor } from './connections';
import {
  checkRunExternalId,
  checkRunSummary,
  checkRunVerdict,
  NO_ANNOTATIONS_DIGEST,
  parseCheckRunExternalId,
} from './render';
import {
  applyReviewThreads,
  MAX_COMMENT_PAGES,
  plannedCounts,
  planReviewThreads,
  type ReviewThreadContext,
  type ThreadPlan,
} from './threads';
import { githubWebBase, parseRepoRef } from './url';

/** github.md §5.3: pages of pull request files one job reads at most. */
export const MAX_FILE_PAGES = 30;
// The bound on pages of comments, of the issue comments that hold the summary and of the pull
// request's review comments alike, lives in threads.ts, which reads the review comments by it.
export { MAX_COMMENT_PAGES };
/**
 * github.md §5.3 (ruling R7): the most requests a job makes besides creating, resolving and
 * reopening review threads:
 * - the App, the installation, its token, the repository and the pull request (5);
 * - every page of files, review comments, review threads and issue comments it may read;
 * - the check run: its listing, its creation or update before the threads, and the PATCH that
 *   corrects it when applying the threads changed what it says (3);
 * - the summary: its creation or edit (1);
 * - what a token refreshed after a 401 adds: the new token and the request made again (2).
 * With the creations (`MAX_CREATION_REQUESTS`: one review, and each comment alone when GitHub
 * refuses it), the resolutions and reopenings (at most `MAX_GITHUB_THREAD_UPDATES`) and the notes
 * of fixed issues in the threads people replied in (at most `MAX_FIXED_NOTES`) this stays within
 * `MAX_GITHUB_REQUESTS`, so the check run and the summary are always written.
 */
export const REQUESTS_OUTSIDE_THREADS =
  5 + MAX_FILE_PAGES + MAX_COMMENT_PAGES + MAX_THREAD_PAGES + 3 + MAX_COMMENT_PAGES + 1 + 2;
export const REPOSITORY_MISMATCH =
  "The workflow's GitHub repository is not the repository Qualor is mapped to";

type Inline = SummaryInput['inline'];
/**
 * Nothing to say about inline comments: the analysis is not the pull request's latest, or the
 * pull request is not open, or could not be read.
 */
const NO_INLINE: Inline = { commented: 0, unplaced: 0, skipped: null };
/** Reading or changing the threads failed: the summary says they could not be updated this time. */
const NOT_UPDATED: Inline = { commented: 0, unplaced: 0, skipped: 'failed' };

/** The plan of Qualor's threads (github.md §6.4), and the context it is applied in. */
interface PlannedThreads {
  ctx: ReviewThreadContext;
  plan: ThreadPlan;
}

/** What the summary says of the threads: the analyzers' counts, and the AI findings without one. */
interface Threads {
  inline: Inline;
  /** The AI findings that got no thread this time; the summary lists them (R18). */
  aiNotPosted: readonly DesiredAiIssue[];
}

/** What the pull request part found before anything is written (github.md §5.2 step 4). */
interface PullRequestPart {
  /** Null when the analysis is not the pull request's latest, or it could not be read. */
  pull: GitHubPullRequest | null;
  /**
   * What the check run says first: the plan's counts, with the updates the App may not make
   * (`plannedCounts`), or why there are none.
   */
  inline: Inline;
  /** The threads' plan, when ruling T3 or the AI review allows one and it could be made. */
  planned: PlannedThreads | null;
  /**
   * Where to look for the people's notes Qualor answers (6I-4), for an open pull request; null
   * otherwise, and when AI review is not active for the project.
   */
  replies: ReplyWindow | null;
}
const NO_PULL_REQUEST: PullRequestPart = {
  pull: null,
  inline: NO_INLINE,
  planned: null,
  replies: null,
};

/**
 * Ruling T3: why an open pull request's analyzer threads are left as they are, or null. The AI
 * review's threads are not: their lines are those of the head the review read.
 */
function threadsSkipped(
  payload: DecorationPayload,
  pull: GitHubPullRequest,
  revision: string,
): Inline['skipped'] {
  if (payload.github?.checkout !== 'head') return 'checkout_other';
  return pull.head.sha === revision ? null : 'stale';
}

/**
 * github.md §6.4: the plan of Qualor's threads on an open pull request: the pull request's files
 * (a file the page bound cuts places no issue: its issues count as not placed) and what the threads
 * need. The analyzers' threads are in it when `analyzers`, that is when the pull request's head is
 * the analysed revision, checked out by the workflow. Reads only.
 */
async function planThreads(
  deps: DecorationDeps,
  client: GitHubClient,
  loaded: Loaded,
  pull: GitHubPullRequest,
  botLogin: string,
  analyzers: boolean,
  replies: ReplyWindow | null,
): Promise<PlannedThreads> {
  const number = loaded.branch.name;
  const files = await client.pullRequestFiles(number, MAX_FILE_PAGES);
  const ctx: ReviewThreadContext = {
    db: deps.db,
    client,
    number,
    projectId: loaded.project.id,
    branchId: loaded.branch.id,
    headSha: pull.head.sha,
    files: files.items,
    analyzers,
    botLogin,
    replies,
    issueUrl: (issueId) => issueUrl(deps.publicUrl, loaded.project.id, issueId),
    ...(deps.maxThreadUpdates === undefined ? {} : { maxThreadUpdates: deps.maxThreadUpdates }),
  };
  return { ctx, plan: await planReviewThreads(ctx) };
}

/**
 * github.md §5.2 step 4: the pull request, its title and link recorded on the branch, and for an
 * open one the plan of its threads (§6.4) and where its people's notes are looked for (6I-4).
 * Nothing is written to GitHub. The analyzers' threads are planned when ruling T3 allows it; the
 * AI review's, whenever the branch has a finished review, so a decoration of a project without one
 * reads no more than before: where no plan is made no reply is found either, and it waits for a
 * decoration that makes one. A pull request that is closed, merged ones included, loses the copies
 * of its repository the AI review kept (R16). A failure goes to `failures`: a pull request that cannot be
 * read is left as it is, with nothing said about inline comments; a plan that cannot be made leaves
 * `pull` as it is, so the summary comment is still written, and says the inline comments could not
 * be updated.
 */
async function readPullRequest(
  deps: DecorationDeps,
  client: GitHubClient,
  loaded: Loaded,
  payload: DecorationPayload,
  botLogin: string,
  failures: Failures,
): Promise<PullRequestPart> {
  let pull: GitHubPullRequest;
  try {
    pull = await client.pullRequest(loaded.branch.name);
    await recordMergeRequest(
      deps.db,
      loaded,
      { title: pull.title, url: pull.html_url },
      githubWebBase(loaded.connection.baseUrl),
    );
  } catch (err) {
    failures.add(err);
    return NO_PULL_REQUEST;
  }
  if (pull.state !== 'open') {
    if (pull.state === 'closed') await deleteBranchSnapshots(deps.db, loaded.branch.id);
    return { pull, inline: NO_INLINE, planned: null, replies: null };
  }
  const replies = await replyWindow(deps.db, loaded.project, loaded.branch.id);
  const skipped = threadsSkipped(payload, pull, loaded.revision);
  const inline: Inline = { ...NO_INLINE, skipped };
  if (skipped !== null && (await newestReviewedHead(deps.db, loaded.branch.id)) === null) {
    return { pull, inline, planned: null, replies };
  }
  try {
    const planned = await planThreads(
      deps,
      client,
      loaded,
      pull,
      botLogin,
      skipped === null,
      replies,
    );
    const { commented, unplaced, unresolved } = plannedCounts(
      planned.plan,
      client.mayResolveThreads,
    );
    return { pull, inline: { commented, unplaced, skipped, unresolved }, planned, replies };
  } catch (err) {
    failures.add(err);
    return { pull, inline: NOT_UPDATED, planned: null, replies };
  }
}

/**
 * The threads' plan applied (§6.4); a failure goes to `failures`, and its counts are unknown. The
 * analyzers' threads were skipped for the reason `skipped`, if any: the summary keeps saying so.
 */
async function applyThreads(
  planned: PlannedThreads,
  skipped: Inline['skipped'],
  failures: Failures,
): Promise<Threads> {
  const applied = await attempt(failures, () => applyReviewThreads(planned.ctx, planned.plan));
  if (applied === null) return { inline: NOT_UPDATED, aiNotPosted: [] };
  const { commented, unplaced, unresolved, aiNotPosted } = applied;
  return { inline: { commented, unplaced, skipped, unresolved }, aiNotPosted };
}

/** github.md §6.1: the check run of this analysis, its summary the summary comment's `body`. */
function checkRunFields(deps: DecorationDeps, loaded: Loaded, body: string): CheckRunUpdate {
  const { conclusion, title } = checkRunVerdict(loaded.gate);
  return {
    conclusion,
    title,
    summary: checkRunSummary(body),
    detailsUrl: branchUrl(deps.publicUrl, loaded),
    externalId: checkRunExternalId(loaded.analysis.id, NO_ANNOTATIONS_DIGEST),
  };
}

/** A check run of Qualor's already says what `desired` says. */
function says(run: GitHubCheckRun, desired: CheckRunUpdate): boolean {
  return (
    run.conclusion === desired.conclusion &&
    (run.output.title ?? '') === desired.title &&
    comparable(run.output.summary ?? '') === comparable(desired.summary) &&
    // GitHub fills in a details URL of its own when none is sent: compare only one Qualor sent.
    (desired.detailsUrl === null || run.details_url === desired.detailsUrl) &&
    run.external_id === desired.externalId
  );
}

/**
 * github.md §6.1: Qualor's check run of this name on the revision, read before written. One with
 * the digest of no annotations (every check run Qualor writes has it, and a 0.11 one without
 * annotations) that says what `desired` says → nothing; the same digest and anything else changed
 * → PATCH. None of Qualor's, or the newest has another digest (a 0.11 check run with annotations,
 * which GitHub cannot take off it) → a new check run, which GitHub shows (and branch protection
 * uses) in its place. Returns the id of the check run that now says it.
 */
async function reconcileCheckRun(
  client: GitHubClient,
  name: string,
  revision: string,
  desired: CheckRunUpdate,
): Promise<number> {
  const current =
    (await client.checkRuns(revision, name))
      .map((run) => ({ run, ids: parseCheckRunExternalId(run.external_id) }))
      .filter((c) => c.ids !== null)
      .sort((x, y) => y.run.id - x.run.id)[0] ?? null;
  if (current === null || current.ids?.digest !== NO_ANNOTATIONS_DIGEST) {
    return (await client.createCheckRun({ ...desired, name, headSha: revision })).id;
  }
  if (!says(current.run, desired)) await client.updateCheckRun(current.run.id, desired);
  return current.run.id;
}

/**
 * github.md §6.2–§6.3: the summary comment, recognised by the App's bot login and the marker.
 * Answers the comments it listed, which hold the commands people gave (6I-4): the ones it saw when
 * the page bound cut the listing.
 */
async function reconcileComment(
  deps: DecorationDeps,
  client: GitHubClient,
  loaded: Loaded,
  number: string,
  body: string,
  slug: string,
): Promise<readonly GitHubComment[]> {
  const listed = await client.issueComments(number, MAX_COMMENT_PAGES);
  const login = `${slug}[bot]`;
  const own = listed.items.find((c) => {
    if (c.user?.type !== 'Bot' || c.user.login !== login || c.body === null) return false;
    const marker = markerOf(c.body);
    return marker?.kind === 'summary' && marker.projectId === loaded.project.id;
  });
  if (own) {
    if (comparable(own.body ?? '') !== comparable(body)) await client.updateComment(own.id, body);
  } else if (listed.complete) {
    await client.createComment(number, body);
  } else {
    // Beyond the page bound the summary may exist unseen: never post a second one.
    deps.logger?.warn(
      { analysisId: loaded.analysis.id, connectionId: loaded.connection.id },
      'GitHub pull request has too many comments to find the Qualor summary; not posting one',
    );
  }
  return listed.items;
}

/**
 * The summary comment's body (github.md §6.2) with `threads.inline` as its sentence on inline
 * comments and `review` as the state of the AI review (the pull request's head as it is now, when
 * it is known), which lists the findings in `threads.aiNotPosted` with the ones on no changed line.
 */
function summaryFor(
  deps: DecorationDeps,
  loaded: Loaded,
  data: SummaryData,
  review: ReviewSummaryState | null,
  pull: GitHubPullRequest | null,
  threads: Threads,
): string {
  return summaryBody({
    projectId: loaded.project.id,
    revision: loaded.revision,
    gate: loaded.gate,
    newIssues: data.newIssues,
    topIssues: data.top,
    topIssuesTotal: data.total,
    inline: threads.inline,
    branchUrl: branchUrl(deps.publicUrl, loaded),
    mergeRequestHead: pull !== null && pull.head.sha !== loaded.revision ? pull.head.sha : null,
    vocabulary: 'github',
    smallChangesetLines: data.smallChangesetLines,
    review: withUnplacedFindings(
      withMergeRequestHead(review, pull?.head.sha ?? null),
      threads.aiNotPosted.map((issue) =>
        unplacedFinding(issue, issueUrl(deps.publicUrl, loaded.project.id, issue.id)),
      ),
    ),
  });
}

/**
 * github.md §5.2 steps 5–7, in this order: the check run, saying what the plan will do (as
 * GitLab's commit status comes first); the threads; the summary comment, saying what came of
 * them; the check run once more only when that differs from what it said (a position GitHub
 * refused, a thread gone, a failure); and last the answers to the people's notes (6I-4), which the
 * plan and the comments the summary read hold. A stop ends the job at once once the check run is
 * written. Returns the error the job fails with, or null.
 */
async function writeDecoration(
  deps: DecorationDeps,
  client: GitHubClient,
  loaded: Loaded,
  part: PullRequestPart,
  slug: string,
  failures: Failures,
): Promise<ScmError | null> {
  const data = await summaryData(deps.db, loaded, deps.publicUrl);
  const review = await loadReviewSummary(deps.db, loaded.analysis.id, deps.publicUrl);
  const expected: Threads = {
    inline: part.inline,
    aiNotPosted: part.planned?.plan.aiNotPosted ?? [],
  };
  const planned = summaryFor(deps, loaded, data, review, part.pull, expected);
  const name = statusName(loaded.project.key);
  const runId = await attempt(failures, () =>
    reconcileCheckRun(client, name, loaded.revision, checkRunFields(deps, loaded, planned)),
  );
  if (failures.stop !== null) return failures.stop;
  const threads =
    part.planned === null
      ? expected
      : await applyThreads(part.planned, part.inline.skipped, failures);
  if (failures.stop !== null) return failures.stop;
  const unresolved = threads.inline.unresolved ?? 0;
  if (unresolved > 0) {
    deps.logger?.info(
      { analysisId: loaded.analysis.id, connectionId: loaded.connection.id, unresolved },
      'GitHub conversations not resolved or reopened: the GitHub App needs Contents: Read and write',
    );
  }
  const body = summaryFor(deps, loaded, data, review, part.pull, threads);
  let comments: readonly GitHubComment[] = [];
  if (part.pull?.state === 'open') {
    comments =
      (await attempt(failures, () =>
        reconcileComment(deps, client, loaded, loaded.branch.name, body, slug),
      )) ?? [];
  }
  const changed = checkRunSummary(body) !== checkRunSummary(planned);
  if (runId !== null && changed && failures.stop === null) {
    await attempt(failures, () => client.updateCheckRun(runId, checkRunFields(deps, loaded, body)));
  }
  // Last: what GitHub shows is written before the database takes more work. The replies are the
  // ones the plan found in its listings, and the commands are among the comments the summary's
  // listing read (none when it could not be read). Without a window AI review is not active for
  // the project, and Qualor answers none (6I-4).
  await queueGitHubAnswers(
    deps.db,
    { projectId: loaded.project.id, branchId: loaded.branch.id },
    part.replies,
    `${slug}[bot]`,
    { rounds: part.planned?.plan.rounds ?? [], comments },
  );
  return failures.decisive();
}

/**
 * One GitHub decoration (github.md §5.2): the App, the installation and the repository; for the
 * branch's latest analysis of an open pull request, the plan of its review threads (§6.4), which
 * only reads; the check run of the revision (§6.1), which carries no annotations and says what the
 * plan will do; the threads, their new comments as one review; the summary comment with what came
 * of them; and the check run once more when that changed. A rate limit or the exhausted budget
 * ends the job once the check run is written; any other failure of the pull request part lets the
 * rest go on (the summary then says the inline comments could not be updated this time). Only a
 * transient failure or a rate limit is retried (by the caller, through `failed`); any other error
 * stops the job.
 */
export async function decorateGitHub(
  deps: DecorationDeps,
  payload: DecorationPayload,
  loaded: Loaded,
  failed: (error: ScmError) => DecorationOutcome,
): Promise<DecorationOutcome> {
  const { connection, branch, project, analysis } = loaded;
  // The key is decrypted and the base URL checked against the current rules (scm.md §2.1,
  // github.md §2.2) before any request; the worker's token cache and pacer are shared.
  const found = githubClientFor(connection, deps.scm, deps.runtime);
  if ('problem' in found) return failed(new ScmError('refused', found.problem));
  const ref = parseRepoRef(project.scmProjectRef ?? '');
  if (ref === null) {
    return failed(new ScmError('refused', GITHUB_TEXT.notFound, { reason: 'invalid_input' }));
  }
  const client = found.client;
  try {
    const app = await client.app();
    const repo = await client.useRepository(ref);
    const expected = payload.github?.repositoryId;
    if (expected !== undefined && String(repo.id) !== expected) {
      return failed(new ScmError('refused', REPOSITORY_MISMATCH));
    }
    // One decoration of an installation at a time (inside the organisation's slot): two reviews
    // posted together draw GitHub's secondary rate limit. A busy installation is asked again soon.
    const slot =
      client.installationId === null
        ? null
        : installationSlotKey(connection.baseUrl, client.installationId);
    if (slot !== null && !deps.runtime.installationSlots.tryTake(slot)) {
      return { kind: 'busy', branchId: branch.id };
    }
    try {
      const failures = new Failures();
      // An analysis that is no longer the branch's latest leaves the threads and the summary as
      // they are, and says nothing about them.
      const latest =
        branch.kind === 'merge_request' &&
        GITHUB_PR_NUMBER.test(branch.name) &&
        branch.lastAnalysisId === analysis.id;
      const part = latest
        ? await readPullRequest(deps, client, loaded, payload, `${app.slug}[bot]`, failures)
        : NO_PULL_REQUEST;
      const error = await writeDecoration(deps, client, loaded, part, app.slug, failures);
      return error === null ? { kind: 'done', connectionId: connection.id } : failed(error);
    } finally {
      if (slot !== null) deps.runtime.installationSlots.release(slot);
    }
  } catch (err) {
    if (err instanceof ScmError) return failed(err);
    throw err;
  }
}

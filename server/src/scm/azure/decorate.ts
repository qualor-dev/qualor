import { deleteBranchSnapshots } from '../../review/lifecycle';
import { withMergeRequestHead } from '../../review/render';
import type { DecorationDeps, DecorationOutcome } from '../decorate';
import {
  branchUrl,
  comparable,
  loadReviewSummary,
  recordMergeRequest,
  summaryData,
  type Loaded,
  type SummaryData,
} from '../decoration-data';
import { attempt, Failures } from '../failures';
import { markerOf } from '../markdown';
import { ScmError } from '../provider';
import type { DecorationPayload } from '../queue';
import { azureStatusFor, statusName, summaryBody, type SummaryInput } from '../render';
import {
  AZURE_PR_ID,
  AzureError,
  type AzureDevOpsClient,
  type AzureIteration,
  type AzurePullRequest,
  type AzureStatus,
  type AzureThread,
} from './client';
import { azureClientFor } from './connections';
import { azureWebBase } from './url';

export const AZURE_REPOSITORY_MISMATCH =
  "The pipeline's Azure Repos repository is not the repository Qualor is mapped to";

type Inline = SummaryInput['inline'];
/** Nothing to say about inline comments: no comment was created or changed, and none is owed. */
const NO_INLINE: Inline = { commented: 0, unplaced: 0, skipped: null };
/** Reading or changing the threads failed: the summary says they could not be updated this time. */
const NOT_UPDATED: Inline = { commented: 0, unplaced: 0, skipped: 'failed' };

/** What Task 6's thread reconciliation is given: everything the decoration has read so far. */
export interface AzureThreadsInput {
  deps: DecorationDeps;
  client: AzureDevOpsClient;
  loaded: Loaded;
  repositoryId: string;
  prId: number;
  pullRequest: AzurePullRequest;
  /** The iteration holding the analysed commit (the pull request's newest). */
  analysed: AzureIteration;
  /** Qualor's identity in Azure DevOps (the author of its threads). */
  identityId: string;
}

/**
 * Where Task 6 plugs in `reconcileAzureThreads`: Qualor's inline threads for the analysed
 * iteration, between the status and the summary. Called only when the analysis is the pull
 * request's newest iteration and the pipeline checked out its head. Until then it changes nothing
 * and reports no inline comments.
 */
function reconcileThreads(input: AzureThreadsInput): Promise<Inline> {
  void input;
  return Promise.resolve(NO_INLINE);
}

/** The newest iteration (the highest id) whose source commit is `revision`, or null. */
function iterationOf(
  iterations: readonly AzureIteration[],
  revision: string,
): AzureIteration | null {
  const wanted = revision.toLowerCase();
  let found: AzureIteration | null = null;
  for (const i of iterations) {
    if (i.sourceRefCommit === wanted && (found === null || i.id > found.id)) found = i;
  }
  return found;
}

/** Posts `status` on the iteration unless the newest status there of this name already says it. */
async function reconcilePullRequestStatus(
  client: AzureDevOpsClient,
  repositoryId: string,
  prId: number,
  status: AzureStatus,
): Promise<void> {
  // The newest status of this name is the one with the highest id: the list's order says nothing.
  const current = (await client.iterationStatuses(repositoryId, prId, status.iterationId))
    .filter((s) => s.name === status.name)
    .reduce<{ id: number; state: string; description: string } | null>(
      (newest, s) => (newest === null || s.id > newest.id ? s : newest),
      null,
    );
  if (current?.state === status.state && current.description === status.description) return;
  await client.postPullRequestStatus(repositoryId, prId, status);
}

/** The thread of Qualor's summary: its first comment is the identity's and carries the marker. */
function ownSummary(
  threads: readonly AzureThread[],
  identityId: string,
  projectId: string,
): { threadId: number; commentId: number; content: string } | null {
  for (const thread of threads) {
    const first = thread.comments[0];
    if (first === undefined || first.authorId !== identityId) continue;
    const marker = markerOf(first.content);
    if (marker?.kind === 'summary' && marker.projectId === projectId) {
      return { threadId: thread.id, commentId: first.id, content: first.content };
    }
  }
  return null;
}

/**
 * The summary: its thread's first comment edited when it differs, else a closed thread on the pull
 * request as a whole. Another identity's thread with the marker is left alone (Azure DevOps has no
 * deletion of others' threads).
 */
async function reconcileSummary(
  client: AzureDevOpsClient,
  repositoryId: string,
  prId: number,
  loaded: Loaded,
  identityId: string,
  body: string,
): Promise<void> {
  const threads = await client.threads(repositoryId, prId);
  const own = ownSummary(threads, identityId, loaded.project.id);
  if (own === null) {
    await client.createThread(repositoryId, prId, { content: body, status: 'closed' });
  } else if (comparable(own.content) !== comparable(body)) {
    await client.editComment(repositoryId, prId, own.threadId, own.commentId, body);
  }
}

function summaryFor(
  deps: DecorationDeps,
  loaded: Loaded,
  data: SummaryData,
  review: Awaited<ReturnType<typeof loadReviewSummary>>,
  pull: AzurePullRequest,
  inline: Inline,
): string {
  const head = pull.headSha?.toLowerCase() ?? null;
  return summaryBody({
    projectId: loaded.project.id,
    revision: loaded.revision,
    gate: loaded.gate,
    newIssues: data.newIssues,
    topIssues: data.top,
    topIssuesTotal: data.total,
    inline,
    branchUrl: branchUrl(deps.publicUrl, loaded),
    mergeRequestHead: head !== null && head !== loaded.revision.toLowerCase() ? head : null,
    vocabulary: 'azure',
    smallChangesetLines: data.smallChangesetLines,
    review: withMergeRequestHead(review, head),
  });
}

/** The status of the analysis as Azure DevOps takes it. */
function statusOf(deps: DecorationDeps, loaded: Loaded): Omit<AzureStatus, 'iterationId'> {
  return {
    ...azureStatusFor(loaded.gate),
    targetUrl: branchUrl(deps.publicUrl, loaded),
    genre: 'qualor',
    name: statusName(loaded.project.key),
  };
}

function finish(
  connectionId: string,
  failures: Failures,
  failed: (error: ScmError) => DecorationOutcome,
): DecorationOutcome {
  const error = failures.decisive();
  return error === null ? { kind: 'done', connectionId } : failed(error);
}

/**
 * One Azure DevOps decoration: the client and the repository check; a branch analysis gets a
 * commit status. A pull request gets, in this order, its status on the analysed iteration (the one
 * a "Status check" branch policy reads), Qualor's threads (Task 6), and the summary thread. A
 * completed or abandoned pull request only has its title recorded and its snapshots deleted.
 */
export async function decorateAzure(
  deps: DecorationDeps,
  payload: DecorationPayload,
  loaded: Loaded,
  failed: (error: ScmError, circuit?: boolean) => DecorationOutcome,
): Promise<DecorationOutcome> {
  const { connection, branch, project, analysis } = loaded;
  const found = azureClientFor(connection, deps.scm, deps.runtime);
  if ('problem' in found) return failed(new AzureError('refused', found.problem), false);
  const client = found.client;
  const repositoryId = project.scmProjectRef ?? '';
  if (
    payload.azure?.repositoryId !== undefined &&
    payload.azure.repositoryId.toLowerCase() !== repositoryId.toLowerCase()
  ) {
    return failed(new AzureError('refused', AZURE_REPOSITORY_MISMATCH), false);
  }
  try {
    const identity = await client.connectionData();
    if (branch.kind !== 'merge_request' || !AZURE_PR_ID.test(branch.name)) {
      await client.postCommitStatus(repositoryId, loaded.revision, statusOf(deps, loaded));
      return { kind: 'done', connectionId: connection.id };
    }
    const prId = Number(branch.name);
    const pull = await client.pullRequest(repositoryId, prId);
    await recordMergeRequest(
      deps.db,
      loaded,
      { title: pull.title, url: pull.webUrl },
      azureWebBase(connection.baseUrl),
    );
    if (pull.status !== 'active') {
      await deleteBranchSnapshots(deps.db, branch.id);
      return { kind: 'done', connectionId: connection.id };
    }
    const failures = new Failures();
    const iterations = await client.iterations(repositoryId, prId);
    const analysed = iterationOf(iterations, loaded.revision);
    const newest = iterations.reduce((n, i) => Math.max(n, i.id), 0);
    if (analysed === null) {
      deps.logger?.info(
        { analysisId: analysis.id, connectionId: connection.id },
        'no iteration of the pull request has the analysed commit',
      );
    } else {
      await attempt(failures, () =>
        reconcilePullRequestStatus(client, repositoryId, prId, {
          ...statusOf(deps, loaded),
          iterationId: analysed.id,
        }),
      );
      if (failures.stop !== null) return failed(failures.stop);
    }
    // Only the pull request's latest analysis speaks for it: an older one leaves the threads and
    // the summary as they are.
    if (branch.lastAnalysisId !== analysis.id) return finish(connection.id, failures, failed);
    let inline: Inline;
    if (payload.azure?.checkout !== 'head') {
      inline = { ...NO_INLINE, skipped: 'checkout_other' };
    } else if (analysed === null || analysed.id !== newest) {
      inline = { ...NO_INLINE, skipped: 'stale' };
    } else {
      inline =
        (await attempt(failures, () =>
          reconcileThreads({
            deps,
            client,
            loaded,
            repositoryId,
            prId,
            pullRequest: pull,
            analysed,
            identityId: identity.id,
          }),
        )) ?? NOT_UPDATED;
      if (failures.stop !== null) return failed(failures.stop);
    }
    const data = await summaryData(deps.db, loaded, deps.publicUrl);
    const review = await loadReviewSummary(deps.db, analysis.id, deps.publicUrl);
    const body = summaryFor(deps, loaded, data, review, pull, inline);
    await attempt(failures, () =>
      reconcileSummary(client, repositoryId, prId, loaded, identity.id, body),
    );
    return finish(connection.id, failures, failed);
  } catch (err) {
    if (err instanceof ScmError) return failed(err);
    throw err;
  }
}

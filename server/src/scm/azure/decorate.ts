import { deleteBranchSnapshots } from '../../review/lifecycle';
import { withMergeRequestHead } from '../../review/render';
import { queueAzureAnswers, replyWindow } from '../../review/reply-queue';
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
import { azureStatusFor, azureStatusName, summaryBody, type SummaryInput } from '../render';
import {
  AZURE_PR_ID,
  AzureError,
  type AzureDevOpsClient,
  type AzureIteration,
  type AzurePullRequest,
  type AzureStatus,
  type AzureThread,
} from './client';
import { clearScmProblem, isScmBackgroundProblem, recordScmProblem } from '../problems';
import { azureClientFor, clientProblemCode, problemCode } from './connections';
import { reconcileAzureThreads } from './threads';
import { azureWebBase } from './url';

export const AZURE_REPOSITORY_MISMATCH =
  "The pipeline's Azure Repos repository is not the repository Qualor is mapped to";

type Inline = SummaryInput['inline'];
/** Nothing to say about inline comments: no comment was created or changed, and none is owed. */
const NO_INLINE: Inline = { commented: 0, unplaced: 0, skipped: null };
/** Reading or changing the threads failed: the summary says they could not be updated this time. */
const NOT_UPDATED: Inline = { commented: 0, unplaced: 0, skipped: 'failed' };

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

/**
 * Posts `status` on the iteration unless Qualor's own newest status there of its context already
 * says it. Another identity's status in the context is not Qualor's: a Status check policy whose
 * Authorized identity is Qualor's reads only Qualor's.
 */
async function reconcilePullRequestStatus(
  client: AzureDevOpsClient,
  repositoryId: string,
  prId: number,
  status: AzureStatus,
  identityId: string,
): Promise<void> {
  // The newest status of the context (genre and name) is the one with the highest id: the list's
  // order says nothing.
  const own = (authorId: string | null) =>
    authorId !== null && authorId.toLowerCase() === identityId.toLowerCase();
  const current = (await client.iterationStatuses(repositoryId, prId, status.iterationId))
    .filter((s) => own(s.authorId) && s.genre === status.genre && s.name === status.name)
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
 * deletion of others' threads). Answers the threads it listed, which the answers to the people's
 * comments are found in.
 */
async function reconcileSummary(
  client: AzureDevOpsClient,
  repositoryId: string,
  prId: number,
  loaded: Loaded,
  identityId: string,
  body: string,
): Promise<AzureThread[]> {
  const threads = await client.threads(repositoryId, prId);
  const own = ownSummary(threads, identityId, loaded.project.id);
  if (own === null) {
    await client.createThread(repositoryId, prId, { content: body, status: 'closed' });
  } else if (comparable(own.content) !== comparable(body)) {
    await client.editComment(repositoryId, prId, own.threadId, own.commentId, body);
  }
  return threads;
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

/**
 * The status of the analysis as Azure DevOps takes it: the genre `qualor` and the project key, which
 * a Status check policy names `qualor/<project key>`.
 */
function statusOf(deps: DecorationDeps, loaded: Loaded): Omit<AzureStatus, 'iterationId'> {
  return {
    ...azureStatusFor(loaded.gate),
    targetUrl: branchUrl(deps.publicUrl, loaded),
    genre: 'qualor',
    name: azureStatusName(loaded.project.key),
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
 * One Azure DevOps decoration, and what it says of the connection: a credential or permission
 * failure that decided the job is recorded on the connection (its settings page shows it), and a
 * decoration in which every step succeeded clears it. A transient failure, a rate limit or a
 * mismatch of repositories leaves it as it was.
 */
export async function decorateAzure(
  deps: DecorationDeps,
  payload: DecorationPayload,
  loaded: Loaded,
  failed: (error: ScmError, circuit?: boolean) => DecorationOutcome,
): Promise<DecorationOutcome> {
  const seen: { decisive: ScmError | null } = { decisive: null };
  const outcome = await decorateAzureSteps(deps, payload, loaded, (error, circuit) => {
    seen.decisive = error;
    return failed(error, circuit);
  });
  const connectionId = loaded.connection.id;
  if (outcome.kind === 'done') {
    await keepOutcome(deps, connectionId, () => clearScmProblem(deps.db, connectionId));
  } else if (seen.decisive !== null) {
    const code = problemCodeOf(seen.decisive);
    if (code !== null) {
      await keepOutcome(deps, connectionId, () => recordScmProblem(deps.db, connectionId, code));
    }
  }
  return outcome;
}

/**
 * A write of the connection's problem is not worth failing the job for: when it fails, the job's
 * outcome stands and a warning is logged (the connection's id only, never the database's words).
 */
async function keepOutcome(
  deps: DecorationDeps,
  connectionId: string,
  write: () => Promise<void>,
): Promise<void> {
  try {
    await write();
  } catch {
    deps.logger?.warn({ connectionId }, 'could not update the Azure DevOps connection problem');
  }
}

/** The code a failure records, or null when it passes by itself or is not the connection's. */
function problemCodeOf(error: ScmError) {
  const code = problemCode(error);
  return isScmBackgroundProblem(code) ? code : null;
}

/**
 * The steps of one Azure DevOps decoration: the client and the repository check; a branch analysis gets a
 * commit status. A pull request gets, in this order, its status on the analysed iteration (the one
 * a "Status check" branch policy reads), Qualor's inline threads, the summary thread, and the
 * answers to the people's replies and commands queued (6I-4). A completed or abandoned pull
 * request only has its title recorded and its snapshots deleted.
 */
async function decorateAzureSteps(
  deps: DecorationDeps,
  payload: DecorationPayload,
  loaded: Loaded,
  failed: (error: ScmError, circuit?: boolean) => DecorationOutcome,
): Promise<DecorationOutcome> {
  const { connection, branch, project, analysis } = loaded;
  const found = azureClientFor(connection, deps.scm, deps.runtime);
  if ('problem' in found) {
    // The stored credential cannot be read, or the address is no longer allowed: no request is made.
    const code = clientProblemCode(found.problem);
    if (isScmBackgroundProblem(code)) {
      await keepOutcome(deps, connection.id, () => recordScmProblem(deps.db, connection.id, code));
    }
    return failed(new AzureError('refused', found.problem), false);
  }
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
        reconcilePullRequestStatus(
          client,
          repositoryId,
          prId,
          { ...statusOf(deps, loaded), iterationId: analysed.id },
          identity.id,
        ),
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
          reconcileAzureThreads({
            deps,
            client,
            loaded,
            repositoryId,
            prId,
            analysed,
            identityId: identity.id,
            failures,
          }).then((result) => ({ ...result, skipped: null })),
        )) ?? NOT_UPDATED;
      if (failures.stop !== null) return failed(failures.stop);
    }
    const data = await summaryData(deps.db, loaded, deps.publicUrl);
    const review = await loadReviewSummary(deps.db, analysis.id, deps.publicUrl);
    const body = summaryFor(deps, loaded, data, review, pull, inline);
    const threads = await attempt(failures, () =>
      reconcileSummary(client, repositoryId, prId, loaded, identity.id, body),
    );
    // Last: what Azure DevOps shows is written before the database takes more work. The replies
    // and commands are the ones in the threads the summary listed (none when they could not be
    // read): no request of their own. Without AI review active for the project there is no
    // window, and Qualor answers none (6I-4).
    if (threads !== null) {
      await queueAzureAnswers(
        deps.db,
        { projectId: project.id, branchId: branch.id },
        await replyWindow(deps.db, project, branch.id),
        identity.id,
        threads,
      );
    }
    return finish(connection.id, failures, failed);
  } catch (err) {
    if (err instanceof ScmError) return failed(err);
    throw err;
  }
}

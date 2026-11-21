import { assertNever } from '@qualor/shared';
import { eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { projects, scmConnections } from '../db/schema';
import { gitlabClientFor, type ScmConnectionRow, type ScmDeps } from './connections';
import { GITHUB_PR_NUMBER } from './github/client';
import { githubClientFor } from './github/connections';
import { parseRepoRef } from './github/url';
import { GITLAB_MR_IID } from './gitlab/client';
import { ScmError } from './provider';
import type { ScmRuntime } from './runtime';

/** A merge request, or a GitHub pull request, as an AI review reads it before it runs (6I-3). */
export interface MergeRequestState {
  state: 'open' | 'merged' | 'closed';
  draft: boolean;
  /** Its head commit as the provider says it is now; null when it does not say. */
  headSha: string | null;
}

/**
 * GitLab's states. `locked` is a merge request GitLab is merging at this moment: still open until
 * it says merged.
 */
const GITLAB_STATES: Readonly<Record<string, MergeRequestState['state']>> = {
  opened: 'open',
  locked: 'open',
  merged: 'merged',
  closed: 'closed',
};

/**
 * What it takes to ask a provider about one merge request: sends the requests, and answers the
 * state, or null when the provider names a state Qualor does not know. Throws {@link ScmError} when
 * a request fails.
 */
type Ask = () => Promise<MergeRequestState | null>;

/** The GitHub installation tokens (and the mutation pacer) a worker's clients share. */
type GitHubTokens = Pick<ScmRuntime, 'githubTokens' | 'githubPacer'>;

/**
 * The GitLab question, or null when there is nothing to ask: the id is no merge request's, or the
 * connection cannot be used (a token that no longer decrypts, an address the rules no longer
 * allow). Nothing is sent before the question is asked.
 */
function gitlabAsk(
  connection: ScmConnectionRow,
  ref: string,
  iid: string,
  scm: ScmDeps,
): Ask | null {
  if (!GITLAB_MR_IID.test(iid)) return null;
  const found = gitlabClientFor(connection, scm);
  if ('problem' in found) return null;
  return async () => {
    const mr = await found.client.mergeRequest(ref, iid);
    // Its own keys only: a state such as `constructor` is one Qualor does not know, never "not open".
    const state = Object.hasOwn(GITLAB_STATES, mr.state) ? GITLAB_STATES[mr.state] : undefined;
    if (state === undefined) return null;
    // A GitLab before 14 says a draft by `work_in_progress` only.
    const draft = mr.draft || mr.work_in_progress;
    return { state, draft, headSha: mr.diff_refs?.head_sha ?? mr.sha };
  };
}

/** The state of a pull request: GitHub says `closed` for a merged one too. Null for any other state. */
function pullState(pull: { state: string; merged: boolean }): 'open' | 'merged' | 'closed' | null {
  if (pull.state === 'open') return 'open';
  if (pull.state !== 'closed') return null;
  return pull.merged ? 'merged' : 'closed';
}

/**
 * The GitHub question, or null when there is nothing to ask (as {@link gitlabAsk}). GitHub says
 * `closed` for a pull request that was merged too: its `merged` flag tells them apart.
 */
function githubAsk(
  connection: ScmConnectionRow,
  ref: string,
  number: string,
  scm: ScmDeps,
  tokens: GitHubTokens | undefined,
): Ask | null {
  const repository = parseRepoRef(ref);
  if (repository === null || !GITHUB_PR_NUMBER.test(number)) return null;
  const found = githubClientFor(connection, scm, tokens);
  if ('problem' in found) return null;
  return async () => {
    await found.client.useRepository(repository);
    const pull = await found.client.pullRequest(number);
    const state = pullState(pull);
    if (state === null) return null;
    return { state, draft: pull.draft, headSha: pull.head.sha };
  };
}

/**
 * `ask` made as the `scm` worker's jobs make theirs (scm.md §4.2): it takes a slot of the
 * project's organisation and passes the connection's circuit, and waits for neither, so a read that
 * cannot start answers null at once. The circuit hears what came of it as it does from a
 * decoration: a request that came back, whatever it says, is an answer (the provider is up), and one
 * that failed is reported by its error ({@link CircuitBreaker.reportError}).
 */
async function throughRuntime(
  runtime: ScmRuntime,
  organizationId: string,
  connectionId: string,
  ask: Ask,
): Promise<MergeRequestState | null> {
  const { circuit, slots } = runtime;
  if (!slots.tryTake(organizationId)) return null;
  try {
    if (!circuit.tryPass(connectionId)) return null;
    try {
      const state = await ask();
      circuit.success(connectionId);
      return state;
    } catch (err) {
      if (err instanceof ScmError) circuit.reportError(connectionId, err);
      else circuit.release(connectionId);
      throw err;
    }
  } finally {
    slots.release(organizationId);
  }
}

/**
 * What the merge request `mergeRequestId` of the project's mapped GitLab project (or pull request
 * of its GitHub repository) is now: open, merged or closed, whether it is a draft, and its head
 * commit. One read, made through the project's connection with the current rules for its address
 * and its key. Null when that cannot be told: the project is not mapped, its connection cannot be
 * used, the id is no merge request's, or the provider failed or refused. An SCM error is no answer,
 * never a state; anything else (the database, a bug) is thrown.
 *
 * With the `scm` worker's `runtime` the read shares its state: the organisation's slots, the
 * connection's circuit (null when no slot is free or the circuit is open) and the GitHub
 * installation tokens. The review job reads without it. A job that passes the circuit itself and
 * takes no slot (an answer to a reply) shares only the tokens (`tokens`), so that the read and the
 * job's other requests use one installation token.
 */
export async function readMergeRequestState(
  deps: { db: Executor; scm: ScmDeps; runtime?: ScmRuntime; tokens?: GitHubTokens },
  projectId: string,
  mergeRequestId: string,
): Promise<MergeRequestState | null> {
  const [found] = await deps.db
    .select({
      ref: projects.scmProjectRef,
      organizationId: projects.organizationId,
      connection: scmConnections,
    })
    .from(projects)
    .innerJoin(scmConnections, eq(scmConnections.id, projects.scmConnectionId))
    .where(eq(projects.id, projectId));
  if (!found || found.ref === null) return null;
  const { connection, organizationId } = found;
  const { runtime, scm } = deps;
  let ask: Ask | null;
  switch (connection.provider) {
    case 'gitlab':
      ask = gitlabAsk(connection, found.ref, mergeRequestId, scm);
      break;
    case 'github':
      ask = githubAsk(connection, found.ref, mergeRequestId, scm, runtime ?? deps.tokens);
      break;
    default:
      return assertNever(connection.provider, 'provider');
  }
  if (ask === null) return null;
  try {
    return runtime === undefined
      ? await ask()
      : await throughRuntime(runtime, organizationId, connection.id, ask);
  } catch (err) {
    if (err instanceof ScmError) return null;
    throw err;
  }
}

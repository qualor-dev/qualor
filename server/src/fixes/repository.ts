import { randomUUID } from 'node:crypto';
import { assertNever, type ScmProvider } from '@qualor/shared';
import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { projects, scmConnections } from '../db/schema';
import type { ProjectRow } from '../projects/access';
import type { WorkerLogger } from '../queue/worker';
import type { AzureDevOpsClient, AzurePullRequest } from '../scm/azure/client';
import { azureClientFor } from '../scm/azure/connections';
import { gitlabClientFor, type ScmConnectionRow, type ScmDeps } from '../scm/connections';
import type { GitHubClient, GitHubPullState } from '../scm/github/client';
import { githubClientFor } from '../scm/github/connections';
import { parseRepoRef } from '../scm/github/url';
import type { GitLabClient, GitLabMergeRequestState } from '../scm/gitlab/client';
import { ScmError } from '../scm/provider';
import type { ScmRuntime } from '../scm/runtime';

/**
 * The repository of a project's fixes (0.16 fix MRs §6.7), the same for GitLab, GitHub and Azure
 * DevOps: the reads the result check needs, and the writes of the commit and close jobs (ruling
 * F11). Every forced branch write and every delete re-reads the branch head right before it and
 * stops when the head is not the one the caller expects (B10: GitLab and GitHub take no expected
 * head, and Azure DevOps holds to one on a push and a ref move, not on a delete).
 */

/** R15: a base file is read raw up to this size (the clients' 8 MiB default stays elsewhere). */
export const FIX_BASE_MAX_BYTES = 32 * 1024 * 1024;

/**
 * Azure sub-plan 6, Review Focus 3: a base file the repository can tell it will not hand over whole,
 * so the upload check refuses it by `rule` (never a partial file): over {@link FIX_BASE_MAX_BYTES}
 * (`too_large`), or not UTF-8 text (`not_utf8`). Azure DevOps' raw read says so; the GitLab and
 * GitHub clients throw an SCM error instead.
 */
export class FixFileUnreadable extends Error {
  constructor(
    readonly rule: 'too_large' | 'not_utf8',
    readonly path: string,
  ) {
    super(`the base file ${path} cannot be read whole (${rule})`);
    this.name = 'FixFileUnreadable';
  }
}

/** An MR (GitLab) or pull request (GitHub, Azure DevOps) of a fix branch. */
export interface ChangeRequest {
  number: number;
  url: string;
  state: 'open' | 'closed' | 'merged';
  conflict: boolean;
  headSha: string | null;
}

/** The fix branch's one commit (§6.7): the uploaded files on `baseSha`, under the MR title. */
export interface FixCommitInput {
  branch: string;
  /** A commit sha, never a branch name (ruling T5b). */
  baseSha: string;
  /** Files that exist at `baseSha` (§6.7: a fix never adds one), with their new text. */
  files: readonly { path: string; content: string }[];
  message: string;
  /**
   * The head the branch must still have when it is written: Qualor's last commit, or null for a
   * branch that must not exist yet. Any other head is a person's (B10, §11.2): nothing is written.
   */
  expectedHead: string | null;
}

export interface FixRepository {
  readonly provider: ScmProvider;
  /** The project's main branch, as Qualor knows it. */
  readonly mainBranch: string;
  /** The head sha of a branch; null when there is no such branch. */
  branchHead(name: string): Promise<string | null>;
  /** Whether `ancestor` is `of` or one of its ancestors. */
  isAncestor(ancestor: string, of: string): Promise<boolean>;
  /**
   * A file's text at a commit, read raw up to {@link FIX_BASE_MAX_BYTES} (R15); null when absent.
   * {@link FixFileUnreadable} when the repository says it cannot hand the file over whole.
   */
  fileAt(path: string, sha: string): Promise<string | null>;
  /**
   * The commit, written to `branch`: the branch is made there, or force-moved there when its head
   * is still `expectedHead` (re-read right before the write, B10); `takenOver` and nothing written
   * to the branch when it is not.
   */
  commit(input: FixCommitInput): Promise<{ sha: string } | { takenOver: true }>;
  /**
   * Deletes the branch when its head is still `expectedHead` (re-read right before, B10):
   * `deleted`, `gone` when there is no such branch, `taken_over` (kept) when a person moved it,
   * `kept` when the provider refuses the delete for good (ruling FW4: a ruleset or a protected
   * branch; GitHub 422, GitLab 403 or 422, Azure DevOps 403). Any other failure is thrown.
   */
  deleteBranch(name: string, expectedHead: string): Promise<BranchDelete>;
  /**
   * The open MR from `branch` of this repository into the main branch, or null: a closed or
   * merged one is not found, nor a fork's from a branch of the same name (ruling T10a).
   */
  findChange(branch: string): Promise<ChangeRequest | null>;
  readChange(number: number): Promise<ChangeRequest>;
  /** A new MR from `branch` into the main branch. */
  openChange(input: { branch: string; title: string; body: string }): Promise<ChangeRequest>;
  updateChange(number: number, input: { title: string; body: string }): Promise<void>;
  /** Comments `comment` on the MR, then closes it. */
  closeChange(number: number, comment: string): Promise<void>;
}

/** What the commit and close jobs write, the same on both providers ({@link FixRepository}). */
type FixWrites = Pick<
  FixRepository,
  'commit' | 'findChange' | 'readChange' | 'openChange' | 'updateChange' | 'closeChange'
>;

/** How a branch delete ended ({@link FixRepository.deleteBranch}). */
export type BranchDelete = 'deleted' | 'gone' | 'taken_over' | 'kept';

/**
 * Ruling FW4: the statuses with which a provider refuses a branch delete for good (a ruleset that
 * restricts deletions, a protected branch): GitHub 422 (a missing ref is no refusal: the client
 * answers it as gone). GitLab answers 400 when a pre-receive hook refuses, 403 when the user may
 * not delete, 405 for a protected branch or the HEAD branch, and 422 for a rule. Azure DevOps
 * answers a refused ref update in a 200 body (a policy, a missing permission), which its client
 * throws as 403, as it does an HTTP 403 (Azure sub-plan 6, ruling 8). A retry would be refused
 * again.
 */
const REFUSED_DELETE: Readonly<Record<FixRepository['provider'], readonly number[]>> =
  Object.freeze({
    github: [422],
    gitlab: [400, 403, 405, 422],
    azure: [403],
  });

/**
 * The branch is deleted when its head is `expectedHead`, re-read right before (B10); `remove`
 * answers false when the branch went in between. A delete the provider refuses for good is `kept`
 * (ruling FW4), not thrown.
 */
async function deleteIfHead(
  provider: FixRepository['provider'],
  branchHead: () => Promise<string | null>,
  expectedHead: string,
  remove: () => Promise<boolean>,
): Promise<BranchDelete> {
  const head = await branchHead();
  if (head === null) return 'gone';
  if (head !== expectedHead) return 'taken_over';
  try {
    return (await remove()) ? 'deleted' : 'gone';
  } catch (err) {
    const status = err instanceof ScmError ? err.status : null;
    if (status !== null && REFUSED_DELETE[provider].includes(status)) return 'kept';
    throw err;
  }
}

/** A GitLab MR as a fix reads it; `locked` (a merge in progress) is still open. */
function gitlabChange(mr: GitLabMergeRequestState): ChangeRequest {
  let state: ChangeRequest['state'] = 'open';
  if (mr.state === 'merged') state = 'merged';
  else if (mr.state === 'closed') state = 'closed';
  return { number: mr.iid, url: mr.url, state, conflict: mr.conflict, headSha: mr.sha };
}

/** A GitHub pull request as a fix reads it: a closed one that was merged is `merged`. */
function githubChange(pull: GitHubPullState): ChangeRequest {
  let state: ChangeRequest['state'] = 'open';
  if (pull.merged) state = 'merged';
  else if (pull.state === 'closed') state = 'closed';
  return {
    number: pull.number,
    url: pull.url,
    state,
    conflict: pull.conflict,
    headSha: pull.headSha,
  };
}

/**
 * An Azure DevOps pull request as a fix reads it: `completed` is merged, `abandoned` closed. A
 * conflict is Azure DevOps' own `mergeStatus`; the head is null until it has merged once.
 */
function azureChange(pull: AzurePullRequest): ChangeRequest {
  let state: ChangeRequest['state'] = 'open';
  if (pull.status === 'completed') state = 'merged';
  else if (pull.status === 'abandoned') state = 'closed';
  return {
    number: pull.id,
    url: pull.webUrl,
    state,
    conflict: pull.mergeStatus === 'conflicts',
    headSha: pull.headSha?.toLowerCase() ?? null,
  };
}

/** A just-opened MR, as the provider answered it: open, no conflict known yet. */
const opened = (created: { url: string; number: number }): ChangeRequest => ({
  number: created.number,
  url: created.url,
  state: 'open',
  conflict: false,
  headSha: null,
});

/**
 * GitLab (§6.7): the head re-read right before one `POST …/repository/commits` with `start_sha`
 * (a sha, ruling T5b), `force` when the branch exists, and `update` actions only.
 */
function gitlabWrites(client: GitLabClient, ref: string, mainBranch: string): FixWrites {
  return {
    commit: async (input) => {
      const head = await client.branchHead(ref, input.branch);
      if (head !== input.expectedHead) return { takenOver: true };
      const sha = await client.commitOnto(ref, {
        branch: input.branch,
        startSha: input.baseSha,
        message: input.message,
        actions: input.files.map((f) => ({
          action: 'update' as const,
          path: f.path,
          content: f.content,
        })),
        force: head !== null,
      });
      return { sha };
    },
    findChange: async (branch) => {
      const found = await client.openMergeRequestFrom(ref, branch, mainBranch);
      return found === null ? null : gitlabChange(found);
    },
    readChange: async (number) => gitlabChange(await client.mergeRequestState(ref, number)),
    openChange: async ({ branch, title, body }) => {
      const created = await client.openMergeRequest(ref, {
        source: branch,
        target: mainBranch,
        title,
        description: body,
      });
      return opened({ url: created.url, number: created.iid });
    },
    updateChange: (number, { title, body }) =>
      client.updateMergeRequest(ref, number, { title, description: body }),
    closeChange: async (number, comment) => {
      await client.createNote(ref, String(number), comment);
      await client.updateMergeRequest(ref, number, { stateEvent: 'close' });
    },
  };
}

/**
 * GitHub (§6.7, R14): a blob per file, a tree on the base commit's tree, a commit whose parent is
 * `baseSha`, then the head re-read right before the ref is made or force-moved (B10).
 */
function githubWrites(client: GitHubClient, mainBranch: string): FixWrites {
  return {
    commit: async (input) => {
      const entries: { path: string; blobSha: string }[] = [];
      for (const file of input.files) {
        entries.push({ path: file.path, blobSha: await client.createBlob(file.content) });
      }
      const tree = await client.createTree(await client.commitTreeSha(input.baseSha), entries);
      const sha = await client.createCommit({
        message: input.message,
        tree,
        parents: [input.baseSha],
      });
      const head = await client.branchSha(input.branch);
      if (head !== input.expectedHead) return { takenOver: true };
      if (head === null) await client.createBranch(input.branch, sha);
      else await client.updateBranch(input.branch, sha, true);
      return { sha };
    },
    findChange: async (branch) => {
      const found = await client.openPullRequestFrom(branch, mainBranch);
      return found === null ? null : githubChange(found);
    },
    readChange: async (number) => githubChange(await client.pullRequestState(number)),
    openChange: async ({ branch, title, body }) =>
      opened(await client.openPullRequest({ head: branch, base: mainBranch, title, body })),
    updateChange: (number, { title, body }) => client.updatePullRequest(number, { title, body }),
    closeChange: async (number, comment) => {
      await client.createComment(String(number), comment);
      await client.updatePullRequest(number, { state: 'closed' });
    },
  };
}

/** Where a refresh's commit waits while the branch is moved to it: no branch, so no build. */
const AZURE_TEMPORARY_REF = 'refs/qualor/fix-tmp/';

type Logged = Pick<WorkerLogger, 'warn'> | undefined;

/**
 * Azure DevOps (sub-plan 6, probe item 22): a push takes an expected old head, but a commit whose
 * parent is not that head is refused (22d), and a stale push looks the same (22e).
 */
function azureWrites(
  client: AzureDevOpsClient,
  repositoryId: string,
  mainBranch: string,
  logger: Logged,
): FixWrites {
  const branchHead = (name: string) => client.branchHead(repositoryId, name);
  const pushTo = (ref: string, input: FixCommitInput) =>
    client.push(repositoryId, {
      ref,
      oldObjectId: null,
      parent: input.baseSha,
      message: input.message,
      files: input.files,
    });

  /**
   * A new branch: one push of `edit` changes on `baseSha`, its old head the zero id. A branch made
   * in between is refused like any push; the head read again says it is a person's.
   */
  const firstCommit = async (input: FixCommitInput) => {
    try {
      return { sha: await pushTo(`refs/heads/${input.branch}`, input) };
    } catch (err) {
      if (err instanceof ScmError && err.kind === 'refused') {
        if ((await branchHead(input.branch)) !== null) return { takenOver: true as const };
      }
      throw err;
    }
  };

  /** Best effort: a temporary ref left behind is no branch; the log says so, without Azure's words. */
  const dropTemporary = async (ref: string, sha: string) => {
    try {
      await client.deleteRef(repositoryId, ref, sha);
    } catch (err) {
      logger?.warn(
        err instanceof ScmError
          ? { errorKind: err.kind, httpStatus: err.status, request: err.request }
          : { errorKind: 'other' },
        'fix commit: the temporary ref of a refresh could not be deleted',
      );
    }
  };

  /**
   * B10 on Azure DevOps (ruling 2): the commit goes to a temporary ref, the head is read again,
   * then the branch is moved from Qualor's last commit to it (a ref update need not be a
   * fast-forward; a stale old id is a person's push), and the temporary ref is deleted.
   */
  const refresh = async (input: FixCommitInput, head: string) => {
    const temporary = `${AZURE_TEMPORARY_REF}${randomUUID()}`;
    const sha = await pushTo(temporary, input);
    try {
      if ((await branchHead(input.branch)) !== head) return { takenOver: true as const };
      try {
        await client.updateRef(repositoryId, `refs/heads/${input.branch}`, head, sha);
      } catch (err) {
        if (err instanceof ScmError && err.reason === 'stale') return { takenOver: true as const };
        throw err;
      }
      return { sha };
    } finally {
      await dropTemporary(temporary, sha);
    }
  };

  return {
    commit: async (input) => {
      const head = await branchHead(input.branch);
      if (head !== input.expectedHead) return { takenOver: true };
      return head === null ? firstCommit(input) : refresh(input, head);
    },
    findChange: async (branch) => {
      // Ruling T10a: a fork's pull request from a branch of the same name is never the fix's.
      const found = (await client.pullRequestsFrom(repositoryId, branch, mainBranch)).find(
        (pull) => !pull.fork,
      );
      if (found === undefined) return null;
      // Ledger ruling: `lastMergeSourceCommit` lags, and is null until Azure DevOps has merged
      // once, so a pull request whose create answer was lost would never be adopted (and a second
      // create is refused, TF401179). Its source branch is this branch: its head is the PR's head.
      return { ...azureChange(found), headSha: await branchHead(branch) };
    },
    readChange: async (number) => azureChange(await client.pullRequest(repositoryId, number)),
    openChange: async ({ branch, title, body }) => {
      const created = await client.createPullRequest(repositoryId, {
        sourceBranch: branch,
        targetBranch: mainBranch,
        title,
        description: body,
      });
      return opened({ url: created.webUrl, number: created.id });
    },
    updateChange: (number, { title, body }) =>
      client.updatePullRequest(repositoryId, number, { title, description: body }),
    // Ruling 7: a thread on the whole pull request, closed (never an active comment), then abandoned.
    closeChange: async (number, comment) => {
      await client.createThread(repositoryId, number, { content: comment, status: 'closed' });
      await client.updatePullRequest(repositoryId, number, { status: 'abandoned' });
    },
  };
}

export interface FixScmDeps {
  db: Db;
  scm: ScmDeps;
  runtime?: ScmRuntime;
  /** Where a best-effort SCM step that failed is reported (Azure DevOps' temporary ref). */
  logger?: Pick<WorkerLogger, 'warn'>;
}

/**
 * Why a project's fix repository cannot be used now: the project is not mapped to a repository,
 * the connection does not allow fix MRs (B2, read again here, so a switch turned off meanwhile
 * fails closed), or no client can be made for the connection (a key that no longer decrypts, an
 * address the rules no longer allow, a repository reference that is no `owner/repo`).
 */
export type FixRepositoryProblem = 'scm_not_bound' | 'fixes_disabled' | 'connection';

/** The fixed text of each problem: the upload's 409 or failure, and the commit job's failure. */
export const FIX_REPOSITORY_PROBLEM_TEXT: Readonly<Record<FixRepositoryProblem, string>> =
  Object.freeze({
    scm_not_bound: 'The project is not mapped to a repository',
    fixes_disabled:
      "An organisation admin has not allowed fix merge requests on the project's SCM connection",
    connection:
      "The project's SCM connection cannot be used (its key no longer decrypts, its address is no longer allowed, or the repository reference is wrong); an organisation admin must check it",
  });

function gitlabRepository(
  connection: ScmConnectionRow,
  deps: FixScmDeps,
  ref: string,
  mainBranch: string,
): FixRepository | { problem: FixRepositoryProblem } {
  const made = gitlabClientFor(connection, deps.scm);
  if ('problem' in made) return { problem: 'connection' };
  const { client } = made;
  const branchHead = (name: string) => client.branchHead(ref, name);
  return {
    provider: 'gitlab',
    mainBranch,
    branchHead,
    isAncestor: async (ancestor, of) => {
      if (ancestor === of) return true;
      return (await client.mergeBase(ref, ancestor, of))?.toLowerCase() === ancestor;
    },
    fileAt: (path, sha) => client.fileText(ref, path, sha, { maxBytes: FIX_BASE_MAX_BYTES }),
    deleteBranch: (name, expectedHead) =>
      deleteIfHead(
        'gitlab',
        () => branchHead(name),
        expectedHead,
        () => client.deleteBranch(ref, name),
      ),
    ...gitlabWrites(client, ref, mainBranch),
  };
}

/** GitHub: the client is bound to the repository first (`useRepository`, one request). */
async function githubRepository(
  connection: ScmConnectionRow,
  deps: FixScmDeps,
  ref: string,
  mainBranch: string,
): Promise<FixRepository | { problem: FixRepositoryProblem }> {
  const repository = parseRepoRef(ref);
  const made = githubClientFor(connection, deps.scm, deps.runtime);
  if (repository === null || 'problem' in made) return { problem: 'connection' };
  const { client } = made;
  await client.useRepository(repository);
  const branchHead = (name: string) => client.branchSha(name);
  return {
    provider: 'github',
    mainBranch,
    branchHead,
    isAncestor: async (ancestor, of) => {
      if (ancestor === of) return true;
      const status = await client.compareStatus(ancestor, of);
      return status === 'ahead' || status === 'identical';
    },
    fileAt: (path, sha) => client.rawFileText(path, sha, FIX_BASE_MAX_BYTES),
    deleteBranch: (name, expectedHead) =>
      deleteIfHead(
        'github',
        () => branchHead(name),
        expectedHead,
        () => client.deleteBranch(name),
      ),
    ...githubWrites(client, mainBranch),
  };
}

/**
 * Azure DevOps (sub-plan 6): the repository by its id (`scmProjectRef`, a lower-case GUID). Ancestry
 * is the commit two commits have in common (`diffs/commits`, item 22a); a base file is read raw up
 * to {@link FIX_BASE_MAX_BYTES} (item 22b), and one over it or not UTF-8 text is
 * {@link FixFileUnreadable}. A delete does not hold to the old id (item 22j): the head read right
 * before it is the only guard, as on GitHub.
 */
export function azureRepository(
  client: AzureDevOpsClient,
  repositoryId: string,
  mainBranch: string,
  logger?: Pick<WorkerLogger, 'warn'>,
): FixRepository {
  const branchHead = (name: string) => client.branchHead(repositoryId, name);
  return {
    provider: 'azure',
    mainBranch,
    branchHead,
    isAncestor: async (ancestor, of) => {
      if (ancestor === of) return true;
      try {
        return (await client.commonCommit(repositoryId, ancestor, of)) === ancestor;
      } catch (err) {
        // A commit the repository does not have is no ancestor (as GitLab's 404 and GitHub's).
        if (err instanceof ScmError && err.kind === 'not_found') return false;
        throw err;
      }
    },
    fileAt: async (path, sha) => {
      const read = await client.fileBytes(repositoryId, path, sha, FIX_BASE_MAX_BYTES);
      if ('text' in read) return read.text;
      if (read.skipped === 'missing') return null;
      throw new FixFileUnreadable(read.skipped === 'too_large' ? 'too_large' : 'not_utf8', path);
    },
    deleteBranch: (name, expectedHead) =>
      deleteIfHead(
        'azure',
        () => branchHead(name),
        expectedHead,
        async () => {
          await client.deleteRef(repositoryId, `refs/heads/${name}`, expectedHead);
          return true;
        },
      ),
    ...azureWrites(client, repositoryId, mainBranch, logger),
  };
}

/** The SCM settings of the repository's client, bound to `signal` when one is given. */
function boundTo(scm: ScmDeps, signal: AbortSignal | undefined): ScmDeps {
  if (signal === undefined) return scm;
  return {
    ...scm,
    clientOptions: { ...scm.clientOptions, signal },
    githubClientOptions: { ...scm.githubClientOptions, signal },
    azureClientOptions: { ...scm.azureClientOptions, signal },
  };
}

/**
 * The fix repository of the project as it is mapped now: the project's binding and its
 * connection's `fix_mrs_allowed` are read again (fail closed), never taken from `project`. A
 * GitHub repository costs one request to bind the client; an SCM error of it is thrown. With a
 * `signal`, every request of the repository is given up once it aborts (ruling T9k): the one in
 * flight is cut and no later one is sent.
 */
export async function openFixRepository(
  deps: FixScmDeps,
  project: ProjectRow,
  options: { signal?: AbortSignal } = {},
): Promise<FixRepository | { problem: FixRepositoryProblem }> {
  const row = await mappingOf(deps.db, project.id);
  if (row === null) return { problem: 'scm_not_bound' };
  if (!row.connection.fixMrsAllowed) return { problem: 'fixes_disabled' };
  return repositoryOf(deps, row, options.signal);
}

/**
 * R18: the project's fix repository for the sync pass, which tracks the open MRs of a project
 * until they end even when its connection no longer allows fix MRs (B2): then `writable` is false
 * and the pass reads only (no comment, close or branch delete). Otherwise as
 * {@link openFixRepository}: the mapping read again, a GitHub repository bound with one request.
 */
export async function openTrackingRepository(
  deps: FixScmDeps,
  project: ProjectRow,
): Promise<{ repo: FixRepository; writable: boolean } | { problem: FixRepositoryProblem }> {
  const row = await mappingOf(deps.db, project.id);
  if (row === null) return { problem: 'scm_not_bound' };
  const repo = await repositoryOf(deps, row, undefined);
  return 'problem' in repo ? repo : { repo, writable: row.connection.fixMrsAllowed };
}

interface Mapping {
  ref: string;
  mainBranch: string;
  connection: ScmConnectionRow;
}

/** The project's repository reference, main branch and connection as stored now; null unmapped. */
async function mappingOf(db: Db, projectId: string): Promise<Mapping | null> {
  const [row] = await db
    .select({
      ref: projects.scmProjectRef,
      mainBranch: projects.mainBranchName,
      connection: scmConnections,
    })
    .from(projects)
    .innerJoin(scmConnections, eq(scmConnections.id, projects.scmConnectionId))
    .where(eq(projects.id, projectId));
  if (!row || row.ref === null) return null;
  return { ref: row.ref, mainBranch: row.mainBranch, connection: row.connection };
}

/** The repository of a mapping, its client bound to `signal` when one is given. */
async function repositoryOf(
  deps: FixScmDeps,
  row: Mapping,
  signal: AbortSignal | undefined,
): Promise<FixRepository | { problem: FixRepositoryProblem }> {
  const bound = { ...deps, scm: boundTo(deps.scm, signal) };
  switch (row.connection.provider) {
    case 'github':
      return githubRepository(row.connection, bound, row.ref, row.mainBranch);
    case 'gitlab':
      return gitlabRepository(row.connection, bound, row.ref, row.mainBranch);
    case 'azure': {
      const made = azureClientFor(row.connection, bound.scm, deps.runtime);
      if ('problem' in made) return { problem: 'connection' };
      return azureRepository(made.client, row.ref, row.mainBranch, deps.logger);
    }
    default:
      return assertNever(row.connection.provider, 'provider');
  }
}

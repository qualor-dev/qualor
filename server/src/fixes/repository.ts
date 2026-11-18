import { eq } from 'drizzle-orm';
import type { Db } from '../db/client';
import { projects, scmConnections } from '../db/schema';
import type { ProjectRow } from '../projects/access';
import { gitlabClientFor, type ScmConnectionRow, type ScmDeps } from '../scm/connections';
import { githubClientFor } from '../scm/github/connections';
import { parseRepoRef } from '../scm/github/url';
import type { ScmRuntime } from '../scm/runtime';

/**
 * The repository of a project's fixes (0.16 fix MRs §6.7), the same for GitLab and GitHub. This
 * part has the reads the result check needs (ruling F11); the commit job (Task 10) adds the writes.
 */

/** R15: a base file is read raw up to this size (the clients' 8 MiB default stays elsewhere). */
export const FIX_BASE_MAX_BYTES = 32 * 1024 * 1024;

/** An MR (GitLab) or pull request (GitHub) of a fix branch. */
export interface ChangeRequest {
  number: number;
  url: string;
  state: 'open' | 'closed' | 'merged';
  conflict: boolean;
  headSha: string | null;
}

export interface FixRepository {
  readonly provider: 'gitlab' | 'github';
  /** The project's main branch, as Qualor knows it. */
  readonly mainBranch: string;
  /** The head sha of a branch; null when there is no such branch. */
  branchHead(name: string): Promise<string | null>;
  /** Whether `ancestor` is `of` or one of its ancestors. */
  isAncestor(ancestor: string, of: string): Promise<boolean>;
  /** A file's text at a commit, read raw up to {@link FIX_BASE_MAX_BYTES} (R15); null when absent. */
  fileAt(path: string, sha: string): Promise<string | null>;
}

export interface FixScmDeps {
  db: Db;
  scm: ScmDeps;
  runtime?: ScmRuntime;
}

/**
 * Why a project's fix repository cannot be used now: the project is not mapped to a repository,
 * the connection does not allow fix MRs (B2, read again here, so a switch turned off meanwhile
 * fails closed), or no client can be made for the connection (a key that no longer decrypts, an
 * address the rules no longer allow, a repository reference that is no `owner/repo`).
 */
export type FixRepositoryProblem = 'scm_not_bound' | 'fixes_disabled' | 'connection';

function gitlabRepository(
  connection: ScmConnectionRow,
  deps: FixScmDeps,
  ref: string,
  mainBranch: string,
): FixRepository | { problem: FixRepositoryProblem } {
  const made = gitlabClientFor(connection, deps.scm);
  if ('problem' in made) return { problem: 'connection' };
  const { client } = made;
  return {
    provider: 'gitlab',
    mainBranch,
    branchHead: (name) => client.branchHead(ref, name),
    isAncestor: async (ancestor, of) => {
      if (ancestor === of) return true;
      return (await client.mergeBase(ref, ancestor, of))?.toLowerCase() === ancestor;
    },
    fileAt: (path, sha) => client.fileText(ref, path, sha, { maxBytes: FIX_BASE_MAX_BYTES }),
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
  return {
    provider: 'github',
    mainBranch,
    branchHead: (name) => client.branchSha(name),
    isAncestor: async (ancestor, of) => {
      if (ancestor === of) return true;
      const status = await client.compareStatus(ancestor, of);
      return status === 'ahead' || status === 'identical';
    },
    fileAt: (path, sha) => client.rawFileText(path, sha, FIX_BASE_MAX_BYTES),
  };
}

/** The SCM settings of the repository's client, bound to `signal` when one is given. */
function boundTo(scm: ScmDeps, signal: AbortSignal | undefined): ScmDeps {
  if (signal === undefined) return scm;
  return {
    ...scm,
    clientOptions: { ...scm.clientOptions, signal },
    githubClientOptions: { ...scm.githubClientOptions, signal },
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
  const [row] = await deps.db
    .select({
      ref: projects.scmProjectRef,
      mainBranch: projects.mainBranchName,
      connection: scmConnections,
    })
    .from(projects)
    .innerJoin(scmConnections, eq(scmConnections.id, projects.scmConnectionId))
    .where(eq(projects.id, project.id));
  if (!row || row.ref === null) return { problem: 'scm_not_bound' };
  if (!row.connection.fixMrsAllowed) return { problem: 'fixes_disabled' };
  const bound = { ...deps, scm: boundTo(deps.scm, options.signal) };
  return row.connection.provider === 'github'
    ? githubRepository(row.connection, bound, row.ref, row.mainBranch)
    : gitlabRepository(row.connection, bound, row.ref, row.mainBranch);
}

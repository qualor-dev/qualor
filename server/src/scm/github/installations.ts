import type { ScmConnectionRow, ScmDeps } from '../connections';
import { ScmError } from '../provider';
import type { InstallationTokenCache, MutationPacer } from './app-auth';
import type { GITHUB_PAGE_SIZE, GitHubInstallationAccess, GitHubRepoSummary } from './client';
import { githubClientFor } from './connections';

export type { GitHubInstallationAccess, GitHubRepoSummary };

/** Installations one listing reads at most (100 to a page): far more than any App has. */
const MAX_INSTALLATION_PAGES = 10;

/** Every installation the App's JWT lists (suspended ones left out): no token, no repository call. */
async function allInstallations(
  client: Extract<ReturnType<typeof githubClientFor>, { client: unknown }>['client'],
): Promise<GitHubInstallationAccess[]> {
  const installations: GitHubInstallationAccess[] = [];
  for (let page = 1; page <= MAX_INSTALLATION_PAGES; page++) {
    const { items, hasMore } = await client.installations(page);
    installations.push(...items);
    if (!hasMore) break;
  }
  return installations;
}

/**
 * The App's installations with whether each grants Contents, Workflows and Secrets (write): the JWT's
 * `GET /app/installations` alone, so an installation whose repositories cannot be read still counts.
 */
export async function listInstallations(
  row: ScmConnectionRow,
  deps: ScmDeps,
): Promise<GitHubInstallationAccess[]> {
  const made = githubClientFor(row, deps);
  if ('problem' in made) {
    throw new ScmError('refused', made.problem, { reason: 'invalid_input' });
  }
  return allInstallations(made.client);
}

/**
 * One page of the repositories the App can reach, across all of its installations. The App's JWT
 * lists the installations; each installation's repositories come with a token that asks for
 * Metadata (read) only. The repositories of the installations are one list in the order GitHub
 * answers them, `perPage` to a page; reading stops as soon as the page and one more are known.
 * Suspended installations are not listed; one whose token GitHub refuses (403, 404) is left out of
 * both lists. `installations` is every other installation, with whether it grants Contents,
 * Workflows and Secrets (write), which CI setup needs. Errors are `ScmError`s, as for every
 * GitHub call.
 */
export async function listInstallationRepositories(
  row: ScmConnectionRow,
  deps: ScmDeps,
  runtime: { githubTokens: InstallationTokenCache; githubPacer: MutationPacer } | undefined,
  opts: { page: number; perPage: typeof GITHUB_PAGE_SIZE },
): Promise<{
  repositories: GitHubRepoSummary[];
  installations: GitHubInstallationAccess[];
  hasMore: boolean;
}> {
  const made = githubClientFor(row, deps, runtime);
  if ('problem' in made) {
    throw new ScmError('refused', made.problem, { reason: 'invalid_input' });
  }
  const { client } = made;
  const installations = await allInstallations(client);
  const start = (opts.page - 1) * opts.perPage;
  const want = start + opts.perPage + 1;
  const found: GitHubRepoSummary[] = [];
  /** Installations whose repositories could not be read (a token GitHub refused): left out. */
  const unavailable = new Set<number>();
  collect: for (const installation of installations) {
    const own: GitHubRepoSummary[] = [];
    try {
      for (let page = 1; ; page++) {
        const { items, hasMore } = await client.installationRepositories(
          installation.installationId,
          page,
        );
        own.push(...items);
        if (found.length + own.length >= want || !hasMore) break;
      }
    } catch (err) {
      // One broken installation (removed, or without a permission) must not hide the others.
      if (err instanceof ScmError && (err.kind === 'auth' || err.kind === 'not_found')) {
        unavailable.add(installation.installationId);
        continue;
      }
      throw err;
    }
    found.push(...own);
    if (found.length >= want) break collect;
  }
  return {
    repositories: found.slice(start, start + opts.perPage),
    installations: installations.filter((i) => !unavailable.has(i.installationId)),
    hasMore: found.length > start + opts.perPage,
  };
}

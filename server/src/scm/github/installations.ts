import type { ScmConnectionRow, ScmDeps } from '../connections';
import { ScmError } from '../provider';
import type { InstallationTokenCache, MutationPacer } from './app-auth';
import type { GITHUB_PAGE_SIZE, GitHubInstallationAccess, GitHubRepoSummary } from './client';
import { githubClientFor } from './connections';

export type { GitHubInstallationAccess, GitHubRepoSummary };

/** Installations one listing reads at most (100 to a page): far more than any App has. */
const MAX_INSTALLATION_PAGES = 10;

/**
 * One page of the repositories the App can reach, across all of its installations. The App's JWT
 * lists the installations; each installation's repositories come with a token that asks for
 * Metadata (read) only. The repositories of the installations are one list in the order GitHub
 * answers them, `perPage` to a page; reading stops as soon as the page and one more are known.
 * `installations` is every installation, with whether it grants Workflows and Secrets (write), which
 * CI setup needs. Errors are `ScmError`s, as for every GitHub call.
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
  const installations: GitHubInstallationAccess[] = [];
  for (let page = 1; page <= MAX_INSTALLATION_PAGES; page++) {
    const { items, hasMore } = await client.installations(page);
    installations.push(...items);
    if (!hasMore) break;
  }
  const start = (opts.page - 1) * opts.perPage;
  const want = start + opts.perPage + 1;
  const found: GitHubRepoSummary[] = [];
  collect: for (const installation of installations) {
    for (let page = 1; ; page++) {
      const { items, hasMore } = await client.installationRepositories(
        installation.installationId,
        page,
      );
      found.push(...items);
      if (found.length >= want) break collect;
      if (!hasMore) break;
    }
  }
  return {
    repositories: found.slice(start, start + opts.perPage),
    installations,
    hasMore: found.length > start + opts.perPage,
  };
}

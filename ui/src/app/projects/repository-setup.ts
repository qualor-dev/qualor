import type { ItemOf, ResponseBody } from '../api/types';

/** The types and words that the **Add repositories** page and its parts share. */
export type Connection = ItemOf<'/api/v0/scm-connections'>;
export type Provider = Connection['provider'];
export type Repository = ResponseBody<
  '/api/v0/scm-connections/{id}/repositories',
  'get'
>['items'][number];
export type SetupRun = ResponseBody<'/api/v0/repository-setups/{id}', 'get'>;
export type RunItem = SetupRun['items'][number];

/** At most this many repositories in one run (the server's limit). */
export const MAX_REPOSITORIES = 50;

/** A repository's state in the progress list and on its result, each with its badge. */
export type ItemState =
  'merge_request' | 'snippet' | 'already' | 'ci_failed' | 'failed' | 'working' | 'waiting';

/** The provider's name for people ("GitHub Enterprise" for a server of one's own). */
export function providerName(connection: Pick<Connection, 'provider' | 'baseUrl'>): string {
  if (connection.provider === 'gitlab') return 'GitLab';
  return githubCloud(connection.baseUrl) ? 'GitHub' : 'GitHub Enterprise';
}

/** github.com's API, or a GHE.com tenant's (`api.<name>.ghe.com`). */
function githubCloud(baseUrl: string): boolean {
  const host = hostOf(baseUrl);
  return host === 'api.github.com' || host.endsWith('.ghe.com');
}

function hostOf(url: string): string {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return url;
  }
}

/** Where a connection is, as people know it: github.com rather than its API's address. */
export function connectionHost(connection: Pick<Connection, 'provider' | 'baseUrl'>): string {
  const host = hostOf(connection.baseUrl);
  return connection.provider === 'github' && host.startsWith('api.') ? host.slice(4) : host;
}

/** `#7` for a GitHub pull request, `!7` for a GitLab merge request, from its address. */
export function mergeRequestNumber(url: string): string | null {
  const github = /\/pull\/(\d+)\/?$/.exec(url);
  if (github) return `#${github[1]}`;
  const gitlab = /\/merge_requests\/(\d+)\/?$/.exec(url);
  return gitlab ? `!${gitlab[1]}` : null;
}

/** A repository's path split for reading: the owner muted, the last segment set in bold. */
export function pathParts(path: string): { owner: string; last: string } {
  const at = path.lastIndexOf('/');
  return { owner: path.slice(0, at + 1), last: path.slice(at + 1) };
}

/**
 * A repository's state. A failed CI setup with its project made is `ci_failed`; without a project,
 * `failed`. While the run works, the first repository not done is the one in hand (`working`).
 */
export function itemState(item: RunItem, run: SetupRun | null): ItemState {
  switch (item.ciOutcome) {
    case 'merge_request':
      return 'merge_request';
    case 'snippet':
    case 'skipped':
      return 'snippet';
    case 'already':
      return 'already';
    case 'failed':
      return item.projectOutcome === 'failed' ? 'failed' : 'ci_failed';
    default: {
      const first = run?.items.find((i) => i.ciOutcome === 'pending');
      return run?.status === 'running' && first?.ref === item.ref ? 'working' : 'waiting';
    }
  }
}

/**
 * Why a repository failed, in the page's own words: the server's are English (setup-run.ts).
 * `provider` names GitHub or GitLab when the run's connection is known.
 */
export function errorText(item: RunItem, provider: string | null): string {
  const error = item.error;
  const who = provider ?? $localize`:@@addRepos.error.theProvider:The provider`;
  switch (error?.code) {
    case 'not_found':
      return $localize`:@@addRepos.error.notFound:The repository was not found, or the connection cannot reach it.`;
    case 'key_taken':
      return $localize`:@@addRepos.error.keyTaken:Every project key Qualor would give this repository is taken.`;
    case 'connection_gone':
      return $localize`:@@addRepos.error.connectionGone:The connection was deleted.`;
    case 'connection_unusable':
      return $localize`:@@addRepos.error.connectionUnusable:The connection cannot be used. Test it in the settings.`;
    case 'project_gone':
      return $localize`:@@addRepos.error.projectGone:The project was deleted.`;
    case 'permission':
      return permissionText(error.message);
    case 'rate_limited':
      return $localize`:@@addRepos.error.rateLimited:${who}:provider: is rate limiting Qualor. Try again later.`;
    case 'unavailable':
      return $localize`:@@addRepos.error.unavailable:${who}:provider: could not be reached. Try again later.`;
    case 'refused':
      return $localize`:@@addRepos.error.refused:${who}:provider: refused the change.`;
    case 'bad_answer':
      return $localize`:@@addRepos.error.badAnswer:The answer of ${who}:provider: was not understood.`;
    case 'budget':
      return $localize`:@@addRepos.error.budget:Qualor needed too many requests to ${who}:provider: for this repository.`;
    case 'abandoned':
      return $localize`:@@addRepos.error.abandoned:The run stopped before this repository.`;
    default:
      return $localize`:@@addRepos.error.internal:Something went wrong. The server log has the details.`;
  }
}

/** The server's three permission texts (setup-run.ts), in the page's words. */
function permissionText(message: string): string {
  if (message.startsWith('The GitHub App')) {
    return $localize`:@@addRepos.error.githubPermission:The GitHub App needs the Workflows and Secrets permissions, read and write.`;
  }
  if (message.startsWith('The GitLab token')) {
    return $localize`:@@addRepos.error.gitlabPermission:The GitLab token needs the api scope and the Maintainer role.`;
  }
  return $localize`:@@addRepos.error.readPermission:The connection was refused access to the repository.`;
}

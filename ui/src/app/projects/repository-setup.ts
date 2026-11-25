import type { ItemOf, ResponseBody } from '../api/types';
import { assertNever, SCM_PROVIDERS, type ScmProvider } from '../shared/scm-provider';

/** The types and words that the **Add repositories** page and its parts share. */
export type Connection = ItemOf<'/api/v0/scm-connections'>;
export type Provider = ScmProvider;
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
  switch (connection.provider) {
    case 'gitlab':
      return 'GitLab';
    case 'github':
      return githubCloud(connection.baseUrl) ? 'GitHub' : 'GitHub Enterprise';
    case 'azure':
      return 'Azure DevOps';
    default:
      return assertNever(connection.provider, 'provider');
  }
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
  const githubApi = connection.provider === 'github' && host.startsWith('api.'); // provider-guard: only GitHub's API host differs
  return githubApi ? host.slice(4) : host;
}

/** `#7` for a GitHub pull request, `!7` for a GitLab merge request or an Azure DevOps pull request. */
export function mergeRequestNumber(url: string): string | null {
  for (const provider of SCM_PROVIDERS) {
    const { pattern, prefix } = MERGE_REQUEST_URL[provider];
    const found = pattern.exec(url);
    if (found) return `${prefix}${found[1]}`;
  }
  return null;
}

/** The provider whose pull or merge request address this is; null for any other address. */
export function providerOfUrl(url: string): Provider | null {
  return SCM_PROVIDERS.find((provider) => MERGE_REQUEST_URL[provider].pattern.test(url)) ?? null;
}

/** How each provider's merge request address ends, and how its number is written. */
export const MERGE_REQUEST_URL: Record<ScmProvider, { pattern: RegExp; prefix: string }> = {
  github: { pattern: /\/pull\/(\d+)\/?$/, prefix: '#' },
  gitlab: { pattern: /\/merge_requests\/(\d+)\/?$/, prefix: '!' },
  azure: { pattern: /\/_git\/[^/]+\/pullrequest\/(\d+)\/?$/, prefix: '!' },
};

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
 * The run's `connection` names the provider when it is known. The texts never read the server's
 * message, only its code and, for a refusal, the stage it happened in.
 */
export function errorText(
  item: RunItem,
  connection: Pick<Connection, 'provider' | 'baseUrl'> | null,
): string {
  const error = item.error;
  const who =
    (connection ? providerName(connection) : null) ??
    $localize`:@@addRepos.error.theProvider:The provider`;
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
      return permissionText(connection?.provider ?? null, error.stage);
    case 'rate_limited':
      return $localize`:@@addRepos.error.rateLimited:${who}:provider: is rate limiting Qualor. Try again later.`;
    case 'unavailable':
      return $localize`:@@addRepos.error.unavailable:${who}:provider: could not be reached. Try again later.`;
    case 'refused':
      // The stage tells a refused read (before any change) from a refused change.
      if (error.stage === 'read') {
        return $localize`:@@addRepos.error.refusedRead:${who}:provider: refused a request to read the repository.`;
      }
      return $localize`:@@addRepos.error.refused:${who}:provider: refused the change.`;
    case 'bad_answer':
      return $localize`:@@addRepos.error.badAnswer:The answer of ${who}:provider: was not understood.`;
    case 'budget':
      return $localize`:@@addRepos.error.budget:Qualor needed too many requests to ${who}:provider: for this repository.`;
    case 'no_agent_pool':
      return $localize`:@@addRepos.error.noAgentPool:This Azure DevOps project has no agent pool with that name. Check the name, or leave it empty to use Microsoft-hosted agents.`;
    case 'pipeline_name_taken':
      return $localize`:@@addRepos.error.pipelineNameTaken:Both names Qualor gives a pipeline (Qualor, and Qualor with the repository's name) are taken in this project. Rename or delete one of those pipelines, then try again.`;
    case 'abandoned':
      return $localize`:@@addRepos.error.abandoned:The run stopped before this repository.`;
    default:
      return $localize`:@@addRepos.error.internal:Something went wrong. The server log has the details.`;
  }
}

/**
 * What a refused permission needs, by provider and stage: a read (or an unknown provider or
 * stage) says the same for all; a change names what CI setup needs on the provider.
 */
function permissionText(provider: Provider | null, stage: 'read' | 'change' | null): string {
  if (provider === null || stage !== 'change') {
    return $localize`:@@addRepos.error.readPermission:The connection was refused access to the repository.`;
  }
  switch (provider) {
    case 'github':
      return $localize`:@@addRepos.error.githubPermission:The GitHub App needs the Contents, Workflows and Secrets permissions, read and write.`;
    case 'gitlab':
      return $localize`:@@addRepos.error.gitlabPermission:The GitLab token needs the api scope and the Maintainer role.`;
    case 'azure':
      // A personal access token without the pipelines scopes is refused (HTTP 401) as `change` too.
      return $localize`:@@addRepos.error.azurePermission:The Azure DevOps identity needs Contribute and Create branch on the repository, Contribute to pull requests, Edit build pipeline in the project, the User role on the agent pool's queue, and read access to the project's agent pools. A personal access token also needs the Build (Read & execute), Agent Pools (Read) and Pipeline Resources (Use and manage) scopes.`;
    default:
      return assertNever(provider, 'provider');
  }
}

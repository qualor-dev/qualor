/** github.md §2.2–§2.3: GitHub's API base URLs, their web base, and repository references. */

const GHE_COM = /^https:\/\/api\.([a-z0-9-]+)\.ghe\.com$/;
const API_ROOT_HINT =
  'Use the API root: https://api.github.com, https://api.<subdomain>.ghe.com or https://<host>/api/v3';

/**
 * Checks a base URL already normalised by `normalBaseUrl` and allowed by `scmBaseUrlProblem`
 * (scm.md §2.1): github.com's API root, a GHE.com API root, or an Enterprise Server's `/api/v3`.
 */
export function githubBaseUrlProblem(normalised: string): string | null {
  const url = new URL(normalised);
  const host = url.hostname.toLowerCase();
  const path = url.pathname.replace(/\/$/, '');
  if (host === 'github.com' || host === 'www.github.com') return 'Use https://api.github.com';
  if (host === 'api.github.com') return path === '' ? null : 'Use https://api.github.com';
  if (GHE_COM.test(`${url.protocol}//${host}`) && url.port === '') {
    return path === '' ? null : API_ROOT_HINT;
  }
  return path.endsWith('/api/v3') ? null : API_ROOT_HINT;
}

/** github.md §2.2: where GitHub's own links (a pull request's `html_url`) live. */
export function githubWebBase(baseUrl: string): string {
  if (baseUrl === 'https://api.github.com') return 'https://github.com';
  const ghe = GHE_COM.exec(baseUrl);
  if (ghe?.[1]) return `https://${ghe[1]}.ghe.com`;
  if (baseUrl.endsWith('/api/v3')) return baseUrl.slice(0, -'/api/v3'.length);
  return baseUrl;
}

/** github.md §2.3: `owner/repo`, nothing else. */
export const GITHUB_REPO_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;

export interface GitHubRepoRef {
  owner: string;
  repo: string;
}

export function parseRepoRef(ref: string): GitHubRepoRef | null {
  if (!GITHUB_REPO_PATTERN.test(ref)) return null;
  const [owner, repo] = ref.split('/') as [string, string];
  return { owner, repo };
}

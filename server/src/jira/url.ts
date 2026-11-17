import type { JiraDeployment } from '../db/schema';
import { MAX_WEBHOOK_URL_LENGTH } from '../webhooks/url';
import { baseUrlProblem, isInternalHostAllowed, normalBaseUrl } from '../scm/url';

/** spec §6.1: a Jira Cloud site's host, one label under `atlassian.net`. */
const CLOUD_SITE_HOST = /^[a-z0-9][a-z0-9-]{0,62}\.atlassian\.net$/;

/** spec §6.1: the gateway address a scoped API token needs, the cloud id a UUID. */
const API_URL =
  /^https:\/\/api\.atlassian\.com\/ex\/jira\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The gateway's origin, whose cloud id {@link normalJiraUrl} stores in lower case. */
const GATEWAY_ORIGIN = 'https://api.atlassian.com';

/**
 * spec §6.1: the problem with a connection's `siteUrl`, or null.
 * - Cloud: `https://<name>.atlassian.net` only, with no path, port, credentials, query or
 *   fragment; `QUALOR_JIRA_INTERNAL_HOSTS` never allows another host.
 * - Data Center: the base URL with its context path, under the rules of every base URL Qualor
 *   calls (scm/url.ts): `https`, or `http` and non-public addresses only for a host listed in
 *   `QUALOR_JIRA_INTERNAL_HOSTS`; link-local and cloud metadata addresses never.
 * At most 2 048 characters in both.
 */
export function jiraSiteUrlProblem(
  raw: string,
  deployment: JiraDeployment,
  internalHosts: ReadonlySet<string>,
): string | null {
  if (deployment === 'data_center') {
    return baseUrlProblem(raw, internalHosts, {
      variable: 'QUALOR_JIRA_INTERNAL_HOSTS',
      credential: 'the token',
    });
  }
  if (raw.length > MAX_WEBHOOK_URL_LENGTH) return 'The URL is too long';
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return 'Not a valid URL';
  }
  if (url.username !== '' || url.password !== '') {
    return 'The URL must not contain credentials; use the email and the token';
  }
  if (url.search !== '' || raw.includes('?')) return 'The URL must not contain a query';
  if (url.hash !== '' || raw.includes('#')) return 'The URL must not contain a fragment';
  if (
    url.protocol !== 'https:' ||
    !CLOUD_SITE_HOST.test(url.hostname) ||
    url.port !== '' ||
    url.pathname !== '/'
  ) {
    return 'A Jira Cloud site URL is https://<name>.atlassian.net, with no path';
  }
  return null;
}

/**
 * spec §6.1: the problem with a Cloud connection's `apiUrl`, or null:
 * `https://api.atlassian.com/ex/jira/<cloud id>`, the cloud id a UUID in any case, nothing after it.
 */
export function jiraApiUrlProblem(raw: string): string | null {
  return API_URL.test(raw)
    ? null
    : 'The API URL is https://api.atlassian.com/ex/jira/<cloud id>, the cloud id a UUID';
}

/**
 * The stored form of a site or API URL: normalised without a trailing slash (scm/url.ts), and the
 * cloud id of a gateway address in lower case. A Data Center's path keeps its case.
 */
export function normalJiraUrl(raw: string): string {
  const normal = normalBaseUrl(raw);
  return new URL(normal).origin === GATEWAY_ORIGIN ? normal.toLowerCase() : normal;
}

/**
 * Whether the requests to this URL may use internal addresses (`allowInternalHosts` of the client):
 * a Data Center host listed in `QUALOR_JIRA_INTERNAL_HOSTS` with its port; never a Cloud site,
 * whose addresses must be public. False for a URL that cannot be read.
 */
export function jiraHostAllowed(
  url: string,
  deployment: JiraDeployment,
  internalHosts: ReadonlySet<string>,
): boolean {
  if (deployment === 'cloud') return false;
  try {
    return isInternalHostAllowed(new URL(url), internalHosts);
  } catch {
    return false;
  }
}

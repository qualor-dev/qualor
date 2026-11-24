/**
 * Azure DevOps address rules: which deployment a base URL is, whether its shape is right, and the
 * web URLs. Pure helpers, no I/O.
 *
 * Inputs are base URLs already normalised by `normalBaseUrl` (`new URL(raw).href` without trailing
 * slashes), which lower-cases the host and keeps the scheme, port and path; `baseUrlProblem` has
 * already refused queries, fragments and credentials. The host is still compared case-insensitively
 * here so these helpers do not depend on that.
 */

export type AzureDeployment = 'services' | 'server';

/** An Azure DevOps repository id (a GUID). */
export const AZURE_REPOSITORY_ID =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const ORGANIZATION = /^[A-Za-z0-9][A-Za-z0-9-]{0,48}[A-Za-z0-9]$|^[A-Za-z0-9]$/;
const SERVICES_HINT = 'Use https://dev.azure.com/<organization>';
const SERVER_HINT = 'Use the collection URL, e.g. https://ado.example.com/DefaultCollection';

function isServicesHost(host: string): boolean {
  return host === 'dev.azure.com' || host.endsWith('.visualstudio.com');
}

/** Services (dev.azure.com, *.visualstudio.com) or Server, from the host alone. */
export function azureDeployment(normalisedBaseUrl: string): AzureDeployment {
  return isServicesHost(new URL(normalisedBaseUrl).hostname.toLowerCase()) ? 'services' : 'server';
}

/** What is wrong with the shape of a normalised base URL, or null. */
export function azureBaseUrlProblem(normalised: string): string | null {
  const url = new URL(normalised);
  const host = url.hostname.toLowerCase();
  const path = url.pathname.replace(/\/+$/, '');
  const segments = path === '' ? [] : path.slice(1).split('/');
  const emptySegment = segments.includes('');
  if (!isServicesHost(host)) return segments.length > 0 && !emptySegment ? null : SERVER_HINT;
  const plain = url.protocol === 'https:' && url.port === '' && url.search === '';
  if (!plain || emptySegment) return SERVICES_HINT;
  if (host === 'dev.azure.com') {
    const [organization] = segments;
    return segments.length === 1 && organization !== undefined && ORGANIZATION.test(organization)
      ? null
      : SERVICES_HINT;
  }
  const label = host.slice(0, -'.visualstudio.com'.length);
  return segments.length === 0 && ORGANIZATION.test(label) ? null : SERVICES_HINT;
}

/** Web and API share one base URL on both deployments. */
export function azureWebBase(normalisedBaseUrl: string): string {
  return normalisedBaseUrl;
}

/** A pipeline's web URL: the project by name (`<project>/_build?definitionId=<id>`). */
export function azurePipelineWebUrl(
  normalisedBaseUrl: string,
  projectName: string,
  definitionId: number,
): string {
  return `${azureWebBase(normalisedBaseUrl)}/${encodeURIComponent(projectName)}/_build?definitionId=${definitionId}`;
}

/** A pull request's web URL, from the repository's `webUrl`. */
export function azurePullRequestWebUrl(repositoryWebUrl: string, id: number): string {
  return `${repositoryWebUrl}/pullrequest/${id}`;
}

/**
 * Where identities are looked up: Services keeps them on a host of their own, `vssps.dev.azure.com/<org>`
 * for `https://dev.azure.com/<org>` and `<org>.vssps.visualstudio.com` for `https://<org>.visualstudio.com`;
 * a Server collection answers them itself. The caller applies the same address rules as to the base.
 */
export function azureIdentitiesBase(
  normalisedBaseUrl: string,
  deployment: AzureDeployment,
): string {
  if (deployment === 'server') return normalisedBaseUrl;
  const url = new URL(normalisedBaseUrl);
  const host = url.hostname.toLowerCase();
  if (host === 'dev.azure.com')
    return `https://vssps.dev.azure.com${url.pathname.replace(/\/+$/, '')}`;
  const label = host.slice(0, -'.visualstudio.com'.length);
  return `https://${label}.vssps.visualstudio.com`;
}

/** Where Azure DevOps posts service hooks for a connection: Qualor's public URL plus the route. */
export function azureWebhookUrl(publicUrl: string, connectionId: string): string {
  return `${publicUrl.replace(/\/+$/, '')}/api/v0/azure-devops/webhooks/${connectionId}`;
}

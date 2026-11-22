/**
 * How an Azure DevOps connection authenticates (migration 0034, `scm_connections.azure_auth`).
 * Kept apart from the schema so the schema imports no more than this list.
 */
export const AZURE_AUTH_KINDS = [
  'pat',
  'service_principal_secret',
  'service_principal_certificate',
] as const;
export type AzureAuthKind = (typeof AZURE_AUTH_KINDS)[number];

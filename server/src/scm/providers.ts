import { SCM_PROVIDERS, type ScmProvider } from '@qualor/shared';
import { SCM_PROJECT_REF_PATTERN } from '../patterns';
import type { AzureAuthKind } from './azure/auth-kinds';
import { AZURE_REPOSITORY_ID } from './azure/url';
import { GITHUB_REPO_PATTERN } from './github/url';

/** The fields an SCM connection PATCH may send (routes/scm-connections.ts). */
export interface ConnectionPatch {
  baseUrl?: string;
  /** GitLab's token; Azure DevOps' PAT or client secret. */
  token?: string;
  appId?: string;
  privateKey?: string;
  webhookSecret?: string | null;
  ciSetupAllowed?: boolean;
  fixMrsAllowed?: boolean;
  azureAuth?: AzureAuthKind;
  tenantId?: string;
  clientId?: string;
  /** Azure DevOps: the certificate and its private key, one PEM text. */
  certificate?: string;
}

/** What differs between the providers where a connection or its mapping is checked. */
export interface ProviderDescriptor {
  /** The provider's name, as texts and log lines say it. */
  label: string;
  /** The PATCH fields of the other providers: each is a 422 on its own path. */
  foreignFields: readonly (keyof ConnectionPatch)[];
  /** What a project reference must be (the 422 of a wrong one). */
  projectRefText: string;
  /** Why `ref` is not a project reference of this provider, or null. */
  projectRefProblem(ref: string): string | null;
  /** The form a project reference is stored in. */
  storedRef(ref: string): string;
}

const AZURE_FIELDS = ['azureAuth', 'tenantId', 'clientId', 'certificate'] as const;

/** A provider whose references are checked against `pattern` and stored as sent. */
function asSent(text: string, pattern: RegExp) {
  return {
    projectRefText: text,
    projectRefProblem: (ref: string) => (pattern.test(ref) ? null : text),
    storedRef: (ref: string) => ref,
  };
}

const AZURE_REF_TEXT = 'Use the Azure DevOps repository id (pick it from the list)';

/** One descriptor per provider (Azure DevOps sub-plan 2, from sub-plan 1's ledger). */
export const PROVIDER: Record<ScmProvider, ProviderDescriptor> = {
  gitlab: {
    label: 'GitLab',
    foreignFields: ['appId', 'privateKey', ...AZURE_FIELDS],
    // scm.md §2.2: the project id or its full path.
    ...asSent(
      'Use the GitLab project id or its full path (group/project)',
      SCM_PROJECT_REF_PATTERN,
    ),
  },
  github: {
    label: 'GitHub',
    foreignFields: ['token', 'ciSetupAllowed', ...AZURE_FIELDS],
    // github.md §2.3: owner/repo.
    ...asSent('Use the GitHub repository as owner/repo', GITHUB_REPO_PATTERN),
  },
  azure: {
    label: 'Azure DevOps',
    // Qualor makes the service hooks' password itself (sub-plan 5); CI setup arrives with
    // sub-plan 7. Fix pull requests are allowed with `fixMrsAllowed` (sub-plan 6).
    foreignFields: ['appId', 'privateKey', 'webhookSecret', 'ciSetupAllowed'],
    // Design §7.2: the repository's GUID, which survives renames; Azure DevOps writes it in lower
    // case.
    projectRefText: AZURE_REF_TEXT,
    projectRefProblem: (ref) => (AZURE_REPOSITORY_ID.test(ref) ? null : AZURE_REF_TEXT),
    storedRef: (ref) => ref.toLowerCase(),
  },
};

/** `Not a field of a GitLab connection`, `… of an Azure DevOps connection`. */
export function notAFieldText(provider: ScmProvider): string {
  const { label } = PROVIDER[provider];
  return `Not a field of ${/^[AEIOU]/.test(label) ? 'an' : 'a'} ${label} connection`;
}

/**
 * Why `ref` is no project reference of any provider, or null: what a project without a connection
 * may hold (its connection, once set, checks it as its own).
 */
export function anyProjectRefProblem(ref: string): string | null {
  return SCM_PROVIDERS.some((provider) => PROVIDER[provider].projectRefProblem(ref) === null)
    ? null
    : 'Use a GitLab project id or full path, a GitHub owner/repo, or an Azure DevOps repository id';
}

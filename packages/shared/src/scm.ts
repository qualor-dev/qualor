/** The source-control providers Qualor talks to. Every branch on a provider must cover each one. */
export const SCM_PROVIDERS = ['gitlab', 'github', 'azure'] as const;
export type ScmProvider = (typeof SCM_PROVIDERS)[number];

/** The `default` arm of a switch over a closed set: a new member that is not handled fails to compile. */
export function assertNever(value: never, what?: string): never {
  throw new Error(`unexpected ${what ?? 'value'}: ${describe(value)}`);
}

/** The value as text: an object with a string `provider` (a connection, a row) prints that, not [object Object]. */
function describe(value: unknown): string {
  if (typeof value === 'object' && value !== null) {
    const provider = (value as { provider?: unknown }).provider;
    if (typeof provider === 'string') return provider;
  }
  return String(value);
}

/** One character a project key may hold (`project.key` of qualor.yml, the server's projects). */
const KEY_CHARACTER = /^[A-Za-z0-9._/:-]$/;

/**
 * The project key of an Azure DevOps repository, as Add repositories and the scanner in Azure
 * Pipelines make it: `<project>/<repository>` with every character a key may not hold made `-`,
 * runs of `-` collapsed and trimmed. A name of other scripts only leaves no letter or digit: the
 * repository's id (lower-cased) is the key then.
 */
export function azureProjectKey(name: string, repositoryId: string): string {
  const key = [...name]
    .map((c) => (KEY_CHARACTER.test(c) ? c : '-'))
    .join('')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-+$/g, '');
  return /[A-Za-z0-9]/.test(key) ? key : repositoryId.toLowerCase();
}

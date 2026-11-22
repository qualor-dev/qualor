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

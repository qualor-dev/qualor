/** The source-control providers Qualor talks to. Every branch on a provider must cover each one. */
export const SCM_PROVIDERS = ['gitlab', 'github'] as const;
export type ScmProvider = (typeof SCM_PROVIDERS)[number];

/** The `default` arm of a switch over a closed set: a new member that is not handled fails to compile. */
export function assertNever(value: never, what?: string): never {
  throw new Error(`unexpected ${what ?? 'value'}: ${String(value)}`);
}

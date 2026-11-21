/**
 * The UI never imports packages/shared (AGENTS.md rule 5), so it keeps its own copy of the provider
 * list. tools/provider-branches.test.ts keeps it equal to the shared one.
 */
export const SCM_PROVIDERS = ['gitlab', 'github'] as const;
export type ScmProvider = (typeof SCM_PROVIDERS)[number];

export function assertNever(value: never, what?: string): never {
  throw new Error(`unexpected ${what ?? 'value'}: ${String(value)}`);
}

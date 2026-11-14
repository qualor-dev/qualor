/**
 * Orders the vulnerability modules share. A leaf module: the pure document builders
 * (`export/*-documents.ts`) take it without pulling in the database modules.
 */

/** The vulnerability severities, worst first. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
export type VulnerabilitySeverity = (typeof SEVERITIES)[number];

/** Code-unit order (not locale-dependent): the same on every database collation. */
export function compare(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

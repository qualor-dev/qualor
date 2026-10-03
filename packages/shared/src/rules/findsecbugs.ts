import { z } from 'zod';
import table from '../../rules/findsecbugs.json' with { type: 'json' };
import type { Severity } from '../report/taxonomy';

/**
 * FindSecBugs (plan 6A, config.md §6): the SpotBugs plugin qualor/scanner installs into SpotBugs'
 * plugin/ directory (tools/analyzers/install.sh; tools/ci.test.ts checks they agree).
 */
export const FINDSECBUGS_VERSION = '1.14.0';

export const FINDSECBUGS_BASES = ['taint', 'misuse', 'review', 'source', 'endpoint'] as const;

const patternSchema = z.strictObject({
  kind: z.enum(['issue', 'hotspot']),
  severity: z.enum(['high', 'medium', 'low', 'info']),
  basis: z.enum(FINDSECBUGS_BASES),
});
export type FindsecbugsPattern = z.infer<typeof patternSchema>;

const tableSchema = z.strictObject({
  $comment: z.string(),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  patterns: z.record(z.string().regex(/^[A-Z][A-Z0-9_]*$/), patternSchema),
});

const parsed = tableSchema.parse(table);

/** The FindSecBugs version findsecbugs.json describes. */
export const FINDSECBUGS_TABLE_VERSION: string = parsed.version;

/** report-format.md §7.1: every pattern of the bundled FindSecBugs, by bug pattern type. */
export const FINDSECBUGS_PATTERNS: ReadonlyMap<string, FindsecbugsPattern> = new Map(
  Object.entries(parsed.patterns),
);

export function findsecbugsPattern(id: string): FindsecbugsPattern | undefined {
  return FINDSECBUGS_PATTERNS.get(id);
}

const ONE_LOWER: Readonly<Record<Severity, Severity>> = {
  blocker: 'high',
  high: 'medium',
  medium: 'low',
  low: 'info',
  info: 'info',
};

/**
 * report-format.md §7.1: the pattern's severity, one step lower for a result SpotBugs reports at
 * SARIF `note` (FindSecBugs' low confidence). SpotBugs' own level is not used otherwise: its rank
 * formula puts every FindSecBugs result at `warning` or `note`.
 */
export function findsecbugsSeverity(
  pattern: FindsecbugsPattern,
  level: string | undefined,
): Severity {
  return level === 'note' ? ONE_LOWER[pattern.severity] : pattern.severity;
}

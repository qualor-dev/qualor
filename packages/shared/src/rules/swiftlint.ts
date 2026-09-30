import { z } from 'zod';
import table from '../../rules/swiftlint-rules.json' with { type: 'json' };
import type { Quality, Severity } from '../report/taxonomy';

/**
 * SwiftLint (plan 8F, config.md §6). `SWIFTLINT_VERSION` is the SwiftLint the qualor/scanner image
 * ships (tools/analyzers/install.sh; tools/ci.test.ts checks they agree). The CLI runs only a
 * SwiftLint of the same major.minor, because swiftlint-rules.json describes that version.
 */
export const SWIFTLINT_VERSION = '0.65.1';

export const SWIFTLINT_KINDS = ['lint', 'idiomatic', 'style', 'metrics', 'performance'] as const;
export type SwiftlintKind = (typeof SWIFTLINT_KINDS)[number];

const ruleSchema = z.strictObject({
  kind: z.enum(SWIFTLINT_KINDS),
  optIn: z.boolean(),
  sourceKit: z.boolean(),
  analyzer: z.boolean(),
  enabledByDefault: z.boolean(),
});
export type SwiftlintRule = z.infer<typeof ruleSchema>;

const tableSchema = z.strictObject({
  $comment: z.string(),
  version: z.string(),
  rules: z.record(z.string().regex(/^[a-z][a-z0-9_]*$/), ruleSchema),
});

/** Every rule of the pinned SwiftLint, by identifier (swiftlint-rules.json, generated). */
export const SWIFTLINT_RULES: ReadonlyMap<string, SwiftlintRule> = new Map(
  Object.entries(tableSchema.parse(table).rules),
);

export function swiftlintVersionSupported(version: string): boolean {
  const [major, minor] = SWIFTLINT_VERSION.split('.');
  const m = /^(\d+)\.(\d+)\.\d+$/.exec(version);
  return m !== null && m[1] === major && m[2] === minor;
}

/** report-format.md §7.1: `lint` rules are about correctness; every other kind, and a rule the table does not know, is maintainability. */
export function swiftlintQuality(ruleId: string): Quality {
  return SWIFTLINT_RULES.get(ruleId)?.kind === 'lint' ? 'reliability' : 'maintainability';
}

/**
 * report-format.md §7.1: an error is high; a warning is medium for `lint` rules and low otherwise;
 * a note is low and level `none` is info (a rule set to `none` never reaches the report from
 * SwiftLint itself, this keeps the mapping total).
 */
export function swiftlintSeverity(
  ruleId: string,
  level: 'error' | 'warning' | 'note' | 'none',
): Severity {
  if (level === 'error') return 'high';
  if (level === 'note') return 'low';
  if (level === 'none') return 'info';
  return SWIFTLINT_RULES.get(ruleId)?.kind === 'lint' ? 'medium' : 'low';
}

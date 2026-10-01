/**
 * Go (plan 9C, config.md §6). The versions the qualor/scanner image ships
 * (tools/analyzers/install-go.sh; tools/ci.test.ts checks they agree) and the version policy.
 * Also the rule tables (generated from the pinned tools) and the severity helpers of the mappings.
 */
import { z } from 'zod';
import table from '../../rules/go-rules.json' with { type: 'json' };
import type { IssueKind, Quality, Severity } from '../report/taxonomy';

export const GO_VERSION = '1.27.1';
/** The oldest `go` the Go engines run with (staticcheck 2026.2 supports the two newest Go releases). */
export const GO_MIN_VERSION = '1.26';
export const STATICCHECK_VERSION = '2026.2.1';
export const GOSEC_VERSION = '2.29.0';
/** gosec's noisiest rules, left out by default: G104 (unchecked errors), G115 (integer conversions) and G304 (file path from a variable, a false positive on idiomatic file reads). */
export const GOSEC_DEFAULT_EXCLUDE: readonly string[] = ['G104', 'G115', 'G304'];
export const GOSEC_RULE_ID = /^G\d{3}$/;

function majorMinor(version: string): [number, number] | null {
  const m = /^(\d+)\.(\d+)/.exec(version);
  return m === null ? null : [Number(m[1]), Number(m[2])];
}

/** A `go` of GO_MIN_VERSION or newer (`1.26`, `1.27.1`, `1.28rc1`). */
export function goVersionSupported(version: string): boolean {
  const v = majorMinor(version);
  const min = majorMinor(GO_MIN_VERSION) as [number, number];
  return v !== null && (v[0] > min[0] || (v[0] === min[0] && v[1] >= min[1]));
}

function sameMinor(pinned: string, version: string): boolean {
  const a = majorMinor(pinned);
  const b = /^\d+\.\d+\.\d+$/.test(version) ? majorMinor(version) : null;
  return a !== null && b !== null && a[0] === b[0] && a[1] === b[1];
}

/** staticcheck's own scheme is `year.minor.patch` (`2026.2.1`): the pinned year.minor only. */
export function staticcheckVersionSupported(version: string): boolean {
  return sameMinor(STATICCHECK_VERSION, version);
}

export function gosecVersionSupported(version: string): boolean {
  return sameMinor(GOSEC_VERSION, version);
}

const tableSchema = z.strictObject({
  $comment: z.string(),
  go: z.string(),
  staticcheck: z.strictObject({
    version: z.string(),
    checks: z.array(z.string().regex(/^(SA|S|ST|QF|U)\d{4}$/)),
  }),
  govet: z.strictObject({ analyzers: z.array(z.string().regex(/^[a-z][a-z0-9]*$/)) }),
  gosec: z.strictObject({ version: z.string(), rules: z.array(z.string().regex(GOSEC_RULE_ID)) }),
});
const TABLE = tableSchema.parse(table);

/** The versions packages/shared/rules/go-rules.json was generated from (tools/analyzers/go-rules.mjs). */
export const GO_RULES_TABLE: Readonly<{ go: string; staticcheck: string; gosec: string }> = {
  go: TABLE.go,
  staticcheck: TABLE.staticcheck.version,
  gosec: TABLE.gosec.version,
};
export const STATICCHECK_CHECKS: ReadonlySet<string> = new Set(TABLE.staticcheck.checks);
export const GOVET_ANALYZERS: ReadonlySet<string> = new Set(TABLE.govet.analyzers);
export const GOSEC_RULES: ReadonlySet<string> = new Set(TABLE.gosec.rules);

export interface GoRuleMeta {
  quality: Quality;
  kind: IssueKind;
  defaultSeverity: Severity;
}

const meta = (quality: Quality, defaultSeverity: Severity): GoRuleMeta => ({
  quality,
  kind: 'issue',
  defaultSeverity,
});

/**
 * report-format.md §7.1: staticcheck by check family. SA2 (concurrency) and SA5 (correctness) are
 * bugs that bite at run time; SA1019 is a deprecated API, a maintenance concern; SA6 is performance;
 * U1000 is dead code; the simplifications (S), style (ST) and quick fixes (QF) are low.
 */
export function staticcheckRule(id: string): GoRuleMeta {
  if (/^SA[25]\d{3}$/.test(id)) return meta('reliability', 'high');
  if (id === 'SA1019') return meta('maintainability', 'low');
  if (/^SA6\d{3}$/.test(id)) return meta('maintainability', 'medium');
  if (/^SA\d{4}$/.test(id)) return meta('reliability', 'medium');
  if (id === 'U1000') return meta('maintainability', 'medium');
  return meta('maintainability', 'low');
}

/** report-format.md §7.1: go vet reports likely bugs; unkeyed composite literals are style. */
export function govetRule(name: string): GoRuleMeta {
  return name === 'composites' ? meta('maintainability', 'low') : meta('reliability', 'medium');
}

const GOSEC_SEVERITY: Readonly<Record<string, Severity>> = {
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

/** report-format.md §7.1: the HIGH/MEDIUM/LOW tag gosec's SARIF puts on each rule; none → medium. */
export function gosecSeverity(tags: readonly string[]): Severity {
  for (const t of tags) if (Object.hasOwn(GOSEC_SEVERITY, t)) return GOSEC_SEVERITY[t] as Severity;
  return 'medium';
}

import { z } from 'zod';
import { coverageMeasures, type CoverageCounts } from './metrics';
import type { Report } from './report/schema';
import { ISSUE_KINDS, LANGUAGES, REPORT_QUALITIES, SEVERITIES } from './report/taxonomy';

const count = z.number().int().min(0);
const block = z.strictObject({
  path: z.string(),
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
});

export const expectedSchema = z.strictObject({
  description: z.string().min(1),
  engines: z.array(z.string()),
  findingsExhaustive: z.boolean(),
  findings: z.array(
    z.strictObject({
      ruleKey: z.string().regex(/^[a-z0-9-]+:.+$/),
      path: z.string(),
      startLine: z.number().int().min(1),
      severity: z.enum(SEVERITIES).optional(),
      quality: z.enum(REPORT_QUALITIES).optional(),
      kind: z.enum(ISSUE_KINDS).optional(),
    }),
  ),
  files: z.record(
    z.string(),
    z.strictObject({
      language: z.enum(LANGUAGES),
      kind: z.enum(['main', 'test']),
      lines: count.optional(),
      ncloc: count.optional(),
      commentLines: count.optional(),
      functions: count.optional(),
      classes: count.optional(),
      statements: count.optional(),
      complexity: count.optional(),
      cognitiveComplexity: count.optional(),
    }),
  ),
  duplications: z.array(z.strictObject({ blocks: z.array(block).min(2) })),
  coverage: z
    .strictObject({
      lines_to_cover: count,
      uncovered_lines: count,
      conditions_to_cover: count,
      uncovered_conditions: count,
      coverage: z.number().min(0).max(100),
    })
    .nullable(),
  // Dependency licences (6M): when present, the report's entries must equal this list exactly.
  dependencies: z
    .array(
      z.strictObject({
        path: z.string(),
        ecosystem: z.string(),
        name: z.string(),
        version: z.string(),
        licenses: z.array(z.string()),
      }),
    )
    .optional(),
  notes: z.record(z.string(), z.string()).optional(),
});

export type Expected = z.infer<typeof expectedSchema>;

export interface Mismatch {
  kind:
    | 'engine'
    | 'missing-finding'
    | 'unexpected-finding'
    | 'file'
    | 'duplication'
    | 'coverage'
    | 'dependency';
  detail: string;
}

const findingKey = (ruleKey: string, path: string | null, line: number, severity?: string) => {
  const suffix = severity ? ` [${severity}]` : '';
  return `${ruleKey} ${path ?? '(project)'}:${line}${suffix}`;
};

/** The order of two strings by code unit, for sorting. */
function compareText(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function rangeLength(ranges: readonly (readonly [number, number])[]): number {
  return ranges.reduce((n, [a, b]) => n + (b - a + 1), 0);
}

const METRIC_FIELDS = [
  'ncloc',
  'commentLines',
  'functions',
  'classes',
  'statements',
  'complexity',
  'cognitiveComplexity',
] as const;

type ExpectedFinding = Expected['findings'][number];
type ReportFile = Report['files'][number];

/** Every expected engine ran with status ok. */
function compareEngines(expected: Expected, report: Report, out: Mismatch[]): void {
  for (const id of expected.engines) {
    const e = report.engines.find((x) => x.id === id);
    if (!e || e.status !== 'ok') {
      out.push({
        kind: 'engine',
        detail: `${id}: expected status ok, got ${e?.status ?? 'absent'}`,
      });
    }
  }
}

/** Each rule's quality and kind, by rule key. */
function ruleTraits(report: Report): { quality: Map<string, string>; kinds: Map<string, string> } {
  const quality = new Map<string, string>();
  for (const e of report.engines)
    for (const r of e.rules) if (r.quality) quality.set(`${e.id}:${r.id}`, r.quality);
  // A rule without a kind is an issue (report-format.md).
  const kinds = new Map<string, string>();
  for (const e of report.engines)
    for (const r of e.rules) kinds.set(`${e.id}:${r.id}`, r.kind ?? 'issue');
  return { quality, kinds };
}

/** The report's findings as the fixture names them. */
function actualFindings(report: Report) {
  return report.findings.map((f) => ({
    ruleKey: `${f.engineId}:${f.ruleId}`,
    path: f.location?.path ?? null,
    line: f.location?.startLine ?? 1,
    severity: f.severity,
    engine: f.engineId,
  }));
}
type ActualFinding = ReturnType<typeof actualFindings>[number];

/** The same rule and place, and the severity, quality and kind `e` names, if any. */
function findingMatches(
  a: ActualFinding,
  e: ExpectedFinding,
  quality: ReadonlyMap<string, string>,
  kinds: ReadonlyMap<string, string>,
): boolean {
  return (
    a.ruleKey === e.ruleKey &&
    a.path === e.path &&
    a.line === e.startLine &&
    (e.severity === undefined || a.severity === e.severity) &&
    (e.quality === undefined || quality.get(a.ruleKey) === e.quality) &&
    (e.kind === undefined || (kinds.get(a.ruleKey) ?? 'issue') === e.kind)
  );
}

/** Each expected finding matches an actual one of its own; with `findingsExhaustive`, no more. */
function compareFindings(expected: Expected, report: Report, out: Mismatch[]): void {
  const { quality, kinds } = ruleTraits(report);
  const actual = actualFindings(report);
  const matched = new Set<number>();
  for (const e of expected.findings) {
    const i = actual.findIndex(
      (a, idx) => !matched.has(idx) && findingMatches(a, e, quality, kinds),
    );
    if (i === -1)
      out.push({
        kind: 'missing-finding',
        detail: findingKey(e.ruleKey, e.path, e.startLine, e.severity),
      });
    else matched.add(i);
  }
  if (!expected.findingsExhaustive) return;
  actual.forEach((a, idx) => {
    if (!matched.has(idx) && expected.engines.includes(a.engine)) {
      out.push({
        kind: 'unexpected-finding',
        detail: findingKey(a.ruleKey, a.path, a.line, a.severity),
      });
    }
  });
}

/** One file's language, kind, lines and the metrics `want` names. */
function compareFile(
  path: string,
  want: Expected['files'][string],
  f: ReportFile,
  out: Mismatch[],
): void {
  if (f.language !== want.language)
    out.push({
      kind: 'file',
      detail: `${path}: language expected ${want.language}, got ${f.language}`,
    });
  if (f.kind !== want.kind)
    out.push({ kind: 'file', detail: `${path}: kind expected ${want.kind}, got ${f.kind}` });
  if (want.lines !== undefined && f.lines !== want.lines)
    out.push({ kind: 'file', detail: `${path}: lines expected ${want.lines}, got ${f.lines}` });
  for (const field of METRIC_FIELDS) {
    const w = want[field];
    const got = f.metrics?.[field];
    if (w !== undefined && got !== w)
      out.push({ kind: 'file', detail: `${path}: ${field} expected ${w}, got ${got ?? 'none'}` });
  }
}

function compareFiles(expected: Expected, report: Report, out: Mismatch[]): void {
  for (const [path, want] of Object.entries(expected.files)) {
    const f = report.files.find((x) => x.path === path);
    if (!f) {
      out.push({ kind: 'file', detail: `${path}: missing from report` });
      continue;
    }
    compareFile(path, want, f, out);
  }
}

/** A duplication group as its sorted blocks. */
function groupKey(g: {
  blocks: readonly { path: string; startLine: number; endLine: number }[];
}): string {
  return g.blocks
    .map((b) => `${b.path}:${b.startLine}-${b.endLine}`)
    .sort()
    .join('|');
}

function compareDuplications(expected: Expected, report: Report, out: Mismatch[]): void {
  const actualGroups = new Set(report.duplications.map(groupKey));
  const expectedGroups = new Set(expected.duplications.map(groupKey));
  for (const g of expectedGroups)
    if (!actualGroups.has(g)) out.push({ kind: 'duplication', detail: `missing group ${g}` });
  for (const g of actualGroups)
    if (!expectedGroups.has(g)) out.push({ kind: 'duplication', detail: `unexpected group ${g}` });
}

interface DependencyView {
  path: string;
  ecosystem: string;
  name: string;
  version: string;
  licenses: string[];
}

function depKey(d: { path: string; ecosystem: string; name: string; version: string }): string {
  return `${d.path} ${d.ecosystem} ${d.name}@${d.version}`;
}

function dependencyView(d: {
  path: string;
  ecosystem: string;
  name: string;
  version: string;
  licenses: readonly string[];
}): DependencyView {
  return {
    path: d.path,
    ecosystem: d.ecosystem,
    name: d.name,
    version: d.version,
    licenses: [...d.licenses],
  };
}

function byDepKey(a: DependencyView, b: DependencyView): number {
  return compareText(depKey(a), depKey(b));
}

/** Dependency licences (6M): the report's entries equal the expected list exactly. */
function compareDependencies(
  dependencies: NonNullable<Expected['dependencies']>,
  report: Report,
  out: Mismatch[],
): void {
  const want = dependencies.map(dependencyView).sort(byDepKey);
  const got = (report.dependencies ?? []).map(dependencyView).sort(byDepKey);
  const wantByKey = new Map(want.map((d) => [depKey(d), d]));
  const gotByKey = new Map(got.map((d) => [depKey(d), d]));
  for (const [k, w] of wantByKey) {
    const g = gotByKey.get(k);
    if (!g) out.push({ kind: 'dependency', detail: `${k}: missing from report` });
    else if (JSON.stringify(g.licenses) !== JSON.stringify(w.licenses))
      out.push({
        kind: 'dependency',
        detail: `${k}: licenses expected [${w.licenses.join(', ')}], got [${g.licenses.join(', ')}]`,
      });
  }
  for (const k of gotByKey.keys())
    if (!wantByKey.has(k)) out.push({ kind: 'dependency', detail: `${k}: unexpected` });
}

/** Adds one file's coverage to the project's counts. */
function addFileCoverage(acc: CoverageCounts, f: ReportFile): CoverageCounts {
  const c = f.coverage;
  if (!c) return acc;
  const total = c.branches.reduce((n, [, t]) => n + t, 0);
  const hit = c.branches.reduce((n, [, , h]) => n + h, 0);
  acc.uncoveredLines += rangeLength(c.uncovered);
  acc.linesToCover += rangeLength(c.covered) + rangeLength(c.uncovered);
  acc.conditionsToCover += total;
  acc.uncoveredConditions += total - hit;
  return acc;
}

/** The project's coverage measures from its main files, or `null` when none has coverage. */
function reportCoverage(report: Report): ReturnType<typeof coverageMeasures> | null {
  const covered = report.files.filter((f) => f.kind === 'main' && f.coverage);
  if (covered.length === 0) return null;
  return coverageMeasures(
    covered.reduce(addFileCoverage, {
      linesToCover: 0,
      uncoveredLines: 0,
      conditionsToCover: 0,
      uncoveredConditions: 0,
    }),
  );
}

function compareCoverage(expected: Expected, report: Report, out: Mismatch[]): void {
  const measures = reportCoverage(report);
  if (expected.coverage === null) {
    if (measures !== null)
      out.push({ kind: 'coverage', detail: 'no coverage expected, but the report has coverage' });
  } else if (measures === null) {
    out.push({ kind: 'coverage', detail: 'coverage expected, but the report has none' });
  } else {
    for (const [key, want] of Object.entries(expected.coverage)) {
      const got = measures[key as keyof typeof measures];
      const ok = key === 'coverage' ? got !== null && Math.abs(got - want) <= 0.1 : got === want;
      if (!ok) out.push({ kind: 'coverage', detail: `${key} expected ${want}, got ${got}` });
    }
  }
}

export function compareFixture(expected: Expected, report: Report): Mismatch[] {
  const out: Mismatch[] = [];
  compareEngines(expected, report, out);
  compareFindings(expected, report, out);
  compareFiles(expected, report, out);
  compareDuplications(expected, report, out);
  if (expected.dependencies !== undefined) compareDependencies(expected.dependencies, report, out);
  compareCoverage(expected, report, out);
  return out;
}

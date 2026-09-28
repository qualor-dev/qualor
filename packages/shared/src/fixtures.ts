import { z } from 'zod';
import { coverageMeasures } from './metrics';
import type { Report } from './report/schema';
import { LANGUAGES, QUALITIES, SEVERITIES } from './report/taxonomy';

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
      quality: z.enum(QUALITIES).optional(),
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
  notes: z.record(z.string(), z.string()).optional(),
});

export type Expected = z.infer<typeof expectedSchema>;

export interface Mismatch {
  kind: 'engine' | 'missing-finding' | 'unexpected-finding' | 'file' | 'duplication' | 'coverage';
  detail: string;
}

const findingKey = (ruleKey: string, path: string | null, line: number, severity?: string) =>
  `${ruleKey} ${path ?? '(project)'}:${line}${severity ? ` [${severity}]` : ''}`;

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

export function compareFixture(expected: Expected, report: Report): Mismatch[] {
  const out: Mismatch[] = [];

  for (const id of expected.engines) {
    const e = report.engines.find((x) => x.id === id);
    if (!e || e.status !== 'ok') {
      out.push({
        kind: 'engine',
        detail: `${id}: expected status ok, got ${e?.status ?? 'absent'}`,
      });
    }
  }

  const quality = new Map<string, string>();
  for (const e of report.engines)
    for (const r of e.rules) if (r.quality) quality.set(`${e.id}:${r.id}`, r.quality);

  const actual = report.findings.map((f) => ({
    ruleKey: `${f.engineId}:${f.ruleId}`,
    path: f.location?.path ?? null,
    line: f.location?.startLine ?? 1,
    severity: f.severity,
    engine: f.engineId,
  }));
  const matched = new Set<number>();
  for (const e of expected.findings) {
    const i = actual.findIndex(
      (a, idx) =>
        !matched.has(idx) &&
        a.ruleKey === e.ruleKey &&
        a.path === e.path &&
        a.line === e.startLine &&
        (e.severity === undefined || a.severity === e.severity) &&
        (e.quality === undefined || quality.get(a.ruleKey) === e.quality),
    );
    if (i === -1)
      out.push({
        kind: 'missing-finding',
        detail: findingKey(e.ruleKey, e.path, e.startLine, e.severity),
      });
    else matched.add(i);
  }
  if (expected.findingsExhaustive) {
    actual.forEach((a, idx) => {
      if (!matched.has(idx) && expected.engines.includes(a.engine)) {
        out.push({
          kind: 'unexpected-finding',
          detail: findingKey(a.ruleKey, a.path, a.line, a.severity),
        });
      }
    });
  }

  for (const [path, want] of Object.entries(expected.files)) {
    const f = report.files.find((x) => x.path === path);
    if (!f) {
      out.push({ kind: 'file', detail: `${path}: missing from report` });
      continue;
    }
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

  const groupKey = (g: {
    blocks: readonly { path: string; startLine: number; endLine: number }[];
  }) =>
    g.blocks
      .map((b) => `${b.path}:${b.startLine}-${b.endLine}`)
      .sort()
      .join('|');
  const actualGroups = new Set(report.duplications.map(groupKey));
  const expectedGroups = new Set(expected.duplications.map(groupKey));
  for (const g of expectedGroups)
    if (!actualGroups.has(g)) out.push({ kind: 'duplication', detail: `missing group ${g}` });
  for (const g of actualGroups)
    if (!expectedGroups.has(g)) out.push({ kind: 'duplication', detail: `unexpected group ${g}` });

  const covered = report.files.filter((f) => f.kind === 'main' && f.coverage);
  const measures =
    covered.length === 0
      ? null
      : coverageMeasures(
          covered.reduce(
            (acc, f) => {
              const c = f.coverage;
              if (!c) return acc;
              const total = c.branches.reduce((n, [, t]) => n + t, 0);
              const hit = c.branches.reduce((n, [, , h]) => n + h, 0);
              acc.uncoveredLines += rangeLength(c.uncovered);
              acc.linesToCover += rangeLength(c.covered) + rangeLength(c.uncovered);
              acc.conditionsToCover += total;
              acc.uncoveredConditions += total - hit;
              return acc;
            },
            { linesToCover: 0, uncoveredLines: 0, conditionsToCover: 0, uncoveredConditions: 0 },
          ),
        );
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
  return out;
}

import { describe, expect, it } from 'vitest';
import { makeReport } from '../test/make-report';
import { compareFixture, expectedSchema, type Expected } from './fixtures';

const expected: Expected = expectedSchema.parse({
  description: 'test',
  engines: ['eslint'],
  findingsExhaustive: true,
  findings: [{ ruleKey: 'eslint:no-console', path: 'src/a.ts', startLine: 3, severity: 'medium' }],
  files: { 'src/a.ts': { language: 'typescript', kind: 'main', ncloc: 8, complexity: 2 } },
  duplications: [],
  coverage: {
    lines_to_cover: 3,
    uncovered_lines: 1,
    conditions_to_cover: 2,
    uncovered_conditions: 1,
    coverage: 60,
  },
});

describe('expectedSchema', () => {
  it('is strict', () => {
    expect(() => expectedSchema.parse({ ...expected, extra: 1 })).toThrow();
  });
});

describe('compareFixture', () => {
  it('passes for a matching report', () => {
    expect(compareFixture(expected, makeReport())).toEqual([]);
  });

  it('reports a missing engine or a non-ok engine', () => {
    const r = makeReport();
    r.engines[0]!.status = 'failed';
    expect(compareFixture(expected, r).map((m) => m.kind)).toContain('engine');
  });

  it('reports missing and unexpected findings', () => {
    const r = makeReport();
    r.findings[0]!.location!.startLine = 4;
    const kinds = compareFixture(expected, r).map((m) => m.kind);
    expect(kinds).toContain('missing-finding');
    expect(kinds).toContain('unexpected-finding');
  });

  it('ignores unexpected findings when not exhaustive', () => {
    const r = makeReport();
    r.findings.push({ ...r.findings[0]!, ruleId: 'eqeqeq' });
    expect(compareFixture({ ...expected, findingsExhaustive: false }, r)).toEqual([]);
    expect(compareFixture(expected, r).map((m) => m.kind)).toEqual(['unexpected-finding']);
  });

  it('checks severity when given', () => {
    const r = makeReport();
    r.findings[0]!.severity = 'high';
    expect(compareFixture(expected, r).map((m) => m.kind)).toEqual([
      'missing-finding',
      'unexpected-finding',
    ]);
  });

  it('compares only the file metrics that are specified', () => {
    const r = makeReport();
    r.files[0]!.metrics!.statements = 999;
    expect(compareFixture(expected, r)).toEqual([]);
    r.files[0]!.metrics!.ncloc = 9;
    expect(compareFixture(expected, r)).toEqual([
      { kind: 'file', detail: 'src/a.ts: ncloc expected 8, got 9' },
    ]);
  });

  it('reports a missing file', () => {
    expect(
      compareFixture(expected, makeReport({ files: [], findings: [] })).map((m) => m.kind),
    ).toContain('file');
  });

  it('matches duplication groups irrespective of block order', () => {
    const blocks = [
      { path: 'src/a.ts', startLine: 1, endLine: 5 },
      { path: 'src/b.ts', startLine: 2, endLine: 6 },
    ];
    const e = { ...expected, duplications: [{ blocks }] };
    expect(
      compareFixture(e, makeReport({ duplications: [{ blocks: [...blocks].reverse() }] })),
    ).toEqual([]);
    expect(compareFixture(e, makeReport()).map((m) => m.kind)).toEqual(['duplication']);
  });

  it('checks coverage totals computed from the report', () => {
    expect(
      compareFixture(
        { ...expected, coverage: { ...expected.coverage!, coverage: 61 } },
        makeReport(),
      ),
    ).toEqual([{ kind: 'coverage', detail: 'coverage expected 61, got 60' }]);
    expect(
      compareFixture({ ...expected, coverage: null }, makeReport()).map((m) => m.kind),
    ).toEqual(['coverage']);
  });
});

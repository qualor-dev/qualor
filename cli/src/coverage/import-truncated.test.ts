import { describe, expect, it, vi } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import type * as GoCover from './gocover';
import { importCoverage } from './import';

// The real caps take hundreds of megabytes to reach: the Go parser runs here with small ones.
vi.mock('./gocover', async (importOriginal) => {
  const real = await importOriginal<typeof GoCover>();
  return {
    ...real,
    parseGoCover: (absPath: string) =>
      real.parseGoCover(absPath, { distinctLines: 250, lineVisits: 1_000_000 }),
  };
});

const tmp = useTempDirs();

describe('importCoverage of a truncated report (plan 9C)', () => {
  it('keeps the part read before the limit and warns COVERAGE_REPORT_TRUNCATED', async () => {
    const root = tmp();
    let profile = 'mode: set\n';
    for (let i = 0; i < 10; i++) profile += `x/a${i}.go:1.1,100.2 1 1\n`;
    const sources: Record<string, string> = {};
    for (let i = 0; i < 10; i++) sources[`x/a${i}.go`] = 'package x\n';
    writeTree(root, { 'coverage.out': profile, ...sources });
    const warnings = new Warnings();
    const map = await importCoverage({
      root,
      reports: [{ path: 'coverage.out', format: 'auto' }],
      files: Object.keys(sources).map((p) => ({ path: p, kind: 'main' as const, lines: 100 })),
      pathPrefixes: [],
      warnings,
      log: silentLogger,
    });
    expect([...map.keys()].sort()).toEqual(['x/a0.go', 'x/a1.go', 'x/a2.go']);
    expect(warnings.list()).toEqual([
      expect.objectContaining({
        code: 'COVERAGE_REPORT_TRUNCATED',
        count: 1,
      }),
    ]);
  });
});

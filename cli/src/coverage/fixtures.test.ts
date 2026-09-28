import { describe, expect, it } from 'vitest';
import { coverageSummary, FIXTURE_NAMES, loadFixture } from '../../test/fixtures';
import { discoverFiles } from '../discovery/discover';
import { readSource } from '../discovery/source';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { importCoverage } from './import';

describe.each(FIXTURE_NAMES)('fixture %s', (name) => {
  it('reproduces the coverage numbers of expected.json', async () => {
    const { dir, config, expected } = loadFixture(name);
    const warnings = new Warnings();
    const files = discoverFiles({ root: dir, config, warnings, log: silentLogger });
    const map = await importCoverage({
      root: dir,
      reports: config.coverage.reports,
      files: files.map((f) => ({ path: f.path, kind: f.kind, lines: readSource(f.absPath).lines })),
      pathPrefixes: config.coverage.pathPrefixes,
      warnings,
      log: silentLogger,
    });
    const want = expected.coverage;
    if (want === null) {
      expect(map.size).toBe(0);
      return;
    }
    const got = coverageSummary(map);
    expect({ ...got, coverage: undefined }).toEqual({ ...want, coverage: undefined });
    expect(Math.abs((got.coverage ?? 0) - want.coverage)).toBeLessThanOrEqual(0.1);
    expect(warnings.list()).toEqual([]);
  });
});

import { describe, expect, it } from 'vitest';
import { FIXTURE_NAMES, loadFixture, METRIC_FIELDS } from '../../test/fixtures';
import { testParsers } from '../../test/parsers';
import { discoverFiles } from '../discovery/discover';
import { silentLogger } from '../log';
import { analyzeFiles } from '../scan/analyze-files';
import { Warnings } from '../warnings';

describe.each(FIXTURE_NAMES)('fixture %s', (name) => {
  it('matches the language, kind, lines and metrics in expected.json', async () => {
    const { dir, config, expected } = loadFixture(name);
    const warnings = new Warnings();
    const analyzed = analyzeFiles(
      discoverFiles({ root: dir, config, warnings, log: silentLogger }),
      {
        parsers: await testParsers(),
        warnings,
        log: silentLogger,
      },
    );
    for (const [path, want] of Object.entries(expected.files)) {
      const got = analyzed.find((a) => a.file.path === path);
      expect(got, path).toBeDefined();
      expect([got?.file.language, got?.file.kind], path).toEqual([want.language, want.kind]);
      if (want.lines !== undefined) expect(got?.lines, `${path} lines`).toBe(want.lines);
      for (const field of METRIC_FIELDS) {
        const w = want[field];
        if (w !== undefined) expect(got?.metrics?.[field], `${path} ${field}`).toBe(w);
      }
    }
    expect(warnings.list()).toEqual([]);
  });
});

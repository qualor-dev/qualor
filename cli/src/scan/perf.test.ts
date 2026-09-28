import { parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { generateSources } from '../../test/generate';
import { testParsers } from '../../test/parsers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { discoverFiles } from '../discovery/discover';
import { detectDuplications } from '../duplication/detect';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { analyzeFiles, duplicationFilter, duplicationInputs } from './analyze-files';

const tmp = useTempDirs();

describe('performance', () => {
  it(
    'discovers, measures and checks 30k generated lines well inside the budget',
    { timeout: 120_000 },
    async () => {
      const root = tmp();
      writeTree(root, Object.fromEntries(generateSources(125, 20).map((f) => [f.path, f.text])));
      const config = parseConfig({ version: 1 });
      const parsers = await testParsers();
      const warnings = new Warnings();
      const started = performance.now();
      const files = discoverFiles({ root, config, warnings, log: silentLogger });
      const analyzed = analyzeFiles(files, {
        parsers,
        warnings,
        log: silentLogger,
        collectUnits: duplicationFilter(config),
      });
      const groups = detectDuplications(duplicationInputs(analyzed), config.duplication);
      const elapsed = performance.now() - started;
      expect(files).toHaveLength(125);
      expect(analyzed.reduce((n, a) => n + a.lines, 0)).toBe(29_875);
      expect(groups).toHaveLength(7);
      expect(groups[0]).toEqual({
        blocks: [
          { path: 'src/m0.ts', startLine: 1, endLine: 23 },
          { path: 'src/m1.ts', startLine: 1, endLine: 23 },
        ],
      });
      // ≈0.4 s locally; the 60 s budget for 300k lines is benchmarked nightly by CLI step 14.
      expect(elapsed).toBeLessThan(20_000);
    },
  );
});

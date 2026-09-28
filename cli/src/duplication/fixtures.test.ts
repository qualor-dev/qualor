import { describe, expect, it } from 'vitest';
import { FIXTURE_NAMES, loadFixture } from '../../test/fixtures';
import { testParsers } from '../../test/parsers';
import { discoverFiles } from '../discovery/discover';
import { silentLogger } from '../log';
import { analyzeFiles, duplicationFilter, duplicationInputs } from '../scan/analyze-files';
import { Warnings } from '../warnings';
import { detectDuplications } from './detect';

describe.each(FIXTURE_NAMES)('fixture %s', (name) => {
  it('finds exactly the duplications in expected.json', async () => {
    const { dir, config, expected } = loadFixture(name);
    const warnings = new Warnings();
    const analyzed = analyzeFiles(
      discoverFiles({ root: dir, config, warnings, log: silentLogger }),
      {
        parsers: await testParsers(),
        warnings,
        log: silentLogger,
        collectUnits: duplicationFilter(config),
      },
    );
    const key = (g: { blocks: { path: string; startLine: number; endLine: number }[] }) =>
      g.blocks
        .map((b) => `${b.path}:${b.startLine}-${b.endLine}`)
        .sort()
        .join('|');
    const got = detectDuplications(duplicationInputs(analyzed), config.duplication).map(key).sort();
    expect(got).toEqual(expected.duplications.map(key).sort());
  });
});

import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import { sonarAnalyzerKeys } from './sonaranalyzer-keys.mjs';

const sarif = (rules: object[]) => {
  const file = path.join(mkdtempSync(path.join(os.tmpdir(), 'sonar-keys-')), 'a.sarif');
  writeFileSync(file, JSON.stringify({ runs: [{ tool: { driver: { rules } } }] }));
  return file;
};

describe('sonaranalyzer-keys.mjs', () => {
  it('lists the S#### ids, and with enabledOnly only those enabled by default in every log', () => {
    const a = sarif([
      { id: 'S107', defaultConfiguration: { enabled: false } },
      { id: 'S1481' },
      { id: 'CA1822' },
      { id: 'S100', defaultConfiguration: { level: 'warning' } },
    ]);
    const b = sarif([{ id: 'S100', defaultConfiguration: { enabled: false } }, { id: 'S2325' }]);
    expect(sonarAnalyzerKeys([a, b])).toEqual(['S100', 'S107', 'S1481', 'S2325']);
    expect(sonarAnalyzerKeys([a, b], { enabledOnly: true })).toEqual(['S1481', 'S2325']);
  });
});

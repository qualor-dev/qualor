import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { lineHash, REDACTED, splitSourceLines } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { FIXTURES_DIR } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { loadExternalSarif } from './external';
import { fileLines, normalizeCaptures } from './normalize';

const tmp = useTempDirs();
const SECRET = 'Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1';
const FIXTURE = path.join(FIXTURES_DIR, 'mixed-secrets');
const SAMPLES = path.resolve(FIXTURES_DIR, '..', 'packages', 'shared', 'test', 'sarif-samples');

describe('cross-engine secret redaction on the mixed-secrets fixture', () => {
  it('never shows the Gitleaks secret in another engine’s snippet, and leaves its hashes alone', () => {
    const dir = tmp();
    const gitleaks = readFileSync(path.join(SAMPLES, 'gitleaks.sarif'), 'utf8').replaceAll(
      'file:///fixture-root',
      pathToFileURL(FIXTURE).href,
    );
    const lint = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'team-lint', rules: [{ id: 'template-literal' }] } },
          results: [
            {
              ruleId: 'template-literal',
              message: { text: 'Prefer a helper' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/config.ts' },
                    region: { startLine: 4 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    writeTree(dir, { 'gitleaks.sarif': gitleaks, 'lint.sarif': lint });
    const captures = loadExternalSarif(
      [{ path: path.join(dir, 'gitleaks.sarif') }, { path: path.join(dir, 'lint.sarif') }],
      { root: FIXTURE, warnings: new Warnings() },
    );
    const out = normalizeCaptures(captures, {
      repoRoot: FIXTURE,
      readLines: fileLines(FIXTURE),
      knownPaths: new Set(['src/config.ts', 'src/run.ts']),
      log: silentLogger,
    });
    expect(out.engines.map((e) => [e.id, e.status])).toEqual([
      ['ext-gitleaks', 'ok'],
      ['team-lint', 'ok'],
    ]);
    const lintFinding = out.findings.find((f) => f.engineId === 'team-lint');
    expect(lintFinding?.snippet?.lines[1]).toContain(REDACTED);
    expect(JSON.stringify(out)).not.toContain(SECRET);
    const lines = splitSourceLines(readFileSync(path.join(FIXTURE, 'src', 'config.ts'), 'utf8'));
    expect(lintFinding?.lineHash).toBe(lineHash(lines, 4, 4));
  });
});

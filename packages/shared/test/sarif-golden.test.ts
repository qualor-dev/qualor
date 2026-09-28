import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { expectedSchema } from '../src/fixtures';
import { splitSourceLines } from '../src/hash';
import { engineMapping } from '../src/sarif/mappings';
import { normalizeSarif } from '../src/sarif/normalize';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../../..');

const SAMPLE_FIXTURE = {
  eslint: { fixture: 'ts-basic', sourceRoots: [] },
  pmd: { fixture: 'java-basic', sourceRoots: ['src/main/java'] },
  spotbugs: { fixture: 'java-basic', sourceRoots: ['src/main/java'] },
  gitleaks: { fixture: 'mixed-secrets', sourceRoots: [] },
  semgrep: { fixture: 'mixed-secrets', sourceRoots: [] },
  roslyn: { fixture: 'csharp-basic', sourceRoots: [] },
} as const;

function readLines(fixture: string) {
  return (p: string): string[] | null => {
    try {
      return splitSourceLines(readFileSync(path.join(repo, 'fixtures', fixture, p), 'utf8'));
    } catch {
      return null;
    }
  };
}

describe.each(Object.entries(SAMPLE_FIXTURE))(
  'golden SARIF: %s',
  (engine, { fixture, sourceRoots }) => {
    const sample = JSON.parse(
      readFileSync(path.join(here, 'sarif-samples', `${engine}.sarif`), 'utf8'),
    ) as unknown;
    const out = normalizeSarif(sample, {
      engineId: engine,
      repoRoot: '/fixture-root',
      readLines: readLines(fixture),
      sourceRoots,
      ...(engineMapping(engine) && { mapping: engineMapping(engine) }),
    });
    const expected = expectedSchema.parse(
      JSON.parse(readFileSync(path.join(repo, 'fixtures', fixture, 'expected.json'), 'utf8')),
    );
    const quality = new Map(out.rules.map((r) => [r.id, r.quality]));
    const actual = out.findings.map((f) => ({
      ruleKey: `${engine}:${f.ruleId}`,
      path: f.location?.path,
      startLine: f.location?.startLine,
      severity: f.severity,
      quality: quality.get(f.ruleId),
    }));
    const mine = expected.findings.filter((f) => f.ruleKey.startsWith(`${engine}:`));

    it('normalises without warnings', () => {
      expect(out.warnings).toEqual([]);
    });

    it('matches the reviewed snapshot', async () => {
      await expect(`${JSON.stringify(out, null, 2)}\n`).toMatchFileSnapshot(
        path.join(here, 'sarif-samples', `${engine}.normalized.json`),
      );
    });

    it('contains exactly the findings listed in the fixture expected.json', () => {
      const key = (f: {
        ruleKey: string;
        path?: string | undefined;
        startLine?: number | undefined;
      }) => `${f.ruleKey} ${f.path}:${f.startLine}`;
      expect(actual.map(key).sort()).toEqual(mine.map(key).sort());
      for (const e of mine) {
        const a = actual.find((x) => key(x) === key(e))!;
        if (e.severity) expect(a.severity, key(e)).toBe(e.severity);
        if (e.quality) expect(a.quality, key(e)).toBe(e.quality);
      }
    });

    if (engine === 'gitleaks' || engine === 'semgrep') {
      it('never contains the fixture secret', () => {
        expect(JSON.stringify(out)).not.toContain('Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1');
      });
    }
  },
);

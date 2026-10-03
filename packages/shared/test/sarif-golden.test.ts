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

interface SampleFixture {
  fixture: string;
  sourceRoots: readonly string[];
  /**
   * The engine id to normalise and build rule keys with, when it differs from this sample's own
   * key (Phase 8A: `roslyn-sonar` is a second, separate sample of the `roslyn` engine — the
   * bundled SonarAnalyzer.CSharp's rules — rather than a bigger `roslyn.sarif`, so each sample
   * keeps its own `.sarif`/`.normalized.json` and the "contains exactly" check below only ever
   * answers for the rules its own sample defines). Defaults to the sample's own key.
   */
  engineId?: string;
}

const SAMPLE_FIXTURE: Record<string, SampleFixture> = {
  eslint: { fixture: 'ts-basic', sourceRoots: [] },
  pmd: { fixture: 'java-basic', sourceRoots: ['src/main/java'] },
  spotbugs: { fixture: 'java-basic', sourceRoots: ['src/main/java'] },
  findsecbugs: { fixture: 'java-security', sourceRoots: ['src/main/java'], engineId: 'spotbugs' },
  gitleaks: { fixture: 'mixed-secrets', sourceRoots: [] },
  semgrep: { fixture: 'mixed-secrets', sourceRoots: [] },
  roslyn: { fixture: 'csharp-basic', sourceRoots: [] },
  'roslyn-sonar': { fixture: 'csharp-basic', sourceRoots: [], engineId: 'roslyn' },
  ruff: { fixture: 'python-basic', sourceRoots: [] },
  detekt: { fixture: 'kotlin-basic', sourceRoots: [] },
};

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
  (sampleId, { fixture, sourceRoots, engineId }) => {
    const engine = engineId ?? sampleId;
    const sample = JSON.parse(
      readFileSync(path.join(here, 'sarif-samples', `${sampleId}.sarif`), 'utf8'),
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
    // Scoped to the rules this sample actually defines: when two samples share an engine id
    // (roslyn / roslyn-sonar), each one's expected.json findings are its own rules' only, never
    // the other sample's.
    const ruleIds = new Set(out.rules.map((r) => r.id));
    const mine = expected.findings.filter(
      (f) => f.ruleKey.startsWith(`${engine}:`) && ruleIds.has(f.ruleKey.slice(engine.length + 1)),
    );

    it('normalises without warnings', () => {
      expect(out.warnings).toEqual([]);
    });

    it('matches the reviewed snapshot', async () => {
      await expect(`${JSON.stringify(out, null, 2)}\n`).toMatchFileSnapshot(
        path.join(here, 'sarif-samples', `${sampleId}.normalized.json`),
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

    if (sampleId === 'gitleaks' || sampleId === 'semgrep') {
      it('never contains the fixture secret', () => {
        expect(JSON.stringify(out)).not.toContain('Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1');
      });
    }
  },
);

import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../test/tmp';
import { BENCH_QUALOR_YML, BENCH_SEED, DEFAULT_FILES, generateRepo, runBench } from './bench';

const tmp = useTempDirs();

function tree(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const d of readdirSync(root, { recursive: true, withFileTypes: true })) {
    if (!d.isFile()) continue;
    const abs = path.join(d.parentPath, d.name);
    out[path.relative(root, abs).split(path.sep).join('/')] = readFileSync(abs, 'utf8');
  }
  return out;
}

describe('benchmark (CLI step 14)', () => {
  it('generates 239-line TypeScript files and disables every analyzer', () => {
    expect(generateRepo(tmp(), 10)).toBe(2_390);
    for (const analyzer of ['eslint', 'pmd', 'spotbugs', 'semgrep', 'gitleaks']) {
      expect(BENCH_QUALOR_YML).toContain(`  ${analyzer}:\n    enabled: false`);
    }
  });

  it('is deterministic: a fixed seed generates the same repository every time', () => {
    expect(BENCH_SEED).toBe(1);
    const [a, b] = [tmp(), tmp()];
    generateRepo(a, 21);
    generateRepo(b, 21);
    const ta = tree(a);
    expect(Object.keys(ta)).toHaveLength(22);
    expect(tree(b)).toEqual(ta);
  });

  it('defaults to about 300k lines (1 256 files of 239 lines)', () => {
    expect(DEFAULT_FILES * 239).toBe(300_184);
  });

  it(
    'times a warm dry-run scan of a small generated repo against the budget',
    { timeout: 120_000 },
    () => {
      const r = runBench({ files: 20, budgetSeconds: 60, keep: false });
      expect(r).toMatchObject({ files: 20, lines: 4_780, budgetSeconds: 60, ok: true });
      expect(r.seconds).toBeGreaterThan(0);
    },
  );

  it(
    'kills a scan that runs past ten times the budget instead of hanging',
    { timeout: 60_000 },
    () => {
      // A 2 ms budget allows 20 ms, which no scan (not even the start of node) fits in.
      expect(() => runBench({ files: 1, budgetSeconds: 0.002, keep: false })).toThrow(
        'did not finish within 0.02 s (10 times the budget)',
      );
    },
  );
});

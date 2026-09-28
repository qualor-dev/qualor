import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FIXTURES_DIR } from '../../test/fixtures';
import { testParsers } from '../../test/parsers';
import { detectDuplications, type DuplicationInput } from './detect';
import { lineUnits } from './tokens';

const DEFAULTS = { minTokens: 100, minLines: 10 };
const DUP_A = readFileSync(path.join(FIXTURES_DIR, 'ts-basic', 'src', 'dup-a.ts'), 'utf8');

async function input(p: string, text: string): Promise<DuplicationInput> {
  const tree = (await testParsers()).parse('typescript', text);
  if (tree === null) throw new Error('timeout');
  try {
    return { path: p, units: lineUnits(tree.rootNode, 'ecmascript') };
  } finally {
    tree.delete();
  }
}

describe('detectDuplications', () => {
  it('merges three copies into one group', async () => {
    const files = await Promise.all(['a.ts', 'b.ts', 'c.ts'].map((p) => input(p, DUP_A)));
    expect(detectDuplications(files, DEFAULTS)).toEqual([
      {
        blocks: [
          { path: 'a.ts', startLine: 1, endLine: 15 },
          { path: 'b.ts', startLine: 1, endLine: 15 },
          { path: 'c.ts', startLine: 1, endLine: 15 },
        ],
      },
    ]);
  });

  it('requires both thresholds', async () => {
    const files = await Promise.all(['a.ts', 'b.ts'].map((p) => input(p, DUP_A)));
    expect(detectDuplications(files, { minTokens: 100, minLines: 16 })).toEqual([]);
    expect(detectDuplications(files, { minTokens: 1_000, minLines: 10 })).toEqual([]);
  });

  it('ignores comments but not renamed identifiers', async () => {
    const commented = await input('x.ts', DUP_A.replace('const tax', '// differs\n  const tax'));
    const renamed = await input('y.ts', DUP_A.replaceAll('subtotal', 'net'));
    const original = await input('a.ts', DUP_A);
    expect(detectDuplications([original, commented], DEFAULTS)).toEqual([
      {
        blocks: [
          { path: 'a.ts', startLine: 1, endLine: 15 },
          { path: 'x.ts', startLine: 1, endLine: 16 },
        ],
      },
    ]);
    expect(detectDuplications([original, renamed], DEFAULTS)).toEqual([]);
  });

  it('reports periodic code in one file once, as two adjacent halves', async () => {
    const text =
      Array.from({ length: 40 }, (_, i) => `total += values[${i % 2}] * factor + offset;`).join(
        '\n',
      ) + '\n';
    expect(detectDuplications([await input('r.ts', text)], DEFAULTS)).toEqual([
      {
        blocks: [
          { path: 'r.ts', startLine: 1, endLine: 20 },
          { path: 'r.ts', startLine: 21, endLine: 40 },
        ],
      },
    ]);
  });

  it('returns nothing for no input or files without shared windows', async () => {
    expect(detectDuplications([], DEFAULTS)).toEqual([]);
    expect(detectDuplications([await input('a.ts', 'const a = 1;\n')], DEFAULTS)).toEqual([]);
  });
});

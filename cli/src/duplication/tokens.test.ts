import { describe, expect, it } from 'vitest';
import { testParsers } from '../../test/parsers';
import { lineUnits } from './tokens';

async function units(text: string) {
  const tree = (await testParsers()).parse('typescript', text);
  if (tree === null) throw new Error('timeout');
  try {
    return lineUnits(tree.rootNode, 'ecmascript');
  } finally {
    tree.delete();
  }
}

describe('lineUnits', () => {
  it('groups leaf tokens by line, drops comments and blank lines, tracks brackets', async () => {
    const u = await units('function f(a) { // note\n\n  return `x${a}`;\n}\n');
    expect(
      u.map(({ startLine, endLine, tokens, delta }) => [startLine, endLine, tokens, delta]),
    ).toEqual([
      [1, 1, 6, 1],
      [3, 3, 8, 0],
      [4, 4, 1, -1],
    ]);
  });

  it('gives equal lines equal hashes, independent of comments and indentation', async () => {
    const [a] = await units('  const x = 1; // one\n');
    const [b] = await units('const x = 1; /* two */\n');
    const [c] = await units('const y = 1;\n');
    expect(a!.hash).toBe(b!.hash);
    expect(a!.hash).not.toBe(c!.hash);
    expect(a!.hash).toMatch(/^[0-9a-f]{16}$/);
  });

  it('spans multi-line template literals (the closing backtick starts a unit of its own)', async () => {
    const u = await units('const s = `a\nb\nc`;\n');
    expect(u.map((x) => [x.startLine, x.endLine, x.tokens])).toEqual([
      [1, 3, 5],
      [3, 3, 2],
    ]);
  });
});

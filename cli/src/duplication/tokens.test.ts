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

  it('drops Python comments and docstrings, so two copies with other docs hash the same', async () => {
    const tree = (await testParsers()).parse(
      'python',
      'def f(a):\n    """One."""\n    return a + 1  # x\n\n\ndef g(a):\n    """Two,\n    longer."""\n    return a + 1\n',
    );
    if (tree === null) throw new Error('timeout');
    try {
      const u = lineUnits(tree.rootNode, 'python');
      expect(u.map((x) => x.startLine)).toEqual([1, 3, 6, 9]);
      expect(u[1]?.hash).toBe(u[3]?.hash);
    } finally {
      tree.delete();
    }
  });

  it('tokenises Kotlin: string templates balance and comments are left out (phase 8E)', async () => {
    const parsers = await testParsers();
    const tree = parsers.parse('kotlin', 'val s = "a ${b}" // c\n')!;
    try {
      // val, s, =, ", `a `, ${, b, }, " — the comment is not a token
      expect(lineUnits(tree.rootNode, 'kotlin')).toMatchObject([
        { startLine: 1, endLine: 1, tokens: 9, delta: 0 },
      ]);
    } finally {
      tree.delete();
    }
  });

  it('counts Swift string interpolation as a bracket, so it balances (plan 8F)', async () => {
    const tree = (await testParsers()).parse(
      'swift',
      'let s = "a \\(x) b"\nlet m = """\n  hi \\(y)\n  """\nf(a,\n  b)\n',
    );
    if (tree === null) throw new Error('timeout');
    try {
      const u = lineUnits(tree.rootNode, 'swift');
      expect(u.map((x) => [x.startLine, x.delta])).toEqual([
        [1, 0],
        [2, 0],
        [3, 0],
        [4, 0],
        [5, 1],
        [6, -1],
      ]);
    } finally {
      tree.delete();
    }
  });

  it('drops PHP comments of every kind, so two copies with other comments hash the same (plan 9A)', async () => {
    const tree = (await testParsers()).parse(
      'php',
      '<?php\nfunction f($a) {\n    // one\n    return $a + 1; # x\n}\nfunction g($a) {\n    /* two */\n    return $a + 1;\n}\n',
    );
    if (tree === null) throw new Error('timeout');
    try {
      const u = lineUnits(tree.rootNode, 'php');
      expect(u.map((x) => x.startLine)).toEqual([1, 2, 4, 5, 6, 8, 9]);
      expect(u[2]?.hash).toBe(u[5]?.hash);
    } finally {
      tree.delete();
    }
  });

  it('drops Ruby comments and __END__ data, and counts #{ as a bracket (plan 9B)', async () => {
    const parsers = await testParsers();
    const unitsOf = (source: string) => {
      const tree = parsers.parse('ruby', source);
      if (tree === null) throw new Error('timeout');
      try {
        return lineUnits(tree.rootNode, 'ruby');
      } finally {
        tree.delete();
      }
    };
    const copies = unitsOf('def f(a)\n  # One.\n  a + 1 # x\nend\n\ndef g(a)\n  a + 1\nend\n');
    expect(copies.map((u) => u.startLine)).toEqual([1, 3, 4, 6, 7, 8]);
    expect(copies[1]?.hash).toBe(copies[4]?.hash);
    expect(unitsOf('s = "a #{b} c"\nf(a,\n  b)\n').map((u) => [u.startLine, u.delta])).toEqual([
      [1, 0],
      [2, 1],
      [3, -1],
    ]);
    expect(unitsOf('x = 1\n__END__\nnot ruby (\n').map((u) => u.startLine)).toEqual([1]);
    expect(unitsOf('=begin\nzz\n=end\nx = 2\n').map((u) => u.startLine)).toEqual([4]);
  });

  it('tokenises Go like the other C-like languages: comments out, brackets balanced (plan 9C)', async () => {
    const tree = (await testParsers()).parse(
      'go',
      'package p\n\nvar s = `a\nb` // c\n\nfunc f() {\n\tg(1,\n\t\t2)\n}\n',
    );
    if (tree === null) throw new Error('timeout');
    try {
      const u = lineUnits(tree.rootNode, 'go');
      // [startLine, endLine, tokens, delta]; the raw string's closing backtick is a token of line 4.
      expect(u.map((x) => [x.startLine, x.endLine, x.tokens, x.delta])).toEqual([
        [1, 1, 2, 0],
        [3, 4, 5, 0],
        [4, 4, 1, 0],
        [6, 6, 5, 1],
        [7, 7, 4, 1],
        [8, 8, 2, -1],
        [9, 9, 1, -1],
      ]);
    } finally {
      tree.delete();
    }
  });
});

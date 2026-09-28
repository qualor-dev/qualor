import { describe, expect, it } from 'vitest';
import { testParsers } from '../../test/parsers';
import type { GrammarId } from '../parse/grammars';
import { computeMetrics } from './metrics';
import { familyOf } from './rules';

async function metricsOf(grammar: GrammarId, text: string) {
  const parsers = await testParsers();
  const tree = parsers.parse(grammar, text);
  if (tree === null) throw new Error('parse timed out');
  try {
    return computeMetrics(tree.rootNode, familyOf(grammar));
  } finally {
    tree.delete();
  }
}

describe('computeMetrics (ecmascript)', () => {
  it('counts else-if without extra nesting and a trailing else (Campbell)', async () => {
    const m = await metricsOf(
      'typescript',
      'function f(a, b, c) {\n  if (a) {\n  } else if (b) {\n    if (c) {\n    }\n  } else {\n  }\n}\n',
    );
    expect(m).toMatchObject({ functions: 1, complexity: 4, cognitiveComplexity: 5, statements: 3 });
  });

  it('counts each run of like logical operators once for cognitive complexity', async () => {
    const m = await metricsOf(
      'typescript',
      'function f(a, b, c, d) {\n  return a && b && c || d;\n}\n',
    );
    expect(m).toMatchObject({ complexity: 4, cognitiveComplexity: 2 });
  });

  it('does not start a new run of like logical operators for redundant parentheses', async () => {
    const wrap = (expr: string) =>
      metricsOf('typescript', `function f(a, b, c) {\n  return ${expr};\n}\n`);
    // Grouping parentheses have no effect on which sub-expressions belong to the same
    // sequence of logical operators (ruling C3): `(a && b) && c` is one run, same as `a && b && c`.
    await expect(wrap('(a && b) && c')).resolves.toMatchObject({
      complexity: 3,
      cognitiveComplexity: 1,
    });
    await expect(wrap('a && (b && c)')).resolves.toMatchObject({
      complexity: 3,
      cognitiveComplexity: 1,
    });
    // A change of operator still starts a new run, parentheses or not.
    await expect(wrap('(a && b) || c')).resolves.toMatchObject({
      complexity: 3,
      cognitiveComplexity: 2,
    });
  });

  it('treats negation as starting a new run, unlike redundant parentheses', async () => {
    // Extension of ruling C3, pinned here: only purely syntactic grouping (redundant parentheses)
    // is transparent to a run of like logical operators. Campbell's cognitive-complexity paper
    // does not name `!` explicitly, but a unary operator is not grouping syntax — it changes the
    // value being combined — so `!(a && b)` is treated as a new sub-expression: the `&&` inside it
    // does not continue the run of the `&&` outside it, same as any other non-transparent node
    // (a call, an assignment, …) standing between them would.
    const m = await metricsOf('typescript', 'function f(a, b, c) {\n  return !(a && b) && c;\n}\n');
    expect(m).toMatchObject({ complexity: 3, cognitiveComplexity: 2 });
  });

  it('adds a nesting level inside nested functions', async () => {
    const m = await metricsOf(
      'typescript',
      'function f(xs) {\n  xs.forEach((x) => {\n    if (x) {\n      console.log(x);\n    }\n  });\n}\n',
    );
    expect(m).toMatchObject({ functions: 2, complexity: 3, cognitiveComplexity: 2 });
  });

  it('counts case labels but not default for cyclomatic complexity, the switch once for cognitive', async () => {
    const m = await metricsOf(
      'typescript',
      'function f(x) {\n  switch (x) {\n    case 1:\n      return 1;\n    case 2:\n      return 2;\n    default:\n      return 0;\n  }\n}\n',
    );
    expect(m).toMatchObject({ ncloc: 10, complexity: 3, cognitiveComplexity: 1, statements: 4 });
  });

  it('counts classes, methods, comment lines and code lines', async () => {
    const m = await metricsOf(
      'typescript',
      '/**\n * Doc.\n */\nexport class A {\n  m(): number {\n    return 1; // trailing\n  }\n}\n',
    );
    expect(m).toEqual({
      ncloc: 5,
      commentLines: 4,
      functions: 1,
      classes: 1,
      statements: 1,
      complexity: 1,
      cognitiveComplexity: 0,
    });
  });

  it('handles JSX in JavaScript and TSX', async () => {
    expect(
      await metricsOf(
        'javascript',
        'const C = () => <div>{a ? b : c}</div>;\nfunction* g() { yield 1; }\n',
      ),
    ).toMatchObject({ ncloc: 2, functions: 2, complexity: 3, cognitiveComplexity: 1 });
    expect(
      await metricsOf('tsx', 'export const C = (p: { a: boolean }) => (p.a ? <b /> : <i />);\n'),
    ).toMatchObject({ functions: 1, complexity: 2 });
  });

  it('counts every line of a multi-line literal as code, and CRLF like LF', async () => {
    expect((await metricsOf('typescript', 'const s = `a\n\nb`;\n')).ncloc).toBe(3);
    expect(await metricsOf('typescript', 'const a = 1;\r\n// c\r\nconst b = 2;\r\n')).toMatchObject(
      {
        ncloc: 2,
        commentLines: 1,
      },
    );
  });

  it('survives a 20 000-operand chain without overflowing the stack', async () => {
    const chain = Array.from({ length: 20_000 }, (_, i) => `a${i}`).join(' && ');
    const m = await metricsOf('typescript', `const x = ${chain};\n`);
    expect(m).toMatchObject({ ncloc: 1, complexity: 19_999, cognitiveComplexity: 1 });
  });
});

describe('computeMetrics (java)', () => {
  it('counts constructors, compact constructors, types, labels and lambdas', async () => {
    const m = await metricsOf(
      'java',
      'class J {\n  // c\n  J() {}\n  int f(int x) {\n    switch (x) { case 1: return 1; case 2, 3: return 2; default: return 0; }\n  }\n  Runnable r = () -> { if (true) {} };\n  interface I {}\n  enum E { A }\n  record R(int a) { R {} }\n}\n',
    );
    expect(m).toEqual({
      ncloc: 10,
      commentLines: 1,
      functions: 3,
      classes: 4,
      statements: 5,
      complexity: 6,
      cognitiveComplexity: 2,
    });
  });

  it('does not start a new run of like logical operators for redundant parentheses, but negation does', async () => {
    const wrap = (expr: string) =>
      metricsOf(
        'java',
        `class J {\n  boolean f(boolean a, boolean b, boolean c) {\n    return ${expr};\n  }\n}\n`,
      );
    await expect(wrap('(a && b) && c')).resolves.toMatchObject({
      complexity: 3,
      cognitiveComplexity: 1,
    });
    await expect(wrap('a && (b && c)')).resolves.toMatchObject({
      complexity: 3,
      cognitiveComplexity: 1,
    });
    await expect(wrap('(a && b) || c')).resolves.toMatchObject({
      complexity: 3,
      cognitiveComplexity: 2,
    });
    await expect(wrap('!(a && b) && c')).resolves.toMatchObject({
      complexity: 3,
      cognitiveComplexity: 2,
    });
  });
});

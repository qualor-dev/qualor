import { beforeAll, describe, expect, it } from 'vitest';
import { testParsers } from '../../test/parsers';
import type { Parsers } from '../parse/grammars';
import { computeMetrics } from './metrics';

// The parsers are shared by the whole test run (test/parsers.ts): never delete them here.
let parsers: Parsers;
beforeAll(async () => {
  parsers = await testParsers();
});

function metrics(source: string) {
  const tree = parsers.parse('csharp', source);
  if (tree === null) throw new Error('parse timed out');
  try {
    return computeMetrics(tree.rootNode, 'csharp');
  } finally {
    tree.delete();
  }
}

describe('C# metrics (report-format.md §6, ruling D14)', () => {
  it('counts methods, constructors, operators, local functions and bodied accessors, not auto-accessors', () => {
    const m = metrics(`class C {
  public int Auto { get; set; }
  public int Arrow => 1;
  public int Full { get { return 1; } set { } }
  public int this[int i] => i;
  public C() {}
  ~C() {}
  public static C operator +(C a, C b) => a;
  public static implicit operator int(C c) => 0;
  int M() { int L(int y) => y; return L(1); }
}
record R(int X); struct S {} interface I {} enum E { A }
`);
    // Arrow, get, set, indexer, ctor, dtor, operator +, conversion, M, L
    expect(m.functions).toBe(10);
    expect(m.classes).toBe(5);
  });

  it('counts decisions like Java: if, loops, cases, catch, ?:, runs of && and ||; not ?? or patterns', () => {
    const m = metrics(`class C {
  int M(int a, bool b, bool c, object o, int[] xs) {
    if (a > 0 && b || c) { }
    foreach (var x in xs) { }
    for (;;) { break; }
    while (a > 0) { a--; }
    do { } while (false);
    try { } catch (System.Exception) { }
    var t = b ? 1 : 2;
    switch (a) { case 1: case 2: break; default: break; }
    var r = a switch { 1 => 2, 3 => 4, _ => 0 };
    var n = o ?? xs;
    if (o is int and > 0 or < -1) { }
    return a;
  }
}
`);
    // 1 function + if + && + || + foreach + for + while + do + catch + ?: + case 1 + case 2
    // + arm 1 + arm 3 + second if = 15
    expect(m.complexity).toBe(15);
  });

  it('computes cognitive complexity with nesting and else-if like Java', () => {
    const m = metrics(`class Pricing {
  int Discount(int total, bool member) {
    if (total > 10000 && member) { return 1; }
    else if (total > 5000) { return 2; }
    foreach (var i in new int[0]) { if (i > 0) { } else { } }
    return 0;
  }
}
`);
    // if +1, && +1, else if +1, foreach +1, nested if +2, else +1 = 7
    expect(m.cognitiveComplexity).toBe(7);
  });

  it('treats //, /* */ and /// as comments and preprocessor lines as code', () => {
    const m = metrics(`/// <summary>Doc</summary>
// line
/* block */
#if DEBUG
class A { }
#endif
`);
    expect(m.commentLines).toBe(3);
    expect(m.ncloc).toBe(3);
  });
});

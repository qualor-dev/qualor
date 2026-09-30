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
  const tree = parsers.parse('swift', source);
  if (tree === null) throw new Error('parse timed out');
  try {
    expect(tree.rootNode.hasError).toBe(false);
    return computeMetrics(tree.rootNode, 'swift');
  } finally {
    tree.delete();
  }
}

describe('Swift metrics (report-format.md §6, plan 8F)', () => {
  it('counts funcs, init, deinit, accessors, observers and shorthand getters; types and extensions', () => {
    const m = metrics(`protocol Shape { func area() -> Double }
struct Point { var x: Int }
enum Kind { case a }
class Store {
    var auto: Int = 0
    var count: Int { return 1 }
    var total: Int {
        get { 1 }
        set { }
    }
    var watched: Int = 0 {
        willSet { }
        didSet { }
    }
    init() { }
    deinit { }
    subscript(i: Int) -> Int { i }
    func m() { }
}
extension Store { func extra() { } }
actor Counter { }
func top() { let f = { (x: Int) in x } }
`);
    // count, get, set, willSet, didSet, init, deinit, the subscript's shorthand body, m, extra, top
    // (area is a requirement without a body; the closure is not a function)
    expect(m.functions).toBe(11);
    // protocol, struct, enum, class, extension, actor
    expect(m.classes).toBe(6);
    // return 1; get's 1; the subscript's i; let f; the closure's x
    expect(m.statements).toBe(5);
    expect(m.complexity).toBe(11);
    expect(m.cognitiveComplexity).toBe(0);
  });

  it('counts if, the loops, guard, catch, ?:, cases and runs of && and ||; not ?? or default', () => {
    const m = metrics(`func f(a: Int, b: Bool, c: Bool, xs: [Int], o: Int?) -> Int {
    if a > 0 && b || c { }
    for x in xs { }
    while a > 0 { }
    repeat { } while false
    guard let v = o else { return 0 }
    do { try g() } catch { }
    let t = b ? 1 : 2
    switch a {
    case 1, 2: break
    case 3: break
    default: break
    }
    let n = o ?? 0
    return a
}
`);
    // 1 + if + && + || + for + while + repeat + guard + catch + ?: + case 1, 2 + case 3 = 12
    expect(m.complexity).toBe(12);
    // if +1, the && run +1, the || run +1, for, while, repeat, guard, catch, ?:, switch +1 each = 10
    expect(m.cognitiveComplexity).toBe(10);
    // if, for, while, repeat, guard, return 0, do, try g(), let t, switch, 3 × break, let n, return a
    expect(m.statements).toBe(15);
  });

  it('nests like Java, with else if as a hybrid increment and an empty else block counting', () => {
    const m = metrics(`func g(a: Int) -> Int {
    if a > 0 {
        for _ in 0..<a {
            if a > 1 { }
        }
    } else if a < 0 {
    } else {
    }
    return 0
}
`);
    // g + if + for + if + else if = 5
    expect(m.complexity).toBe(5);
    // if +1, for +2 (nesting 1), inner if +3, else if +1, else +1 = 8
    expect(m.cognitiveComplexity).toBe(8);
    expect(m.statements).toBe(4);
  });

  it('treats parentheses around a run of && as transparent', () => {
    const m = metrics('let r = (a && b) && c\nlet s = a && b || c\n');
    // r: two && nodes, one run; s: && and ||, two runs
    expect(m.complexity).toBe(4);
    expect(m.cognitiveComplexity).toBe(3);
  });

  it('counts //, /// and /* */ lines as comments, and only code lines as ncloc', () => {
    const m = metrics('// one\n/* two\n   three */\n/// doc\nlet a = 1 // trailing\n');
    expect(m.commentLines).toBe(5);
    expect(m.ncloc).toBe(1);
  });

  it('counts top-level code and block items as statements, never declarations', () => {
    const m = metrics(`import Foundation
let a = 1
print(a)
func f() {
    let b = 2
    b + 1
    if b > 0 { return }
}
class C { var p = 1; func m() { print(1) } }
`);
    // let a, print(a); let b, b + 1, if, return; print(1). Not import, func, class or the member p.
    expect(m.statements).toBe(7);
    expect(m.functions).toBe(2);
    expect(m.classes).toBe(1);
  });

  it('parses newer Swift: typed throws, macros, consume, some View, if expressions', () => {
    const m = metrics(`func f() throws(MyError) -> Int { 1 }
#Preview { Text("x") }
@MainActor struct V: View { var body: some View { Text("a") } }
func g(_ x: consuming Foo) { let y = consume x; _ = y }
let v = if a { 1 } else { 2 }
`);
    // f, body (a shorthand getter), g; if = 1
    expect(m.functions).toBe(3);
    expect(m.complexity).toBe(4);
    expect(m.cognitiveComplexity).toBe(2);
  });
});

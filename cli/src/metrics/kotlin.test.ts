import { beforeAll, describe, expect, it } from 'vitest';
import { testParsers } from '../../test/parsers';
import type { Parsers } from '../parse/grammars';
import { hasRealParseErrors } from './errors';
import { computeMetrics } from './metrics';
import { FAMILY_RULES } from './rules';

// The parsers are shared by the whole test run (test/parsers.ts): never delete them here.
let parsers: Parsers;
beforeAll(async () => {
  parsers = await testParsers();
});

function parse(source: string) {
  const tree = parsers.parse('kotlin', source);
  if (tree === null) throw new Error('parse timed out');
  return tree;
}

function metrics(source: string) {
  const tree = parse(source);
  try {
    return computeMetrics(tree.rootNode, 'kotlin');
  } finally {
    tree.delete();
  }
}

describe('Kotlin metrics (report-format.md §6, phase 8E)', () => {
  it('counts functions, secondary constructors and bodied accessors; classes, objects and companions', () => {
    const m = metrics(`class Shop(val name: String) {
    init { println(name) }
    constructor() : this("x")
    val size: Int get() = 1
    var count: Int = 0
        get() { return field }
        set(value) { field = value }
    val plain: Int
        get
    fun price(a: Int): Int {
        val f = fun(x: Int) = x
        val g = { y: Int -> y }
        fun local() = 1
        return f(a) + g(a) + local()
    }
    abstract fun later(): Int
    companion object {
        const val K = 1
    }
}
object Registry
interface Named
enum class Color { RED }
data class Point(val x: Int)
typealias Id = Int
`);
    // constructor, get() = 1, get() { }, set() { }, price, local, later; not the bodiless `get`,
    // the init block, the anonymous function or the lambda
    expect(m.functions).toBe(7);
    // Shop, companion object, Registry, Named, Color, Point
    expect(m.classes).toBe(6);
    // price: val f, val g, return; init: println; getter: return; setter: field = value
    expect(m.statements).toBe(6);
    expect(m.complexity).toBe(7);
    expect(m.cognitiveComplexity).toBe(0);
    expect(m.ncloc).toBe(25);
  });

  it('counts decisions like Java: if (also as an expression), loops, when entries, catch, runs of && and ||; not ?: or ?.', () => {
    const m = metrics(`fun decide(a: Int, b: Boolean, c: Boolean, xs: List<Int>, o: Any?): Int {
    if (a > 0 && b || c) { }
    for (x in xs) { }
    while (a > 0) { }
    do { } while (false)
    try { } catch (e: IllegalStateException) { } catch (e: Exception) { }
    val t = if (b) 1 else 2
    val w = when (a) { 1, 2 -> 3; 4 -> 5; else -> 0 }
    val n = o ?: 0
    val s = o?.toString()
    return a
}
`);
    // 1 function + if + && + || + for + while + do + 2 catch + if-expression + 2 when entries = 12
    expect(m.complexity).toBe(12);
    // if 1, && 1, || 1, for 1, while 1, do 1, catch 1+1, if-expression 1 + its else 1, when 1 = 11
    expect(m.cognitiveComplexity).toBe(11);
    // the ten entries of the function's block
    expect(m.statements).toBe(10);
  });

  it('computes cognitive complexity with nesting and else-if like Java', () => {
    const m = metrics(`class Pricing {
    fun discount(total: Int, member: Boolean): Int {
        if (total > 10000 && member) { return 1 }
        else if (total > 5000) { return 2 }
        for (i in listOf(1)) { if (i > 0) { } else { } }
        return 0
    }
}
`);
    // if +1, && +1, else if +1, for +1, nested if +2, else +1 = 7
    expect(m.cognitiveComplexity).toBe(7);
    expect(m.complexity).toBe(6);
  });

  it('treats //, /* */ and KDoc as comments and raw strings as code', () => {
    const m = metrics(`// line comment
/* block
   comment */
/** KDoc */
fun f(): String {
    val s = """
        raw
    """
    return s // trailing
}
`);
    expect(m.commentLines).toBe(5); // lines 1, 2, 3, 4 and 9
    expect(m.ncloc).toBe(6); // lines 5 to 10
  });

  it('counts the entries of blocks and lambda bodies as statements, not brace-less branches', () => {
    const m = metrics(`fun f(a: Int, xs: List<Int>): Int {
    var i = 0
    i = 1
    i++
    println(i)
    xs.forEach { x ->
        println(x)
        println(x)
    }
    if (a > 0) i = 3 else i = 4
    return i
}
`);
    // var, =, ++, println, forEach, the lambda's two println, if, return = 9
    expect(m.statements).toBe(9);
    expect(m.complexity).toBe(2);
    expect(m.cognitiveComplexity).toBe(2); // if +1, else +1
  });

  it('counts a script’s top-level calls as statements, not its top-level properties', () => {
    const m = metrics(`plugins {
    kotlin("jvm") version "2.0.21"
}

val v = 1
repositories {
    mavenCentral()
}
`);
    // plugins, repositories, and one entry in each lambda; `val v` is a declaration
    expect(m.statements).toBe(4);
    expect(m.functions).toBe(0);
  });
});

describe('Kotlin parse errors (Review Focus 4)', () => {
  const benign = FAMILY_RULES.kotlin.benignMissing;

  it('does not count the missing separator of a one-line class body as a syntax error', () => {
    const tree = parse('class A { fun f() {} }\n');
    try {
      expect(tree.rootNode.hasError).toBe(true);
      expect(hasRealParseErrors(tree.rootNode, benign)).toBe(false);
      expect(computeMetrics(tree.rootNode, 'kotlin')).toMatchObject({ functions: 1, classes: 1 });
    } finally {
      tree.delete();
    }
  });

  it('still reports real errors, including two one-line class bodies in a row', () => {
    for (const source of ['fun broken( {\n', 'class A { fun f() {} }\nobject O { val x = 1 }\n']) {
      const tree = parse(source);
      try {
        expect(hasRealParseErrors(tree.rootNode, benign), source).toBe(true);
      } finally {
        tree.delete();
      }
    }
  });

  it('treats any missing node as real for a family without benign ones', () => {
    const tree = parse('class A { fun f() {} }\n');
    try {
      expect(hasRealParseErrors(tree.rootNode)).toBe(true);
    } finally {
      tree.delete();
    }
  });
});

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
  const tree = parsers.parse('go', source);
  if (tree === null) throw new Error('parse timed out');
  try {
    expect(tree.rootNode.hasError).toBe(false);
    return computeMetrics(tree.rootNode, 'go');
  } finally {
    tree.delete();
  }
}

const EVERYTHING = `package main

// Doc comment.
type Shape interface{ Area() float64 }

type Point struct{ X, Y int }

type ID int

/* block
   comment */
func (p *Point) Area() float64 { return 0 }

func f(a int, xs []int, ch chan int, v any) (int, error) {
	if a > 0 && a < 10 || a == 20 {
		return 1, nil
	} else if a < 0 {
		return 2, nil
	} else {
		a++
	}
	for i := 0; i < 3; i++ {
	}
	for _, x := range xs {
		_ = x
	}
	switch a {
	case 1, 2:
	case 3:
		fallthrough
	default:
	}
	switch v.(type) {
	case int:
	}
	select {
	case <-ch:
	default:
	}
	g := func() int { return (a + 1) }
	defer g()
	go g()
	var y = a
	const z = 1
	ch <- y
	x := struct{ A int }{1}
	_ = x
	goto end
end:
	return a, nil
}
`;

describe('Go metrics (report-format.md §6, plan 9C)', () => {
  it('counts functions, methods, struct and interface types, statements and every decision', () => {
    const m = metrics(EVERYTHING);
    // 51 lines - 5 blank - 3 comment lines (3, 10, 11) = 43
    expect(m.ncloc).toBe(43);
    expect(m.commentLines).toBe(3);
    // Area, f (the func literal is not a function)
    expect(m.functions).toBe(2);
    // Shape, Point; not ID (a named int) nor the anonymous struct of x
    expect(m.classes).toBe(2);
    // f's list: if, for, for, switch, type switch, select, g :=, defer, go, var, const, send,
    // x :=, _ = x, goto, the labelled return = 16; return 1, return 2, a++, _ = x, fallthrough,
    // the literal's return, Area's return = 7; total 23
    expect(m.statements).toBe(23);
    // 2 functions + if + the && run + the || run + else if + 2 for + case 1,2 / 3 / int / <-ch = 12
    expect(m.complexity).toBe(12);
    // if +1, || +1, && +1, else if +1, else +1, for +1, for +1, switch +1, type switch +1,
    // select +1 = 10
    expect(m.cognitiveComplexity).toBe(10);
  });

  it('parses generics, type sets, range over int and labels; nesting adds to cognitive complexity', () => {
    const m = metrics(`package gen

type List[T any] struct{ items []T }

type Number interface{ ~int | ~float64 }

type Alias = List[int]

func Map[T, U any](xs []T, f func(T) U) []U {
	out := make([]U, 0, len(xs))
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}

func (l *List[T]) Each(f func(T) bool) {
outer:
	for i := range 10 {
		for _, it := range l.items {
			if !f(it) || (i > 3 && i < 5) {
				continue outer
			}
		}
	}
}

func Sum[N Number](ns ...N) (s N) {
	for _, n := range ns {
		s += n
	}
	return
}
`);
    expect(m.ncloc).toBe(27);
    expect(m.functions).toBe(3);
    // List, Number; not the alias
    expect(m.classes).toBe(2);
    // Map 4 (out :=, for, return, out =); Each 4 (the labelled for, inner for, if, continue); Sum 3
    expect(m.statements).toBe(11);
    // 3 functions + Map's for + Each's for, for, if, ||, && + Sum's for = 10
    expect(m.complexity).toBe(10);
    // Map for +1; Each for +1, inner for +2, if +3, || +1, && +1 (the parentheses are transparent,
    // but && is another operator); Sum for +1 = 10
    expect(m.cognitiveComplexity).toBe(10);
  });

  it('counts // and /* */ lines as comments and only code lines as ncloc', () => {
    const m = metrics('package p\n\n// one\n/* two\n   three */\nvar a = 1 // trailing\n');
    // comment lines 3, 4, 5, 6 (the trailing comment); code lines 1 and 6
    expect(m.commentLines).toBe(4);
    expect(m.ncloc).toBe(2);
  });
});

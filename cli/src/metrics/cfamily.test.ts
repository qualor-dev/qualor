import { beforeAll, describe, expect, it } from 'vitest';
import { testParsers } from '../../test/parsers';
import type { GrammarId, Parsers } from '../parse/grammars';
import { computeMetrics } from './metrics';

let parsers: Parsers;
beforeAll(async () => {
  parsers = await testParsers();
});

function metrics(grammar: GrammarId, source: string, clean = true) {
  const tree = parsers.parse(grammar, source);
  if (tree === null) throw new Error('parse timed out');
  try {
    if (clean) expect(tree.rootNode.hasError).toBe(false);
    return computeMetrics(tree.rootNode, 'cfamily');
  } finally {
    tree.delete();
  }
}

const C_SAMPLE = `#include <stdio.h>
#define MAX(a, b) ((a) > (b) ? (a) : (b))
/* block */
struct P { int x; };
enum E { A, B };
typedef int T;
static int f(int a, int b) {
    // line
    if (a > 0 && b > 0 || a < -1) {
        return 1;
    } else if (a == 0) {
        for (int i = 0; i < 3; i++) { a++; }
    } else {
        while (a) { a--; }
    }
    do { b--; } while (b > 0);
    switch (a) {
    case 1:
    case 2: break;
    default: break;
    }
    goto end;
end:
    return a ? b : 0;
}
#ifdef X
int g(void) { return 1; }
#else
int g(void) { return 2; }
#endif
`;

const CPP_SAMPLE = `#include <vector>
namespace ns {
template <typename T>
class Box {
public:
    Box() = default;
    explicit Box(T v) : v_(v) {}
    ~Box() {}
    T get() const { return v_; }
    void set(T v);
    bool operator==(const Box& o) const { return v_ == o.v_; }
private:
    T v_{};
};
template <typename T>
void Box<T>::set(T v) { v_ = v; }
struct S { int a; };
union U { int i; float f; };
enum class Color { Red, Green };
}
int run(std::vector<int>& xs) {
    int n = 0;
    for (auto x : xs) { n += x; }
    auto add = [&](int y) { return n + y; };
    try {
        if (n > 3 and n < 9) throw 1;
    } catch (const std::exception& e) {
        n = -1;
    } catch (...) {
        n = -2;
    }
    if constexpr (sizeof(int) == 4) { n++; }
    struct S2 *p = nullptr;
    return add(n) > 0 ? 1 : not n;
}
`;

describe('C and C++ metrics (report-format.md §6, plan 9D)', () => {
  it('counts a C file: functions in both #ifdef branches, struct definitions, decisions, nesting', () => {
    const m = metrics('c', C_SAMPLE);
    // f, and g twice (both preprocessor branches are parsed)
    expect(m.functions).toBe(3);
    // struct P (enum E and the typedef are not classes)
    expect(m.classes).toBe(1);
    // f 1 + if + && + || + else if + for + while + do + case 1 + case 2 + ?: = 11; g + g = 2
    expect(m.complexity).toBe(13);
    // if 1, || run 1, && run 1, else if 1 (hybrid), its else 1, for 2 (nesting 1), while 2
    // (nesting 1), do 1, switch 1, ?: 1
    expect(m.cognitiveComplexity).toBe(12);
    // f: if, return 1, else if, for, a++, while, a--, do, b--, switch, break, break, goto,
    // labelled, return = 15 (the for's int i is an initialiser); g: return, return = 17
    expect(m.statements).toBe(17);
    // 30 lines - the comment-only lines 3 and 8 = 28
    expect(m.ncloc).toBe(28);
    expect(m.commentLines).toBe(2);
  });

  it('counts a C++ file: bodies only, class/struct/union definitions, range for, catch, and/or', () => {
    const m = metrics('cpp', CPP_SAMPLE);
    // Box(T v), ~Box, get, operator==, Box<T>::set, run (not = default, not the set declaration,
    // not the lambda)
    expect(m.functions).toBe(6);
    // Box, S, U (not enum class, not struct S2 *p)
    expect(m.classes).toBe(3);
    // 6 functions + range for + if + and + catch + catch + if constexpr + ?: = 13
    expect(m.complexity).toBe(13);
    // range for 1, if 1, and 1, catch 1, catch 1, if constexpr 1, ?: 1 = 7; `try` does not nest,
    // so the if inside it is at nesting 0; the lambda's body adds nothing
    expect(m.cognitiveComplexity).toBe(7);
    // Box: return v_, return v_ == o.v_ (get, ==); set: v_ = v; run: int n, for, n += x, auto add,
    // the lambda's return, try, if, throw, n = -1, n = -2, if constexpr, n++, struct S2 *p, return
    // = 2 + 1 + 14 = 17
    expect(m.statements).toBe(17);
    expect(m.ncloc).toBe(35);
  });

  it('treats parentheses around a run of && as transparent, and and/or like &&/||', () => {
    // C++: tree-sitter-c parses `and` as an identifier (C has it only as an <iso646.h> macro).
    const m = metrics(
      'cpp',
      'int r(int a, int b, int c) { return (a && b) && c; }\nint s(int a, int b, int c) { return a and b or c; }\n',
    );
    // r: 1 + one && run (2 operators) = 3; s: 1 + and + or = 3
    expect(m.complexity).toBe(6);
    // r: one run; s: two runs
    expect(m.cognitiveComplexity).toBe(3);
  });

  it('counts declarations inside blocks only, never file-level ones or for initialisers', () => {
    const m = metrics(
      'c',
      'int g1 = 1;\nextern int g2;\nvoid f(void) {\n    int a = 0;\n    for (int i = 0; i < 2; i++) a += i;\n}\n',
    );
    // int a, for, a += i
    expect(m.statements).toBe(3);
    expect(m.functions).toBe(1);
  });

  it('nests an else-if chain like Java, with a plain else counting', () => {
    const m = metrics(
      'c',
      `int h(int a) {
    if (a > 0) {
        for (int i = 0; i < a; i++) {
            if (a > 1) { a--; }
        }
    } else if (a < 0) {
        a++;
    } else {
        a = 0;
    }
    return a;
}
`,
    );
    // h + if + for + if + else if = 5
    expect(m.complexity).toBe(5);
    // if 1, for 2, inner if 3, else if 1, else 1 = 8
    expect(m.cognitiveComplexity).toBe(8);
  });

  // tree-sitter-cpp 0.23.4 gives (printed before the rules were written):
  // (translation_unit (function_definition type: (primitive_type)
  //   declarator: (function_declarator declarator: (identifier) parameters: (parameter_list …))
  //   body: (try_statement body: (compound_statement (return_statement (identifier)))
  //     (catch_clause parameters: (parameter_list)
  //       body: (compound_statement (return_statement (number_literal)))))))
  // The `body` field is the try_statement itself, so `isFunction` (a body field) needs no extra
  // case, and the catch_clause sits inside the try_statement.
  it('counts a function-try-block as one function with its catch (Review Focus 5)', () => {
    const m = metrics(
      'cpp',
      'int f(int a) try {\n    return a;\n} catch (...) {\n    return 0;\n}\n',
    );
    // A definition with a body is a function (report-format.md §6), whatever node holds the body.
    expect(m.functions).toBe(1);
    // f 1 + catch 1
    expect(m.complexity).toBe(2);
    // the try_statement (the body, a statement) + return a + return 0 = 3
    expect(m.statements).toBe(3);
  });
});

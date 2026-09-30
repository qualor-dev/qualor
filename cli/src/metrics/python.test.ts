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
  const tree = parsers.parse('python', source);
  if (tree === null) throw new Error('parse timed out');
  try {
    expect(tree.rootNode.hasError).toBe(false);
    return computeMetrics(tree.rootNode, 'python');
  } finally {
    tree.delete();
  }
}

describe('Python metrics (report-format.md §6, plan 8C)', () => {
  it('counts def, async def, methods and nested functions, not lambdas; classes', () => {
    const m = metrics(`class A:
    def m(self):
        return 1

    async def n(self):
        f = lambda x: x
        return f


@decorator
def top():
    def inner():
        pass
    return inner
`);
    // m, n, top, inner
    expect(m.functions).toBe(4);
    expect(m.classes).toBe(1);
    // return 1; f = …; return f; pass; return inner
    expect(m.statements).toBe(5);
  });

  it('counts if, elif, loops, except and except*, ?:, and/or runs and cases (not case _ or comprehensions)', () => {
    const m = metrics(`def f(a, b, c, xs):
    if a and b or c:
        pass
    elif a:
        pass
    else:
        pass
    for x in xs:
        pass
    while a:
        break
    try:
        pass
    except ValueError:
        pass
    except* TypeError:
        pass
    y = 1 if a else 2
    match a:
        case 1:
            pass
        case 2 | 3:
            pass
        case _:
            pass
    return [x for x in xs if x]
`);
    // def 1 + if + and + or + elif + for + while + except + except* + ?: + case 1 + case 2|3 = 12
    expect(m.complexity).toBe(12);
    // if +1, the or-run +1, the and-run inside it +1, elif +1, else +1, for +1, while +1,
    // except +1, except* +1, ?: +1, match +1 = 11 (all at nesting 0)
    expect(m.cognitiveComplexity).toBe(11);
    expect(m.statements).toBe(18);
  });

  it('adds nesting to cognitive complexity like Java', () => {
    const m = metrics(`def g(xs):
    for x in xs:
        if x:
            while x:
                x -= 1
    return 0
`);
    // for +1, if +2, while +3
    expect(m.cognitiveComplexity).toBe(6);
  });

  it('counts comments and docstrings (and other bare string statements) as comment lines, not code', () => {
    const m = metrics(`"""Module docstring."""
# a comment
import os


def f():
    """Function
    docstring."""
    "a" "b"
    return os.sep  # trailing
`);
    // lines 1, 2, 7, 8, 9 and the trailing comment on 10
    expect(m.commentLines).toBe(6);
    // import os (3), def f (6), return (10)
    expect(m.ncloc).toBe(3);
    // import, return: the docstring and "a" "b" are not statements
    expect(m.statements).toBe(2);
  });
});

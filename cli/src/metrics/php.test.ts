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
  const tree = parsers.parse('php', source);
  if (tree === null) throw new Error('parse timed out');
  try {
    expect(tree.rootNode.hasError).toBe(false);
    return computeMetrics(tree.rootNode, 'php');
  } finally {
    tree.delete();
  }
}

describe('PHP metrics (report-format.md §6, plan 9A)', () => {
  it('counts functions and methods with a body, not closures or abstract methods; classes, interfaces, traits, enums', () => {
    const m = metrics(`<?php
function top() { return fn($x) => $x; }
$h = function () { return 1; };
abstract class A { abstract public function m(); public function n() { return 1; } }
interface I { public function x(); }
trait T { public function t() {} }
enum E: int { case A = 1; public function label(): string { return 'a'; } }
`);
    // top, n, t, label (m and x have no body; the closure and the fn only open a context)
    expect(m.functions).toBe(4);
    expect(m.classes).toBe(4);
    // return fn; $h = …; return 1 (closure); return 1 (n); return 'a'
    expect(m.statements).toBe(5);
    expect(m.complexity).toBe(4);
    expect(m.cognitiveComplexity).toBe(0);
  });

  it('counts if, elseif, else if, loops, cases, match arms, catch, ?: and and/or runs, not ?? or default', () => {
    const m = metrics(`<?php
function f($a, $b, $c, $xs) {
    if ($a && $b || $c) {
        echo 1;
    } elseif ($b) {
        echo 2;
    } else if ($c) {
        echo 3;
    } else {
        echo 4;
    }
    foreach ($xs as $x) {}
    for ($i = 0; $i < 3; $i++) {}
    while ($a) { break; }
    do { $a--; } while ($a and $b or $c);
    switch ($a) { case 1: case 2: echo 1; break; default: echo 2; }
    $r = match ($a) { 1, 2 => 'x', 3 => 'y', default => 'z' };
    try { g(); } catch (E1 | E2 $e) {} finally {}
    $y = $a ? 1 : 2;
    $z = $a ?? $b;
    return $r;
}
`);
    // f 1 + if 1 + (|| 1, && 1) + elseif 1 + else-if 1 + foreach, for, while, do 4 + (or 1, and 1)
    // + case 1, case 2 + match arms "1, 2" and "3" + catch 1 + ?: 1 = 18 (?? and default add nothing)
    expect(m.complexity).toBe(18);
    // if 1, the || run 1, the && run 1, elseif 1 (hybrid), else-if 1 (hybrid), its else 1,
    // foreach, for, while, do 4, the or run 1, the and run 1, switch 1, match 1, catch 1, ?: 1 = 16
    expect(m.cognitiveComplexity).toBe(16);
    // if, echo x4, the else-if's if, foreach, for, while, break, do, $a--, switch, echo, break, echo,
    // $r =, try, g(), $y =, $z =, return = 22
    expect(m.statements).toBe(22);
  });

  it('adds nesting to cognitive complexity, and a closure nests one level deeper', () => {
    const m = metrics(`<?php
function g($xs) {
    foreach ($xs as $x) {
        if ($x) {
            while ($x) {
                $x--;
            }
        }
    }
    return array_map(function ($v) { return $v ? 1 : 0; }, $xs);
}
`);
    // foreach +1, if +2, while +3; the closure's ?: at nesting 1: +2 = 8
    expect(m.cognitiveComplexity).toBe(8);
    expect(m.complexity).toBe(5);
    expect(m.statements).toBe(6);
  });

  it('counts //, #, /* */ and /** */ as comments, inline HTML rows as code, and <?= as a statement', () => {
    const m = metrics(`<?php
/**
 * Doc block.
 */
// line comment
# hash comment
function h(): int
{
    return 1; // trailing
}
?>
<p>Hello</p>
<?php if ($ok): ?>
  <b><?= $name ?></b>
<?php endif; ?>
`);
    // lines 2-4, 5, 6 and the trailing comment on 9
    expect(m.commentLines).toBe(6);
    // 1, 7, 8, 9, 10, 11 (?>), 12 (<p>), 13, 14, 15
    expect(m.ncloc).toBe(10);
    // return; the alternative-syntax if; the <?= expression
    expect(m.statements).toBe(3);
    expect(m.functions).toBe(1);
    expect(m.complexity).toBe(2);
    expect(m.cognitiveComplexity).toBe(1);
  });
});

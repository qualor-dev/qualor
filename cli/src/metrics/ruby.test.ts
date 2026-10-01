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
  const tree = parsers.parse('ruby', source);
  if (tree === null) throw new Error('parse timed out');
  try {
    expect(tree.rootNode.hasError).toBe(false);
    return computeMetrics(tree.rootNode, 'ruby');
  } finally {
    tree.delete();
  }
}

describe('Ruby metrics (report-format.md §6, plan 9B)', () => {
  it('counts def, def self and endless defs, not blocks or lambdas; class and module, not class << self', () => {
    const m = metrics(`module Shop
  class Cart
    def add(item) = items << item

    def self.build
      new
    end

    class << self
      def helper; end
    end

    def each_item
      items.each { |i| yield i }
      fn = ->(x) { x * 2 }
      fn.call(1)
    end
  end
end
`);
    // add, self.build, helper, each_item
    expect(m.functions).toBe(4);
    expect(m.classes).toBe(2);
    // items << item (the endless body); new; items.each, yield i, fn = …, x * 2, fn.call(1)
    expect(m.statements).toBe(7);
    expect(m.complexity).toBe(4);
    expect(m.cognitiveComplexity).toBe(0);
    // 19 lines - blank lines 4, 8, 12
    expect(m.ncloc).toBe(16);
  });

  it('counts every decision of report-format.md §6', () => {
    const m = metrics(`def f(a, b, c, xs)
  if a and b or c
    1
  elsif a
    2
  else
    3
  end
  return 0 unless b
  x = 1 if c
  while a
    break
  end
  until b do b = true end
  for x in xs do x end
  a += 1 while a < 3
  case a
  when 1 then :one
  when 2, 3 then :few
  else :many
  end
  case xs
  in [] then :empty
  in [y] if y > 0 then :one
  else :many
  end
  v = Integer(a) rescue 0
  a ? b : c
  !a && (b && c) || c
end
`);
    // def 1; if, and, or, elsif = 4; unless/if modifiers 2; while, until, for, while modifier 4;
    // when ×2, in ×2 = 4; rescue modifier 1; ?: 1; ||, &&, the parenthesised && = 3. Total 20.
    expect(m.complexity).toBe(20);
    // if +1, the or-run +1, the and-run +1, elsif +1, else +1; unless +1, if +1; while, until,
    // for, while modifier +4; case +1, case/in +1; rescue modifier +1; ?: +1; || +1, && +1 (the
    // parenthesised && continues that run: no increment). Total 17, all at nesting 0.
    expect(m.cognitiveComplexity).toBe(17);
    // 12 statements of the body; then 1, 2, 3; break; b = true; x; :one, :few, :many;
    // :empty, :one, :many. Total 24 (the parenthesised b && c is not a statement).
    expect(m.statements).toBe(24);
  });

  it('adds nesting inside blocks and control flow', () => {
    const m = metrics(`def g(xs)
  xs.each do |x|
    if x
      while x
        x -= 1
      end
    end
  end
  0
end
`);
    // the block adds one level: if +2, while +3
    expect(m.cognitiveComplexity).toBe(5);
    expect(m.complexity).toBe(3);
    expect(m.statements).toBe(5);
  });

  it('counts rescue clauses, not begin/else/ensure, and their bodies as statements', () => {
    const m = metrics(`def risky
  yield
rescue ArgumentError => e
  raise e
rescue StandardError
  nil
else
  :ok
ensure
  log("done")
end

def wrap
  begin
    work
  rescue IOError
    retry
  end
end
`);
    // risky 1 + rescue 2; wrap 1 + rescue 1
    expect(m.complexity).toBe(5);
    expect(m.cognitiveComplexity).toBe(3);
    // yield, raise e, nil, :ok, log(...); begin, work, retry
    expect(m.statements).toBe(8);
    expect(m.ncloc).toBe(18);
  });

  it('counts # and =begin comments, a heredoc as code, and __END__ data as neither', () => {
    const m = metrics(`# frozen_string_literal: true
=begin
A block comment.
=end
require "json" # trailing

def h
  <<~TEXT
    heredoc line
  TEXT
end
__END__
data that is not code
`);
    // lines 1, 2-4, and the trailing comment on 5
    expect(m.commentLines).toBe(5);
    // require (5), def h (7), the heredoc (8-10), end (11)
    expect(m.ncloc).toBe(6);
    // require, the heredoc start
    expect(m.statements).toBe(2);
  });
});

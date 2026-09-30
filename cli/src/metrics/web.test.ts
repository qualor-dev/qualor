import { beforeAll, describe, expect, it } from 'vitest';
import { testParsers } from '../../test/parsers';
import { lineUnits } from '../duplication/tokens';
import type { GrammarId, Parsers } from '../parse/grammars';
import { computeMetrics } from './metrics';
import { familyOf } from './rules';

// The parsers are shared by the whole test run (test/parsers.ts): never delete them here.
let parsers: Parsers;
beforeAll(async () => {
  parsers = await testParsers();
});

function withTree<T>(
  grammar: GrammarId,
  source: string,
  f: (root: Parameters<typeof computeMetrics>[0]) => T,
): T {
  const tree = parsers.parse(grammar, source);
  if (tree === null) throw new Error('parse timed out');
  try {
    expect(tree.rootNode.hasError).toBe(false);
    return f(tree.rootNode);
  } finally {
    tree.delete();
  }
}

describe('HTML and CSS metrics (report-format.md §6, plan 8D)', () => {
  it('CSS: code and comment lines only; a line with code and a comment counts as both', () => {
    const css =
      '/* header */\n.a {\n  color: #fff; /* trailing */\n}\n\n@media (min-width: 1px) {\n  .b { margin: 0 auto; }\n}\n';
    expect(withTree('css', css, (r) => computeMetrics(r, familyOf('css')))).toEqual({
      ncloc: 6,
      commentLines: 2,
      functions: 0,
      classes: 0,
      statements: 0,
      complexity: 0,
      cognitiveComplexity: 0,
    });
  });

  it('HTML: multi-line comments are comment lines; blank lines inside <script> are not code', () => {
    const html =
      '<!DOCTYPE html>\n<!-- a\n     comment -->\n<p class="x">Hello\n  world</p>\n<script>\n  let a = 1;\n\n  let b = 2;\n</script>\n';
    expect(withTree('html', html, (r) => computeMetrics(r, familyOf('html')))).toEqual({
      ncloc: 7,
      commentLines: 2,
      functions: 0,
      classes: 0,
      statements: 0,
      complexity: 0,
      cognitiveComplexity: 0,
    });
  });

  it('CSS duplication tokens keep colour and number values whole (margin: 1px ≠ margin: 2px)', () => {
    const hash = (src: string) =>
      withTree('css', src, (r) => lineUnits(r, familyOf('css'))[0]!.hash);
    expect(hash('.a { margin: 1px; color: #fff; }\n')).not.toBe(
      hash('.a { margin: 2px; color: #fff; }\n'),
    );
    expect(hash('.a { color: #fff; }\n')).not.toBe(hash('.a { color: #000; }\n'));
    expect(hash('.a { margin: 1px; }\n')).toBe(hash('.a  {  margin:1px; }\n'));
  });
});

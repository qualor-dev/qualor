import type { Node } from 'web-tree-sitter';
import { describe, expect, it } from 'vitest';
import { hasRealParseErrors } from './errors';

/**
 * A node that reports an error but has no visible child holding it: web-tree-sitter hides a
 * MISSING node of a hidden grammar symbol, so only the S-expression shows it.
 */
function hiddenChild(sexp: string): Node {
  return {
    hasError: true,
    isError: false,
    isMissing: false,
    children: [],
    toString: () => sexp,
  } as unknown as Node;
}

const BENIGN = new Set(['_class_member_semi']);

describe('hasRealParseErrors: a hidden child decides by the S-expression (final review, minor 6)', () => {
  it('ignores a hidden benign MISSING, by name or as a quoted token', () => {
    expect(
      hasRealParseErrors(hiddenChild('(class_body (MISSING _class_member_semi))'), BENIGN),
    ).toBe(false);
    expect(hasRealParseErrors(hiddenChild('(x (MISSING ";"))'), new Set([';']))).toBe(false);
  });

  it('raises PARSE_ERRORS for a hidden MISSING that is not benign', () => {
    expect(hasRealParseErrors(hiddenChild('(class_body (MISSING _class_member_semi))'))).toBe(true);
    expect(hasRealParseErrors(hiddenChild('(class_body (MISSING "}"))'), BENIGN)).toBe(true);
    expect(
      hasRealParseErrors(
        hiddenChild('(class_body (MISSING _class_member_semi) (MISSING identifier))'),
        BENIGN,
      ),
    ).toBe(true);
  });

  it('raises PARSE_ERRORS for a benign MISSING next to a real ERROR or UNEXPECTED', () => {
    for (const sexp of [
      '(class_body (MISSING _class_member_semi) (ERROR (identifier)))',
      '(class_body (ERROR) (MISSING _class_member_semi))',
      '(class_body (MISSING _class_member_semi) (UNEXPECTED "@"))',
    ]) {
      expect(hasRealParseErrors(hiddenChild(sexp), BENIGN), sexp).toBe(true);
    }
  });
});

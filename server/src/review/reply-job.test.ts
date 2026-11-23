import { describe, expect, it } from 'vitest';
import { statusComment } from './reply-job';

describe('the changelog comment of a status a reply changed', () => {
  it('names the author in a code span, as before', () => {
    expect(statusComment('wont_fix', 'octocat')).toBe(
      "Won't fix after `octocat` replied in the merge request.",
    );
    expect(statusComment('false_positive', 'Ann Smith')).toBe(
      'False positive after `Ann Smith` replied in the merge request.',
    );
  });

  it('lengthens the fence of a name with a backtick, so the span stays one', () => {
    expect(statusComment('wont_fix', 'a`b')).toBe(
      "Won't fix after ``a`b`` replied in the merge request.",
    );
    expect(statusComment('wont_fix', 'a``b`c')).toBe(
      "Won't fix after ```a``b`c``` replied in the merge request.",
    );
    // A backtick at an edge needs padding, or it would join the fence.
    expect(statusComment('wont_fix', '`x`')).toBe(
      "Won't fix after `` `x` `` replied in the merge request.",
    );
  });
});

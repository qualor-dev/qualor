import { describe, expect, it } from 'vitest';
import { CARRY_OVER_COMMENT_CHARS, carryOverComment, planCarryOver } from './carry-over';
import type { LiveIssue } from './plan';

const live = (o: Partial<LiveIssue> & { id: string; engineId: string }): LiveIssue => ({
  ruleKey: `${o.engineId}:r`,
  cwe: [89],
  path: 'A.java',
  startLine: 7,
  status: 'open',
  duplicateOfIssueId: null,
  ...o,
});

describe('planCarryOver (data-model.md §5.3, plan 6B-1)', () => {
  const q = live({ id: 'q', engineId: 'qualor', ruleKey: 'qualor:java/sql-injection' });

  it('gives a new qualor root the false positive of a duplicate dedupe just pointed at it', () => {
    const sb = live({
      id: 's',
      engineId: 'spotbugs',
      ruleKey: 'spotbugs:SQL_INJECTION_JDBC',
      status: 'false_positive',
    });
    expect(planCarryOver([q, sb], [{ id: 's', duplicateOf: 'q' }], new Set(['q']))).toEqual([
      {
        issueId: 'q',
        status: 'false_positive',
        sourceIssueId: 's',
        sourceRuleKey: 'spotbugs:SQL_INJECTION_JDBC',
      },
    ]);
  });

  it('prefers false_positive, then the higher-priority engine, the lower rule key, the lower id', () => {
    const won = live({ id: 'a', engineId: 'semgrep', ruleKey: 'semgrep:x', status: 'wont_fix' });
    const fpLow = live({
      id: 'b',
      engineId: 'gosec',
      ruleKey: 'gosec:G202',
      status: 'false_positive',
    });
    const fpHigh = live({
      id: 'c',
      engineId: 'spotbugs',
      ruleKey: 'spotbugs:z',
      status: 'false_positive',
    });
    const fpHigh2 = live({
      id: 'd',
      engineId: 'spotbugs',
      ruleKey: 'spotbugs:a',
      status: 'false_positive',
    });
    const changes = ['a', 'b', 'c', 'd'].map((id) => ({ id, duplicateOf: 'q' }));
    expect(
      planCarryOver([q, won, fpLow, fpHigh, fpHigh2], changes, new Set(['q']))[0],
    ).toMatchObject({
      status: 'false_positive',
      sourceIssueId: 'd',
    });
    expect(
      planCarryOver([q, won], [{ id: 'a', duplicateOf: 'q' }], new Set(['q']))[0],
    ).toMatchObject({
      status: 'wont_fix',
      sourceIssueId: 'a',
    });
  });

  it('carries nothing in every other case', () => {
    const fp = (o: Partial<LiveIssue> = {}) =>
      live({ id: 's', engineId: 'spotbugs', status: 'false_positive', ...o });
    const point = [{ id: 's', duplicateOf: 'q' }];
    // An issue that already existed (not created by this analysis): the status is never retaken.
    expect(planCarryOver([q, fp()], point, new Set())).toEqual([]);
    // A new root of another engine.
    const semgrep = live({ id: 'q', engineId: 'semgrep' });
    expect(planCarryOver([semgrep, fp()], point, new Set(['q']))).toEqual([]);
    // A new qualor issue that is itself a duplicate (of gitleaks, say).
    expect(
      planCarryOver([q, fp()], [...point, { id: 'q', duplicateOf: 'g' }], new Set(['q'])),
    ).toEqual([]);
    // A new qualor issue that already has a status (inherited from the reference branch).
    expect(planCarryOver([{ ...q, status: 'wont_fix' }, fp()], point, new Set(['q']))).toEqual([]);
    // Open, resolved or closed duplicates; a duplicate of the same engine; a duplicate of another root.
    for (const status of ['open', 'resolved', 'closed'] as const) {
      expect(planCarryOver([q, fp({ status })], point, new Set(['q'])), status).toEqual([]);
    }
    expect(
      planCarryOver(
        [q, fp({ engineId: 'qualor', ruleKey: 'qualor:java/other' })],
        point,
        new Set(['q']),
      ),
    ).toEqual([]);
    expect(planCarryOver([q, fp()], [{ id: 's', duplicateOf: 'other' }], new Set(['q']))).toEqual(
      [],
    );
  });

  it('applies the planned pointer changes over the pointers the issues had', () => {
    const pointed = live({
      id: 's',
      engineId: 'spotbugs',
      status: 'false_positive',
      duplicateOfIssueId: 'q',
    });
    // Already pointing at q, unchanged by this dedupe: still a source.
    expect(planCarryOver([q, pointed], [], new Set(['q']))).toHaveLength(1);
    // Pointing at q before, moved away now: not a source.
    expect(planCarryOver([q, pointed], [{ id: 's', duplicateOf: null }], new Set(['q']))).toEqual(
      [],
    );
  });
});

describe('carryOverComment (plan 6B-1)', () => {
  it('names the source rule and quotes its comment, cut to the changelog bound', () => {
    expect(carryOverComment('spotbugs:X', null)).toBe('Status carried over from spotbugs:X.');
    expect(carryOverComment('spotbugs:X', '  ')).toBe('Status carried over from spotbugs:X.');
    expect(carryOverComment('spotbugs:X', 'a UUID from our table')).toBe(
      'Status carried over from spotbugs:X. a UUID from our table',
    );
    const long = carryOverComment('spotbugs:X', 'y'.repeat(5_000));
    expect(long).toHaveLength(CARRY_OVER_COMMENT_CHARS);
    expect(long.endsWith('…')).toBe(true);
  });

  it('cuts by code points, never inside a surrogate pair (a lone surrogate fails the jsonb write)', () => {
    const note = 'Status carried over from spotbugs:X. ';
    // The astral character's high surrogate sits at code unit 1,998, where a cut by code units falls.
    const comment = `${'y'.repeat(CARRY_OVER_COMMENT_CHARS - 2 - note.length)}😀${'z'.repeat(100)}`;
    expect(`${note}${comment}`.charCodeAt(CARRY_OVER_COMMENT_CHARS - 2)).toBe(0xd83d);
    const cut = carryOverComment('spotbugs:X', comment);
    expect(cut.endsWith('😀…')).toBe(true);
    expect(Array.from(cut)).toHaveLength(CARRY_OVER_COMMENT_CHARS);
    expect(cut).not.toMatch(
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/,
    );
    // Within the bound in code points (Postgres char_length), even when longer in code units.
    const astral = '😀'.repeat(CARRY_OVER_COMMENT_CHARS - note.length);
    expect(carryOverComment('spotbugs:X', astral)).toBe(`${note}${astral}`);
  });
});

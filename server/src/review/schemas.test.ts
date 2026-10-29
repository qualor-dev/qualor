import { describe, expect, it } from 'vitest';
import type { z } from 'zod';
import {
  ANSWER_LIMITS,
  judgeAnswerSchema,
  REPLY_INTENTS,
  replyAnswerSchema,
  REVIEW_NOTES,
  reviewFindingOf,
  reviewSummarySchema,
  specialistAnswerSchema,
  verifyAnswerSchema,
} from './schemas';

/** A finding as a specialist writes it, every key given. */
const finding = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  category: 'logic',
  severity: 'major',
  confidence: 'high',
  path: 'src/cart.ts',
  line: 12,
  endLine: 14,
  title: 'The loop stops one item early',
  body: 'The bound is `i < n - 1`, so the last item is never added. Use `i < n`.',
  assumption: null,
  suggestion: { startLine: 12, endLine: 12, lines: ['for (let i = 0; i < n; i += 1) {'] },
  ...over,
});
const judged = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  ...finding(),
  sources: ['s1', 's3'],
  priorId: null,
  ...over,
});
const judgeAnswer = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  findings: [judged()],
  dropped: [{ source: 's2', reason: 'The analyzers already report it.' }],
  prior: [{ id: 'issue-1', status: 'fixed', reason: 'The check is now on line 20.' }],
  summary: { verdict: 'One major logic error in the cart total.', walkthrough: ['Adds a total.'] },
  ...over,
});
const text = (length: number): string => 'x'.repeat(length);
const many = <T>(count: number, make: () => T): T[] => Array.from({ length: count }, make);

const passes = (schema: z.ZodType, value: unknown): boolean => schema.safeParse(value).success;

describe('the review answer schemas', () => {
  it('strict schemas refuse unknown keys, out-of-range lines, over-long text and more than 40 findings', () => {
    expect(passes(specialistAnswerSchema, { findings: [finding()] })).toBe(true);
    expect(passes(specialistAnswerSchema, { findings: [] })).toBe(true);
    expect(passes(judgeAnswerSchema, judgeAnswer())).toBe(true);
    expect(passes(verifyAnswerSchema, { verdict: 'confirmed', reason: 'Input reaches it.' })).toBe(
      true,
    );

    // Unknown keys, at every level.
    expect(passes(specialistAnswerSchema, { findings: [], notes: 'none' })).toBe(false);
    expect(passes(specialistAnswerSchema, { findings: [finding({ fix: 'x' })] })).toBe(false);
    expect(
      passes(specialistAnswerSchema, {
        findings: [finding({ suggestion: { startLine: 12, endLine: 12, lines: [], why: 'x' } })],
      }),
    ).toBe(false);
    // A judge's keys are not a specialist's.
    expect(passes(specialistAnswerSchema, { findings: [judged()] })).toBe(false);
    expect(passes(judgeAnswerSchema, judgeAnswer({ approved: true }))).toBe(false);
    expect(passes(judgeAnswerSchema, judgeAnswer({ findings: [judged({ reviewer: 'x' })] }))).toBe(
      false,
    );
    expect(
      passes(judgeAnswerSchema, judgeAnswer({ dropped: [{ source: 's1', reason: 'r', by: 'x' }] })),
    ).toBe(false);
    expect(
      passes(
        judgeAnswerSchema,
        judgeAnswer({ prior: [{ id: 'issue-1', status: 'fixed', reason: 'r', line: 3 }] }),
      ),
    ).toBe(false);
    expect(
      passes(
        judgeAnswerSchema,
        judgeAnswer({ summary: { verdict: 'v', walkthrough: [], approve: true } }),
      ),
    ).toBe(false);
    expect(
      passes(verifyAnswerSchema, { verdict: 'confirmed', reason: 'r', confidence: 'high' }),
    ).toBe(false);

    // Lines: whole numbers from 1, and a range that does not end before it starts.
    for (const lines of [
      { line: 0 },
      { line: -3 },
      { line: 2.5 },
      { line: '12' },
      { line: Number.MAX_SAFE_INTEGER + 1, endLine: null },
      { endLine: 0 },
      { endLine: 11 },
      { suggestion: { startLine: 0, endLine: 1, lines: [] } },
      { suggestion: { startLine: 13, endLine: 12, lines: [] } },
      { suggestion: { startLine: 12, endLine: 12.5, lines: [] } },
    ]) {
      expect(
        passes(specialistAnswerSchema, { findings: [finding(lines)] }),
        JSON.stringify(lines),
      ).toBe(false);
    }
    expect(passes(specialistAnswerSchema, { findings: [finding({ line: 12, endLine: 12 })] })).toBe(
      true,
    );

    // Text: at its bound it passes, one character over it is refused, and so is blank text.
    const bounded: [string, number, (value: string) => Record<string, unknown>][] = [
      ['title', 120, (value) => ({ findings: [finding({ title: value })] })],
      ['body', 1_200, (value) => ({ findings: [finding({ body: value })] })],
      ['assumption', 300, (value) => ({ findings: [finding({ assumption: value })] })],
      ['path', 1_024, (value) => ({ findings: [finding({ path: value })] })],
      [
        'suggestion line',
        400,
        (value) => ({
          findings: [finding({ suggestion: { startLine: 1, endLine: 1, lines: [value] } })],
        }),
      ],
    ];
    for (const [name, max, answer] of bounded) {
      expect(passes(specialistAnswerSchema, answer(text(max))), name).toBe(true);
      expect(passes(specialistAnswerSchema, answer(text(max + 1))), name).toBe(false);
    }
    for (const key of ['title', 'body', 'path']) {
      expect(passes(specialistAnswerSchema, { findings: [finding({ [key]: '' })] }), key).toBe(
        false,
      );
      expect(passes(specialistAnswerSchema, { findings: [finding({ [key]: ' \n ' })] }), key).toBe(
        false,
      );
    }
    const judgeBounded: [string, number, (value: string) => Record<string, unknown>][] = [
      ['verdict', 200, (value) => judgeAnswer({ summary: { verdict: value, walkthrough: [] } })],
      [
        'walkthrough',
        200,
        (value) => judgeAnswer({ summary: { verdict: 'v', walkthrough: [value] } }),
      ],
      [
        'prior reason',
        300,
        (value) => judgeAnswer({ prior: [{ id: 'issue-1', status: 'present', reason: value }] }),
      ],
    ];
    for (const [name, max, answer] of judgeBounded) {
      expect(passes(judgeAnswerSchema, answer(text(max))), name).toBe(true);
      expect(passes(judgeAnswerSchema, answer(text(max + 1))), name).toBe(false);
    }
    expect(passes(verifyAnswerSchema, { verdict: 'rejected', reason: text(300) })).toBe(true);
    expect(passes(verifyAnswerSchema, { verdict: 'rejected', reason: text(301) })).toBe(false);
    expect(passes(verifyAnswerSchema, { verdict: 'rejected', reason: '' })).toBe(false);
    // A reason for dropping a finding is a few words: a longer one is cut, never the judge's answer
    // refused for it. One must be given still.
    const dropped = (reason: string) =>
      judgeAnswerSchema.safeParse(judgeAnswer({ dropped: [{ source: 's1', reason }] }));
    expect(dropped(text(150)).data?.dropped[0]?.reason).toBe(text(150));
    expect(dropped(text(2_000)).data?.dropped[0]?.reason).toBe(`${text(149)}…`);
    expect(dropped(' ').success).toBe(false);

    // Counts: 30 findings of a specialist, 40 of the judge, 6 walkthrough points, 30 lines written.
    expect(passes(specialistAnswerSchema, { findings: many(30, finding) })).toBe(true);
    expect(passes(specialistAnswerSchema, { findings: many(31, finding) })).toBe(false);
    expect(passes(judgeAnswerSchema, judgeAnswer({ findings: many(40, judged) }))).toBe(true);
    expect(passes(judgeAnswerSchema, judgeAnswer({ findings: many(41, judged) }))).toBe(false);
    const walkthrough = (count: number) =>
      judgeAnswer({ summary: { verdict: 'v', walkthrough: many(count, () => 'A step.') } });
    expect(passes(judgeAnswerSchema, walkthrough(6))).toBe(true);
    expect(passes(judgeAnswerSchema, walkthrough(7))).toBe(false);
    const written = (count: number) => ({
      findings: [
        finding({ suggestion: { startLine: 1, endLine: 2, lines: many(count, () => 'x();') } }),
      ],
    });
    expect(passes(specialistAnswerSchema, written(30))).toBe(true);
    expect(passes(specialistAnswerSchema, written(31))).toBe(false);

    // Values outside their lists.
    for (const over of [
      { category: 'style' },
      { severity: 'high' },
      { severity: 'blocker' },
      { confidence: 'certain' },
    ]) {
      expect(
        passes(specialistAnswerSchema, { findings: [finding(over)] }),
        JSON.stringify(over),
      ).toBe(false);
    }
    expect(
      passes(
        judgeAnswerSchema,
        judgeAnswer({ prior: [{ id: 'issue-1', status: 'open', reason: 'r' }] }),
      ),
    ).toBe(false);
    expect(passes(verifyAnswerSchema, { verdict: 'likely', reason: 'r' })).toBe(false);

    // Every key of an answer is there: none is left out.
    for (const key of ['findings', 'dropped', 'prior', 'summary']) {
      const answer = Object.fromEntries(
        Object.entries(judgeAnswer()).filter(([name]) => name !== key),
      );
      expect(passes(judgeAnswerSchema, answer), key).toBe(false);
    }
    expect(
      passes(judgeAnswerSchema, judgeAnswer({ findings: [judged({ sources: undefined })] })),
    ).toBe(false);
    expect(passes(verifyAnswerSchema, { verdict: 'confirmed' })).toBe(false);
  });

  it('cleans the words of a finding as the assistant’s answers are cleaned, and leaves its code alone', () => {
    // Bidirectional controls, zero-width and other invisible characters, a line separator and a
    // control, in the texts of a finding a person reads, and an invisible one in a line of code.
    const code = 'for (let i = 0;​ i < n; i += 1) {';
    const parsed = specialistAnswerSchema.parse({
      findings: [
        finding({
          title: 'The loop‮stops one item ea​rly\n/close',
          body: 'The bound is `i < n -​ 1`,‮so the last item is never added. Use `i < n`.\u0007',
          assumption: 'It⁦runs once﻿.',
          suggestion: { startLine: 12, endLine: 12, lines: [code] },
        }),
      ],
    });
    const [only] = parsed.findings;
    if (only === undefined) throw new Error('no finding');
    expect(reviewFindingOf(only)).toMatchObject({
      // One line: the rest of a title is not kept.
      title: 'The loop stops one item early',
      body: 'The bound is `i < n - 1`, so the last item is never added. Use `i < n`.',
      assumption: 'It runs once.',
      suggestion: { startLine: 12, endLine: 12, lines: [code] },
    });
    // A text that is nothing but such characters is blank: refused, or no assumption at all.
    const blank = '​⁠‮ ﻿';
    expect(passes(specialistAnswerSchema, { findings: [finding({ title: blank })] })).toBe(false);
    expect(passes(specialistAnswerSchema, { findings: [finding({ body: blank })] })).toBe(false);
    const quiet = specialistAnswerSchema.parse({ findings: [finding({ assumption: blank })] });
    expect(reviewFindingOf(quiet.findings[0]!).assumption).toBeNull();
    // The judge's findings are read the same way.
    const judgedParse = judgeAnswerSchema.parse(
      judgeAnswer({ findings: [judged({ title: 'A‮bug', body: 'Re​al.' })] }),
    );
    expect(judgedParse.findings[0]).toMatchObject({ title: 'A bug', body: 'Real.' });
  });

  it('an optional part may be left out or null, and reads as null', () => {
    for (const over of [
      { endLine: undefined, assumption: undefined, suggestion: undefined },
      { endLine: null, assumption: null, suggestion: null },
      // A blank assumption says nothing.
      { endLine: null, assumption: '  ', suggestion: null },
    ]) {
      const parsed = specialistAnswerSchema.parse({ findings: [finding(over)] });
      const [only] = parsed.findings;
      if (only === undefined) throw new Error('no finding');
      expect(reviewFindingOf(only)).toEqual({
        category: 'logic',
        severity: 'major',
        confidence: 'high',
        path: 'src/cart.ts',
        line: 12,
        endLine: 12,
        title: 'The loop stops one item early',
        body: 'The bound is `i < n - 1`, so the last item is never added. Use `i < n`.',
        assumption: null,
        suggestion: null,
      });
    }
    expect(
      passes(judgeAnswerSchema, judgeAnswer({ findings: [judged({ priorId: undefined })] })),
    ).toBe(true);
    // A suggestion of no lines deletes the lines it replaces.
    expect(
      passes(specialistAnswerSchema, {
        findings: [finding({ suggestion: { startLine: 12, endLine: 13, lines: [] } })],
      }),
    ).toBe(true);
  });
});

describe('the reply answer schema', () => {
  const reply = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    intent: 'priority',
    verdict: 'wont_fix',
    answer: 'Understood: this stays as it is for this release.',
    ...over,
  });

  it('takes exactly an intent, a verdict and an answer', () => {
    expect(REPLY_INTENTS).toEqual(['priority', 'factual', 'question', 'other']);
    expect(replyAnswerSchema.parse(reply())).toEqual(reply());
    for (const intent of REPLY_INTENTS) {
      for (const verdict of ['keep', 'wont_fix', 'false_positive']) {
        expect(passes(replyAnswerSchema, reply({ intent, verdict })), `${intent} ${verdict}`).toBe(
          true,
        );
      }
    }
    // Unknown keys, a missing key and a value of another kind are refused: the whole answer with them.
    expect(passes(replyAnswerSchema, reply({ resolve: true }))).toBe(false);
    for (const key of ['intent', 'verdict', 'answer']) {
      const without = Object.fromEntries(Object.entries(reply()).filter(([name]) => name !== key));
      expect(passes(replyAnswerSchema, without), key).toBe(false);
    }
    for (const over of [
      { intent: 'complaint' },
      { intent: 'Priority' },
      { intent: null },
      { verdict: 'resolved' },
      { verdict: 'false-positive' },
      { verdict: 'KEEP' },
      { verdict: ['keep'] },
      { answer: null },
      { answer: ['Fine.'] },
      { answer: 3 },
    ]) {
      expect(passes(replyAnswerSchema, reply(over)), JSON.stringify(over)).toBe(false);
    }
    expect(passes(replyAnswerSchema, [reply()])).toBe(false);
    expect(passes(replyAnswerSchema, null)).toBe(false);
  });

  it('keeps an answer to at most 1 200 characters, and lets it be empty', () => {
    expect(passes(replyAnswerSchema, reply({ answer: text(1_200) }))).toBe(true);
    expect(passes(replyAnswerSchema, reply({ answer: text(1_201) }))).toBe(false);
    // A thanks needs no answer: nothing is posted for an empty one with the verdict keep.
    expect(replyAnswerSchema.parse(reply({ verdict: 'keep', answer: '' })).answer).toBe('');
    expect(replyAnswerSchema.parse(reply({ verdict: 'keep', answer: '  \n ' })).answer).toBe('');
  });

  it('cleans the answer as the words of a finding are cleaned', () => {
    // Bidirectional controls, zero-width and invisible characters, a line separator and a control.
    const parsed = replyAnswerSchema.parse(
      reply({
        verdict: 'keep',
        answer:
          'The bound is `i < n -\u{200b} 1`,\u{202e}so it\u{2028}skips one\u0007item.\n\n\n\nUse `i < n`.',
      }),
    );
    expect(parsed.answer).toBe('The bound is `i < n - 1`, so it skips one item.\n\nUse `i < n`.');
    // A text that is nothing but such characters says nothing.
    const blank = '\u{200b}\u{2060}\u{202e} \u{feff}';
    expect(replyAnswerSchema.parse(reply({ verdict: 'keep', answer: blank })).answer).toBe('');
  });
});

describe('ANSWER_LIMITS', () => {
  it('holds the values of the contract, which the prompts state and the storing of findings checks', () => {
    expect(ANSWER_LIMITS).toEqual({
      specialistFindings: 30,
      judgeFindings: 40,
      dropped: 120,
      sources: 120,
      priorVerdicts: 50,
      pathChars: 1_024,
      titleChars: 120,
      bodyChars: 1_200,
      assumptionChars: 300,
      reasonChars: 300,
      dropReasonChars: 150,
      verdictChars: 200,
      walkthroughItems: 6,
      walkthroughChars: 200,
      suggestionReplacedLines: 15,
      suggestionLines: 30,
      suggestionLineChars: 400,
      idChars: 64,
      replyChars: 1_200,
    });
  });
});

describe('the summary a run keeps', () => {
  it('takes every note the review makes of itself, the time limit too, and no other', () => {
    const summary = { verdict: 'v', walkthrough: ['w'], notes: ['time_limit_reached'] };
    expect(reviewSummarySchema.safeParse(summary).success).toBe(true);
    expect(REVIEW_NOTES).toContain('time_limit_reached');
    const all = { ...summary, notes: [...REVIEW_NOTES] };
    expect(reviewSummarySchema.safeParse(all).success).toBe(true);
    expect(reviewSummarySchema.safeParse({ ...summary, notes: ['time_up'] }).success).toBe(false);
  });
});

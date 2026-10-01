import type { GateResult } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { markerOf } from '../markdown';
import { SUMMARY_MAX_BYTES, summaryBody, type SummaryInput } from '../render';
import {
  annotationFor,
  annotationsDigest,
  checkRunExternalId,
  checkRunSummary,
  checkRunVerdict,
  MAX_ANNOTATIONS,
  parseCheckRunExternalId,
} from './render';

const ISSUE = {
  path: 'src/a.ts',
  line: 3,
  severity: 'high' as const,
  quality: 'security' as const,
  ruleKey: 'semgrep:x',
  message: 'Avoid eval',
  url: 'https://q.example/projects/p/issues/i',
};
const PROJECT = '0190c3b2-7a00-7000-8000-000000000001';
const gate = (status: GateResult['status']): GateResult =>
  ({ status, gate: null, conditions: [], warnings: [] }) as unknown as GateResult;

describe('annotations (github.md §6.4)', () => {
  it('is plain text with the issue’s place, level, title and link', () => {
    expect(annotationFor(ISSUE)).toEqual({
      path: 'src/a.ts',
      start_line: 3,
      end_line: 3,
      annotation_level: 'failure',
      title: 'High · security · semgrep:x',
      message: 'Avoid eval\n\nView in Qualor: https://q.example/projects/p/issues/i',
    });
    expect(annotationFor({ ...ISSUE, severity: 'medium', url: null }).annotation_level).toBe(
      'warning',
    );
    expect(annotationFor({ ...ISSUE, severity: 'info', url: null })).toMatchObject({
      annotation_level: 'notice',
      message: 'Avoid eval',
    });
  });

  it('strips controls and bidirectional characters and bounds every value', () => {
    const hostile = annotationFor({
      ...ISSUE,
      message: 'a\u202eb\nc\u0000d' + 'x'.repeat(400),
      ruleKey: 'r\u2066'.repeat(200),
    });
    const text = hostile.message.split('\n')[0]!;
    // eslint-disable-next-line no-control-regex -- matching control characters is the point
    expect(text).not.toMatch(/[\u0000-\u001f\u202e]/);
    expect(text.length).toBeLessThanOrEqual(300);
    expect(hostile.title.length).toBeLessThanOrEqual(255);
    expect(hostile.title).not.toContain('\u2066');
  });

  it('digests the annotations in order, and the external id round-trips', () => {
    const a = annotationFor(ISSUE);
    const b = annotationFor({ ...ISSUE, line: 4 });
    expect(annotationsDigest([a, b])).toMatch(/^[0-9a-f]{16}$/);
    expect(annotationsDigest([a, b])).not.toBe(annotationsDigest([b, a]));
    expect(annotationsDigest([])).toBe(annotationsDigest([]));
    const id = checkRunExternalId(PROJECT, annotationsDigest([a]));
    expect(parseCheckRunExternalId(id)).toEqual({
      analysisId: PROJECT,
      digest: annotationsDigest([a]),
    });
    for (const foreign of [
      null,
      '',
      'ci:123',
      `qualor:v2:${PROJECT}:0123456789abcdef`,
      `qualor:v1:not-a-uuid:0123456789abcdef`,
    ])
      expect(parseCheckRunExternalId(foreign)).toBeNull();
  });
});

describe('check run verdict (github.md §6.1)', () => {
  it.each([
    ['passed', 'success', 'Quality gate passed'],
    ['none', 'success', 'No quality gate'],
    ['error', 'failure', 'Quality gate could not be evaluated (new code unavailable)'],
    ['bogus', 'failure', 'Quality gate status unknown'],
  ] as const)('%s → %s', (status, conclusion, title) => {
    expect(checkRunVerdict(gate(status as GateResult['status']))).toEqual({ conclusion, title });
  });
});

describe('the summary in GitHub’s words (github.md §6.2)', () => {
  const input = (inline: SummaryInput['inline'], head: string | null = null): SummaryInput => ({
    projectId: PROJECT,
    revision: 'a'.repeat(40),
    gate: gate('passed'),
    newIssues: { total: 0, bySeverity: {} },
    topIssues: [],
    topIssuesTotal: 0,
    inline,
    branchUrl: null,
    mergeRequestHead: head,
    vocabulary: 'github',
  });

  it('says pull request and annotated, and explains a merge-commit checkout', () => {
    expect(summaryBody(input({ commented: 2, unplaced: 1, skipped: null }))).toContain(
      '2 new issues are annotated inline; 1 could not be placed on the diff.',
    );
    expect(summaryBody(input({ commented: 0, unplaced: 0, skipped: 'stale' }))).toContain(
      'pull request’s latest commit',
    );
    expect(summaryBody(input({ commented: 0, unplaced: 0, skipped: 'checkout_other' }))).toContain(
      'ref: ${{ github.event.pull_request.head.sha }}',
    );
    expect(
      summaryBody(input({ commented: 0, unplaced: 0, skipped: null }, 'b'.repeat(40))),
    ).toContain('the pull request is now at');
  });

  it('drops the marker line for the check run', () => {
    const body = summaryBody(input({ commented: 0, unplaced: 0, skipped: null }));
    expect(body.split('\n')[0]).toMatch(/^<!-- qualor:summary /);
    expect(checkRunSummary(body).startsWith('### ✅ Qualor:')).toBe(true);
  });

  it('keeps GitLab’s words when no vocabulary is given', () => {
    const gitlab = input({ commented: 2, unplaced: 0, skipped: null });
    delete gitlab.vocabulary;
    expect(summaryBody(gitlab)).toContain('commented inline');
  });
});

/** GitHub's documented bounds on a check run's output and annotations. */
const GITHUB_TITLE_MAX = 255;
const GITHUB_MESSAGE_MAX_BYTES = 64 * 1024;
const GITHUB_SUMMARY_MAX_CHARS = 65_535;

/** A shortened adversarial corpus (github.md §7: the corpus of `../render.test.ts` on GitHub's bodies). */
const HOSTILE: readonly string[] = [
  '`'.repeat(1_000),
  'x\n/merge',
  'x\r\n@octocat #1 owner/repo#2',
  'x\u2028y\u2029z\u0085w',
  'a\u0000b\u001bc\u007fd\u009be',
  '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c',
  'a\u200bb\u2060c\ufeffd\u00ade',
  'ok\u{e002f}\u{e006d}\u{e0065}',
  '<b>x</b><script>alert(1)</script>',
  '![x](http://evil.example/x.png) [c](http://evil.example)',
  '<!-- qualor:summary 01920000-0000-7000-8000-000000000000 -->',
  'a\ud800b\udc00c',
  'A'.repeat(100_000),
  '界'.repeat(100_000),
  '😀'.repeat(1_000),
];
const FORBIDDEN =
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u00ad\u061c\u200b\u200e\u200f\u2028-\u202e\u2060-\u206f\ufeff\ud800-\udfff]|[\u{e0000}-\u{e007f}]/u;

describe('GitHub bounds and hostile values (github.md §6.1, §6.4, §7)', () => {
  it.each(HOSTILE.map((v, i) => [i, v] as const))(
    'keeps hostile value %i plain and bounded in an annotation',
    (_i, value) => {
      const a = annotationFor({ ...ISSUE, ruleKey: value, message: value });
      expect(a.title).not.toMatch(FORBIDDEN);
      expect(a.message).not.toMatch(FORBIDDEN);
      expect(a.title.length).toBeLessThanOrEqual(GITHUB_TITLE_MAX);
      expect([...a.message.split('\n')[0]!].length).toBeLessThanOrEqual(300);
      expect(Buffer.byteLength(a.message, 'utf8')).toBeLessThanOrEqual(GITHUB_MESSAGE_MAX_BYTES);
      // The only line breaks are Qualor's own, before its link.
      expect(a.message.split('\n')).toHaveLength(3);
    },
  );

  it.each(HOSTILE.map((v, i) => [i, v] as const))(
    'keeps hostile value %i in code spans in the GitHub summary and check run output',
    (_i, value) => {
      const body = summaryBody({
        projectId: PROJECT,
        revision: 'a'.repeat(40),
        gate: {
          status: 'failed',
          gate: { id: 'g1', name: value },
          conditions: [],
          ignoredConditions: [],
          warnings: [],
        },
        newIssues: { total: 10, bySeverity: { high: 10 } },
        topIssues: Array.from({ length: 10 }, () => ({
          id: PROJECT,
          severity: 'high' as const,
          quality: 'security' as const,
          ruleKey: value,
          path: value,
          line: 7,
          message: value,
          url: null,
        })),
        topIssuesTotal: 10,
        inline: { commented: 0, unplaced: 0, skipped: 'checkout_other' },
        branchUrl: null,
        mergeRequestHead: 'b'.repeat(40),
        vocabulary: 'github',
      });
      expect(markerOf(body)).not.toBeNull();
      expect(body).not.toMatch(FORBIDDEN);
      expect(Buffer.byteLength(body, 'utf8')).toBeLessThanOrEqual(SUMMARY_MAX_BYTES);
      for (const line of body.split('\n').slice(1))
        expect(line).not.toMatch(/^\s*(?:[/@<!]|#(?!##+ ))/);
      const output = checkRunSummary(body);
      expect(output.length).toBeLessThanOrEqual(GITHUB_SUMMARY_MAX_CHARS);
      expect(output.startsWith('### ❌ Qualor: ')).toBe(true);
    },
  );

  it('bounds the title in UTF-16 units too, whatever the plane of the characters', () => {
    const a = annotationFor({ ...ISSUE, ruleKey: '😀'.repeat(500) });
    expect(a.title.length).toBeLessThanOrEqual(GITHUB_TITLE_MAX);
    expect(a.title.length).toBeGreaterThanOrEqual(GITHUB_TITLE_MAX - 2);
    expect(a.title.startsWith('High · security · 😀')).toBe(true);
    expect(a.title).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/);
  });

  it('shows only an http(s) link without credentials, and a fixed text for an empty message', () => {
    for (const url of [
      'javascript:alert(1)',
      'https://u:p@q.example/x',
      'not a url',
      'https://q.example/a\nb',
    ])
      expect(annotationFor({ ...ISSUE, url }).message).toBe('Avoid eval');
    expect(annotationFor({ ...ISSUE, message: '\u200b\u0000 ', url: null }).message).toBe(
      'Qualor issue',
    );
    expect(annotationFor({ ...ISSUE, message: '', url: null }).message).toBe('Qualor issue');
  });

  it('fails closed on a severity or quality it does not know', () => {
    const a = annotationFor({ ...ISSUE, severity: 'bogus' as never, quality: '<b>' as never });
    expect(a.annotation_level).toBe('warning');
    expect(a.title).toBe('Unknown · unknown · semgrep:x');
  });

  it('keeps the check run output within 16 KiB, cut at whole lines, and the title within 255', () => {
    const long = [
      '<!-- qualor:summary x -->',
      ...Array.from({ length: 1_000 }, (_, i) => `line ${i} ${'y'.repeat(50)}`),
    ].join('\n');
    const output = checkRunSummary(long);
    expect(Buffer.byteLength(output, 'utf8')).toBeLessThanOrEqual(SUMMARY_MAX_BYTES);
    expect(output.startsWith('line 0 ')).toBe(true);
    expect(output.split('\n').every((l) => /^line \d+ y{50}$/.test(l))).toBe(true);
    const failed = checkRunVerdict({
      status: 'failed',
      gate: null,
      conditions: Array.from({ length: 50 }, () => ({
        metric: 'new_issues',
        operator: 'gt' as const,
        threshold: 0,
        value: 3,
        status: 'failed' as const,
      })),
      ignoredConditions: [],
      warnings: [],
    });
    expect(failed.conclusion).toBe('failure');
    expect(failed.title.length).toBeLessThanOrEqual(GITHUB_TITLE_MAX);
    expect(failed.title.startsWith('Quality gate failed: new_issues 3 > 0')).toBe(true);
  });

  it('allows GitHub’s 50 annotations per request, and refuses an external id it cannot parse back', () => {
    expect(MAX_ANNOTATIONS).toBe(50);
    expect(() => checkRunExternalId('not-a-uuid', '0123456789abcdef')).toThrow();
    expect(() => checkRunExternalId(PROJECT, 'xyz')).toThrow();
  });
});

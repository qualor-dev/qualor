import type { GateResult } from '@qualor/shared';
import { marked } from 'marked';
import { beforeAll, describe, expect, it } from 'vitest';
import { safeCodeSpan, safePlainValue } from '@qualor/shared';
import {
  badSectionLine,
  checkProse,
  FIXED_TEXT,
  FORBIDDEN_ANYWHERE,
  outsideCodeSpans,
  outsideProseSpans,
  SUMMARY_FIXED_TEXT,
} from '../../test/markdown-check';
import { AI_SECTION_MAX_BYTES, aiSummarySection, type ReviewSummaryState } from '../review/render';
import {
  codeSpan,
  fixedMarker,
  issueMarker,
  markerOf,
  MAX_RULE_LINK_CHARS,
  notedFixes,
  plainProse,
  plainValue,
  qualorLink,
  ruleDocUrl,
  ruleKeyMarkdown,
  safeProse,
  summaryMarker,
  TRACKER_LIKE,
} from './markdown';
import {
  commitStatusFor,
  fixedNote,
  INLINE_MAX_BYTES,
  inlineBody,
  mergeRequestTitle,
  STATUS_NAME_MAX_CHARS,
  statusName,
  SUMMARY_MAX_BYTES,
  summaryBody,
  type SummaryInput,
} from './render';

const PROJECT = '01920000-0000-7000-8000-000000000000';
const ISSUE = '01920000-0000-7000-8000-000000000001';

/** A message that tries everything GitLab Markdown could turn into an action or a link. */
const HOSTILE = [
  '@all please /merge',
  '\n/approve\n/merge',
  '![x](http://evil.example/x.png)',
  '<img src=x onerror=alert(1)>',
  '[link](http://evil.example)',
  'http://evil.example/auto',
  '`` code `` and ```',
  '#1 !2 ~label %milestone $`x`$',
  '<!-- qualor:issue 01920000-0000-7000-8000-00000000ffff -->',
  '\u202eevil\u2066',
  '\r\n- [ ] task',
].join(' ');

function gate(status: GateResult['status'], conditions: GateResult['conditions'] = []): GateResult {
  return {
    status,
    gate: status === 'none' ? null : { id: 'g1', name: 'Qualor `way` @all' },
    conditions,
    ignoredConditions: [],
    warnings: [],
  };
}

const failed = gate('failed', [
  { metric: 'new_issues', operator: 'gt', threshold: 0, value: 3, status: 'failed' },
  { metric: 'new_coverage', operator: 'lt', threshold: 80, value: 91.25, status: 'passed' },
  {
    metric: 'new_duplicated_lines_density',
    operator: 'gt',
    threshold: 3,
    value: null,
    status: 'no_value',
  },
]);

/** A finished review in which every slot of the model's words, a path and a title holds `value`. */
function hostileReview(value: string): ReviewSummaryState {
  const url = `https://q.example/projects/${PROJECT}/issues/${ISSUE}`;
  return {
    kind: 'done',
    verdict: value,
    walkthrough: [value, value],
    counts: { high: 1, medium: 1, low: 1 },
    unplaced: Array.from({ length: 3 }, () => ({
      severity: 'high',
      path: value,
      line: 7,
      title: value,
      url,
    })),
    moreUnplaced: 2,
    reviewedSha: 'abcdef0123456789abcdef0123456789abcdef01',
    mergeRequestHeadSha: 'b'.repeat(40),
    tokenLimitReached: true,
    snapshotPartial: true,
    notes: ['reviewer_unreadable', 'verification_capped'],
    fixPrompt: Array.from({ length: 3 }, () => ({
      path: value,
      line: 7,
      title: value,
      body: value,
    })),
  };
}

function summary(overrides: Partial<SummaryInput> = {}): string {
  return summaryBody({
    projectId: PROJECT,
    revision: 'abcdef0123456789abcdef0123456789abcdef01',
    gate: failed,
    newIssues: { total: 3, bySeverity: { high: 1, medium: 2, low: 0 } },
    topIssues: [
      {
        id: ISSUE,
        severity: 'high',
        quality: 'security',
        ruleKey: 'semgrep:@all /merge',
        path: 'src/a.ts',
        line: 12,
        message: HOSTILE,
        url: `https://q.example/projects/${PROJECT}/issues/${ISSUE}`,
      },
      {
        id: ISSUE,
        severity: 'medium',
        quality: 'maintainability',
        ruleKey: 'eslint:no-console',
        path: 'src/`x`.ts',
        line: null,
        message: 'plain',
        url: null,
      },
      {
        id: ISSUE,
        severity: 'medium',
        quality: 'reliability',
        ruleKey: 'r',
        path: null,
        line: null,
        message: '/merge',
        url: null,
      },
    ],
    topIssuesTotal: 3,
    inline: { commented: 2, unplaced: 1, skipped: null },
    branchUrl: `https://q.example/projects/${PROJECT}/branches/b1`,
    mergeRequestHead: null,
    ...overrides,
  });
}

describe('comment safety (scm.md §6)', () => {
  it('wraps a value in a code span it cannot close, on one line, without controls', () => {
    expect(codeSpan('plain')).toBe('` plain `');
    expect(codeSpan('a ` b')).toBe('`` a ` b ``');
    expect(codeSpan('``x``')).toBe('``` ``x`` ```');
    expect(codeSpan('line\nbreak\r\u2028sep')).toBe('` line break  sep `');
    expect(codeSpan('\u202eright\u2066')).toBe('`  right  `');
    expect(codeSpan('')).toBe('` `');
    expect(codeSpan('x'.repeat(500), 10)).toBe(`\` ${'x'.repeat(9)}… \``);
    // Code points, not UTF-16 units: an emoji is never cut in half.
    expect(plainValue('😀😀😀', 2)).toBe('😀…');
  });

  it('keeps every hostile value inside code spans, and no line starts with a quick action', () => {
    const bodies = [
      summary(),
      inlineBody({
        issueId: ISSUE,
        severity: 'blocker',
        quality: 'security',
        ruleKey: 'external:@all /merge [x](http://evil)',
        message: HOSTILE,
        url: null,
      }),
    ];
    for (const body of bodies) {
      for (const line of body.split('\n')) {
        expect(line, line).not.toMatch(/^\s*\//);
        const markdown = outsideCodeSpans(line);
        for (const bad of [
          '@all',
          '<img',
          '![',
          '](http://evil',
          'http://evil',
          '/merge',
          '/approve',
          '<!--',
          '\u202e',
        ]) {
          if (line.startsWith('<!-- qualor:')) continue;
          expect(markdown, line).not.toContain(bad);
        }
      }
    }
  });

  it('marks the summary and the inline note on their first line only', () => {
    const body = summary();
    expect(body.split('\n')[0]).toBe(summaryMarker(PROJECT));
    expect(markerOf(body)).toEqual({ kind: 'summary', projectId: PROJECT });
    const inline = inlineBody({
      issueId: ISSUE,
      severity: 'low',
      quality: 'maintainability',
      ruleKey: 'eslint:no-console',
      message: '<!-- qualor:summary 01920000-0000-7000-8000-000000000000 -->',
      url: null,
    });
    expect(markerOf(inline)).toEqual({ kind: 'issue', issueId: ISSUE });
    expect(markerOf(`LGTM\n${summaryMarker(PROJECT)}`)).toBeNull();
    expect(markerOf(`${summaryMarker(PROJECT)} trailing`)).toBeNull();
    expect(markerOf('<!-- qualor:summary not-a-uuid -->')).toBeNull();
  });
});

describe('summary, inline note and commit status (scm.md §5)', () => {
  const B = `https://q.example/projects/${PROJECT}/branches/b1`;
  const I = `https://q.example/projects/${PROJECT}/issues/${ISSUE}`;

  it('shows the verdict, every condition, the counts, the issues and the link', () => {
    const body = summary();
    const lines = body.split('\n');
    expect(lines[1]).toBe('### ❌ Qualor: quality gate failed');
    expect(body).toContain(
      '`` Qualor `way` @all `` · analysis ` abcdef012345 ` · **3 new issues** in this merge request',
    );
    expect(body).toContain(
      [
        '| | Condition | Value | Required |',
        '|---|---|---|---|',
        '| ❌ | New issues | 3 | ≤ 0 |',
        '| ✅ | Coverage on new code | 91.3% | ≥ 80 |',
        '| ➖ | Duplication on new code | — | ≤ 3 |',
      ].join('\n'),
    );
    expect(body).toContain('**By severity:** 🔴 1 high · 🟠 2 medium');
    expect(body).toContain(
      [
        '#### Most severe new issues',
        '',
        `1. 🔴 **High** · security · \` semgrep:@all /merge \` · [\` src/a.ts:12 \`](${I})\\`,
      ].join('\n'),
    );
    expect(body).toContain(
      '2. 🟠 **Medium** · maintainability · ` eslint:no-console ` · `` src/`x`.ts ``\\\n   plain',
    );
    expect(body).toContain('3. 🟠 **Medium** · reliability · ` r `\\\n   ` /merge `');
    expect(body).toContain(
      `2 new issues are commented inline; 1 could not be placed on the diff. · **[Open in Qualor →](${B})**`,
    );
    expect(body).not.toContain('View in Qualor');
  });

  it('puts an icon on the headline for every gate status', () => {
    const head = (g: GateResult) => summary({ gate: g }).split('\n')[1];
    expect(head(gate('passed'))).toBe('### ✅ Qualor: quality gate passed');
    expect(head(failed)).toBe('### ❌ Qualor: quality gate failed');
    expect(head(gate('error'))).toBe('### ⚠️ Qualor: the quality gate could not be evaluated');
    expect(head(gate('none'))).toBe('### ➖ Qualor: no quality gate');
    expect(head({ ...gate('passed'), status: 'weird' } as unknown as GateResult)).toBe(
      '### ⚠️ Qualor: quality gate status unknown',
    );
  });

  it('shows a plain gate name in bold, and any other in a code span', () => {
    const named = (name: string) =>
      summary({ gate: { ...failed, gate: { id: 'g', name } } }).split('\n')[3];
    expect(named('Qualor way')).toBe(
      '**Qualor way** · analysis ` abcdef012345 ` · **3 new issues** in this merge request',
    );
    expect(named('Équipe 2')).toMatch(/^\*\*Équipe 2\*\* · /);
    for (const odd of ['a_b_', '**x', ' lead', 'www.evil.example', 'deadbeef1', 'x‮y', '#1'])
      expect(named(odd), odd).toMatch(/^`/);
    expect(summary({ gate: gate('none') }).split('\n')[3]).toMatch(/^analysis ` abcdef012345 ` · /);
  });

  it('counts new issues in the request’s words, or says they are not available', () => {
    const line = (total: number | null, vocabulary?: 'github') =>
      summary({ newIssues: { total, bySeverity: {} }, ...(vocabulary ? { vocabulary } : {}) });
    expect(line(1)).toContain('· **1 new issue** in this merge request');
    expect(line(0)).toContain('· **no new issues** in this merge request');
    expect(line(25, 'github')).toContain('· **25 new issues** in this pull request');
    const none = line(null);
    expect(none.split('\n')[3]).toBe('`` Qualor `way` @all `` · analysis ` abcdef012345 `');
    expect(none).toContain('**New issues:** not available (no new-code baseline)');
    expect(none).not.toContain('**By severity:**');
  });

  it('marks every severity, and only the non-zero ones', () => {
    const body = summary({
      newIssues: {
        total: 15,
        bySeverity: { blocker: 1, high: 2, medium: 3, low: 4, info: 5 },
      },
    });
    expect(body).toContain(
      '**By severity:** ⛔ 1 blocker · 🔴 2 high · 🟠 3 medium · 🟡 4 low · 🔵 5 info',
    );
    expect(summary({ newIssues: { total: 0, bySeverity: { high: 0 } } })).not.toContain(
      'By severity',
    );
  });

  it('writes the passing side as Required, labels metrics from the catalog, and skips rows', () => {
    const g: GateResult = {
      ...gate('passed', [
        { metric: 'new_coverage', operator: 'lt', threshold: 80, value: 100, status: 'passed' },
        { metric: 'coverage', operator: 'lt', threshold: 50.5, value: 0, status: 'failed' },
        { metric: 'new_high_issues', operator: 'gt', threshold: 2, value: 1, status: 'passed' },
        {
          metric: 'new_security_rating',
          operator: 'gt',
          threshold: 1,
          value: 1,
          status: 'passed',
        },
        { metric: 'my_metric', operator: 'gt', threshold: 1, value: 2.25, status: 'failed' },
        { metric: 'Bad Key|', operator: 'gt', threshold: 1, value: 2, status: 'failed' },
      ]),
      ignoredConditions: [
        { metric: 'new_line_coverage', reason: 'small_changeset' },
        { metric: 'ncloc', reason: 'overall_on_branch' },
        { metric: 'new_branch_coverage', reason: 'weird' as never },
      ],
    };
    const body = summary({ gate: g, smallChangesetLines: 20 });
    expect(body).toContain(
      [
        '| ✅ | Coverage on new code | 100.0% | ≥ 80 |',
        '| ❌ | Coverage | 0.0% | ≥ 50.5 |',
        '| ✅ | New high issues | 1 | ≤ 2 |',
        '| ✅ | Security rating on new code | 1 | ≤ 1 |',
        '| ❌ | `my_metric` | 2.3 | ≤ 1 |',
        '| ❌ | unknown metric | 2 | ≤ 1 |',
        '| ➖ | Line coverage on new code | — | skipped: fewer than 20 new lines |',
        '| ➖ | Lines of code | — | skipped: overall condition on a branch |',
        '| ➖ | Condition coverage on new code | — | skipped |',
      ].join('\n'),
    );
    expect(summary({ gate: g })).toContain(
      '| ➖ | Line coverage on new code | — | skipped: small change |',
    );
    expect(summary({ gate: gate('passed') })).not.toContain('| Condition |');
  });

  it('says why no inline comments were made, and when the merge request moved on', () => {
    expect(summary({ inline: { commented: 0, unplaced: 0, skipped: 'stale' } })).toContain(
      'Inline comments wait for the analysis',
    );
    // The AI review's threads follow the head it read, so they are posted in such a pipeline too:
    // the sentence speaks for the analyzers' issues, whatever else the merge request has.
    expect(summary({ inline: { commented: 0, unplaced: 0, skipped: 'merged_result' } })).toContain(
      '\n\nThe analyzers’ issues are not commented inline: this was a merged-results pipeline, whose line numbers are not the merge request’s.',
    );
    expect(summary({ mergeRequestHead: 'f'.repeat(40) })).toContain(
      'the merge request is now at ` ffffffffffff `.',
    );
    // A merged-results pipeline analyses a merge commit that is never the head (scm.md §5.2 item 7).
    expect(
      summary({
        mergeRequestHead: 'f'.repeat(40),
        inline: { commented: 0, unplaced: 0, skipped: 'merged_result' },
      }),
    ).not.toContain('is now at');
    const passed = summaryBody({
      projectId: PROJECT,
      revision: 'a'.repeat(40),
      gate: gate('none'),
      newIssues: { total: null, bySeverity: {} },
      topIssues: [],
      topIssuesTotal: 0,
      inline: { commented: 0, unplaced: 0, skipped: null },
      branchUrl: null,
      mergeRequestHead: null,
    });
    expect(passed).toContain('### ➖ Qualor: no quality gate');
    expect(passed).toContain('**New issues:** not available (no new-code baseline)');
    expect(passed).not.toContain('Most severe');
    expect(passed).not.toContain('Open in Qualor');
  });

  it('says in GitHub’s words how many issues are commented and why there are no inline comments (github.md §6.2)', () => {
    const none = { commented: 0, unplaced: 0, skipped: null };
    const github = (inline: SummaryInput['inline'], mergeRequestHead: string | null = null) =>
      summary({ vocabulary: 'github', inline, mergeRequestHead });
    expect(github({ ...none, commented: 2, unplaced: 1 })).toContain(
      '2 new issues are commented inline; 1 could not be placed on the diff.',
    );
    expect(github({ ...none, commented: 1 })).toContain('1 new issue is commented inline.');
    expect(github({ ...none, skipped: 'stale' })).toContain(
      'Inline comments wait for the analysis of the pull request’s latest commit.',
    );
    // It speaks for the analyzers' issues: the AI review's threads are posted after such a checkout.
    const other = github({ ...none, skipped: 'checkout_other' });
    expect(other).toContain(
      'The analyzers’ issues are not commented inline: the workflow analysed a commit other than the pull request’s head (GitHub’s merge commit, by default); check out the head to get them (`ref: ${{ github.event.pull_request.head.sha }}`).',
    );
    expect(other).not.toContain('No inline comments');
    // Annotations are gone: no GitHub text says so any more.
    for (const skipped of ['stale', 'checkout_other'] as const) {
      expect(github({ ...none, skipped })).not.toMatch(/annotat/i);
    }
    expect(github({ ...none, commented: 2 })).not.toMatch(/annotat/i);
    expect(github(none, 'f'.repeat(40))).toContain('the pull request is now at ` ffffffffffff `.');
  });

  it('says how many conversations GitHub would not let Qualor resolve or reopen, with its plural', () => {
    const none = { commented: 0, unplaced: 0, skipped: null };
    const github = (inline: SummaryInput['inline'], mergeRequestHead: string | null = null) =>
      summary({ vocabulary: 'github', inline, mergeRequestHead });
    const one =
      '1 conversation could not be resolved or reopened: give the GitHub App Contents: Read and write.';
    const three =
      '3 conversations could not be resolved or reopened: give the GitHub App Contents: Read and write.';
    // A line of its own after the inline sentence and the link, before the note that the pull
    // request moved on.
    expect(
      github({ ...none, commented: 2, unresolved: 1 })
        .split('\n')
        .slice(-3),
    ).toEqual([`2 new issues are commented inline. · **[Open in Qualor →](${B})**`, '', one]);
    expect(
      github({ ...none, commented: 2, unresolved: 3 }, 'f'.repeat(40))
        .split('\n')
        .slice(-5),
    ).toEqual([
      `2 new issues are commented inline. · **[Open in Qualor →](${B})**`,
      '',
      three,
      '',
      'This analysis is of ` abcdef012345 `; the pull request is now at ` ffffffffffff `.',
    ]);
    // Beside the sentence of a checkout the analyzers' threads skip: the AI review's are updated.
    expect(github({ ...none, skipped: 'checkout_other', unresolved: 1 })).toContain(`\n\n${one}`);
    // Never the words of a failure: the threads were read and the rest was written.
    expect(github({ ...none, unresolved: 3 })).not.toContain('could not be updated');
    // Nothing to say: no line.
    for (const unresolved of [0, -1, Number.NaN, undefined]) {
      expect(github({ ...none, unresolved }), String(unresolved)).not.toContain(
        'could not be resolved',
      );
    }
  });

  it('ends with how many more issues there are, where they are, and the link', () => {
    const tail = (o: Partial<SummaryInput>) => summary(o).split('\n').at(-1);
    const none = { commented: 0, unplaced: 0, skipped: null };
    expect(tail({ topIssuesTotal: 25, inline: { ...none, commented: 25 } })).toBe(
      `…and 22 more, all commented inline · **[Open in Qualor →](${B})**`,
    );
    // GitHub's findings are review comments too (github.md §6.2): the same words as GitLab's.
    expect(
      tail({ topIssuesTotal: 25, inline: { ...none, commented: 25 }, vocabulary: 'github' }),
    ).toBe(`…and 22 more, all commented inline · **[Open in Qualor →](${B})**`);
    expect(summary({ topIssuesTotal: 25, inline: { commented: 20, unplaced: 5, skipped: null } }))
      .toContain(`   \` /merge \`

…and 22 more

20 new issues are commented inline; 5 could not be placed on the diff. · **[Open in Qualor →](${B})**`);
    expect(tail({ topIssuesTotal: 25, inline: none })).toBe(
      `…and 22 more · **[Open in Qualor →](${B})**`,
    );
    expect(tail({ topIssuesTotal: 25, branchUrl: null, inline: none })).toBe('…and 22 more');
    expect(tail({ inline: none })).toBe(`**[Open in Qualor →](${B})**`);
    expect(tail({ inline: { ...none, commented: 1 } })).toBe(
      `1 new issue is commented inline. · **[Open in Qualor →](${B})**`,
    );
    expect(tail({ topIssuesTotal: 25, inline: { ...none, skipped: 'stale' } })).toBe(
      `Inline comments wait for the analysis of the merge request’s latest commit. · **[Open in Qualor →](${B})**`,
    );
    expect(tail({ mergeRequestHead: 'f'.repeat(40) })).toMatch(/is now at ` ffffffffffff `\.$/);
  });

  it('links an issue without a place with fixed text, and shows a place without a link', () => {
    const issue = {
      id: ISSUE,
      severity: 'low' as const,
      quality: 'security' as const,
      ruleKey: 'k',
      path: null,
      line: null,
      message: 'm',
      url: null,
    };
    const body = summary({
      topIssues: [
        { ...issue, url: I },
        { ...issue, severity: 'info', quality: 'bogus' as never, path: 'a.ts', line: 1 },
        { ...issue, severity: 'bogus' as never },
      ],
      topIssuesTotal: 3,
    });
    expect(body).toContain(`1. 🟡 **Low** · security · \` k \` · [details](${I})\\`);
    expect(body).toContain('2. 🔵 **Info** · unknown · ` k ` · ` a.ts:1 `\\');
    expect(body).toContain('3. ➖ **Unknown** · security · ` k `\\');
  });

  it('puts each issue’s message on a line of its own (a CommonMark hard break)', () => {
    // CommonMark without `breaks`: a plain line break would join the message to the heading.
    const html = marked.parse(summary(), { async: false, gfm: true, breaks: false });
    expect(html).toMatch(/<code>src\/a\.ts:12<\/code><\/a><br>\s*<code>/);
    expect(html).toMatch(/<code>r<\/code><br>\s*<code>\/merge<\/code>/);
    expect(html).not.toContain('\\');
  });

  const SQL_MESSAGE =
    'Data from the HTTP request reaches the text of an SQL query. Pass it as a bound parameter (`query(text, values)`) instead of building the query string from it.';
  const SQL_PROSE =
    'Data from the HTTP request reaches the text of an SQL query. Pass it as a bound parameter (` query(text, values) `) instead of building the query string from it.';

  it('reads an analyzer message as prose, its code in spans, in the summary and the inline note', () => {
    for (const vocabulary of ['gitlab', 'github'] as const) {
      const body = summary({
        vocabulary,
        topIssues: [
          {
            id: ISSUE,
            severity: 'high',
            quality: 'security',
            ruleKey: 'qualor:js/sql-injection',
            path: 'src/a.ts',
            line: 3,
            message: SQL_MESSAGE,
            url: null,
          },
        ],
        topIssuesTotal: 1,
      });
      expect(body, vocabulary).toContain(`\\\n   ${SQL_PROSE}\n`);
      expect(body, vocabulary).not.toContain('`` Data');
    }
    const note = inlineBody({
      issueId: ISSUE,
      severity: 'high',
      quality: 'security',
      ruleKey: 'qualor:js/sql-injection',
      message: SQL_MESSAGE,
      url: null,
    });
    expect(note.split('\n')[3]).toBe(SQL_PROSE);
  });

  it('keeps every line of a multi-line analyzer message, joined into one, in the summary and the inline note', () => {
    for (const message of [
      'Errors unhandled.\nSeverity: LOW\nConfidence: HIGH',
      'Errors unhandled.\r\n  Severity: LOW\r\n\r\nConfidence: HIGH\n',
    ]) {
      const input = {
        issueId: ISSUE,
        severity: 'low' as const,
        quality: 'reliability' as const,
        ruleKey: 'gosec:G104',
        message,
        url: null,
      };
      const joined = 'Errors unhandled. Severity: LOW Confidence: HIGH';
      expect(inlineBody(input).split('\n')[3]).toBe(joined);
      for (const vocabulary of ['gitlab', 'github'] as const) {
        const body = summary({
          vocabulary,
          topIssues: [{ ...input, id: ISSUE, path: 'main.go', line: 3 }],
          topIssuesTotal: 1,
        });
        expect(body, vocabulary).toContain(`\\\n   ${joined}\n`);
      }
    }
  });

  it('never makes a list of a message that starts like an item of one', () => {
    for (const message of ['1) Use a constant here.', '2) Use a constant here.']) {
      const input = {
        issueId: ISSUE,
        severity: 'low' as const,
        quality: 'maintainability' as const,
        ruleKey: 'k',
        message,
        url: null,
      };
      const body = summary({
        topIssues: [{ ...input, id: ISSUE, path: null, line: null }],
        topIssuesTotal: 1,
      });
      const html = marked.parse(body, { async: false, gfm: true, breaks: false });
      // One list of issues, its item's message after a line break, and no stray backslash.
      expect(html.match(/<ol\b/g), message).toHaveLength(1);
      expect(html, message).toMatch(/<br>\s*Use a constant here\./);
      expect(html, message).not.toContain('\\');
      const note = marked.parse(inlineBody(input), { async: false, gfm: true, breaks: false });
      expect(note, message).not.toMatch(/<ol\b/);
      expect(note, message).toContain('<p>Use a constant here.</p>');
    }
  });

  it('keeps mentions, references, HTML and links in a message inert', () => {
    const message = '@team #12 <img src=x> [x](y)';
    const input = {
      issueId: ISSUE,
      severity: 'high' as const,
      quality: 'security' as const,
      ruleKey: 'k',
      message,
      url: null,
    };
    const lines = [
      inlineBody(input).split('\n')[3]!,
      ...(['gitlab', 'github'] as const).map((vocabulary) =>
        summary({
          vocabulary,
          topIssues: [{ ...input, id: ISSUE, path: null, line: null }],
          topIssuesTotal: 1,
        })
          .split('\n')
          .find((l) => l.startsWith('   '))!,
      ),
    ];
    for (const line of lines) {
      // Every word that holds a mark is in a span of its own; nothing is left outside but words.
      expect(line.trim()).toBe('` @team ` ` #12 ` ` <img ` ` src=x> ` ` [x](y) `');
      expect(checkProse(line.trim())).toBe(true);
    }
  });

  it('labels a licence finding with its licensing quality (6M §6)', () => {
    const message =
      "gpl-pkg 2.1.0 is licensed GPL-3.0-only, which the organisation's licence policy forbids (Strong copyleft).";
    expect(
      inlineBody({
        issueId: ISSUE,
        severity: 'high',
        quality: 'licensing',
        ruleKey: 'license:forbidden',
        message,
        url: 'https://q.example/i',
      }),
    ).toMatchInlineSnapshot(`
      "<!-- qualor:issue 01920000-0000-7000-8000-000000000001 -->
      **High** · licensing · \` license:forbidden \`

      gpl-pkg \` 2.1.0 \` is licensed \` GPL-3.0-only \`, which the organisation's licence policy forbids (Strong copyleft).

      [View in Qualor](https://q.example/i)"
    `);
    const body = summary({
      topIssues: [
        {
          id: ISSUE,
          severity: 'high',
          quality: 'licensing',
          ruleKey: 'license:forbidden',
          path: 'web/package-lock.json',
          line: 21,
          message,
          url: null,
        },
      ],
      topIssuesTotal: 1,
    });
    expect(body.split('\n').filter((l) => l.includes('license:forbidden') || l.includes('gpl-pkg')))
      .toMatchInlineSnapshot(`
      [
        "1. 🔴 **High** · licensing · \` license:forbidden \` · \` web/package-lock.json:21 \`\\",
        "   gpl-pkg \` 2.1.0 \` is licensed \` GPL-3.0-only \`, which the organisation's licence policy forbids (Strong copyleft).",
      ]
    `);
  });

  it('stays within 16 KiB by listing fewer issues', () => {
    const many = Array.from({ length: 10 }, () => ({
      id: ISSUE,
      severity: 'high' as const,
      quality: 'security' as const,
      ruleKey: '界'.repeat(100),
      path: `src/${'界'.repeat(200)}`,
      line: 1,
      message: '😀'.repeat(300),
      url: null,
    }));
    const body = summary({ topIssues: many, topIssuesTotal: 500 });
    expect(Buffer.byteLength(body, 'utf8')).toBeLessThanOrEqual(SUMMARY_MAX_BYTES);
    const listed = body.split('\n').filter((l) => /^\d+\. /.test(l)).length;
    expect(listed).toBeGreaterThan(0);
    expect(listed).toBeLessThan(10);
    expect(body).toContain(`…and ${500 - listed} more`);
    expect(body.split('\n').at(-1)).toContain('Open in Qualor');
  });

  it('maps every gate status to a commit status with a catalog-only description', () => {
    expect(commitStatusFor(gate('passed'))).toEqual({
      state: 'success',
      description: 'Quality gate passed',
    });
    expect(commitStatusFor(gate('none'))).toEqual({
      state: 'success',
      description: 'No quality gate',
    });
    expect(commitStatusFor(gate('error')).state).toBe('failed');
    expect(commitStatusFor(failed)).toEqual({
      state: 'failed',
      description: 'Quality gate failed: new_issues 3 > 0',
    });
    const long = gate(
      'failed',
      Array.from({ length: 20 }, () => ({
        metric: 'new_duplicated_lines_density',
        operator: 'gt' as const,
        threshold: 3,
        value: 12.5,
        status: 'failed' as const,
      })),
    );
    expect(commitStatusFor(long).description).toHaveLength(255);
  });

  it('marks a medium-confidence finding of the C# taint engine Possible in the summary and the inline note (R-9)', () => {
    const body = summary({
      topIssues: [
        {
          id: ISSUE,
          severity: 'high',
          quality: 'security',
          ruleKey: 'qualor:csharp/sql-injection',
          path: 'src/A.cs',
          line: 4,
          message: 'csharp.sql-injection: request data reaches the sql-injection sink',
          url: null,
          confidence: 'medium',
        },
        {
          id: ISSUE,
          severity: 'high',
          quality: 'security',
          ruleKey: 'qualor:csharp/sql-injection',
          path: 'src/A.cs',
          line: 9,
          message: 'csharp.sql-injection: request data reaches the sql-injection sink',
          url: null,
          confidence: 'high',
        },
      ],
      topIssuesTotal: 2,
    });
    const items = body.split('\n').filter((l) => /^\d+\. /.test(l));
    expect(items[0]).toContain('**High** · security · Possible · ');
    expect(items[1]).not.toContain('Possible');
    expect(
      inlineBody({
        issueId: ISSUE,
        severity: 'high',
        quality: 'security',
        ruleKey: 'qualor:csharp/xss',
        message: 'm',
        url: null,
        confidence: 'medium',
      }).split('\n')[1],
    ).toBe('**High** · security · Possible · ` qualor:csharp/xss `');
  });

  it('writes the inline note with the rule key and message in code spans', () => {
    expect(
      inlineBody({
        issueId: ISSUE,
        severity: 'medium',
        quality: 'maintainability',
        ruleKey: 'eslint:no-console',
        message: 'Unexpected console statement.',
        url: 'https://q.example/i',
      }),
    ).toBe(
      [
        `<!-- qualor:issue ${ISSUE} -->`,
        '**Medium** · maintainability · ` eslint:no-console `',
        '',
        'Unexpected console statement.',
        '',
        '[View in Qualor](https://q.example/i)',
      ].join('\n'),
    );
    expect(mergeRequestTitle('  Fix\u0000 it\n now ')).toBe('Fix  it  now');
  });
});

/**
 * The adversarial corpus (scm.md §6). Each entry is put into every slot a report or a user can
 * fill (issue message, path, rule key, gate name), and every rendered body must keep the
 * guarantee:
 * - no line starts (after any whitespace) with `/`, so GitLab runs no quick action;
 * - outside code spans only Qualor's fixed text is left: after removing the code spans, the
 *   marker line and Qualor's own links, a line holds nothing but letters, digits and a small set
 *   of punctuation, so no mention, reference, HTML, image, link, autolink or emoji can appear;
 * - no control, line separator, bidirectional control, invisible character or blank filler
 *   anywhere, even inside a code span;
 * - summaries stay within 16 KiB and inline notes within 4 KiB, cut only at whole lines.
 */
const CORPUS: readonly (readonly [string, string])[] = [
  ['backtick', '`'],
  ['backtick runs longer than any fence', '`'.repeat(1_000)],
  ['mixed backtick runs', 'a ` b `` c ``` d ```` e'],
  ['value that starts and ends with backticks', '``/merge``'],
  ['newline quick action', 'x\n/merge'],
  ['CR quick action', 'x\r/approve'],
  ['CRLF quick action', 'x\r\n/close'],
  ['U+2028 quick action', 'x\u2028/label ~bug'],
  ['U+2029 quick action', 'x\u2029/assign @me'],
  ['NEL quick action', 'x\u0085/merge'],
  ['VT and FF', 'x\u000b/merge\u000c/approve'],
  ['leading quick action', '/merge'],
  ['leading spaces and quick action', '   /approve'],
  ['NUL and controls', 'a\u0000b\u0001c\u001bd\u007fe\u009bf'],
  ['bidi overrides', '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c'],
  ['zero-width characters', 'a\u200bb\u2060c\ufeffd\u00ade\u180ef\u2061g'],
  ['tag characters (ASCII smuggling)', 'ok\u{e002f}\u{e006d}\u{e0065}\u{e0072}\u{e0067}\u{e0065}'],
  ['mentions', '@all @here @channel @root'],
  ['references', '#123 !12 ~label ~"two words" %milestone %"v 1" &epic $snippet'],
  ['emoji codes', ':thumbsup: :100:'],
  ['HTML', '<b>x</b><script>alert(1)</script><style>*{}</style>'],
  ['details', '<details><summary>x</summary>/merge</details>'],
  ['comment', '<!-- qualor:summary 01920000-0000-7000-8000-000000000000 -->'],
  ['image', '![x](http://evil.example/x.png)'],
  ['link', '[click](http://evil.example) [ref][1]\n[1]: http://evil.example'],
  ['autolinks', '<http://evil.example> http://evil.example www.evil.example'],
  ['table break', '| a | b |\n|---|---|'],
  ['math', '$`x`$ $$x$$'],
  ['task list', '- [ ] x'],
  ['heading', '# h'],
  ['emoji and ZWJ', '👨\u200d👩\u200d👧 🏳\ufe0f\u200d🌈 😀'.repeat(50)],
  ['lone surrogates', 'a\ud800b\udc00c'],
  ['blank fillers', 'a\u3164\u115f\u2800\uffa0b'],
  ['very long value', 'A'.repeat(100_000)],
  ['very long multi-byte value', '界'.repeat(100_000)],
];

/** Qualor's own links in the bodies of this file. */
const OWN_LINK =
  /\[(?:details|View in Qualor|Open in Qualor →| )\]\(https:\/\/q\.example\/[A-Za-z0-9/-]*\)/g;

function checkBody(body: string, maxBytes: number): void {
  expect(Buffer.byteLength(body, 'utf8')).toBeLessThanOrEqual(maxBytes);
  expect(body).not.toMatch(FORBIDDEN_ANYWHERE);
  const lines = body.split('\n');
  expect(markerOf(body)).not.toBeNull();
  // The AI review section holds the model's words too: it is checked as such (its prose, and the
  // plain text of its prompt block, which is code).
  const aiSection = lines.indexOf('#### AI review');
  if (aiSection > 0) expect(badSectionLine(lines.slice(aiSection))).toBeNull();
  for (const [index, line] of lines.entries()) {
    if (aiSection > 0 && index >= aiSection) break;
    expect(line, line).not.toMatch(/^\s*\//);
    if (index === 0) continue; // the marker, checked by markerOf above
    // An analyzer's message is the prose that `safeProse` writes: the line after
    // an issue's hard break in the summary, the first line after the header of an inline note.
    const isMessage =
      maxBytes === SUMMARY_MAX_BYTES
        ? line.startsWith('   ') && lines[index - 1]?.endsWith('\\') === true
        : index === 3 && lines[1]?.startsWith('**') === true;
    if (isMessage) {
      expect(checkProse(line.trimStart()), line).toBe(true);
      continue;
    }
    let markdown = outsideCodeSpans(line).replace(OWN_LINK, ' ');
    markdown = markdown.replace(/^#{3,4} /, ''); // the fixed headings
    expect(markdown, line).toMatch(
      maxBytes === SUMMARY_MAX_BYTES ? SUMMARY_FIXED_TEXT : FIXED_TEXT,
    );
    // `<` and `>` only as the comparison of a condition, never an HTML tag or autolink.
    expect(markdown, line).not.toMatch(/<\S/);
  }
}

describe('the note of a fixed issue in a thread a person replied in', () => {
  const SHA = 'abcdef0123456789abcdef0123456789abcdef01';
  const OTHER_ISSUE = '01920000-0000-7000-8000-000000000002';

  it('is its marker, with the issue and the full revision, then a sentence with the commit', () => {
    expect(fixedNote(ISSUE, SHA).split('\n')).toEqual([
      `<!-- qualor:fixed ${ISSUE} ${SHA} -->`,
      'Fixed in ` abcdef0 `. Qualor leaves this thread open because someone replied in it.',
    ]);
    // A SHA-256 revision is a full one too.
    const long = 'a'.repeat(64);
    expect(fixedMarker(ISSUE, long)).toBe(`<!-- qualor:fixed ${ISSUE} ${long} -->`);
    // Nothing but an issue's id and a full revision goes in it.
    for (const bad of ['', 'abcdef0', 'A'.repeat(40), 'g'.repeat(40), 'a'.repeat(41), `${SHA} x`]) {
      expect(() => fixedMarker(ISSUE, bad), bad).toThrow();
    }
    expect(() => fixedMarker('x -->\n/merge', SHA)).toThrow();
    // Its text is Qualor's own: fixed words, and the commit in a code span.
    const [, sentence = ''] = fixedNote(ISSUE, SHA).split('\n');
    expect(outsideCodeSpans(sentence)).toMatch(FIXED_TEXT);
    expect(sentence).not.toMatch(/^\s*\//);
  });

  it('is known by its marker as Qualor’s note of a fixed issue: never a thread, never the summary', () => {
    const body = fixedNote(ISSUE, SHA);
    expect(markerOf(body)).toEqual({ kind: 'fixed', issueId: ISSUE, sha: SHA });
    expect(markerOf(`${fixedMarker(ISSUE, SHA)}\r\nFixed`)).toEqual({
      kind: 'fixed',
      issueId: ISSUE,
      sha: SHA,
    });
    // On the first line only, and only as Qualor writes it.
    for (const other of [
      `Thanks\n${body}`,
      `<!-- qualor:fixed ${ISSUE} ${SHA.toUpperCase()} -->`,
      `<!-- qualor:fixed ${ISSUE} -->`,
      `<!-- qualor:fixed ${ISSUE} ${SHA} --> and more`,
      `<!-- qualor:fixed not-a-uuid ${SHA} -->`,
    ]) {
      expect(markerOf(other), other).toBeNull();
    }
    // What a thread's notes say of its issue's fixes: the revisions of its own notes, for that issue.
    const notes = [
      issueMarker(ISSUE),
      body,
      fixedNote(ISSUE, 'b'.repeat(40)),
      fixedNote(OTHER_ISSUE, 'c'.repeat(40)),
      `A person quoting it:\n${body}`,
    ];
    expect(notedFixes(notes, ISSUE)).toEqual(new Set([SHA, 'b'.repeat(40)]));
    expect(notedFixes(notes, OTHER_ISSUE)).toEqual(new Set(['c'.repeat(40)]));
  });
});

describe('commit status name (scm.md §5.1, ruling G4)', () => {
  it('names the Qualor project, so the projects of a monorepo keep their own status', () => {
    expect(statusName('payments/api')).toBe('qualor/payments/api');
    expect(statusName('acme:web-1.2_x')).toBe('qualor/acme:web-1.2_x');
    expect(statusName('a')).not.toBe(statusName('b'));
  });

  it('keeps only the characters a project key may hold', () => {
    expect(statusName('a b\u0000c\n/merge @all')).toBe('qualor/a-b-c-/merge--all');
  });

  it(`is at most ${STATUS_NAME_MAX_CHARS} characters, and two long keys never share one`, () => {
    const long = 'k'.repeat(255);
    const other = `${'k'.repeat(254)}x`;
    expect(statusName(long)).toHaveLength(STATUS_NAME_MAX_CHARS);
    expect(statusName(long)).toMatch(/^qualor\/k+~[0-9a-f]{12}$/);
    expect(statusName(other)).toHaveLength(STATUS_NAME_MAX_CHARS);
    expect(statusName(other)).not.toBe(statusName(long));
    expect(statusName('k'.repeat(248))).toBe(`qualor/${'k'.repeat(248)}`);
    expect(statusName('k'.repeat(249))).toHaveLength(STATUS_NAME_MAX_CHARS);
  });
});

describe('adversarial corpus (scm.md §6)', () => {
  it.each(CORPUS)('keeps %s inert in every slot of every body', (_name, value) => {
    const issue = {
      id: ISSUE,
      severity: 'high' as const,
      quality: 'security' as const,
      ruleKey: value,
      path: value,
      line: 7,
      message: value,
      url: `https://q.example/projects/${PROJECT}/issues/${ISSUE}`,
    };
    const hostileGate: GateResult = { ...failed, gate: { id: 'g1', name: value } };
    checkBody(
      summary({
        gate: hostileGate,
        topIssues: Array.from({ length: 10 }, () => issue),
        topIssuesTotal: 10,
      }),
      SUMMARY_MAX_BYTES,
    );
    // The same value in every slot of the AI review section as well, within the section's bound.
    const withReview = summary({
      gate: hostileGate,
      topIssues: Array.from({ length: 10 }, () => issue),
      topIssuesTotal: 10,
      review: hostileReview(value),
    });
    checkBody(withReview, SUMMARY_MAX_BYTES);
    expect(
      Buffer.byteLength(withReview.slice(withReview.indexOf('#### AI review')), 'utf8'),
    ).toBeLessThanOrEqual(AI_SECTION_MAX_BYTES);
    checkBody(
      summary({
        review: hostileReview(value),
        vocabulary: 'github',
        mergeRequestHead: 'c'.repeat(40),
      }),
      SUMMARY_MAX_BYTES,
    );
    checkBody(
      inlineBody({
        issueId: ISSUE,
        severity: 'blocker',
        quality: 'security',
        ruleKey: value,
        message: value,
        url: `https://q.example/projects/${PROJECT}/issues/${ISSUE}`,
      }),
      INLINE_MAX_BYTES,
    );
    const title = mergeRequestTitle(value);
    expect(title).not.toMatch(FORBIDDEN_ANYWHERE);
    expect([...title].length).toBeLessThanOrEqual(255);
  });

  it('bounds a value by its kind, before the fence is chosen', () => {
    for (const [value, max] of [
      ['m'.repeat(1_000), 300],
      ['p'.repeat(1_000), 200],
      ['k'.repeat(1_000), 100],
    ] as const) {
      const span = codeSpan(value, max);
      expect([...span.slice(2, -2)].length).toBe(max);
    }
    // 1 000 backticks: cut to 100 first, so the fence is 101, not 1 001.
    expect(codeSpan('`'.repeat(1_000))).toBe(
      `${'`'.repeat(100)} ${'`'.repeat(99)}… ${'`'.repeat(100)}`,
    );
  });

  it('drops invisible characters and replaces controls, keeping emoji and ZWJ sequences whole', () => {
    expect(plainValue('a\u200bb\u2060c\ufeffd\u00ade', 100)).toBe('abcde');
    expect(plainValue('ok\u{e002f}\u{e006d}', 100)).toBe('ok');
    expect(plainValue('a\ud800b', 100)).toBe('a\ufffdb');
    expect(plainValue('a\u0000b\u0085c', 100)).toBe('a b c');
    const family = '👨\u200d👩\u200d👧';
    expect(plainValue(family, 100)).toBe(family);
    expect(plainValue('\u00e9'.normalize('NFD').repeat(3), 100)).toBe(
      '\u00e9'.normalize('NFD').repeat(3),
    );
    // A cut never ends inside a grapheme when a whole one fits.
    expect(plainValue(`${family}${family}`, 7)).toBe(`${family}…`);
    expect(plainValue(`e${'\u0301'.repeat(20)}x`, 5)).toHaveLength(5);
  });

  it('never cuts a body in the middle of a line (no half code span)', () => {
    const many = gate(
      'failed',
      Array.from({ length: 2_000 }, () => ({
        metric: 'new_duplicated_lines_density',
        operator: 'gt' as const,
        threshold: 3,
        value: 12.5,
        status: 'failed' as const,
      })),
    );
    const body = summary({ gate: { ...many, gate: { id: 'g', name: '`'.repeat(99) } } });
    checkBody(body, SUMMARY_MAX_BYTES);
    const lines = body.split('\n');
    // The table was shortened at a row's end: every row is whole.
    expect(lines.filter((l) => l.startsWith('| ❌ | Duplication')).length).toBeGreaterThan(10);
    for (const line of lines.filter((l) => l.startsWith('|'))) expect(line, line).toMatch(/\|$/);
    expect(lines.at(-1)).toMatch(/\|$/);
  });

  it("accepts the catalog's own names in the table, such as Won't fix issues", () => {
    const body = summary({
      gate: gate('failed', [
        { metric: 'accepted_issues', operator: 'gt', threshold: 0, value: 4, status: 'failed' },
      ]),
    });
    checkBody(body, SUMMARY_MAX_BYTES);
    expect(body).toContain("| ❌ | Won't fix issues | 4 | ≤ 0 |");
  });

  it('keeps table cells and the commit status free of report-controlled text', () => {
    const odd = gate('failed', [
      {
        metric: 'x` | @all | `y',
        operator: 'gt',
        threshold: 0,
        value: 1,
        status: 'failed',
      },
    ]);
    const body = summary({ gate: odd });
    checkBody(body, SUMMARY_MAX_BYTES);
    expect(body).not.toContain('@all |');
    expect(commitStatusFor(odd).description).toBe('Quality gate failed: unknown metric 1 > 0');
  });

  it('builds links only from an http(s) Qualor URL without Markdown-breaking characters', () => {
    const body = summary({
      branchUrl: 'javascript:alert(1)',
      topIssues: [
        {
          id: ISSUE,
          severity: 'low',
          quality: 'security',
          ruleKey: 'k',
          path: null,
          line: null,
          message: 'm',
          url: 'https://q.example/x) [evil](http://evil.example',
        },
      ],
      topIssuesTotal: 1,
    });
    expect(body).not.toContain('javascript:');
    expect(body).not.toContain('](http://evil');
    expect(outsideCodeSpans(body)).not.toContain('[evil]');
  });

  it('keeps the brackets of an IPv6 host in a link, and encodes them only after the host', () => {
    expect(qualorLink('open', 'http://[::1]:8080/projects/p?x=(1)')).toBe(
      '[open](http://[::1]:8080/projects/p?x=%281%29)',
    );
    expect(qualorLink('open', 'https://[2001:db8::5]/a[b]')).toBe(
      '[open](https://[2001:db8::5]/a%5Bb%5D)',
    );
    expect(qualorLink('open', 'https://q.example/x) [evil](http://e')).toBe(
      '[open](https://q.example/x%29%20%5Bevil%5D%28http://e)',
    );
    // A host name with a character that could end the destination is refused, not encoded.
    expect(qualorLink('open', 'http://a(b).example/x')).toBeNull();
    expect(qualorLink('open', "http://a'b.example/x")).toBeNull();
  });

  it('uses the shared comment safety of packages/shared, one implementation for CLI and server', () => {
    for (const value of ['a\u3164b\u2800c', '`x`', 'line\nbreak', '\u202eevil', '😀😀😀']) {
      expect(plainValue(value, 2)).toBe(safePlainValue(value, 2));
      expect(codeSpan(value)).toBe(safeCodeSpan(value, 100));
      expect(codeSpan(value, 300)).toBe(safeCodeSpan(value, 300));
    }
  });

  it('fails closed on a gate status it does not know', () => {
    const odd = { ...gate('passed'), status: 'weird' } as unknown as GateResult;
    expect(commitStatusFor(odd)).toEqual({
      state: 'failed',
      description: 'Quality gate status unknown',
    });
  });

  it('refuses a marker for anything but a UUID, and reads a marker with a CRLF line end', () => {
    expect(() => summaryMarker('x -->\n/merge')).toThrow();
    expect(markerOf(`${summaryMarker(PROJECT)}\r\nbody`)).toEqual({
      kind: 'summary',
      projectId: PROJECT,
    });
  });
});

describe('rule documentation links in comments', () => {
  const DOCS = 'https://eslint.org/docs/latest/rules/no-console';
  const QUALOR_DOCS =
    'https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/go/sql-injection.md';
  const inline = (ruleKey: string, helpUri: string | null) =>
    inlineBody({
      issueId: ISSUE,
      severity: 'high',
      quality: 'security',
      ruleKey,
      helpUri,
      message: 'm',
      url: null,
    });

  it('links the rule key of the inline note, keeping its code span', () => {
    expect(inline('qualor:go/sql-injection', QUALOR_DOCS).split('\n')[1]).toBe(
      `**High** · security · [\` qualor:go/sql-injection \`](${QUALOR_DOCS})`,
    );
    const html = marked.parse(inline('eslint:no-console', DOCS), { async: false });
    expect(html).toContain(`<a href="${DOCS}"><code>eslint:no-console</code></a>`);
    // Without a link the note is what it always was.
    expect(inline('eslint:no-console', null).split('\n')[1]).toBe(
      '**High** · security · ` eslint:no-console `',
    );
  });

  it('links the rule key of each issue of the summary', () => {
    const body = summary({
      topIssues: [
        {
          id: ISSUE,
          severity: 'medium',
          quality: 'maintainability',
          ruleKey: 'eslint:no-console',
          helpUri: DOCS,
          path: null,
          line: null,
          message: 'plain',
          url: null,
        },
      ],
      topIssuesTotal: 1,
    });
    expect(body).toContain(
      `1. 🟠 **Medium** · maintainability · [\` eslint:no-console \`](${DOCS})\\\n   plain`,
    );
    const html = marked.parse(body, { async: false, gfm: true, breaks: false });
    expect(html).toContain(`<a href="${DOCS}"><code>eslint:no-console</code></a><br>`);
  });

  it('shows only an https link without credentials, spaces or controls, of bounded length', () => {
    for (const helpUri of [
      'http://eslint.org/x',
      'javascript:alert(1)',
      'data:text/html,x',
      '//eslint.org/x',
      '/rules/x',
      'not a url',
      'https://u:p@eslint.org/x',
      'https://eslint.org/a\nb',
      'https://eslint.org/a b',
      'https://eslint.org/‮x',
      'https://eslint.org/​x',
      `https://eslint.org/${'x'.repeat(MAX_RULE_LINK_CHARS)}`,
      '',
      null,
      undefined,
    ]) {
      expect(ruleDocUrl(helpUri), String(helpUri)).toBeNull();
      expect(ruleKeyMarkdown('eslint:no-console', helpUri)).toBe('` eslint:no-console `');
    }
    expect(ruleDocUrl(DOCS)).toBe(DOCS);
    // Within the bound as given, beyond it once encoded: the plain key.
    const parens = `https://eslint.org/${'('.repeat(200)}`;
    expect(ruleDocUrl(parens)).toBe(parens);
    expect(ruleKeyMarkdown('k', parens)).toBe('` k `');
  });

  it('never links a key that could unbalance the link text', () => {
    for (const key of ['a]b', 'a[b', 'a`b', 'a\\b']) {
      expect(ruleKeyMarkdown(key, DOCS)).toBe(codeSpan(key));
    }
  });

  it('encodes what could end the destination, so the link goes nowhere else', () => {
    const md = ruleKeyMarkdown('k', 'https://docs.example/x)[evil](http://evil.example');
    expect(md).toBe('[` k `](https://docs.example/x%29%5Bevil%5D%28http://evil.example)');
    const html = marked.parse(md, { async: false });
    expect(html.match(/<a /g)).toHaveLength(1);
    expect(html).toContain('href="https://docs.example/x%29%5Bevil%5D%28http://evil.example"');
  });

  it.each(CORPUS)('keeps a hostile %s inert as a key and in a link', (_name, value) => {
    // Without spaces too, so more of the corpus gets as far as a link.
    const helpUri = `https://docs.example/${value.replace(/\s/g, '')}`;
    const bodies = [
      inline(value, helpUri),
      inline('eslint:no-console', helpUri),
      summary({
        topIssues: Array.from({ length: 10 }, () => ({
          id: ISSUE,
          severity: 'high' as const,
          quality: 'security' as const,
          ruleKey: value,
          helpUri,
          path: value,
          line: 7,
          message: value,
          url: `https://q.example/projects/${PROJECT}/issues/${ISSUE}`,
        })),
        topIssuesTotal: 10,
      }),
    ];
    for (const [index, body] of bodies.entries()) {
      const max = index < 2 ? INLINE_MAX_BYTES : SUMMARY_MAX_BYTES;
      expect(Buffer.byteLength(body, 'utf8')).toBeLessThanOrEqual(max);
      expect(body).not.toMatch(FORBIDDEN_ANYWHERE);
      for (const line of body.split('\n')) expect(line, line).not.toMatch(/^\s*\//);
      const html = marked.parse(body, { async: false, gfm: true, breaks: false });
      for (const [, href] of html.matchAll(/<a [^>]*href="([^"]*)"/g)) {
        expect(href, href).toMatch(/^https:\/\/(docs|q)\.example\//);
      }
      expect(html).not.toMatch(/<(img|script|style|details)\b/);
    }
  });

  it('writes the same body for the same issues, so an unchanged summary is never edited', () => {
    const input = {
      topIssues: [
        {
          id: ISSUE,
          severity: 'high' as const,
          quality: 'security' as const,
          ruleKey: 'qualor:go/sql-injection',
          helpUri: QUALOR_DOCS,
          path: 'a.go',
          line: 3,
          message: 'm',
          url: null,
        },
      ],
      topIssuesTotal: 1,
    };
    expect(summary(input)).toBe(summary(structuredClone(input)));
  });
});

/**
 * What GitLab and GitHub turn into a link, a mention, a reference or a quick action when it is
 * not in a code span, for the check of `safeProse`'s output against the ordinary reading of it
 * (rather than against the charset alone).
 */
const REFERENCES: readonly (readonly [string, RegExp])[] = [
  ['a sigil of Markdown, a reference or a mention', /[@#~%&$<>[\]*_|=+\\/{}^`]/],
  ['a bang with a number', /!\d/],
  ['an emoji code', /:[\p{L}\p{N}_+-]+:/u],
  // A hash is a word of its own to a provider unless a letter or a decimal digit touches it:
  // GitHub links it beside a circled digit (①), GitLab beside ², ½ and ① as well.
  ['a commit hash', /(?<![\p{L}\p{Nd}])[0-9a-f]{7,64}(?![\p{L}\p{Nd}])/iu],
  // A part of a word that holds a letter and is followed by a hyphen and a digit. What comes before
  // the key in its part does not matter: a provider ends a key at any character that is no ASCII
  // letter or digit, so a digit or a letter of another script before `GH-1` ends nothing.
  ['a tracker key', /\p{L}[\p{L}\p{Nd}\p{M}]*-\p{Nd}/u],
  // GitHub links `www.` wherever it follows a space, a bracket or `*`, `_` or `~`, whatever follows
  // it (a space, a closing mark): `www. x`, `(www. x`, `www.) x`, `www.… x`.
  ['a www address', /(?:^|[\s(*_~])www\./iu],
  // What Azure DevOps's renderer adds (probe item 21): math, task lists, headings, a mention by id
  // and the HTML of a collapsible block.
  ['math', /\$[^$\s]/],
  ['a task list item', /^\s*[-*]\s+\[[ x]\]/i],
  ['a heading', /^#{1,6}\s/],
  ['a mention by id', /@<?[0-9a-f]{8}-/i],
  ['a KaTeX block delimiter', /\$\$/],
  ['a details block', /<details/i],
];

/** What the model's text may be made of, for the corpus and the fuzz of `safeProse`. */
const PROSE_OPTIONS = { maxChars: 20_000, maxLines: 200 } as const;
const prose = (text: string, options: { maxChars?: number; maxLines?: number } = {}): string =>
  safeProse(text, { ...PROSE_OPTIONS, ...options });

/**
 * A line of prose starts with a letter, a digit, a backtick, an opening mark, a dash by itself or
 * the list marker.
 */
const PROSE_LINE_START = /^(?:[\p{L}\p{Nd}`("“‘—–]|- )/u;

/**
 * Everything `safeProse` promises of its output: it is inert in GitLab and GitHub, whatever
 * the text was.
 */
function expectInertProse(out: string, label: string): void {
  expect(out, label).not.toMatch(FORBIDDEN_ANYWHERE);
  expect(markerOf(out), label).toBeNull();
  for (const line of out.split('\n')) {
    const where = `${label} → ${JSON.stringify(line)}`;
    expect(line, where).not.toMatch(/^\s*\//);
    expect(checkProse(line), where).toBe(true);
    if (line !== '') expect(line, where).toMatch(PROSE_LINE_START);
    // The one mark that joins two spans of a word is left out with them: it stands between two
    // `<code>` elements and is no text a provider reads for a link (see the marked check below).
    const outside = outsideProseSpans(line);
    for (const [name, pattern] of REFERENCES)
      expect(outside, `${where}: ${name}`).not.toMatch(pattern);
  }
  const html = marked.parse(out, { async: false, gfm: true, breaks: false });
  expect(html, label).not.toMatch(
    /<(?:a|img|script|style|details|summary|h[1-6]|blockquote|table|hr|pre|iframe|input|br)\b/,
  );
}

describe('safeProse: the model’s words made inert', () => {
  const cp = (...codePoints: number[]): string => String.fromCodePoint(...codePoints);
  /**
   * A tracker key (`GH-1`, `AB1-123`) after characters that are no ASCII letter or digit, named by
   * code point. GitHub links `GH-1` wherever the character before the G is none, and GitLab's Jira
   * pattern ends a key at the same characters.
   */
  const KEYS_AFTER_OTHER_CHARACTERS: readonly string[] = [
    `${cp(0x663)}GH-1`, // ARABIC-INDIC DIGIT THREE
    `${cp(0x663)}gh-1`,
    `${cp(0xff10)}GH-1`, // FULLWIDTH DIGIT ZERO
    `${cp(0x1d7ce)}GH-1`, // MATHEMATICAL BOLD DIGIT ZERO
    `${cp(0x967)}GH-1`, // DEVANAGARI DIGIT ONE
    `9${cp(0x663)}GH-1`,
    `9${cp(0xe9)}GH-1`, // LATIN SMALL LETTER E WITH ACUTE
    `9${cp(0x4e2d)}GH-1`, // a Han character
    `9${cp(0xaa)}GH-1`, // FEMININE ORDINAL INDICATOR, a letter
    `9${cp(0x207f)}GH-1`, // SUPERSCRIPT LATIN SMALL LETTER N, a letter
    `x${cp(0x2019)}${cp(0x663)}GH-1`, // after an apostrophe
    `${cp(0x663)}GH-1.`,
    `(${cp(0x663)}GH-1)`,
    `${cp(0x663)}GH-1${cp(0x2019)}s`,
    `${cp(0x663)}AB1-123`,
  ];

  it('plain words stay plain and list markers are normalised', () => {
    const same = [
      "Don't call it twice; it's slow-ish (see below).",
      '"Quoted" and “curly” words, done!',
      'Café déjà vu naïve 界面 and ß',
      'Line 42 of 7: why? Because.',
      '1) a parenthesis marker stays a word',
    ];
    for (const text of same) expect(prose(text), text).toBe(text);
    expect(prose('* one\n- two\n3. three\n10. ten')).toBe('- one\n- two\n3. three\n10. ten');
    expect(prose('   *   spaced   out  \n\t- tabbed')).toBe('- spaced out\n- tabbed');
    // A marker with nothing after it is no marker: it is not a word either.
    expect(prose('-')).toBe('` - `');
    expect(prose('* ')).toBe('` * `');
    expect(prose('1.')).toBe('1.');
    expect(prose('**bold** and __under__')).toBe('` **bold** ` and ` __under__ `');
    expect(prose('- - nested')).toBe('- ` - ` nested');
    // Only the three markers: a plus is a word like any other.
    expect(prose('+ plus')).toBe('` + ` plus');
    expect(prose('1) one')).toBe('1) one');
    // More than nine digits is no list marker (CommonMark's own bound), only a number, whose full
    // stop is the sentence's.
    expect(prose('1234567890. text')).toBe('` 1234567890 `. text');
  });

  it('puts every other word in a code span', () => {
    expect(prose('Call foo() or a_b, e.g. C++ at 10% or x=1.')).toBe(
      'Call ` foo() ` or ` a_b `, ` e.g `. ` C++ ` at ` 10% ` or ` x=1 `.',
    );
    expect(prose('src/a.ts: it is v2.1 now')).toBe('` src/a.ts `: it is ` v2.1 ` now');
    // A word that ends the way a plain word does, but starts with what it may not: whole when what is
    // left once its marks are off is plain (`(x)`).
    expect(prose("'single' (nested(x)) ((x)")).toBe("` 'single' ` (` nested(x) `) ` ((x) `");
  });

  it('keeps the mark a word that is not plain opens with, and the marks it ends in, outside its span', () => {
    expect(prose('See src/orders/discounts.js.')).toBe('See ` src/orders/discounts.js `.');
    expect(prose('(see x.y)')).toBe('(see ` x.y `)');
    expect(prose('(x.y) “a.b” ‘c.d’, "e.f"; g.h… i.j?!')).toBe(
      '(` x.y `) “` a.b `” ‘` c.d `’, "` e.f `"; ` g.h `… ` i.j `?!',
    );
    // A bracket or a quote that pairs with one inside the word is the code's: it stays in the span.
    expect(prose('Call foo() or f(a). Set x="a" (f(a)) (a)b)')).toBe(
      'Call ` foo() ` or ` f(a) `. Set ` x="a" ` (` f(a) `) ` (a)b `)',
    );
    // A word of marks alone, or one that is plain once its marks are off, is the word as before:
    // `www.` stays whole in its span, which GitHub would link outside it.
    for (const word of ['…', '(', '()', '!?', '("', '.)', '“”']) {
      expect(prose(word), word).toBe(`\` ${word} \``);
    }
    expect(prose('www. (www. www.)')).toBe('` www. ` ` (www. ` ` www.) `');
    // What it takes out of the span is no more than a plain word may open with or end in.
    for (const text of ['See src/a.ts. (x.y) “a.b”, f(a).', '(GH-1) 1234567. x.y:', '((x.y))']) {
      expectInertProse(prose(text), text);
      expect(prose(prose(text)), text).toBe(prose(text));
    }
  });

  it('re-emits the model’s own backtick spans through codeSpan, as CommonMark reads them', () => {
    expect(prose('Call `foo()` now.')).toBe('Call ` foo() ` now.');
    expect(prose('use `two words` here')).toBe('use ` two words ` here');
    expect(prose('use ` padded ` and `` a ` b `` too')).toBe('use ` padded ` and `` a ` b `` too');
    // The mark that follows a span, and the one that opens before it, are part of the word.
    expect(prose('Returns `null`. Or (`undefined`), "`x`"; ok')).toBe(
      'Returns ` null `. Or (` undefined `), "` x `"; ok',
    );
    // A span that is cut off, or that letters come before, is an ordinary word: nothing is lost or
    // joined. Letters after it are a word's ending (below).
    expect(prose('`oops here')).toBe('`` `oops `` here');
    expect(prose('word`glued` and `a`b')).toBe('`` word`glued` `` and ` a `b');
    expect(prose('`` ` ``')).toBe('`` ` ``');
    expect(prose('` `')).toBe('` `');
  });

  it('a sentence ending in 。 or । keeps its last word plain', () => {
    expect(prose('Fix the bug。')).toBe('Fix the bug。');
    expect(prose('バグを直す。 次へ。')).toBe('バグを直す。 次へ。');
    expect(prose('यह ठीक है।')).toBe('यह ठीक है।');
    expect(prose('(done।)')).toBe('(done।)');
    // A mark of no sentence still puts the word in a span, and a hash before 。 is still a hash.
    expect(prose('a、b')).toBe('` a、b `');
    expect(prose('abc1234。')).toBe('` abc1234 `。');
    expectInertProse(prose('Fix the bug。 यह ठीक है।'), 'Fix the bug。 यह ठीक है।');
  });

  it('2–3 stays plain', () => {
    expect(prose('Lines 2–3 changed, see 10–12.')).toBe('Lines 2–3 changed, see 10–12.');
    expect(prose('(5–6)')).toBe('(5–6)');
    // A range of hashes and a dash with nothing after it are no number range; a dash joining a letter and a number is prose.
    expect(prose('1234567–1234890')).toBe('` 1234567–1234890 `');
    expect(prose('a–3')).toBe('a–3');
    expect(prose('2–')).toBe('` 2– `');
  });

  it('TRACKER_LIKE matches as before on the corpus, and a 20 000-character word takes under 20 ms', () => {
    const before = /\p{L}[^-'’]*-\p{Nd}/u;
    const corpus = [
      'GH-26',
      'JIRA-123',
      'AB1-123',
      'X9-1',
      '9GH-1',
      'CU-abc',
      'TICKET-abc',
      'bug-12',
      'task-3',
      'a-b-1',
      "it's-1",
      'it’s-1',
      'état-3',
      '9-1',
      '-1',
      'a-',
      'a-٣',
      '٣GH-1',
      'x’٣GH-1',
      '',
      'abc',
      'a'.repeat(300) + '-9',
      `${'9'.repeat(300)}-9`,
    ];
    // Words of a small alphabet, in every order up to six characters (a seeded walk through them).
    const alphabet = ['a', 'Z', '9', '٣', '-', "'", '’', 'é', '.', '\u0301'];
    let seed = 7;
    const next = (): number => (seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648);
    for (let i = 0; i < 4_000; i += 1) {
      let word = '';
      for (let length = next() % 7; length > 0; length -= 1) {
        word += alphabet[next() % alphabet.length];
      }
      corpus.push(word);
    }
    for (const word of corpus)
      expect(TRACKER_LIKE.test(word), JSON.stringify(word)).toBe(before.test(word));
    // The cases that matter match.
    for (const word of ['GH-26', 'JIRA-123', 'AB1-123', 'X9-1', '9GH-1'])
      expect(TRACKER_LIKE.test(word)).toBe(true);
    for (const word of ['CU-abc', 'TICKET-abc', '9-1', '-1'])
      expect(TRACKER_LIKE.test(word)).toBe(false);
    // A long word without a hyphen, or with hyphens that no digit follows, is read in linear time.
    for (const word of [
      'a'.repeat(20_000),
      `${'a'.repeat(10_000)}${'9'.repeat(10_000)}`,
      '9'.repeat(20_000),
      `${'a'.repeat(19_990)}-x`,
      'a-'.repeat(10_000),
    ]) {
      const started = performance.now();
      expect(TRACKER_LIKE.test(word)).toBe(false);
      expect(performance.now() - started).toBeLessThan(20);
    }
  });

  it('`try`/`catch` becomes two code spans with a plain slash', () => {
    expect(prose('`try`/`catch`')).toBe('` try `/` catch `');
    expect(prose('Use `try`/`catch` around it.')).toBe('Use ` try `/` catch ` around it.');
    // A GitLab or GitHub page shows two code elements and a slash, nothing else.
    expect(marked.parse(prose('`try`/`catch`'), { async: false, gfm: true })).toBe(
      '<p><code>try</code>/<code>catch</code></p>\n',
    );
  });

  it('joins spans by one of / , - + . : and as many spans as the word has, with its marks around', () => {
    expect(prose('`a`/`b`/`c`')).toBe('` a `/` b `/` c `');
    expect(prose('`a`,`b` `a`-`b` `a`+`b` `a`.`b` `a`:`b`')).toBe(
      '` a `,` b ` ` a `-` b ` ` a `+` b ` ` a `.` b ` ` a `:` b `',
    );
    expect(prose('`a`/`b`-`c`+`d`')).toBe('` a `/` b `-` c `+` d `');
    // The mark that opens before the first span and the ones that end after the last are the word's.
    expect(prose('(`a`,`b`) and "`x`-`y`", then `p`:`q`; ok `r`/`s`.')).toBe(
      '(` a `,` b `) and "` x `-` y `", then ` p `:` q `; ok ` r `/` s `.',
    );
    // A span may hold what a span holds, and a closer after a span is no join.
    expect(prose('`two words`/`b` and `c`. `d`')).toBe('` two words `/` b ` and ` c `. ` d `');
    expect(prose('`a` / `b`')).toBe('` a ` ` / ` ` b `');
  });

  it('keeps any other join of spans as one word in one code span, as before', () => {
    // Two marks together, a sigil, a letter or a digit between spans.
    for (const text of [
      '`a`//`b`',
      '`a`/,`b`',
      '`a`:-`b`',
      '`a`@`b`',
      '`a`#`b`',
      '`a`!`b`',
      '`a`?`b`',
      '`a`(`b`',
      '`a`)`b`',
      '`a`b`c`',
      '`a`1`b`',
      '`a`_`b`',
    ]) {
      expect(prose(text), text).toBe(`\`\` ${text} \`\``);
    }
    // A span joined to a plain word, or to an opener, or left open, is one word too.
    for (const text of ['`a`/b', 'a/`b`', '`a`/(`b`)', '`a`/`b', '`a`/`b`/c', '/`a`/`b`']) {
      expect(prose(text), text).toBe(`\`\` ${text} \`\``);
    }
  });

  it('keeps a word’s ending glued to the model’s span plain: letters, then closing marks', () => {
    expect(prose('It throws `CheckoutError`s.')).toBe('It throws ` CheckoutError `s.');
    expect(prose("`codes`'s default")).toBe("` codes `'s default");
    expect(prose('`codes`’s')).toBe('` codes `’s');
    // After joined spans too, with the marks that open before and end after them.
    for (const [text, out] of [
      ['`row`es `map`ed, `fetch`ing', '` row `es ` map `ed, ` fetch `ing'],
      ['`a`/`b`s.', '` a `/` b `s.'],
      ['(`x`s)', '(` x `s)'],
      ['`x`n’t', '` x `n’t'],
      ['`x`é.', '` x `é.'],
    ] as const) {
      expect(prose(text), text).toBe(out);
    }
    // Anything else glued on keeps the whole word in one span, as before: a mark that is no
    // closing one, a digit, a closing mark with more after it, a lone apostrophe, and an ending
    // the plain-word test would not let through alone (a hash, `www.`, a tracker key).
    for (const text of [
      '`x`.com',
      '`x`s.com',
      '`x`@y',
      '`x`#1',
      '`x`!1',
      '`x`(',
      '`x`2',
      '`x`s2',
      "`x`'",
      '`x`-y',
      '`x`deadbeef',
      '`x`www.com',
      '`x`GH-1',
      `\`x\`${String.fromCodePoint(0x301)}s`,
    ]) {
      expect(prose(text), text).toBe(`\`\` ${text} \`\``);
    }
    // Such a word is a word that is not plain: its closing marks are outside its span, and `www`,
    // which GitHub links with the full stop after it, stays in.
    expect(prose('`x`www.')).toBe('`` `x`www ``.');
    for (const text of [
      'It throws `CheckoutError`s.',
      "`codes`'s default",
      '`a`/`b`s.',
      '`x`www. `x`www',
    ]) {
      expectInertProse(prose(text), text);
      expect(prose(prose(text)), text).toBe(prose(text));
    }
  });

  it('writes a word of spans and marks the same again when it is given it again', () => {
    for (const text of [
      '`try`/`catch` and (`a`,`b`) with `x`-`y`.',
      '`a`//`b` `a`@`b` `a`/`b`/c',
      '`` a ` b ``/`c`',
    ]) {
      expect(prose(prose(text)), text).toBe(prose(text));
    }
  });

  it('puts a word that a provider would link or reference in a code span, whatever it looks like', () => {
    const text =
      'See deadbeef0 and 1234567. Also GH-26, JIRA-123 and x-JIRA-9, then v-1 or sha-256.';
    expect(prose(text)).toBe(
      'See ` deadbeef0 ` and ` 1234567 `. Also ` GH-26 `, ` JIRA-123 ` and ` x-JIRA-9 `, then ` v-1 ` or ` sha-256 `.',
    );
    // Six hex characters are an ordinary word, and so are hyphens between letters.
    expect(prose('a decade of well-known facade work')).toBe('a decade of well-known facade work');
    expect(prose('a seven-eight pair')).toBe('a seven-eight pair');
  });

  it('puts a tracker key in a code span whatever letters and digits it is made of', () => {
    // A part that holds a letter and is followed by a hyphen and a digit: the keys of Jira and
    // GitHub's `GH-` are all of that shape. What it leaves out is a number or a range.
    expect(prose('See AB1-123, X9-1, A1-2 and e2e-2 or Gh-7.')).toBe(
      'See ` AB1-123 `, ` X9-1 `, ` A1-2 ` and ` e2e-2 ` or ` Gh-7 `.',
    );
    expect(prose('about 5-10 or 2-way and well-known x-ray')).toBe(
      'about 5-10 or 2-way and well-known x-ray',
    );
    for (const key of [
      'AB1-123',
      'X9-1',
      'A1-2',
      'e2e-2',
      'Gh-7',
      'GH-26',
      'x-JIRA-9',
      'v-1',
      'sha-256',
      'UTF-8',
    ]) {
      expect(prose(key), key).toBe(`\` ${key} \``);
    }
    for (const word of [
      '5-10',
      '2-way',
      'well-known',
      'x-ray',
      'seven-eight',
      '1-2-3',
      'decade-old',
    ]) {
      expect(prose(word), word).toBe(word);
    }
  });

  it('puts a tracker key in a code span whatever stands before it in its part', () => {
    // A digit, or a letter of another script, before the key ends nothing for a provider: GitHub
    // links `GH-1` after an Arabic-Indic digit, an accented letter or a Han character. The rule is
    // the part (a letter, a hyphen, a digit), not what is before the letter: `9GH-1` and `2D-1`,
    // which no provider links, are in a code span too.
    // The bracket and the full stop around a key are a sentence's, outside its span.
    const marked = new Set([`${cp(0x663)}GH-1.`, `(${cp(0x663)}GH-1)`]);
    for (const word of [...KEYS_AFTER_OTHER_CHARACTERS, '9GH-1', '2D-1']) {
      if (!marked.has(word)) expect(prose(word), word).toBe(`\` ${word} \``);
    }
    expect(prose(`${cp(0x663)}GH-1.`)).toBe(`\` ${cp(0x663)}GH-1 \`.`);
    expect(prose(`(${cp(0x663)}GH-1)`)).toBe(`(\` ${cp(0x663)}GH-1 \`)`);
    expect(prose(`see ${cp(0x663)}GH-1 and 9${cp(0xe9)}GH-1 now`)).toBe(
      `see \` ${cp(0x663)}GH-1 \` and \` 9${cp(0xe9)}GH-1 \` now`,
    );
  });

  it('puts www. in a code span whatever follows it and however it is written', () => {
    // GitHub links `www.` wherever a space, a bracket, `*`, `_` or `~` comes before it, whatever
    // comes after (a space, a closing mark), so a word that is `www` and a full stop is not plain.
    expect(prose('www. example')).toBe('` www. ` example');
    expect(prose('(www. x')).toBe('` (www. ` x');
    expect(prose('www.) x')).toBe('` www.) ` x');
    expect(prose('www.: e www.! f www.” h www.… i')).toBe(
      '` www.: ` e ` www.! ` f ` www.” ` h ` www.… ` i',
    );
    expect(prose('WWW. y Www. z')).toBe('` WWW. ` y ` Www. ` z');
    // `www` by itself, or with a mark that is no full stop, is an ordinary word.
    expect(prose('www x www, y www… z')).toBe('www x www, y www… z');
    // A mark on the www does not make it another word to the check.
    const acute = String.fromCodePoint(0x301);
    expect(prose(`www${acute}. x`)).toBe(`\` www${acute}. \` x`);
  });

  it('puts a hash next to a character that is no letter or decimal digit in a code span', () => {
    // GitHub links 7fd1a60① (and GitLab 7fd1a60², 7fd1a60½): the circled digit, the superscript,
    // the fraction and the numeral are numbers but no decimal digits, so they are no plain core.
    expect(prose('7fd1a60① 7fd1a60b① 7fd1a60² 7fd1a60½ 7fd1a60Ⅷ')).toBe(
      '` 7fd1a60① ` ` 7fd1a60b① ` ` 7fd1a60² ` ` 7fd1a60½ ` ` 7fd1a60Ⅷ `',
    );
    expect(prose('Item ① and 2² then ½ and Ⅷ')).toBe('Item ` ① ` and ` 2² ` then ` ½ ` and ` Ⅷ `');
    // A hash with a combining mark is still a hash, and a letter of another script is a letter.
    const acute = String.fromCodePoint(0x301);
    expect(prose(`7fd1a60b${acute} x`)).toBe(`\` 7fd1a60b${acute} \` x`);
    expect(prose('x7fd1a60 7fd1a60x 7fd1a60é')).toBe('x7fd1a60 7fd1a60x 7fd1a60é');
    // A mark between a hash and the letters around it does not take the hash into a word: GitHub
    // reads it as one, GitLab may not, and the check does not.
    expect(prose(`7fd1a60b${acute}word x${acute}7fd1a60`)).toBe(
      `\` 7fd1a60b${acute}word \` \` x${acute}7fd1a60 \``,
    );
  });

  it('keeps what reads as ordinary text plain: combining marks, a dash by itself, the ellipsis', () => {
    const acute = String.fromCodePoint(0x301);
    const decomposed = `cafe${acute} au lait, nai${String.fromCodePoint(0x308)}ve.`;
    expect(prose(decomposed)).toBe(decomposed);
    const devanagari = 'नमस्ते दुनिया, यह एक परीक्षण है.';
    expect(prose(devanagari)).toBe(devanagari);
    // A mark after a digit, or one with nothing before it, is no part of a word.
    expect(prose(`5${acute} ${acute}x`)).toBe(`\` 5${acute} \` \` ${acute}x \``);
    // The dashes of running text, by themselves; a dash that joins two pieces is below.
    expect(prose('a — b – c')).toBe('a — b – c');
    expect(prose('— start')).toBe('— start');
    // A dash that joins two pieces keeps them plain, each checked on its own.
    expect(prose('a—b a–b')).toBe('a—b a–b');
    expect(prose('omits the last `page`—and all rows')).toBe(
      'omits the last ` page `—and all rows',
    );
    expect(prose('the last page—and all rows')).toBe('the last page—and all rows');
    expect(prose('2–3 x-1')).toBe(`2–3 ${prose('x-1')}`);
    // Whatever a provider links beside a dash is still in a span of its own.
    expect(prose('x—#1')).toBe('x—` #1 `');
    expect(prose('see—JIRA-12')).toBe('see—` JIRA-12 `');
    expect(prose('a—https://example.com/x')).toBe('a—` https://example.com/x `');
    expect(prose('a–`#1`')).toBe('a–` #1 `');
    expect(prose('wait… what… really?!')).toBe('wait… what… really?!');
    // An ellipsis closes a word, it does not make one.
    expect(prose('… x')).toBe('` … ` x');
  });

  it('has an oracle that sees what GitHub links and GitLab references', () => {
    const sees = (name: string, text: string): boolean =>
      REFERENCES.find(([n]) => n === name)![1].test(text);
    for (const text of ['see www. example', '(www. x', 'www.) x', '*www. x', 'www.… x', 'WWW. y']) {
      expect(sees('a www address', text), text).toBe(true);
    }
    for (const text of ['www x', 'www, y', 'awww. x', 'x-www. y']) {
      expect(sees('a www address', text), text).toBe(false);
    }
    for (const text of ['7fd1a60①', '7fd1a60½', 'x 7fd1a60. y', '7fd1a60b ']) {
      expect(sees('a commit hash', text), text).toBe(true);
    }
    // A combining mark is no letter or digit to it, so a hash beside one is a hash.
    const acute = String.fromCodePoint(0x301);
    for (const text of [`7fd1a60b${acute}word`, `x${acute}7fd1a60`]) {
      expect(sees('a commit hash', text), text).toBe(true);
    }
    for (const text of ['7fd1a60é', '7fd1a60x', 'x7fd1a60', '123456']) {
      expect(sees('a commit hash', text), text).toBe(false);
    }
    // A key is a letter, a hyphen and a digit in one part, whatever stands before the letter.
    for (const text of [
      'AB1-123',
      'X9-1',
      'x-JIRA-9',
      'GH-26',
      '9GH-1',
      '2D-1',
      ...KEYS_AFTER_OTHER_CHARACTERS,
    ]) {
      expect(sees('a tracker key', text), text).toBe(true);
    }
    for (const text of [
      '5-10',
      '2-way',
      'well-known',
      'x-ray',
      'seven-eight',
      '1-2-3',
      'decade-old',
    ]) {
      expect(sees('a tracker key', text), text).toBe(false);
    }
  });

  it('removes controls, bidirectional and invisible characters, and never joins what they split', () => {
    expect(prose('a\u202eb\u200bc\u2028d\u0000e\u00adf\u200dg\ufeffh\u{e0041}i')).toBe(
      'a b c d e f g h i',
    );
    expect(prose('x\u0085y\u000bz\u000cw\u061cv')).toBe('x y z w v');
    // White space of other kinds separates words as a space does.
    expect(prose('a\u00a0b\u2003c\u3000d\u2009e')).toBe('a b c d e');
    expect(prose('lone \ud800 and \udc00 halves')).toBe('lone ` \ufffd ` and ` \ufffd ` halves');
    // CR and CRLF end a line like LF does, and a line that follows is a line of its own.
    expect(prose('a\r\nb\rc\n/close')).toBe('a\nb\nc\n` /close `');
  });

  it('cuts the text to its bounds and collapses blank lines', () => {
    expect(prose('a\n\n\n\nb')).toBe('a\n\nb');
    expect(prose('\n\n  \na\n \n\n')).toBe('a');
    expect(prose('a\nb\nc', { maxLines: 2 })).toBe('a\nb');
    expect(prose('a\n\n\nb\nc', { maxLines: 3 })).toBe('a\n\nb');
    // The ellipsis of a cut closes a word like a full stop does.
    expect(prose('x'.repeat(50), { maxChars: 10 })).toBe(`${'x'.repeat(9)}…`);
    expect(prose('one two three four five', { maxChars: 12 })).toBe('one two thr…');
    expect(prose('hello wörld 😀😀😀', { maxChars: 14 })).toBe('hello wörld ` 😀 `…');
    for (const text of ['', '   ', '\n \n', '\u200b\u2028']) expect(prose(text), text).toBe('');
    expect(prose('text', { maxChars: 0 })).toBe('');
    expect(prose('text', { maxLines: 0 })).toBe('');
  });

  it('is its own result when it is given it again', () => {
    const texts = [
      'Call `foo()` now, e.g. with @user or #12.\n\n- one\n* two\n3. three\n/close',
      '`` a ` b `` and ` padded ` and `` `x` ``',
      '(`x`), "`y`"; (open `z',
      '```\ncode\n```\n~~~',
    ];
    for (const text of texts) expect(prose(prose(text)), text).toBe(prose(text));
  });

  it.each([
    ['a Markdown link', '[x](https://e.example)', '` [x](https://e.example) `'],
    ['a bare URL', 'https://e.example', '` https://e.example `'],
    ['a www address', 'www.e.example', '` www.e.example `'],
    ['a www link that ends a sentence', 'www. example', '` www. ` example'],
    ['a www link in brackets', '(www. x', '` (www. ` x'],
    ['a www link with a closing bracket', 'www.) x', '` www.) ` x'],
    ['a hash next to a circled digit', '7fd1a60①', '` 7fd1a60① `'],
    ['an image tag', '<img src=x onerror=y>', '` <img ` ` src=x ` ` onerror=y> `'],
    ['a details tag', '<details>', '` <details> `'],
    ['a mention', '@user', '` @user `'],
    ['a mention of a group path', '@group/sub', '` @group/sub `'],
    ['an issue reference', '#12', '` #12 `'],
    ['a merge request reference', '!12', '` !12 `'],
    ['a label', '~label', '` ~label `'],
    ['a milestone', '%milestone', '` %milestone `'],
    ['an epic', '&epic', '` &epic `'],
    ['a snippet', '$snippet', '` $snippet `'],
    ['a quick action line', '/close', '` /close `'],
    ['a quote', '> quote', '` > ` quote'],
    ['a heading', '# heading', '` # ` heading'],
    ['a table row', '| a | b |', '` | ` a ` | ` b ` | `'],
    ['a code fence', '```', '```` ``` ````'],
    ['a tilde fence', '~~~', '` ~~~ `'],
    ['a right-to-left override', 'x\u202ey', 'x y'],
    ['a zero width space', 'x\u200by', 'x y'],
    ['a line separator before a quick action', 'x\u2028/close', 'x ` /close `'],
    [
      'a forged summary marker',
      '<!-- qualor:summary x -->',
      '` <!-- ` ` qualor:summary ` x ` --> `',
    ],
  ] as const)('puts %s in a code span, or leaves it out', (_name, text, expected) => {
    expect(prose(text)).toBe(expected);
  });

  // The plan's corpus and more, each in every place a line of prose can hold it.
  const PROSE_CORPUS: readonly (readonly [string, string])[] = [
    ['a Markdown link', '[x](https://e.example)'],
    ['a bare URL', 'https://e.example'],
    ['a www address', 'www.e.example'],
    ['a www link that ends a sentence', 'www. example'],
    ['a www link in brackets', '(www. x'],
    ['a www link with a closing bracket', 'www.) x'],
    [
      'a www link with a colon, a bang, a curly quote and an ellipsis',
      'www.: e www.! f www.” h www.… i',
    ],
    ['a www link in capitals', 'WWW. y Www. z'],
    ['a hash next to a circled digit', '7fd1a60①'],
    ['a hash next to a superscript, a fraction and a numeral', '7fd1a60² 7fd1a60½ 7fd1a60Ⅷ'],
    ['a hash next to a combining mark', '7fd1a60b\u0301'],
    [
      'a hash split from the letters around it by combining marks',
      `7fd1a60b${String.fromCodePoint(0x301)}word x${String.fromCodePoint(0x301)}7fd1a60`,
    ],
    ['a tracker key with a digit in its first part', 'AB1-123 X9-1'],
    ['a tracker key after a digit of another script', `${cp(0x663)}GH-1`],
    ['a tracker key after a digit and an accented letter', `9${cp(0xe9)}GH-1`],
    [
      'a tracker key after an apostrophe and a digit of another script',
      `x${cp(0x2019)}${cp(0x663)}GH-1`,
    ],
    [
      'a tracker key with a digit in its first part, after a digit of another script',
      `${cp(0x663)}AB1-123`,
    ],
    ['an image tag with a handler', '<img src=x onerror=y>'],
    ['a details tag', '<details>'],
    ['a mention', '@user'],
    ['a mention of a group path', '@group/sub'],
    ['an issue reference', '#12'],
    ['a merge request reference', '!12'],
    ['a label', '~label'],
    ['a milestone', '%milestone'],
    ['an epic', '&epic'],
    ['a snippet', '$snippet'],
    ['a quick action', '/close'],
    ['a quote', '> quote'],
    ['a heading', '# heading'],
    ['a table row', '| a | b |'],
    ['a code fence', '```'],
    ['a tilde fence', '~~~'],
    ['a right-to-left override', 'x\u202ey'],
    ['a zero width space', 'x\u200by'],
    ['a line separator', 'x\u2028/close'],
    ['a forged summary marker', '<!-- qualor:summary x -->'],
    ['a forged issue marker', '<!-- qualor:issue 01920000-0000-7000-8000-00000000ffff -->'],
    ['a commit hash', 'deadbeef0123'],
    ['a tracker key', 'GH-26'],
    ['a Jira key', 'JIRA-123'],
    ['an emoji code', ':thumbsup:'],
    ['an email address', 'someone@example.com'],
    ['an HTML entity', '&lt;script&gt;'],
    ['a script', '<script>alert(1)</script>'],
    ['math', '$`x`$ $$x$$'],
    ['a task list', '- [ ] task'],
    ['a setext underline', '---'],
    ['an escaped bracket', '\\[x\\] end\\'],
    ['a reference link definition', '[1]: http://evil.example'],
    ['a mention in a span', '`@all` and `#1`'],
    ['spans joined by a slash', '`try`/`catch`'],
    [
      'spans joined by the marks that may join them',
      '(`a`,`b`) "`a`-`b`". `a`+`b` `a`.`b` `a`:`b`; `a`/`b`/`c`',
    ],
    ['spans joined by two marks', '`a`//`b` `a`/,`b` `a`:-`b` `a`..`b`'],
    [
      'spans joined by a mark that is active',
      '`a`@`b` `a`#`b` `a`!`b` `a`~`b` `a`%`b` `a`&`b` `a`$`b` `a`<`b` `a`>`b` `a`*`b` `a`_`b` `a`=`b` `a`|`b` `a`\\`b`',
    ],
    ['a span and a word joined by a slash', '`try`/catch try/`catch` `try`/@all'],
    ['spans joined by a slash, and a quick action', '`a`/`b`\n/close\n`a`/`b` /merge'],
    ['spans joined by a slash, and a forged marker', '`a`/`b`<!-- qualor:summary x -->`c`'],
    ['a bare backtick', '`'],
    ['backtick runs', '`'.repeat(500)],
    ['mixed backtick runs', 'a ` b `` c ``` d ```` e'],
    ['tag characters', 'ok\u{e002f}\u{e006d}\u{e0065}'],
    ['controls', 'a\u0000b\u0001c\u001bd\u007fe\u009bf'],
    [
      'bidirectional controls',
      '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c',
    ],
    ['joiners and fillers', 'a\u200db\u200cc\ufe0fd\u3164e\u2800f\u115fg'],
    ['lone surrogates', 'a\ud800b\udc00c'],
    ['a very long word', 'w'.repeat(5_000)],
    ['very many words', 'w '.repeat(5_000)],
  ];
  const PLACES: readonly (readonly [string, (v: string) => string])[] = [
    ['alone', (v) => v],
    ['mid-sentence', (v) => `Look at ${v} now.`],
    ['first on a line', (v) => `${v} comes first\nand a second line`],
    ['on a line of its own', (v) => `fine\n${v}\nfine`],
    ['in list items', (v) => `- ${v}\n* ${v}\n1. ${v}`],
    ['after indentation', (v) => `    ${v}\n\t${v}`],
    ['between blank lines', (v) => `a\n\n\n${v}\n\n\nb`],
    ['in a span of the model’s', (v) => `\`${v}\` and \`\`${v}\`\``],
  ];

  it.each(PROSE_CORPUS)(
    'keeps %s inert in every place a line of prose can hold it',
    (name, value) => {
      for (const [place, put] of PLACES) {
        expectInertProse(prose(put(value)), `${name} ${place}`);
      }
    },
  );

  it('keeps three thousand random mixes of hostile pieces inert, and the result stable', () => {
    const pieces = [
      ...PROSE_CORPUS.map(([, value]) => value).filter((value) => value.length < 200),
      'word',
      'Words',
      "it's",
      'well-known',
      'done.',
      '(open',
      'close)',
      '"q"',
      '“q”',
      'ok,',
      ' ',
      '  ',
      '\t',
      '\n',
      '\n\n',
      '\r\n',
      '\r',
      '\u2028',
      '\u202e',
      '\u200b',
      '`',
      '``',
      '- ',
      '* ',
      '1. ',
      '12.',
      '99999999999. ',
      'ab:cd',
      'x_y',
      '*b*',
      '\\',
      '&amp;',
      'é',
      '界',
      '`a`/`b`',
      '(`a`,`b`).',
      '`a`-`b`',
      '`a`+`b`',
      '`a`.`b`',
      '`a`:`b`',
      '`a`//`b`',
      '`a`@`b`',
      '/`b`',
      '—',
      '–',
    ];
    const next = seededRandom(20_261_024);
    for (let round = 0; round < 3_000; round += 1) {
      const length = 1 + Math.floor(next() * 30);
      let text = '';
      for (let i = 0; i < length; i += 1) {
        text += pieces[Math.floor(next() * pieces.length)]!;
        if (next() < 0.5) text += ' ';
      }
      const out = prose(text);
      expectInertProse(out, `round ${round}: ${JSON.stringify(text)}`);
      expect(prose(out), `round ${round}: ${JSON.stringify(text)}`).toBe(out);
    }
  });

  it('leaves a space where it takes a character out, so that it never joins what stood apart', () => {
    const key = ['sk-test-', '0123456789abcdef'].join('');
    for (const hidden of ['\u200b', '\u2060', '\ufeff', '\u200d', '\u0000', '\u202e', '\u00ad']) {
      const out = prose(`${key.slice(0, 8)}${hidden}${key.slice(8)}`);
      expect(out).not.toContain(key);
      expect(out.replaceAll(/[\s`]/g, '')).toBe(key);
    }
  });
});

describe('plainProse: the model’s words cleaned, for a block that renders nothing', () => {
  const plain = (text: string, options: { maxChars?: number; maxLines?: number } = {}): string =>
    plainProse(text, { ...PROSE_OPTIONS, ...options });

  it('writes each line as it is: no word is put in a code span, no list marker made over', () => {
    const text =
      'Call `foo()` with @user, #12 or x=1.\n* one\n1. two\n/close\n```\n`CheckoutError`s.';
    expect(plain(text)).toBe(text);
  });

  it('cleans as safeProse does: controls, bidirectional, invisible and joiner characters and other white space are spaces', () => {
    expect(plain('a\u202eb\u200bc\u2028d\u0000e\u00adf\u200dg\ufeffh\u{e0041}i')).toBe(
      'a b c d e f g h i',
    );
    expect(plain('x\u0085y\u000bz\u000cw\u061cv')).toBe('x y z w v');
    expect(plain('a\u00a0b\u2003c\u3000d\u2009e\tf')).toBe('a b c d e f');
    // CR and CRLF end a line like LF does; a line keeps no space at its ends.
    expect(plain('a\r\nb\rc\n  /close  ')).toBe('a\nb\nc\n/close');
    const key = ['sk-test-', '0123456789abcdef'].join('');
    expect(plain(`${key.slice(0, 8)}\u200b${key.slice(8)}`)).toBe(
      `${key.slice(0, 8)} ${key.slice(8)}`,
    );
  });

  it('cuts at a grapheme with an ellipsis, to at most maxLines lines, and makes repeated blank lines one', () => {
    expect(plain('a\n\n\n\nb')).toBe('a\n\nb');
    expect(plain('\n\n  \na\n \n\n')).toBe('a');
    expect(plain('a\nb\nc', { maxLines: 2 })).toBe('a\nb');
    expect(plain('a\n\n\nb\nc', { maxLines: 3 })).toBe('a\n\nb');
    expect(plain('x'.repeat(50), { maxChars: 10 })).toBe(`${'x'.repeat(9)}\u2026`);
    expect(plain('hello w\u00f6rld \ud83d\ude00\ud83d\ude00\ud83d\ude00', { maxChars: 14 })).toBe(
      'hello w\u00f6rld \ud83d\ude00\u2026',
    );
    for (const text of ['', '   ', '\n \n', '\u200b\u2028']) expect(plain(text), text).toBe('');
    expect(plain('text', { maxChars: 0 })).toBe('');
    expect(plain('text', { maxLines: 0 })).toBe('');
  });

  it('makes a lone surrogate U+FFFD, as safeProse’s code span does', () => {
    expect(plain('lone \ud800 and \udc00 halves, a\ud800b')).toBe(
      'lone \ufffd and \ufffd halves, a\ufffdb',
    );
  });

  it('keeps the lines safeProse keeps: the same cleaning and cutting, line for line', () => {
    for (const [name, value] of [
      ['a line separator before a quick action', 'x\u2028/close'],
      [
        'bidirectional controls',
        '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c',
      ],
      ['joiners and fillers', 'a\u200db\u200cc\ufe0fd\u3164e\u2800f\u115fg'],
      ['lone surrogates', 'a\ud800b\udc00c'],
      ['tag characters', 'ok\u{e002f}\u{e006d}\u{e0065}'],
      ['controls', 'a\u0000b\u0001c\u001bd\u007fe\u009bf'],
      ['blank lines and line ends', '\r\n\r\na\r\n\r\n\r\nb\rc\u2029d'],
      ['a long text', 'word '.repeat(300)],
      ['many lines', 'a\nb\n\n\nc\n'.repeat(40)],
    ] as const) {
      for (const options of [{}, { maxChars: 50 }, { maxLines: 3 }]) {
        const out = plain(value, options);
        expect(out, name).not.toMatch(FORBIDDEN_ANYWHERE);
        expect(out.split('\n').length, name).toBe(prose(value, options).split('\n').length);
      }
    }
  });
});

describe('the AI review section in the summary', () => {
  const ISSUE_URL = `https://q.example/projects/${PROJECT}/issues/${ISSUE}`;
  const REVIEWED = 'abcdef0123456789abcdef0123456789abcdef01';
  const REVIEW: Extract<ReviewSummaryState, { kind: 'done' }> = {
    kind: 'done',
    verdict:
      'The change adds refunds, but the retry path can charge a customer twice when the first call times out and is repeated.',
    walkthrough: Array.from(
      { length: 6 },
      (_, i) => `Walkthrough item number ${i + 1} describes one part of the change in some detail`,
    ),
    counts: { high: 2, medium: 3, low: 1 },
    unplaced: Array.from({ length: 6 }, (_, i) => ({
      severity: 'medium',
      path: `src/refunds/file${i + 1}.ts`,
      line: i + 10,
      title: `Problem number ${i + 1} sits where no changed line is`,
      url: ISSUE_URL,
    })),
    moreUnplaced: 2,
    reviewedSha: REVIEWED,
    mergeRequestHeadSha: null,
    tokenLimitReached: true,
    snapshotPartial: true,
    notes: ['reviewer_unreadable'],
    fixPrompt: Array.from({ length: 4 }, (_, i) => ({
      path: `src/refunds/file${i + 1}.ts`,
      line: i + 10,
      title: `Problem number ${i + 1} sits where no changed line is`,
      body: 'When the first call times out it is repeated with a new request id, so the provider may charge twice. Send the same idempotency key on every retry. '.repeat(
        2,
      ),
    })),
  };
  const sectionOf = (body: string): string => body.slice(body.indexOf('#### AI review'));
  /** The analyzers' issues the note lists: its numbered items before the AI section. */
  const listedIssues = (body: string): number => {
    const end = body.indexOf('#### AI review');
    const analyzers = end < 0 ? body : body.slice(0, end);
    return analyzers.split('\n').filter((line) => /^\d+\. /.test(line)).length;
  };
  const bytes = (text: string): number => Buffer.byteLength(text, 'utf8');
  /** Ten analyzer issues of the largest size, in the widest characters. */
  const bigIssues = Array.from({ length: 10 }, (_, i) => ({
    id: ISSUE,
    severity: 'high' as const,
    quality: 'security' as const,
    ruleKey: '界'.repeat(100),
    path: `src/${'界'.repeat(200)}`,
    line: i + 1,
    message: '😀'.repeat(300),
    url: null,
  }));

  it('comes last, after the analyzers’ part and behind a blank line', () => {
    const plain = summary();
    const body = summary({ review: REVIEW });
    const at = body.indexOf('\n\n#### AI review\n');
    expect(at).toBeGreaterThan(0);
    expect(body.slice(0, at)).toBe(plain);
    expect(body.slice(at + 2)).toBe(
      aiSummarySection(REVIEW, 'gitlab', AI_SECTION_MAX_BYTES).join('\n'),
    );
    checkBody(body, SUMMARY_MAX_BYTES);
    // Without a review, or with a null one, the summary is what it was.
    expect(summary({ review: null })).toBe(plain);
    expect(plain).not.toContain('AI review');
  });

  it('says in GitHub’s words what GitHub’s summary says, and in GitLab’s what GitLab’s does', () => {
    const moved = { ...REVIEW, mergeRequestHeadSha: 'b'.repeat(40) };
    const github = summary({ review: moved, vocabulary: 'github' });
    expect(github).toContain(
      '; the pull request is now at ` bbbbbbbbbbbb `; the next workflow run reviews the new commits.',
    );
    expect(sectionOf(github)).not.toContain('merge request');
    expect(summary({ review: moved })).toContain(
      '; the merge request is now at ` bbbbbbbbbbbb `; the next pipeline reviews the new commits.',
    );
  });

  it('says how the review stands while it has not finished or did not run', () => {
    const states: [ReviewSummaryState, string][] = [
      [{ kind: 'pending' }, 'AI review in progress…'],
      [
        { kind: 'skipped', reason: 'budget_spent', detail: null },
        'its token budget for today is spent',
      ],
      [{ kind: 'failed', reason: 'provider_error' }, 'The next push reviews again.'],
    ];
    for (const [review, text] of states) {
      const body = summary({ review });
      expect(sectionOf(body)).toContain(text);
      checkBody(body, SUMMARY_MAX_BYTES);
    }
  });

  it('is checked by a body check that refuses markup where it does not belong', () => {
    const body = summary({ review: REVIEW });
    expect(() => checkBody(body, SUMMARY_MAX_BYTES)).not.toThrow();
    // Appended to the section: text out of a code span, or a fixed text of the section out of place.
    for (const bad of [
      'see </details> here',
      'text <details><summary>Prompt for an AI agent</summary>',
      'again #### AI review',
      '**High** sneaks in',
      '- **High** · ` a ` · [View in Qualor](https://evil.example/x)',
      '- **High** · ` a ` · [View in Qualor](http://q.example/x)',
      '[View in Qualor](https://q.example/ok) and [x](https://e.example)',
    ]) {
      expect(() => checkBody(`${body}\n${bad}`, SUMMARY_MAX_BYTES), bad).toThrow();
    }
  });

  it('the summary with a full AI section and ten analyzer issues stays within 16 KiB, dropping in order', () => {
    const body = summary({ topIssues: bigIssues, topIssuesTotal: 500, review: REVIEW });
    checkBody(body, SUMMARY_MAX_BYTES);
    // The section is whole; the analyzers' issue list gave way.
    const whole = sectionOf(body);
    expect(whole).toBe(aiSummarySection(REVIEW, 'gitlab', AI_SECTION_MAX_BYTES).join('\n'));
    expect(whole).toContain('<details><summary>Prompt for an AI agent</summary>');
    expect(bytes(whole)).toBeLessThanOrEqual(AI_SECTION_MAX_BYTES);
    const kept = listedIssues(body);
    expect(kept).toBeGreaterThan(0);
    expect(kept).toBeLessThan(10);
    expect(body).toContain(`…and ${500 - kept} more`);

    // As the note fills up (a table of conditions takes the room), the issue list is cut first,
    // and then the section gives way: its prompt, its walkthrough, the tail of its list of
    // findings, its verdict, and last all of it.
    /** A gate with `rows` failed conditions: the room the note leaves its AI section. */
    const gateRows = (rows: number): GateResult =>
      gate(
        'failed',
        Array.from({ length: rows }, () => ({
          metric: 'new_duplicated_lines_density',
          operator: 'gt' as const,
          threshold: 3,
          value: 12.5,
          status: 'failed' as const,
        })),
      );
    const seen = new Set<string>();
    let previousListed = Infinity;
    let sectionGone = false;
    for (let rows = 0; rows <= 330; rows += 3) {
      const body = summary({
        gate: gateRows(rows),
        topIssues: bigIssues,
        topIssuesTotal: 500,
        review: REVIEW,
      });
      expect(bytes(body), `${rows} rows`).toBeLessThanOrEqual(SUMMARY_MAX_BYTES);
      const listed = listedIssues(body);
      // The issue list gives way before anything of the section does.
      expect(listed, `${rows} rows`).toBeLessThanOrEqual(previousListed);
      previousListed = listed;
      if (!body.includes('#### AI review')) {
        sectionGone = true;
        continue;
      }
      // Once the section is gone it stays gone as the note fills up.
      expect(sectionGone, `${rows} rows`).toBe(false);
      const section = sectionOf(body);
      const prompt = section.includes('<details>');
      const walkthrough = section.includes('- Walkthrough item');
      const unplaced = section.split('\n').filter((line) => line.startsWith('- **Medium**')).length;
      const verdict = section.includes(
        'retry path can charge a customer twice when the first call times out and is repeated.',
      );
      if (!prompt) expect(listed, `${rows} rows`).toBe(0);
      if (prompt) expect(walkthrough && unplaced === 6 && verdict, `${rows} rows`).toBe(true);
      if (walkthrough) expect(unplaced === 6 && verdict, `${rows} rows`).toBe(true);
      if (unplaced > 0) expect(section, `${rows} rows`).toContain('retry path');
      seen.add(`${prompt}|${walkthrough}|${unplaced === 6}|${verdict}`);
    }
    expect([...seen]).toEqual(
      expect.arrayContaining([
        'true|true|true|true',
        'false|true|true|true',
        'false|false|true|true',
        'false|false|false|true',
        'false|false|false|false',
      ]),
    );
    expect(sectionGone).toBe(true);
  });
});

/** A small seeded generator, so that a text that fails can be found again. */
function seededRandom(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4_294_967_296;
  };
}

/**
 * Azure DevOps's renderer (probe item 21): the 40-case corpus the probe posted to real
 * organisations (tools/azure/items/11-markdown-corpus.ts) goes through every slot of the
 * summary and the inline note with the Azure vocabulary. The probe found the code-span and
 * `safeProse` rules held on both deployments; this keeps it so. The corpus is loaded at run time:
 * `tools/` references the server's project, so a static import would cross the server's rootDir.
 * Qualor's other Azure-only notes (`resolvedNote`, `reopenedNote`) hold only an issue id and a
 * full revision, never an analyzer's text, so they take no corpus value.
 */
describe('Azure DevOps renderer (probe item 21)', () => {
  const GUID = '8f2c1a4e-5b7d-4c3a-9e10-2d6f7a8b9c0d';
  const corpusModule = '../../../tools/azure/items/11-markdown-corpus';
  const AZURE_PATTERNS = REFERENCES.filter(([name]) =>
    [
      'math',
      'a task list item',
      'a heading',
      'a mention by id',
      'a KaTeX block delimiter',
      'a details block',
    ].includes(name),
  );
  let cases: readonly (readonly [string, string])[] = [];

  beforeAll(async () => {
    const mod = (await import(/* @vite-ignore */ corpusModule)) as {
      corpus: (userId: string) => (readonly [string, string])[];
    };
    cases = mod.corpus(GUID);
  });

  /** Outside code spans, Azure DevOps has nothing live to render: no pattern of REFERENCES is left. */
  function expectInertOutside(body: string, label: string, maxBytes: number): void {
    checkBody(body, maxBytes);
    const lines = body.split('\n');
    for (const [index, line] of lines.entries()) {
      if (index === 0) continue; // the marker
      const isMessage =
        maxBytes === SUMMARY_MAX_BYTES
          ? line.startsWith('   ') && lines[index - 1]?.endsWith('\\') === true
          : index === 3 && lines[1]?.startsWith('**') === true;
      if (isMessage) {
        expectInertProse(line.trimStart(), label);
        continue;
      }
      const outside = outsideCodeSpans(line)
        .replace(OWN_LINK, ' ')
        .replace(/^#{3,4} /, ''); // the fixed headings
      for (const [name, pattern] of AZURE_PATTERNS)
        expect(outside, `${label} → ${JSON.stringify(line)}: ${name}`).not.toMatch(pattern);
    }
  }

  it('has the whole corpus', () => {
    expect(cases.length).toBe(40);
  });

  it('keeps every value inert as message, rule key, path and package name', () => {
    const url = `https://q.example/projects/${PROJECT}/issues/${ISSUE}`;
    for (const [name, value] of cases) {
      const slots = {
        message: { ruleKey: 'k', path: 'a.ts', message: value },
        'rule key': { ruleKey: value, path: 'a.ts', message: 'm' },
        path: { ruleKey: 'k', path: value, message: 'm' },
        'package name': {
          ruleKey: 'license:forbidden',
          path: 'package-lock.json',
          message: `${value} 2.1.0 is licensed GPL-3.0-only, which the organisation's licence policy forbids (Strong copyleft).`,
        },
      };
      for (const [slot, fields] of Object.entries(slots)) {
        const label = `${name} as ${slot}`;
        const body = summary({
          vocabulary: 'azure',
          topIssues: Array.from({ length: 3 }, () => ({
            id: ISSUE,
            severity: 'high' as const,
            quality: 'security' as const,
            line: 7,
            url,
            ...fields,
          })),
          topIssuesTotal: 3,
        });
        expectInertOutside(body, label, SUMMARY_MAX_BYTES);
        expectInertOutside(
          inlineBody({
            issueId: ISSUE,
            severity: 'blocker',
            quality: 'security',
            ruleKey: fields.ruleKey,
            message: fields.message,
            url,
          }),
          label,
          INLINE_MAX_BYTES,
        );
      }
    }
  });

  it('keeps a hostile gate name inert in the Azure summary', () => {
    for (const [name, value] of cases) {
      expectInertOutside(
        summary({ vocabulary: 'azure', gate: { ...failed, gate: { id: 'g1', name: value } } }),
        name,
        SUMMARY_MAX_BYTES,
      );
    }
  });
});

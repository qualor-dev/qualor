import type { GateResult } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { safeCodeSpan, safePlainValue } from '@qualor/shared';
import {
  FIXED_TEXT,
  FORBIDDEN_ANYWHERE,
  outsideCodeSpans,
  SUMMARY_FIXED_TEXT,
} from '../../test/markdown-check';
import { codeSpan, markerOf, plainValue, qualorLink, summaryMarker } from './markdown';
import {
  commitStatusFor,
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
        `1. 🔴 **High** · security · \` semgrep:@all /merge \` · [\` src/a.ts:12 \`](${I})`,
      ].join('\n'),
    );
    expect(body).toContain(
      '2. 🟠 **Medium** · maintainability · ` eslint:no-console ` · `` src/`x`.ts ``\n   ` plain `',
    );
    expect(body).toContain('3. 🟠 **Medium** · reliability · ` r `\n   ` /merge `');
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
    expect(summary({ inline: { commented: 0, unplaced: 0, skipped: 'merged_result' } })).toContain(
      'merged-results pipeline',
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

  it('ends with how many more issues there are, where they are, and the link', () => {
    const tail = (o: Partial<SummaryInput>) => summary(o).split('\n').at(-1);
    const none = { commented: 0, unplaced: 0, skipped: null };
    expect(tail({ topIssuesTotal: 25, inline: { ...none, commented: 25 } })).toBe(
      `…and 22 more, all commented inline · **[Open in Qualor →](${B})**`,
    );
    expect(
      tail({ topIssuesTotal: 25, inline: { ...none, commented: 25 }, vocabulary: 'github' }),
    ).toBe(`…and 22 more, all annotated inline · **[Open in Qualor →](${B})**`);
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
    expect(body).toContain(`1. 🟡 **Low** · security · \` k \` · [details](${I})`);
    expect(body).toContain('2. 🔵 **Info** · unknown · ` k ` · ` a.ts:1 `');
    expect(body).toContain('3. ➖ **Unknown** · security · ` k `');
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
        '` Unexpected console statement. `',
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
  for (const [index, line] of lines.entries()) {
    expect(line, line).not.toMatch(/^\s*\//);
    if (index === 0) continue; // the marker, checked by markerOf above
    let markdown = outsideCodeSpans(line).replace(OWN_LINK, ' ');
    markdown = markdown.replace(/^#{3,4} /, ''); // the fixed headings
    expect(markdown, line).toMatch(
      maxBytes === SUMMARY_MAX_BYTES ? SUMMARY_FIXED_TEXT : FIXED_TEXT,
    );
    // `<` and `>` only as the comparison of a condition, never an HTML tag or autolink.
    expect(markdown, line).not.toMatch(/<\S/);
  }
}

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

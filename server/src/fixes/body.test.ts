import { marked } from 'marked';
import { describe, expect, it } from 'vitest';
import { outsideCodeSpans } from '../../test/markdown-check';
import {
  cancelComment,
  fixBody,
  fixTitle,
  goneComment,
  MAX_SHOWN_ADDITIONS,
  type FixBodyInput,
} from './body';

const QUALOR_LINK = 'https://qualor.example.com/projects/p1/vulnerabilities?view=vulnerability';

/** Two targets, one unfixable vulnerability and one transitive lockfile with its dependent. */
const base: FixBodyInput = {
  provider: 'gitlab',
  targets: [
    { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' },
    { installed: '2.0.0', target: '2.0.1', lockfile: 'packages/b/package-lock.json' },
  ],
  vulnerabilities: [
    {
      id: 'CVE-2026-9001',
      severity: 'high',
      title: 'Prototype pollution',
      url: 'https://nvd.example/CVE-2026-9001',
    },
    { id: 'GHSA-aaaa-bbbb-cccc', severity: 'critical', title: null, url: null },
  ],
  unfixable: [{ id: 'CVE-2026-9002', severity: 'low', title: 'Slow parsing', url: null }],
  lockfiles: [
    { path: 'package-lock.json', relation: 'direct', mechanism: null, dependents: [] },
    {
      path: 'packages/b/package-lock.json',
      relation: 'transitive',
      mechanism: 'overrides',
      dependents: ['qf-parent'],
    },
  ],
  additions: [],
  majorJumps: [],
  vulnerabilitiesUrl: QUALOR_LINK,
};

const html = (body: string): string =>
  marked.parse(body, { async: false, gfm: true, breaks: false });

/**
 * The cells of a table row as GFM splits it: at each pipe after an even run of backslashes (none
 * included). A renderer drops cells beyond the header's three without a sign, so the source is
 * counted, not the HTML.
 */
function cellsOf(row: string): string[] {
  const cells: string[] = [];
  let current = '';
  let slashes = 0;
  for (const c of row) {
    if (c === '|' && slashes % 2 === 0) {
      cells.push(current);
      current = '';
    } else {
      current += c;
    }
    slashes = c === '\\' ? slashes + 1 : 0;
  }
  cells.push(current);
  return cells.slice(1, -1);
}

/** The rendered cells of the table's first row of values. */
const firstRowCells = (body: string): string[] =>
  [...(html(body).split('<tbody>')[1] ?? '').matchAll(/<td>([\s\S]*?)<\/td>/g)]
    .slice(0, 3)
    .map((m) => m[1] ?? '');

/** The checks every body must pass, whatever its values hold (spec §6.7, B9, scm.md §6). */
function expectInert(body: string): void {
  for (const line of body.split('\n')) {
    // No code span left open or closed early: no backtick outside the spans.
    expect(outsideCodeSpans(line), line).not.toContain('`');
    // Every row of the table has its three cells.
    if (line.startsWith('|')) expect(cellsOf(line), line).toHaveLength(3);
  }
  const rendered = html(body);
  // No link but to the advisory or to Qualor, no HTML element from a value.
  expect(rendered).not.toMatch(/href="[^"]*evil\.example/);
  expect(rendered).not.toMatch(/<b[\s>]/);
  expect(rendered).not.toMatch(/<(?:img|script|iframe|details|h[1-6])\b/);
  for (const row of rendered.match(/<tr>[\s\S]*?<\/tr>/g) ?? []) {
    expect(row.match(/<t[dh][\s>]/g), row).toHaveLength(3);
  }
}

describe('fixTitle and the comments (R29, R30)', () => {
  it('names the package, the installed version and the target', () => {
    expect(fixTitle('qf-a', '1.2.5', '1.2.6')).toBe('Bump qf-a from 1.2.5 to 1.2.6');
    expect(fixTitle('@scope/x', 'v1.0.0', 'v1.0.1')).toBe('Bump @scope/x from v1.0.0 to v1.0.1');
  });

  it('keeps a title on one line, within 255 characters', () => {
    const title = fixTitle(`a\nb${'c'.repeat(400)}`, '1\r\n2', '3\u2028/merge');
    expect(title).not.toMatch(/[\n\r\u2028]/);
    expect([...title].length).toBeLessThanOrEqual(255);
  });

  it('says MR on GitLab and PR on GitHub in the cancel comment', () => {
    expect(cancelComment('gitlab')).toBe(
      'Qualor closed this MR: a member cancelled the fix in Qualor.',
    );
    expect(cancelComment('github')).toBe(
      'Qualor closed this PR: a member cancelled the fix in Qualor.',
    );
  });

  it('names the package and the main branch in the gone comment, in code spans', () => {
    expect(goneComment('qf-a', 'main')).toBe(
      'Qualor no longer finds a vulnerable ` qf-a ` on ` main `',
    );
    // A scope is no mention, a value no link.
    const odd = goneComment('@all/x', 'main](https://evil.example)');
    expectInert(odd);
    expect(outsideCodeSpans(odd)).not.toContain('@');
  });
});

describe('fixBody (spec §6.7, B3, rulings T3i, F25)', () => {
  it('lays out the vulnerabilities, versions, lockfiles, the Qualor link and the last sentence', () => {
    expect(fixBody(base)).toBe(
      [
        '| Vulnerability | Severity | Title |',
        '|---|---|---|',
        '| [` CVE-2026-9001 `](https://nvd.example/CVE-2026-9001) | high | ` Prototype pollution ` |',
        '| ` GHSA-aaaa-bbbb-cccc ` | critical |  |',
        '',
        '**No fixed version yet:** ` CVE-2026-9002 ` (low)',
        '',
        '**Versions:** ` 1.2.5 ` → ` 1.2.6 ` in ` package-lock.json `\\',
        '**Versions:** ` 2.0.0 ` → ` 2.0.1 ` in ` packages/b/package-lock.json `',
        '',
        '- ` package-lock.json `: direct',
        '- ` packages/b/package-lock.json `: transitive — pinned through ` overrides `; remove the pin when ` qf-parent ` brings ` 2.0.1 ` or later',
        '',
        `[Vulnerabilities in Qualor](${QUALOR_LINK})`,
        '',
        'Qualor keeps this MR current and closes it when the vulnerability is gone. Push to this branch to take it over.',
      ].join('\n'),
    );
    expectInert(fixBody(base));
    const rendered = html(fixBody(base));
    expect(rendered.match(/<tr>/g)).toHaveLength(3);
    expect(rendered).toContain('<a href="https://nvd.example/CVE-2026-9001"><code>CVE-2026-9001');
    // The two version lines are two lines on GitLab too (a hard break, not a soft one).
    expect(rendered).toMatch(/<code>package-lock\.json<\/code><br>/);
  });

  it('keeps a hostile advisory title inert: no table break, no link, no HTML', () => {
    const body = fixBody({
      ...base,
      vulnerabilities: [
        { ...base.vulnerabilities[0]!, title: '| [x](https://evil.example) <b>bold</b> |' },
      ],
    });
    expectInert(body);
    expect(firstRowCells(body)[2]).toBe(
      '<code>| [x](https://evil.example) &lt;b&gt;bold&lt;/b&gt; |</code>',
    );
  });

  it('shows an id without a link when its URL is no http(s) URL', () => {
    // Assembled at run time: the scheme is the test's input, not code of its own.
    const script = ['javascript', 'alert(1)'].join(':');
    for (const url of [script, 'data:text/html,x', 'https://u:p@evil.example/x']) {
      const body = fixBody({
        ...base,
        vulnerabilities: [{ ...base.vulnerabilities[0]!, url }],
      });
      expect(body).toContain('| ` CVE-2026-9001 ` | high |');
      expect(html(body)).not.toMatch(/<a href="(?!https:\/\/qualor\.example\.com)/);
    }
  });

  it('leaves the Qualor link out without QUALOR_PUBLIC_URL', () => {
    const body = fixBody({ ...base, vulnerabilitiesUrl: null });
    expect(body).not.toContain('Vulnerabilities in Qualor');
    expect(body).not.toContain('qualor.example.com');
  });

  it('warns of each major version change', () => {
    const body = fixBody({
      ...base,
      majorJumps: [{ installed: '2.0.0', target: '3.1.0', lockfile: 'package-lock.json' }],
    });
    expect(body).toContain(
      '> **Major version change:** ` 2.0.0 ` → ` 3.1.0 ` may need code changes.',
    );
    expect(fixBody(base)).not.toContain('Major version change');
  });

  it('says PR on GitHub in the last sentence', () => {
    expect(fixBody({ ...base, provider: 'github' })).toMatch(
      /\nQualor keeps this PR current and closes it when the vulnerability is gone\. Push to this branch to take it over\.$/,
    );
  });

  it('describes a transitive pin without dependents or mechanism in fixed words', () => {
    const body = fixBody({
      ...base,
      lockfiles: [{ path: 'yarn.lock', relation: 'transitive', mechanism: null, dependents: [] }],
      targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'yarn.lock' }],
    });
    expect(body).toContain(
      '- ` yarn.lock `: transitive — pinned through an override; remove the pin when the packages that depend on it bring ` 1.2.6 ` or later',
    );
  });

  it('leaves out the table and the unfixable line when they are empty', () => {
    const body = fixBody({ ...base, vulnerabilities: [], unfixable: [] });
    expect(body).not.toContain('| Vulnerability |');
    expect(body).not.toContain('No fixed version yet');
    expect(body.startsWith('**Versions:**')).toBe(true);
  });
});

describe('fixBody: the new lockfile entries (ruling T3i)', () => {
  it('lists each path’s new entries, an alias as slot (name@version)', () => {
    const body = fixBody({
      ...base,
      additions: [
        {
          path: 'package-lock.json',
          entries: [
            { slot: null, name: 'qf-a', version: '1.2.6' },
            { slot: 'qf-alias', name: 'qf-b', version: '2.0.0' },
          ],
        },
        {
          path: 'packages/b/package-lock.json',
          entries: [{ slot: 'qf-c', name: 'qf-c', version: '3.0.1' }],
        },
      ],
    });
    expect(body).toContain(
      [
        '**New in the lockfile:**',
        '- ` package-lock.json `: ` qf-a@1.2.6 `, ` qf-alias (qf-b@2.0.0) `',
        '- ` packages/b/package-lock.json `: ` qf-c@3.0.1 `',
      ].join('\n'),
    );
    // After the per-lockfile lines.
    expect(body.indexOf('**New in the lockfile:**')).toBeGreaterThan(body.indexOf(': direct'));
    expectInert(body);
  });

  it(`shows at most ${MAX_SHOWN_ADDITIONS} entries in all, then how many more`, () => {
    const entries = (from: number, n: number) =>
      Array.from({ length: n }, (_, i) => ({
        slot: null,
        name: `dep-${from + i}`,
        version: '1.0.0',
      }));
    const body = fixBody({
      ...base,
      additions: [
        { path: 'package-lock.json', entries: entries(0, 25) },
        { path: 'packages/b/package-lock.json', entries: entries(25, 10) },
        { path: 'packages/c/package-lock.json', entries: entries(35, 5) },
      ],
    });
    expect(body.match(/` dep-\d+@1\.0\.0 `/g)).toHaveLength(MAX_SHOWN_ADDITIONS);
    expect(body).toContain('` dep-29@1.0.0 `\n- and 10 more');
    expect(body).not.toContain('dep-30@');
    expect(body).not.toContain('packages/c/package-lock.json `:');
    expectInert(body);
  });

  it('has no section without additions', () => {
    expect(fixBody(base)).not.toContain('New in the lockfile');
    expect(fixBody({ ...base, additions: [{ path: 'go.sum', entries: [] }] })).not.toContain(
      'New in the lockfile',
    );
  });
});

describe('fixBody: every value is inert (spec §6.7, scm.md §6)', () => {
  const HOSTILE = 'x` | <b>bold</b> ](https://evil.example) ``|';

  it('keeps a dependent and an addition name with backticks, pipes, HTML and links inert', () => {
    const body = fixBody({
      ...base,
      lockfiles: [
        {
          path: 'package-lock.json',
          relation: 'transitive',
          mechanism: HOSTILE,
          dependents: [HOSTILE, '@all'],
        },
      ],
      additions: [
        {
          path: 'package-lock.json',
          entries: [{ slot: HOSTILE, name: HOSTILE, version: HOSTILE }],
        },
      ],
      vulnerabilities: [{ id: HOSTILE, severity: 'high', title: HOSTILE, url: null }],
      unfixable: [{ id: HOSTILE, severity: 'low', title: null, url: null }],
      targets: [{ installed: HOSTILE, target: HOSTILE, lockfile: HOSTILE }],
      majorJumps: [{ installed: HOSTILE, target: HOSTILE, lockfile: HOSTILE }],
    });
    expectInert(body);
    for (const line of body.split('\n')) expect(outsideCodeSpans(line), line).not.toContain('@');
    const rendered = html(body);
    expect(rendered).toContain('&lt;b&gt;bold&lt;/b&gt;');
    expect(rendered.match(/<tr>/g)).toHaveLength(2);
  });

  it('keeps a path with a backtick, and one with a pipe after a backslash, inert', () => {
    // GFM reads `\|` in a cell as a pipe, so a backslash right before a pipe is not shown.
    for (const [path, shown] of [
      ['pa`ck/age-lock.json', 'pa`ck/age-lock.json'],
      ['a\\|b/package-lock.json', 'a|b/package-lock.json'],
      ['a\\\\|b/package-lock.json', 'a\\\\|b/package-lock.json'],
      ['``|`/x', '``|`/x'],
    ] as const) {
      const body = fixBody({
        ...base,
        lockfiles: [{ path, relation: 'direct', mechanism: null, dependents: [] }],
        additions: [{ path, entries: [{ slot: null, name: 'qf-a', version: '1.2.6' }] }],
        targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: path }],
        vulnerabilities: [{ ...base.vulnerabilities[0]!, title: path }],
      });
      expectInert(body);
      expect(html(body).match(/<tr>/g)).toHaveLength(2);
      // The title's cell holds the whole value: the row was not split at its pipe.
      expect(firstRowCells(body)[2], path).toBe(`<code>${shown}</code>`);
    }
  });

  it('caps the table and the unfixable list', () => {
    const many = Array.from({ length: 60 }, (_, i) => ({
      id: `CVE-2026-${1000 + i}`,
      severity: 'medium' as const,
      title: 't',
      url: null,
    }));
    const body = fixBody({ ...base, vulnerabilities: many, unfixable: many });
    expect(html(body).match(/<tr>/g)).toHaveLength(51);
    expect(body).toContain('|\n\nand 10 more vulnerabilities\n');
    expect(body).toContain('` CVE-2026-1049 ` (medium), and 10 more');
    expectInert(body);
  });
});

describe('fixBody: a bounded body (ruling T10d)', () => {
  const LAST =
    'Qualor keeps this MR current and closes it when the vulnerability is gone. Push to this branch to take it over.';
  const long = (prefix: string, i: number) => `${prefix}-${i}-${'x'.repeat(300)}`;

  it('caps the version and lockfile lines at 30 each, then how many more, and drops duplicate targets', () => {
    const targets = Array.from({ length: 40 }, (_, i) => ({
      installed: `1.0.${i}`,
      target: `1.1.${i}`,
      lockfile: `p${i}/package-lock.json`,
    }));
    const body = fixBody({
      ...base,
      targets: [targets[0]!, ...targets, targets[1]!],
      lockfiles: targets.map((t) => ({
        path: t.lockfile,
        relation: 'direct' as const,
        mechanism: null,
        dependents: [],
      })),
    });
    const lines = body.split('\n');
    expect(lines.filter((l) => l.startsWith('**Versions:**'))).toHaveLength(30);
    expect(lines.filter((l) => l.startsWith('**Versions:** ` 1.0.0 `'))).toHaveLength(1);
    expect(body).toContain(
      '**Versions:** ` 1.0.29 ` → ` 1.1.29 ` in ` p29/package-lock.json `\\\nand 10 more',
    );
    expect(lines.filter((l) => / `: direct$/.test(l))).toHaveLength(30);
    expect(body).toContain('- ` p29/package-lock.json `: direct\n- and 10 more');
    expectInert(body);
    expect(html(body)).toMatch(/<code>p29\/package-lock\.json<\/code><br>\s*and 10 more/);
  });

  it('caps the targets a transitive pin names', () => {
    const targets = Array.from({ length: 12 }, (_, i) => ({
      installed: `${i}.0.0`,
      target: `${i}.0.1`,
      lockfile: 'package-lock.json',
    }));
    const body = fixBody({
      ...base,
      targets,
      lockfiles: [
        {
          path: 'package-lock.json',
          relation: 'transitive',
          mechanism: 'overrides',
          dependents: [],
        },
      ],
    });
    expect(body).toContain(
      'bring ` 0.0.1 ` or ` 1.0.1 ` or ` 2.0.1 ` or ` 3.0.1 ` or ` 4.0.1 ` (and 7 more) or later',
    );
  });

  it('keeps a body of 1 000 targets and lockfiles with long paths within 60 000 characters', () => {
    const n = 1_000;
    const targets = Array.from({ length: n }, (_, i) => ({
      installed: `1.0.${i}`,
      target: `2.0.${i}`,
      lockfile: long('pkg', i),
    }));
    const body = fixBody({
      ...base,
      targets,
      majorJumps: targets,
      lockfiles: targets.map((t, i) => ({
        path: t.lockfile,
        relation: 'transitive' as const,
        mechanism: long('mechanism', i),
        dependents: Array.from({ length: 5 }, (_, d) => long(`dep${d}`, i)),
      })),
      vulnerabilities: Array.from({ length: 60 }, (_, i) => ({
        id: `CVE-2026-${10_000 + i}`,
        severity: 'high' as const,
        title: long('title', i),
        url: `https://advisories.example/${'a'.repeat(400)}/${i}`,
      })),
      unfixable: Array.from({ length: 60 }, (_, i) => ({
        id: long('GHSA', i),
        severity: 'low' as const,
        title: null,
        url: null,
      })),
      additions: targets.slice(0, 50).map((t, i) => ({
        path: t.lockfile,
        entries: [{ slot: long('slot', i), name: long('name', i), version: '1.0.0' }],
      })),
    });
    expect(body.length).toBeLessThanOrEqual(60_000);
    expect(body.endsWith(`\n\n${LAST}`)).toBe(true);
    expectInert(body);
    // Cut at whole lines: no line ends in a hard break before the blank line of the end.
    expect(body).not.toContain('\\\n\n');
  });
});

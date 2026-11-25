import { beforeAll, describe, expect, it } from 'vitest';
import {
  codeIssueWorkItem,
  escapeHtml,
  fixedNote,
  foundAgainNote,
  keyOfDescription,
  reconciliationKey,
  vulnerabilityWorkItem,
  workItemOps,
} from './content';
import type { CodeIssueFacts, CommentFacts, VulnerabilityFacts } from '../jira/content';

const PUBLIC = 'https://qualor.example';
const LINK_ID = '0192aaaa-bbbb-7ccc-8ddd-eeeeffff0000';
const KEY = reconciliationKey(LINK_ID, 2);
const code = (over: Partial<CodeIssueFacts> = {}): CodeIssueFacts => ({
  issueId: 'i1',
  projectId: 'p1',
  projectName: 'Payments',
  projectKey: 'pay',
  branchName: 'main',
  path: 'src/a.ts',
  line: 12,
  ruleKey: 'ts:S1',
  ruleName: 'No eval',
  severity: 'high',
  quality: 'security',
  message: 'Do not use eval',
  firstSeenAt: new Date('2026-11-01T10:00:00Z'),
  closedAt: null,
  lastSeenAt: null,
  ...over,
});
const vuln = (over: Partial<VulnerabilityFacts> = {}): VulnerabilityFacts => ({
  projectId: 'p1',
  projectName: 'Payments',
  packageName: 'minimist',
  vulnerabilityId: 'CVE-2021-44906',
  title: 'Prototype pollution',
  severity: 'critical',
  installedVersions: ['1.2.0', '1.2.1'],
  fixedVersion: '1.2.6',
  primaryUrl: 'https://avd.example/cve',
  foundIn: ['main'],
  exploited: null,
  epss: null,
  ...over,
});

/** Our own markup; any other `<` is the input leaking. */
const OWN_TAGS = /<\/?(?:h3|p|pre|code)>|<a href="[^"<>]*">|<\/a>/g;
const stripOwn = (html: string): string => html.replace(OWN_TAGS, '');
const preOf = (html: string): string => /<pre>([\s\S]*?)<\/pre>/.exec(html)?.[1] ?? '';

describe('escapeHtml', () => {
  it('escapes & < > " and the apostrophe', () => {
    expect(escapeHtml(`a&b<c>"d"'e'`)).toBe('a&amp;b&lt;c&gt;&quot;d&quot;&#39;e&#39;');
  });
});

describe('reconciliation key', () => {
  it('is qualor-<32 hex>-<generation>', () => {
    expect(KEY).toBe('qualor-0192aaaabbbb7ccc8dddeeeeffff0000-2');
  });
  it('round-trips through both descriptions', () => {
    expect(keyOfDescription(codeIssueWorkItem(code(), PUBLIC, KEY).descriptionHtml)).toBe(KEY);
    expect(keyOfDescription(vulnerabilityWorkItem(vuln(), PUBLIC, KEY).descriptionHtml)).toBe(KEY);
  });
  it('reads the key after Azure added a space before </p>', () => {
    expect(keyOfDescription(`<p>x</p><p>Qualor reference: ${KEY} </p>`)).toBe(KEY);
  });
  it('lets the last match win over one a message holds', () => {
    const other = reconciliationKey('11111111-1111-1111-1111-111111111111', 1);
    const html = codeIssueWorkItem(code({ message: `Qualor reference: ${other}` }), PUBLIC, KEY);
    expect(keyOfDescription(html.descriptionHtml)).toBe(KEY);
  });
  it('is null when a person removed it, or without a description', () => {
    const html = codeIssueWorkItem(code(), PUBLIC, KEY).descriptionHtml;
    expect(keyOfDescription(html.replace(/<p>Qualor reference:[^<]*<\/p>/, ''))).toBeNull();
    expect(keyOfDescription(null)).toBeNull();
  });
});

describe('code issue work item', () => {
  it('keeps the message verbatim once inside the only pre element', () => {
    const message = 'line 1\n  indented <b>x</b> & "q"\nline 3';
    const html = codeIssueWorkItem(code({ message }), PUBLIC, KEY).descriptionHtml;
    expect(html.match(/<pre>/g)).toHaveLength(1);
    expect(preOf(html)).toBe(escapeHtml(message));
  });
  it('holds the fields, the Qualor link and the key last', () => {
    const c = codeIssueWorkItem(code(), PUBLIC, KEY);
    expect(c.link).toBe('https://qualor.example/projects/p1/issues/i1');
    expect(c.descriptionHtml).toContain('<h3>No eval</h3>');
    expect(c.descriptionHtml).toContain('Project: <code>Payments</code> (<code>pay</code>)');
    expect(c.descriptionHtml).toContain('File: <code>src/a.ts:12</code>');
    expect(c.descriptionHtml).toContain('First seen: 2026-11-01');
    expect(c.descriptionHtml).toContain(
      '<a href="https://qualor.example/projects/p1/issues/i1">Open in Qualor</a>',
    );
    expect(c.descriptionHtml.endsWith(`<p>Qualor reference: ${KEY}</p>`)).toBe(true);
  });
  it('cuts the title to 255 with no line break', () => {
    const message = 'a\r\nb\u2028' + 'x'.repeat(400);
    const t = codeIssueWorkItem(code({ message }), PUBLIC, KEY).title;
    expect(t.length).toBe(255);
    expect(t).not.toMatch(/[\r\n\u2028]/);
  });
  it('has no links without a public URL', () => {
    const c = codeIssueWorkItem(code(), null, KEY);
    expect(c.link).toBeNull();
    expect(c.descriptionHtml).not.toContain('<a ');
    const v = vulnerabilityWorkItem(vuln({ primaryUrl: null }), null, KEY);
    expect(v.link).toBeNull();
    expect(v.descriptionHtml).not.toContain('<a ');
  });
  it('stays within 30 000 characters for a 40 000-character message', () => {
    const c = codeIssueWorkItem(code({ message: '<&>'.repeat(14_000) }), PUBLIC, KEY);
    expect(c.descriptionHtml.length).toBeLessThanOrEqual(30_000);
    expect(keyOfDescription(c.descriptionHtml)).toBe(KEY);
  });
});

describe('vulnerability work item', () => {
  it('holds the lines and the advisory link', () => {
    const c = vulnerabilityWorkItem(vuln(), PUBLIC, KEY);
    expect(c.title).toBe('CVE-2021-44906 in minimist (critical)');
    expect(c.link).toBe('https://qualor.example/projects/p1/vulnerabilities?view=vulnerability');
    expect(c.descriptionHtml).toContain('<h3>CVE-2021-44906: Prototype pollution</h3>');
    expect(c.descriptionHtml).toContain('installed <code>1.2.0</code>, <code>1.2.1</code>');
    expect(c.descriptionHtml).toContain('Fixed in: <code>1.2.6</code>');
    expect(c.descriptionHtml).toContain('<a href="https://avd.example/cve">CVE-2021-44906</a>');
  });
  it('says no fixed version yet', () => {
    const html = vulnerabilityWorkItem(vuln({ fixedVersion: null }), PUBLIC, KEY).descriptionHtml;
    expect(html).toContain('Fixed in: no fixed version yet');
  });
  it('adds the Exploited and EPSS lines only with priority', () => {
    const plain = vulnerabilityWorkItem(vuln(), PUBLIC, KEY).descriptionHtml;
    expect(plain).not.toContain('Exploited');
    expect(plain).not.toContain('EPSS');
    const full = vulnerabilityWorkItem(
      vuln({ exploited: { dateAdded: '2026-10-01' }, epss: { score: 0.1234, percentile: 0.97 } }),
      PUBLIC,
      KEY,
    ).descriptionHtml;
    expect(full).toContain('Exploited: CISA KEV, added 2026-10-01');
    expect(full).toContain('EPSS: 12.3% (percentile 97)');
  });
  it('says "and N more" after 20 places', () => {
    const foundIn = Array.from({ length: 25 }, (_, i) => `b${i}`);
    const html = vulnerabilityWorkItem(vuln({ foundIn }), PUBLIC, KEY).descriptionHtml;
    expect(html).toContain('<code>b19</code> and 5 more');
    expect(html).not.toContain('b20');
  });
  it('escapes the advisory URL in the href', () => {
    const html = vulnerabilityWorkItem(
      vuln({ primaryUrl: 'https://a.example/x?a=1&b="2"<s>' }),
      PUBLIC,
      KEY,
    ).descriptionHtml;
    expect(html).toContain('&amp;b=');
    expect(stripOwn(html)).not.toContain('<');
  });
});

describe('notes', () => {
  const codeFacts: CommentFacts = {
    kind: 'code',
    projectName: 'P',
    day: '2026-11-02',
    link: 'https://qualor.example/projects/p1/issues/i1?a=1&b=2',
    branchName: 'main',
    ruleKey: 'ts:S1',
  };
  const vulnFacts: CommentFacts = {
    kind: 'vulnerability',
    projectName: 'P',
    day: '2026-11-02',
    link: null,
    vulnerabilityId: 'CVE-1',
    packageName: 'pkg',
    foundIn: ['main', '1.0'],
  };
  it('link to Qualor only with a URL, the href escaped', () => {
    expect(fixedNote(codeFacts)).toContain('?a=1&amp;b=2">Open in Qualor</a>');
    expect(foundAgainNote(codeFacts)).toContain('<a href=');
    expect(fixedNote(vulnFacts)).not.toContain('<a ');
    expect(foundAgainNote(vulnFacts)).not.toContain('<a ');
  });
  it('word the texts as Jira does', () => {
    expect(fixedNote(codeFacts)).toContain(
      'no longer finds this issue on <code>main</code> (analysis of 2026-11-02)',
    );
    expect(foundAgainNote(vulnFacts)).toContain(
      'Qualor finds this again: <code>CVE-1</code> in <code>pkg</code> on <code>main</code>, <code>1.0</code>.',
    );
  });
  it('escape what they hold', () => {
    const n = fixedNote({ ...codeFacts, branchName: '<script>' });
    expect(n).toContain('&lt;script&gt;');
    expect(stripOwn(n)).not.toContain('<');
  });
});

describe('safety corpus', () => {
  let cases: readonly (readonly [string, string])[] = [];
  beforeAll(async () => {
    // Loaded at run time: `tools/` references the server's project, so a static import would cross its rootDir.
    const path = '../../../tools/azure/items/11-markdown-corpus';
    const mod = (await import(/* @vite-ignore */ path)) as {
      corpus: (userId: string) => (readonly [string, string])[];
    };
    cases = [
      ...mod.corpus('8f2c1a4e-5b7d-4c3a-9e10-2d6f7a8b9c0d'),
      ['script', '<script>alert(1)</script>'],
      ['img onerror', '<img src=x onerror=alert(1)>'],
      ['marker comment', '<!-- qualor:summary -->'],
      ['work item ref', '#123'],
      ['pr ref', '!123'],
      ['guid mention', '@<8f2c1a4e-5b7d-4c3a-9e10-2d6f7a8b9c0d>'],
      ['suggestion fence', '```suggestion\nfoo\n```'],
      ['entity', '&amp;'],
      ['40 000 characters', '<a href="x">&'.repeat(3_300)],
    ];
  });

  it('keeps every input inert and inside pre or code', () => {
    expect(cases.length).toBeGreaterThan(40);
    for (const [name, value] of cases) {
      const issue = codeIssueWorkItem(
        code({
          message: value,
          ruleName: value,
          path: value,
          projectName: value,
          branchName: value,
        }),
        PUBLIC,
        KEY,
      );
      const vulnerability = vulnerabilityWorkItem(
        vuln({ title: value, packageName: value, installedVersions: [value], foundIn: [value] }),
        PUBLIC,
        KEY,
      );
      for (const html of [issue.descriptionHtml, vulnerability.descriptionHtml]) {
        expect(stripOwn(html), name).not.toContain('<');
        expect(html.length, name).toBeLessThanOrEqual(30_000);
        expect(keyOfDescription(html), name).toBe(KEY);
      }
      // The message sits in the only pre element, escaped.
      expect(preOf(issue.descriptionHtml), name).not.toMatch(/[<>"']/);
      const note = fixedNote({
        kind: 'code',
        projectName: value,
        day: 'd',
        link: null,
        branchName: value,
        ruleKey: value,
      });
      expect(stripOwn(note), name).not.toContain('<');
    }
  });
});

describe('workItemOps', () => {
  const content = codeIssueWorkItem(code(), PUBLIC, KEY);
  const paths = (ops: { path: string }[]) => ops.map((o) => o.path);
  it('holds Repro Steps only when asked', () => {
    const m = { tags: ['a', 'b'], areaPath: null, iterationPath: null };
    expect(paths(workItemOps(content, m, false))).not.toContain(
      '/fields/Microsoft.VSTS.TCM.ReproSteps',
    );
    const ops = workItemOps(content, m, true);
    expect(ops.find((o) => o.path === '/fields/Microsoft.VSTS.TCM.ReproSteps')?.value).toBe(
      content.descriptionHtml,
    );
    expect(ops.find((o) => o.path === '/fields/System.Tags')?.value).toBe('qualor; a; b');
  });
  it('sets the paths and the hyperlink only when present', () => {
    const none = { tags: [], areaPath: null, iterationPath: null };
    const bare = workItemOps(codeIssueWorkItem(code(), null, KEY), none, false);
    expect(paths(bare)).toEqual([
      '/fields/System.Title',
      '/fields/System.Description',
      '/fields/System.Tags',
    ]);
    const set = { tags: [], areaPath: 'P\\A', iterationPath: 'P\\I' };
    const full = workItemOps(content, set, false);
    expect(full.find((o) => o.path === '/fields/System.AreaPath')?.value).toBe('P\\A');
    expect(full.find((o) => o.path === '/fields/System.IterationPath')?.value).toBe('P\\I');
    expect(full.at(-1)).toEqual({
      op: 'add',
      path: '/relations/-',
      value: { rel: 'Hyperlink', url: 'https://qualor.example/projects/p1/issues/i1' },
    });
  });
});

describe('review round 1', () => {
  const quotes = '"'.repeat(300);
  const names = Array.from({ length: 25 }, () => quotes);

  it('bounds the escaped length of identifiers, so the description cap holds', () => {
    const c = vulnerabilityWorkItem(
      vuln({ installedVersions: names, foundIn: names, packageName: quotes, title: quotes }),
      PUBLIC,
      KEY,
    );
    expect(c.descriptionHtml.length).toBeLessThanOrEqual(30_000);
    expect(keyOfDescription(c.descriptionHtml)).toBe(KEY);
    expect(c.descriptionHtml).not.toMatch(/&[a-z#0-9]*…/);
    const again = foundAgainNote({
      kind: 'vulnerability',
      projectName: 'P',
      day: '2026-11-02',
      link: PUBLIC,
      vulnerabilityId: quotes,
      packageName: quotes,
      foundIn: names,
    });
    expect(again.length).toBeLessThanOrEqual(30_000);
  });

  it('cuts the advisory link text', () => {
    const c = vulnerabilityWorkItem(vuln({ vulnerabilityId: quotes }), PUBLIC, KEY);
    const text = /Advisory: <a [^>]*>([^<]*)<\/a>/.exec(c.descriptionHtml)?.[1] ?? '';
    expect(text.length).toBeLessThanOrEqual(255);
  });

  it('strips controls, bidi overrides and lone surrogates from the title', () => {
    const message = 'a\u0000b\u001bc\u007fd\u009be\u202ef\ud800g';
    const t = codeIssueWorkItem(code({ message }), PUBLIC, KEY).title;
    expect(t).toBe('abcdef\ufffdg');
  });

  it('falls back to the rule name, then the rule key, for an empty title', () => {
    expect(codeIssueWorkItem(code({ message: ' \n\u0000 ' }), PUBLIC, KEY).title).toBe('No eval');
    expect(codeIssueWorkItem(code({ message: '', ruleName: '' }), PUBLIC, KEY).title).toBe('ts:S1');
    expect(vulnerabilityWorkItem(vuln({ packageName: '' }), PUBLIC, KEY).title).not.toBe('');
  });

  it('does not read a key from a message that quotes one', () => {
    const other = reconciliationKey('11111111-1111-1111-1111-111111111111', 1);
    const html = codeIssueWorkItem(
      code({ message: `Qualor reference: ${other}` }),
      PUBLIC,
      KEY,
    ).descriptionHtml;
    const without = html.replace(/<p>Qualor reference:[^<]*<\/p>/, '');
    expect(keyOfDescription(without)).toBeNull();
  });

  it('escapes the day in the notes', () => {
    const n = fixedNote({
      kind: 'code',
      projectName: 'P',
      day: '<b>',
      link: null,
      branchName: 'main',
      ruleKey: 'r',
    });
    expect(n).toContain('&lt;b&gt;');
  });
});

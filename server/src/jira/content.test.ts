import { describe, expect, it } from 'vitest';
import {
  codeIssueContent,
  fixedComment,
  foundAgainComment,
  issueFields,
  issueSeverityOf,
  reconciliationLabel,
  vulnerabilityContent,
  type CodeIssueFacts,
  type CommentFacts,
  type VulnerabilityFacts,
} from './content';
import type { JiraMappingRow } from './mapping';

const PUBLIC = 'https://qualor.example';
const ISSUE_LINK = '[Open in Qualor|https://qualor.example/projects/p1/issues/i1]';
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

describe('markup injection', () => {
  const message =
    'See [here|https://evil.example] {html}<b>x</b>{html} !https://evil.example/p.png! *bold* https://evil.example/bare';
  const { description } = codeIssueContent(
    code({ message, ruleName: 'x {noformat} y', path: 'a|b]c' }),
    PUBLIC,
  );
  const open = description.indexOf('{noformat}\n');
  const close = description.lastIndexOf('\n{noformat}');
  const outside = description.slice(0, open) + description.slice(close + 11);

  it('keeps the message verbatim once between the only two noformat tags', () => {
    expect(description.split('\n').filter((l) => l === '{noformat}')).toHaveLength(2);
    expect(description.split(message)).toHaveLength(2);
    expect(description.slice(open + 11, close)).toBe(message);
  });
  it('escapes the heading and identifiers', () => {
    expect(description).toContain('h3. x \\{noformat\\} y');
    expect(description).toContain('File: a\\|b\\]c:12');
  });
  it('has no link, bare URL or bracket outside the block except the Qualor link', () => {
    const rest = outside.replace(ISSUE_LINK, '');
    expect(outside).toContain(ISSUE_LINK);
    expect(rest).not.toContain('://');
    expect(rest).not.toMatch(/(^|[^\\])\[/);
    expect(rest).not.toMatch(/(^|[^\\])\{/);
  });
  it('escapes a vulnerability package and heading', () => {
    const d = vulnerabilityContent(
      vuln({ packageName: 'a|b]c', title: 'x {noformat} http://evil.example y' }),
      PUBLIC,
    ).description;
    expect(d).toContain('Package: a\\|b\\]c, installed');
    expect(d).toContain('h3. CVE\\-2021\\-44906: x \\{noformat\\} http:/\u200B/evil.example y');
    expect(d).not.toContain('{noformat}');
  });
});

describe('code issue', () => {
  it('lays out the description', () => {
    const c = codeIssueContent(code(), PUBLIC);
    expect(c.summary).toBe('Do not use eval');
    expect(c.description.split('\n')).toEqual([
      'h3. No eval',
      '{noformat}',
      'Do not use eval',
      '{noformat}',
      'Project: Payments \\(pay\\)',
      'Branch: main',
      'File: src/a.ts:12',
      'Rule: ts:S1, high, security',
      'First seen: 2026-11-01',
      ISSUE_LINK,
    ]);
  });
  it('leaves out the file and the link when absent', () => {
    const d = codeIssueContent(code({ path: null, line: null }), null).description;
    expect(d).not.toContain('File:');
    expect(d).not.toContain('Open in Qualor');
  });
});

describe('cuts', () => {
  it('cuts the summary at 255 units without breaking an emoji or a line', () => {
    const { summary } = codeIssueContent(code({ message: `${'a\n'.repeat(130)}😀😀😀` }), PUBLIC);
    expect(summary.length).toBeLessThanOrEqual(255);
    expect(summary.endsWith('…')).toBe(true);
    expect(summary).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/);
    expect(summary).not.toMatch(/[\n\r]/);
  });
  it('cuts a summary that ends in emoji exactly at a pair', () => {
    const { summary } = codeIssueContent(code({ message: `${'a'.repeat(253)}😀😀` }), PUBLIC);
    expect(summary.length).toBeLessThanOrEqual(255);
    expect(summary).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/);
  });
  it('keeps a 50 000-character message within 30 000, closed, with the link last', () => {
    const { description } = codeIssueContent(code({ message: 'm'.repeat(50_000) }), PUBLIC);
    expect(description.length).toBeLessThanOrEqual(30_000);
    const lines = description.split('\n');
    expect(lines.filter((l) => l === '{noformat}')).toHaveLength(2);
    expect(description.match(/\{noformat\}/g)).toHaveLength(2);
    expect(lines.at(-1)).toBe(ISSUE_LINK);
    const outside = description.replace(/\{noformat\}[\s\S]*\n\{noformat\}/, '');
    expect(outside.replace(ISSUE_LINK, '')).not.toContain('://');
  });
});

describe('vulnerability', () => {
  it('lays out summary and lines', () => {
    const c = vulnerabilityContent(
      vuln({ exploited: { dateAdded: '2026-10-02' }, epss: { score: 0.1234, percentile: 0.98 } }),
      PUBLIC,
    );
    expect(c.summary).toBe('CVE-2021-44906 in minimist (critical)');
    expect(c.description.split('\n')).toEqual([
      'h3. CVE\\-2021\\-44906: Prototype pollution',
      'Package: minimist, installed 1.2.0, 1.2.1',
      'Fixed in: 1.2.6',
      'Severity: critical',
      'Exploited: CISA KEV, added 2026-10-02',
      'EPSS: 12.3% (percentile 98)',
      'Found in: main',
      'Advisory: [CVE\\-2021\\-44906|https://avd.example/cve]',
      '[Open in Qualor|https://qualor.example/projects/p1/vulnerabilities?view=vulnerability]',
    ]);
  });
  it('leaves out priority lines when null, and the link without a public URL', () => {
    const d = vulnerabilityContent(vuln({ fixedVersion: null }), null).description;
    expect(d).not.toContain('Exploited');
    expect(d).not.toContain('EPSS');
    expect(d).not.toContain('Open in Qualor');
    expect(d).toContain('Fixed in: no fixed version yet');
  });
  it('lists 20 targets and counts the rest', () => {
    const foundIn = Array.from({ length: 25 }, (_, i) => `b${i}`);
    const d = vulnerabilityContent(vuln({ foundIn }), PUBLIC).description;
    expect(d).toContain('b19 and 5 more');
    expect(d).not.toContain('b20');
  });
  it('accepts only http(s) advisories and encodes them', () => {
    const js = vulnerabilityContent(vuln({ primaryUrl: 'javascript:alert(1)' }), PUBLIC);
    expect(js.description).not.toContain('Advisory');
    const odd = vulnerabilityContent(vuln({ primaryUrl: 'https://x.example/a|b]c d' }), PUBLIC);
    expect(odd.description).toContain('|https://x.example/a%7Cb%5Dc%20d]');
  });
});

describe('description bounds and hardening', () => {
  it('stays within 30 000 with a huge advisory url and 20 long versions', () => {
    const d = vulnerabilityContent(
      vuln({
        primaryUrl: `https://x.example/${'a'.repeat(40_000)}`,
        installedVersions: Array.from({ length: 20 }, () => 'v'.repeat(255)),
      }),
      PUBLIC,
    ).description;
    expect(d.length).toBeLessThanOrEqual(30_000);
    expect(d).not.toContain('Advisory');
    expect(d.split('\n').at(-1)).toBe(
      '[Open in Qualor|https://qualor.example/projects/p1/vulnerabilities?view=vulnerability]',
    );
  });
  it('shrinks a code message that grows when escaped, keeping the closing tag and link', () => {
    const { description } = codeIssueContent(
      code({ message: '{noformat}'.repeat(5_000), path: 'p'.repeat(255) }),
      PUBLIC,
    );
    expect(description.length).toBeLessThanOrEqual(30_000);
    const lines = description.split('\n');
    expect(lines.at(-1)).toBe(ISSUE_LINK);
    expect(lines.filter((l) => l === '{noformat}')).toHaveLength(2);
  });
  it('breaks mailto: and file: in a path and a title', () => {
    const c = codeIssueContent(
      code({ path: 'mailto:a@evil.example', ruleName: 'file:///x' }),
      null,
    );
    expect(c.description).toContain('File: mailto:\u200Ba@evil.example');
    expect(c.description).toContain('h3. file:\u200B/\u200B//x');
  });
  it('leaves no icon from a project key or an emoticon', () => {
    const d = codeIssueContent(code({ projectKey: 'y', ruleName: 'a:D' }), null).description;
    expect(d).toContain('Project: Payments \\(y\\)');
    expect(d).toContain('h3. a:\u200BD');
  });
  it('treats U+0085 as a line break so no line-start markup forms', () => {
    const c = codeIssueContent(
      code({ path: 'a\u0085h1. x\u0085* y', message: 'm\u0085h1. x' }),
      null,
    );
    expect(c.summary).toBe('m h1. x');
    expect(c.description).toContain('File: a h1. x \\* y:12');
  });
  it('encodes advisory markup in the link', () => {
    const d = vulnerabilityContent(
      vuln({ primaryUrl: 'https://x.example/{noformat}\\' }),
      PUBLIC,
    ).description;
    expect(d).toContain('Advisory: [CVE\\-2021\\-44906|https://x.example/%7Bnoformat%7D%5C]');
  });
});

describe('fields', () => {
  const mapping = {
    jiraProjectId: '10000',
    issueTypeId: '10001',
    labels: ['sec'],
    priorities: { blocker: '1' },
    labelsAvailable: true,
    priorityAvailable: true,
  } as unknown as JiraMappingRow;
  const content = { summary: 's', description: 'd' };
  const link = { id: '0190aaaa-bbbb-cccc-dddd-eeeeffff0000', generation: 3 };

  it('sets labels and priority', () => {
    expect(issueFields(mapping, content, 'blocker', link)).toEqual({
      project: { id: '10000' },
      issuetype: { id: '10001' },
      summary: 's',
      description: 'd',
      labels: ['qualor', 'sec', 'qualor-0190aaaabbbbccccddddeeeeffff0000-3'],
      priority: { id: '1' },
    });
    expect(reconciliationLabel(link.id, 3)).toMatch(/^qualor-[0-9a-f]{32}-3$/);
  });
  it('leaves out what the screen lacks or the severity does not map', () => {
    const f = issueFields(
      { ...mapping, labelsAvailable: false, priorityAvailable: false },
      content,
      'blocker',
      link,
    );
    expect(f).not.toHaveProperty('labels');
    expect(f).not.toHaveProperty('priority');
    expect(issueFields(mapping, content, 'low', link)).not.toHaveProperty('priority');
  });
  it('maps vulnerability severities', () => {
    expect(issueSeverityOf('critical')).toBe('blocker');
    expect(issueSeverityOf('unknown')).toBe('medium');
    expect(issueSeverityOf('low')).toBe('low');
  });
});

describe('comments', () => {
  const link = 'https://qualor.example/projects/p1/issues/i1';
  const codeFacts: CommentFacts = {
    kind: 'code',
    projectName: 'Payments',
    day: '2026-11-17',
    link,
    branchName: 'main',
    ruleKey: 'ts:S1',
  };
  const vulnFacts: CommentFacts = {
    kind: 'vulnerability',
    projectName: 'Payments',
    day: '2026-11-17',
    link: null,
    vulnerabilityId: 'CVE-2021-44906',
    packageName: 'minimist',
    foundIn: ['main', 'v1'],
  };
  it('writes the four texts', () => {
    expect(fixedComment(codeFacts)).toBe(
      `Qualor no longer finds this issue on main (analysis of 2026-11-17).\n[Open in Qualor|${link}]`,
    );
    expect(fixedComment(vulnFacts)).toBe(
      'Qualor no longer finds CVE\\-2021\\-44906 in minimist on the tracked branches and versions of Payments.',
    );
    expect(foundAgainComment(codeFacts)).toBe(
      `Qualor finds this again: ts:S1 on main (analysis of 2026-11-17).\n[Open in Qualor|${link}]`,
    );
    expect(foundAgainComment(vulnFacts)).toBe(
      'Qualor finds this again: CVE\\-2021\\-44906 in minimist on main, v1.',
    );
  });
});

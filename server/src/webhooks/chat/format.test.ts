import { describe, expect, it } from 'vitest';
import { formatChat } from './format';
import type {
  ChatDigestMessage,
  ChatExploitedMessage,
  ChatGateMessage,
  DigestRow,
  ExploitedRow,
} from './messages';
import { MAX_TARGET_NAMES, parseChatMessage } from './messages';

const P = '0190a6c2-0000-7000-8000-0000000000a1';
const B = '0190a6c2-0000-7000-8000-0000000000b1';
const A = '0190a6c2-0000-7000-8000-0000000000c1';
const O = '0190a6c2-0000-7000-8000-0000000000d1';
const LINKS = { publicUrl: 'https://qualor.example.com' };
const NO_LINKS = { publicUrl: null };
const Z = '\u200B';

const failed: ChatGateMessage = {
  type: 'gate',
  event: 'gate.failed',
  cause: 'analysis',
  project: { id: P, key: 'acme/payments', name: 'Payments' },
  branch: { id: B, name: 'main' },
  analysisId: A,
  revision: '3f9c2e1aa0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5',
  at: '2026-10-19T07:05:00.000Z',
  gate: { name: 'Qualor way', status: 'failed' },
  failed: [
    { metric: 'new_issues', operator: 'gt', threshold: 0, value: 2 },
    { metric: 'new_coverage', operator: 'lt', threshold: 80, value: 61.5 },
  ],
  failedCount: 2,
  newIssues: { security: 2, reliability: 0, maintainability: 0 },
};
const recovered: ChatGateMessage = {
  ...failed,
  event: 'gate.recovered',
  gate: { name: 'Qualor way', status: 'passed' },
  failed: [],
  failedCount: 0,
  newIssues: { security: 0, reliability: 0, maintainability: 0 },
};
const sev = (high = 0) => ({ blocker: 0, high, medium: 0, low: 0, info: 0 });
const row = (i: number, over: Partial<DigestRow> = {}): DigestRow => ({
  projectId: `0190a6c2-0000-7000-8000-${String(i).padStart(12, '0')}`,
  name: `Project ${i}`,
  gate: 'passed',
  newSecurity: 1,
  newBySeverity: sev(1),
  openSecurity: 4,
  ...over,
});
const digest: ChatDigestMessage = {
  type: 'digest',
  week: '2026-W43',
  since: '2026-10-12T07:00:00.000Z',
  until: '2026-10-19T07:00:00.000Z',
  timezone: 'Europe/Berlin',
  scope: { organization: { id: O, name: 'Acme' }, project: null },
  totals: { projects: 14, failing: 1, newSecurity: 3, openSecurity: 42, newBySeverity: sev(3) },
  rows: [
    row(1, { name: 'Payments', gate: 'failed', newSecurity: 2, newBySeverity: sev(2) }),
    row(2, { name: 'Billing' }),
  ],
  moreProjects: 0,
  quietProjects: 12,
  top: [
    {
      id: '0190a6c2-0000-7000-8000-0000000000e1',
      projectId: P,
      projectName: 'Payments',
      severity: 'high',
      ruleName: 'SQL injection',
      message: 'SQL built from request data',
      path: 'src/orders.ts',
      line: 42,
    },
  ],
};

describe('Slack gate messages (golden)', () => {
  it('formats a failed gate with links', () => {
    expect(formatChat('slack', failed, LINKS)).toEqual({
      text: 'Quality gate failed — Payments · main',
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: 'Quality gate failed — Payments · main', emoji: false },
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            verbatim: true,
            text:
              '*Failing conditions*\n' +
              '• Issues on new code: 2 (fails when greater than 0)\n' +
              '• Coverage on new code: 61.5% (fails when less than 80%)',
          },
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            verbatim: true,
            text: '*New code:* Security 2 · Reliability 0 · Maintainability 0',
          },
        },
        {
          type: 'context',
          elements: [
            {
              type: 'mrkdwn',
              verbatim: true,
              text: 'Gate Qualor way · commit `3f9c2e1` · 2026-10-19 07:05 UTC',
            },
          ],
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: 'Open in Qualor' },
              url: `https://qualor.example.com/projects/${P}/branches/${B}`,
              style: 'danger',
            },
          ],
        },
      ],
    });
  });

  it('formats a recovered gate, and says when issues were changed', () => {
    const body = formatChat('slack', { ...recovered, cause: 'reevaluation' }, LINKS) as {
      text: string;
      blocks: { type: string; text?: { text: string } }[];
    };
    expect(body.text).toBe('Quality gate passes again — Payments · main');
    expect(body.blocks[1]!.text!.text).toBe('All conditions pass after issues were changed.');
    expect(JSON.stringify(body)).toContain('"style":"primary"');
  });

  it('has no button and no URL without a public URL (D6)', () => {
    const body = formatChat('slack', failed, NO_LINKS);
    expect(JSON.stringify(body)).not.toContain('"actions"');
    expect(JSON.stringify(body)).not.toContain('https://');
  });

  it('shows at most 5 conditions and says how many more failed', () => {
    const many: ChatGateMessage = {
      ...failed,
      failed: Array.from({ length: 5 }, () => failed.failed[0]!),
      failedCount: 7,
    };
    const text = JSON.stringify(formatChat('slack', many, LINKS));
    expect(text.match(/Issues on new code: 2/g)).toHaveLength(5);
    expect(text).toContain('…and 2 more');
  });

  it('escapes the names a project admin chose (Review Focus 3)', () => {
    const hostile: ChatGateMessage = {
      ...failed,
      project: { ...failed.project, name: '<!channel> *Payments*' },
      gate: { name: '[x](https://evil.example)', status: 'failed' },
    };
    const body = formatChat('slack', hostile, LINKS) as {
      text: string;
      blocks: {
        type: string;
        text?: { type: string; text: string };
        elements?: { text: string }[];
      }[];
    };
    // The top-level text is mrkdwn for Slack's notification: escaped, so nobody is mentioned.
    expect(body.text).toBe(
      `Quality gate failed — &lt;!channel&gt; ${Z}*${Z}Payments${Z}*${Z} · main`,
    );
    // The header is plain_text, which Slack never parses: the raw name, one line.
    expect(body.blocks[0]!.text).toEqual({
      type: 'plain_text',
      text: 'Quality gate failed — <!channel> *Payments* · main',
      emoji: false,
    });
    // Every mrkdwn text is escaped.
    const mrkdwn = body.blocks.flatMap((b) => [
      ...(b.text?.type === 'mrkdwn' ? [b.text.text] : []),
      ...(b.elements ?? []).map((e) => e.text ?? ''),
    ]);
    for (const text of mrkdwn) expect(text).not.toContain('<!channel>');
    // verbatim: Slack skips its own auto-linking and mention parsing of the text.
    for (const b of body.blocks) {
      if (b.text?.type === 'mrkdwn') expect(b.text).toMatchObject({ verbatim: true });
      for (const e of b.elements ?? []) {
        if (typeof e.text === 'string') expect(e).toMatchObject({ verbatim: true });
      }
    }
    // Slack mrkdwn has no `[text](url)` links: the gate name reaches the context as it is.
    expect(mrkdwn.join('\n')).toContain('Gate [x](https://evil.example)');
  });

  it('Slack: bare mentions, channel names and URLs in names stay inert', () => {
    const hostile: ChatGateMessage = {
      ...failed,
      project: { ...failed.project, name: '@here #general https://evil.example' },
      gate: { name: '@channel', status: 'failed' },
    };
    const body = formatChat('slack', hostile, LINKS) as {
      text: string;
      blocks: { text?: { type: string; text: string; verbatim?: boolean } }[];
    };
    expect(body.text).not.toMatch(/@here|#general/);
    for (const b of body.blocks) {
      if (b.text?.type === 'mrkdwn') {
        expect(b.text.verbatim).toBe(true);
        expect(b.text.text).not.toMatch(/@(here|channel|everyone)|#general/);
      }
    }
  });

  it('Teams: a hostile name renders as text, not a link or bold', () => {
    const hostile: ChatGateMessage = {
      ...failed,
      project: { ...failed.project, name: '[click](https://evil.example) **x**' },
    };
    const json = JSON.stringify(formatChat('teams', hostile, LINKS));
    expect(json).not.toContain('[click](');
    expect(json).not.toContain('**x**');
  });
});

describe('Teams gate messages (golden)', () => {
  it('formats a failed gate as an Adaptive Card 1.4 message', () => {
    expect(formatChat('teams', failed, LINKS)).toEqual({
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          contentUrl: null,
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            type: 'AdaptiveCard',
            version: '1.4',
            msteams: { width: 'Full' },
            body: [
              {
                type: 'TextBlock',
                text: 'Quality gate failed — Payments · main',
                weight: 'Bolder',
                size: 'Medium',
                color: 'Attention',
                wrap: true,
              },
              {
                type: 'TextBlock',
                text: 'Failing conditions',
                weight: 'Bolder',
                spacing: 'Medium',
                wrap: true,
              },
              {
                type: 'TextBlock',
                text:
                  '- Issues on new code: 2 (fails when greater than 0)\n' +
                  '- Coverage on new code: 61.5% (fails when less than 80%)',
                wrap: true,
              },
              {
                type: 'FactSet',
                facts: [
                  { title: 'New code', value: 'Security 2 · Reliability 0 · Maintainability 0' },
                  { title: 'Gate', value: 'Qualor way' },
                  { title: 'Commit', value: '3f9c2e1' },
                  { title: 'Time', value: '2026-10-19 07:05 UTC' },
                ],
              },
            ],
            actions: [
              {
                type: 'Action.OpenUrl',
                title: 'Open in Qualor',
                url: `https://qualor.example.com/projects/${P}/branches/${B}`,
              },
            ],
          },
        },
      ],
    });
  });

  it('has no actions without a public URL, and colours a recovery Good', () => {
    const card = (
      formatChat('teams', recovered, NO_LINKS) as {
        attachments: { content: { actions?: unknown; body: { color?: string }[] } }[];
      }
    ).attachments[0]!.content;
    expect(card.actions).toBeUndefined();
    expect(card.body[0]!.color).toBe('Good');
  });
});

describe('digests', () => {
  it('Slack: totals, project rows with links, the folded line and the top issue', () => {
    const json = JSON.stringify(formatChat('slack', digest, LINKS));
    expect(json).toContain('Weekly security digest — Acme');
    expect(json).toContain(
      '*3* new security issues · *1* failing quality gate · *42* open security issues',
    );
    expect(json).toContain(
      `<https://qualor.example.com/projects/${row(1).projectId}|Payments> — gate failed · 2 new (High 2) · 4 open`,
    );
    expect(json).toContain('12 more projects: no new security issues, gate passed');
    expect(json).toContain(
      `High · Payments · <https://qualor.example.com/projects/${P}/issues/0190a6c2-0000-7000-8000-0000000000e1|SQL injection> — \`src/orders.ts:42\``,
    );
    expect(json).toContain('2026-10-12 – 2026-10-19 (Europe/Berlin)');
  });

  it('Slack: 20 rows, then the rest as a count; every text within 3000 characters', () => {
    const big: ChatDigestMessage = {
      ...digest,
      rows: Array.from({ length: 20 }, (_, i) => row(i + 1, { name: 'N'.repeat(500) })),
      moreProjects: 7,
    };
    const body = formatChat('slack', big, LINKS) as { blocks: { text?: { text: string } }[] };
    expect(body.blocks.length).toBeLessThanOrEqual(50);
    for (const b of body.blocks) expect([...(b.text?.text ?? '')].length).toBeLessThanOrEqual(3000);
    // Rows that do not fit in 3000 characters are counted into the "more" line, not cut off.
    const json = JSON.stringify(body);
    const shown = json.split('• <https').length - 1;
    const more = Number(/…and (\d+) more projects/.exec(json)?.[1]);
    expect(shown).toBeLessThan(20);
    expect(shown + more).toBe(27);
  });

  it('Slack: the top issues are whole items within 3000 characters', () => {
    const big: ChatDigestMessage = {
      ...digest,
      top: Array.from({ length: 3 }, () => ({
        ...digest.top[0]!,
        projectName: '*'.repeat(500),
        ruleName: '_'.repeat(500),
        path: '`'.repeat(500),
      })),
    };
    const body = formatChat('slack', big, LINKS) as { blocks: { text?: { text: string } }[] };
    for (const b of body.blocks) expect([...(b.text?.text ?? '')].length).toBeLessThanOrEqual(3000);
    const topText = body.blocks.map((b) => b.text?.text ?? '').find((t) => t.startsWith('*Top'));
    for (const line of (topText ?? '').split('\n').slice(1)) expect(line.endsWith('`')).toBe(true);
  });

  it('Teams: the worst case of markup characters stays under 28 KB', () => {
    const big: ChatDigestMessage = {
      ...digest,
      scope: { ...digest.scope, organization: { id: O, name: '*'.repeat(500) } },
      rows: Array.from({ length: 20 }, (_, i) => row(i + 1, { name: '[*_`'.repeat(125) })),
      top: Array.from({ length: 3 }, () => ({
        ...digest.top[0]!,
        projectName: '*'.repeat(500),
        ruleName: '_'.repeat(500),
        path: '[]'.repeat(250),
      })),
      moreProjects: 7,
    };
    const json = JSON.stringify(formatChat('teams', big, LINKS));
    expect(Buffer.byteLength(json, 'utf8')).toBeLessThan(28_000);
  });

  it('Teams: a digest without a public URL has no links and no actions', () => {
    const json = JSON.stringify(formatChat('teams', digest, NO_LINKS));
    expect(json).not.toContain('https://');
    expect(json).not.toContain('Action.OpenUrl');
    expect(json).toContain('Payments');
  });

  it('a bad time zone does not throw and reads as UTC; markup in it is not shown', () => {
    const bad: ChatDigestMessage = { ...digest, timezone: '*<!channel>*' };
    for (const kind of ['slack', 'teams'] as const) {
      const json = JSON.stringify(formatChat(kind, bad, LINKS));
      expect(json).toContain('(UTC)');
      expect(json).not.toContain('channel');
    }
  });

  it('shows only a hex revision, and escapes an unknown metric key (both kinds)', () => {
    const hostile: ChatGateMessage = {
      ...failed,
      revision: '*<!channel>*',
      failed: [{ metric: '<!channel> *x*', operator: 'gt', threshold: 1, value: 2 }],
      failedCount: 1,
    };
    const slack = JSON.stringify(formatChat('slack', hostile, LINKS));
    expect(slack).not.toContain('<!channel>');
    expect(slack).not.toContain('commit');
    const teams = JSON.stringify(formatChat('teams', hostile, LINKS));
    expect(teams).not.toContain('*x*');
    expect(teams).not.toContain('"Commit"');
  });

  it('Teams: the same digest within 28 KB', () => {
    const big: ChatDigestMessage = {
      ...digest,
      rows: Array.from({ length: 20 }, (_, i) => row(i + 1, { name: 'Ü'.repeat(500) })),
      top: Array.from({ length: 3 }, () => ({
        ...digest.top[0]!,
        message: 'm'.repeat(4000),
        path: 'p'.repeat(4000),
      })),
      moreProjects: 7,
    };
    const json = JSON.stringify(formatChat('teams', big, LINKS));
    expect(Buffer.byteLength(json, 'utf8')).toBeLessThanOrEqual(28_000);
    expect(json).toContain('…and 7 more projects');
  });

  it('a project digest names the project, and no row links without a public URL', () => {
    const one: ChatDigestMessage = {
      ...digest,
      scope: { ...digest.scope, project: { id: P, name: 'Payments' } },
    };
    const json = JSON.stringify(formatChat('slack', one, NO_LINKS));
    expect(json).toContain('Weekly security digest — Payments');
    expect(json).not.toContain('https://');
  });
});

describe('test messages', () => {
  it.each(['slack', 'teams'] as const)('%s: says it works and names the scope', (kind) => {
    const json = JSON.stringify(
      formatChat(
        kind,
        { type: 'test', organization: { id: O, name: 'Acme' }, project: null },
        LINKS,
      ),
    );
    expect(json).toContain('Qualor is connected');
    expect(json).toContain('every project of Acme');
  });
});

describe('parseChatMessage (R5)', () => {
  it('accepts a stored message of its own event and nothing else', () => {
    expect(parseChatMessage('gate.failed', failed)).toEqual(failed);
    expect(parseChatMessage('gate.recovered', failed)).toBeNull();
    expect(parseChatMessage('digest.weekly', failed)).toBeNull();
    expect(parseChatMessage('digest.weekly', digest)).toEqual(digest);
    expect(parseChatMessage('gate.failed', { type: 'gate' })).toBeNull();
    expect(parseChatMessage('gate.failed', null)).toBeNull();
  });
});

const VULN_URL = (id: string) => `https://qualor.example.com/projects/${id}/vulnerabilities`;
const xrow = (i: number, over: Partial<ExploitedRow> = {}): ExploitedRow => ({
  vulnerabilityId: `CVE-2026-${1000 + i}`,
  severity: 'critical',
  title: 'Prototype pollution in lodash',
  packageName: 'lodash',
  installedVersions: ['4.17.20', '4.17.19'],
  fixedVersion: '4.17.21',
  kevDateAdded: '2026-11-03',
  targets: ['main', 'release/2.x'],
  ...over,
});
const exploitedOne: ChatExploitedMessage = {
  type: 'exploited',
  projects: [{ id: P, key: 'acme/payments', name: 'Payments', rows: [xrow(1)], more: 0 }],
  moreProjects: 0,
};
const PB = '0190a6c2-0000-7000-8000-0000000000a2';
const PC = '0190a6c2-0000-7000-8000-0000000000a3';
const exploitedThree: ChatExploitedMessage = {
  type: 'exploited',
  projects: [
    { id: P, key: 'a', name: 'Payments', rows: [1, 2, 3, 4, 5, 6].map((i) => xrow(i)), more: 0 },
    {
      id: PB,
      key: 'b',
      name: 'Billing',
      rows: [7, 8, 9, 10].map((i) => xrow(i, { fixedVersion: null })),
      more: 2,
    },
    { id: PC, key: 'c', name: 'Checkout', rows: [], more: 3 },
  ],
  moreProjects: 4,
};
const ROW1 =
  'CVE-2026-1001* (Critical) in lodash 4.17.20, 4.17.19 — fixed in 4.17.21 · main, release/2.x · in KEV since 2026-11-03';

const vulnSection = {
  critical: 3,
  high: 5,
  exploited: 1 as number | null,
  projects: [
    {
      projectId: P,
      name: 'Payments',
      critical: 2,
      high: 1,
      exploited: 1 as number | null,
      targets: ['main', 'release/2.x'],
      moreTargets: 3,
    },
    {
      projectId: PB,
      name: 'Billing',
      critical: 1,
      high: 4,
      exploited: 0 as number | null,
      targets: ['main'],
      moreTargets: 0,
    },
  ],
  moreProjects: 2,
};
const digestWithVulns: ChatDigestMessage = { ...digest, vulnerabilities: vulnSection };

type SlackOut = {
  text: string;
  blocks: { type: string; text?: { text: string }; elements?: { url?: string }[] }[];
};

describe('exploited messages', () => {
  it('Slack golden: one project, one row', () => {
    expect(formatChat('slack', exploitedOne, LINKS)).toEqual({
      text: 'Exploited vulnerability in Payments',
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: 'Exploited vulnerability in Payments', emoji: false },
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            verbatim: true,
            text: `*<${VULN_URL(P)}|Payments>*\n• *${ROW1}`,
          },
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: 'Open in Qualor' },
              url: VULN_URL(P),
              style: 'danger',
            },
          ],
        },
      ],
    });
  });

  it('Teams golden: one project, one row', () => {
    expect(formatChat('teams', exploitedOne, LINKS)).toEqual({
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          contentUrl: null,
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            type: 'AdaptiveCard',
            version: '1.4',
            msteams: { width: 'Full' },
            body: [
              {
                type: 'TextBlock',
                text: 'Exploited vulnerability in Payments',
                weight: 'Bolder',
                size: 'Medium',
                color: 'Attention',
                wrap: true,
              },
              {
                type: 'TextBlock',
                text: `[Payments](${VULN_URL(P)})`,
                weight: 'Bolder',
                spacing: 'Medium',
                wrap: true,
              },
              { type: 'TextBlock', text: `- CVE-2026-1001${ROW1.slice(14)}`, wrap: true },
            ],
            actions: [{ type: 'Action.OpenUrl', title: 'Open in Qualor', url: VULN_URL(P) }],
          },
        },
      ],
    });
  });

  it('titles: one project with several rows, and several projects', () => {
    const many: ChatExploitedMessage = {
      ...exploitedOne,
      projects: [{ ...exploitedOne.projects[0]!, rows: [xrow(1), xrow(2)] }],
    };
    expect((formatChat('slack', many, LINKS) as SlackOut).text).toBe(
      '2 exploited vulnerabilities in Payments',
    );
    const withMore: ChatExploitedMessage = {
      ...exploitedOne,
      projects: [{ ...exploitedOne.projects[0]!, more: 3 }],
    };
    expect((formatChat('slack', withMore, LINKS) as SlackOut).text).toBe(
      '4 exploited vulnerabilities in Payments',
    );
    expect((formatChat('slack', exploitedThree, LINKS) as SlackOut).text).toBe(
      'Exploited vulnerabilities in 7 projects',
    );
  });

  it('three projects: the third has only its count; the button opens the projects list', () => {
    const slack = formatChat('slack', exploitedThree, LINKS) as SlackOut;
    const texts = slack.blocks.map((b) => b.text?.text ?? '');
    expect(texts[1]).toContain('*<' + VULN_URL(P) + '|Payments>*');
    expect(texts[1]!.split('\n')).toHaveLength(7);
    expect(texts[2]).toContain('no fix yet');
    expect(texts[2]).not.toContain('fixed in');
    expect(texts[2]).toContain('…and 2 more');
    expect(texts[3]).toBe('*<' + VULN_URL(PC) + '|Checkout>*\n…and 3 more');
    expect(texts[4]).toBe('…and 4 more projects');
    const last = slack.blocks[slack.blocks.length - 1]!;
    expect(last.elements![0]!.url).toBe('https://qualor.example.com/projects');
    const teams = JSON.stringify(formatChat('teams', exploitedThree, LINKS));
    expect(teams).toContain('…and 3 more');
    expect(teams).toContain('…and 4 more projects');
    expect(teams).toContain('"url":"https://qualor.example.com/projects"');
  });

  it('Teams golden: three projects, the third with only its count', () => {
    const line = (i: number, fix: string) =>
      `- CVE-2026-${1000 + i} (Critical) in lodash 4.17.20, 4.17.19 — ${fix} · main, release/2.x · in KEV since 2026-11-03`;
    const h = (id: string, name: string) => ({
      type: 'TextBlock',
      text: `[${name}](${VULN_URL(id)})`,
      weight: 'Bolder',
      spacing: 'Medium',
      wrap: true,
    });
    const t = (text: string) => ({ type: 'TextBlock', text, wrap: true });
    expect(formatChat('teams', exploitedThree, LINKS)).toEqual({
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          contentUrl: null,
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            type: 'AdaptiveCard',
            version: '1.4',
            msteams: { width: 'Full' },
            body: [
              {
                type: 'TextBlock',
                text: 'Exploited vulnerabilities in 7 projects',
                weight: 'Bolder',
                size: 'Medium',
                color: 'Attention',
                wrap: true,
              },
              h(P, 'Payments'),
              t([1, 2, 3, 4, 5, 6].map((i) => line(i, 'fixed in 4.17.21')).join('\n')),
              h(PB, 'Billing'),
              t([...[7, 8, 9, 10].map((i) => line(i, 'no fix yet')), '- …and 2 more'].join('\n')),
              h(PC, 'Checkout'),
              t('- …and 3 more'),
              t('…and 4 more projects'),
            ],
            actions: [
              {
                type: 'Action.OpenUrl',
                title: 'Open in Qualor',
                url: 'https://qualor.example.com/projects',
              },
            ],
          },
        },
      ],
    });
  });

  it('has no URL, link or button without a public URL', () => {
    for (const kind of ['slack', 'teams'] as const) {
      const json = JSON.stringify(formatChat(kind, exploitedOne, NO_LINKS));
      expect(json).not.toContain('https://');
      expect(json).not.toContain('"actions"');
      expect(json).not.toContain('Action.OpenUrl');
      expect(json).toContain('CVE-2026-1001');
    }
  });

  it('hostile names and ids stay inert', () => {
    const hostile: ChatExploitedMessage = {
      type: 'exploited',
      projects: [
        {
          id: P,
          key: 'k',
          name: '<!channel> *x* [a](https://evil.example)',
          rows: [
            xrow(1, {
              vulnerabilityId: '<!here>',
              packageName: '@channel',
              targets: ['<@U1>', '*b*'],
              installedVersions: ['_1_'],
            }),
          ],
          more: 0,
        },
      ],
      moreProjects: 0,
    };
    const slack = formatChat('slack', hostile, LINKS) as SlackOut;
    expect(slack.text).not.toMatch(/<!channel>|\*x\*/);
    for (const b of slack.blocks.slice(1)) {
      expect(b.text?.text ?? '').not.toMatch(/<!channel>|<!here>|<@U1>|@channel/);
    }
    const teams = JSON.stringify(formatChat('teams', hostile, LINKS));
    expect(teams).not.toContain('[a](');
    expect(teams).not.toContain('*x*');
  });

  it('worst case stays within Slack sections and the Teams size', () => {
    const big = (kind: 'slack' | 'teams') => {
      const rows = Array.from({ length: 10 }, (_, i) =>
        xrow(i, {
          vulnerabilityId: '*'.repeat(200),
          packageName: '_'.repeat(300),
          installedVersions: ['*'.repeat(300)],
          targets: Array.from({ length: 50 }, () => '`'.repeat(50)),
        }),
      );
      const m: ChatExploitedMessage = {
        type: 'exploited',
        projects: [
          { id: P, key: 'k', name: '['.repeat(300), rows, more: 5 },
          ...Array.from({ length: 19 }, (_, i) => ({
            id: PB,
            key: String(i),
            name: '*'.repeat(300),
            rows: [],
            more: 1,
          })),
        ],
        moreProjects: 9,
      };
      return formatChat(kind, m, LINKS);
    };
    const slack = big('slack') as SlackOut;
    expect(slack.blocks.length).toBeLessThanOrEqual(50);
    for (const b of slack.blocks) {
      expect([...(b.text?.text ?? '')].length).toBeLessThanOrEqual(3000);
    }
    const first = slack.blocks[1]!.text!.text.split('\n');
    // Rows that do not fit are folded into the project's "more" line, whole lines only.
    expect(first[first.length - 1]).toMatch(/^…and \d+ more$/);
    expect(Buffer.byteLength(JSON.stringify(big('teams')), 'utf8')).toBeLessThan(28_000);
  });

  it('parses its own event only', () => {
    expect(parseChatMessage('vulnerabilities.exploited', exploitedOne)).toEqual(exploitedOne);
    expect(parseChatMessage('digest.weekly', exploitedOne)).toBeNull();
    expect(parseChatMessage('vulnerabilities.exploited', digest)).toBeNull();
    expect(parseChatMessage('vulnerabilities.exploited', { ...exploitedOne, x: 1 })).toBeNull();
  });

  it('refuses more rows or projects than the caps', () => {
    const rowsOf = (n: number) => Array.from({ length: n }, (_, i) => xrow(i));
    const p0 = exploitedOne.projects[0]!;
    const rows11 = { ...exploitedOne, projects: [{ ...p0, rows: rowsOf(11) }] };
    expect(parseChatMessage('vulnerabilities.exploited', rows11)).toBeNull();
    const split = {
      ...exploitedOne,
      projects: [
        { ...p0, rows: rowsOf(6) },
        { ...p0, rows: rowsOf(5) },
      ],
    };
    expect(parseChatMessage('vulnerabilities.exploited', split)).toBeNull();
    const projects21 = {
      ...exploitedOne,
      projects: Array.from({ length: 21 }, () => ({ ...p0, rows: [] })),
    };
    expect(parseChatMessage('vulnerabilities.exploited', projects21)).toBeNull();
  });
});

describe('digest vulnerability section', () => {
  it('Slack: its own section between the projects and the top issues', () => {
    const slack = formatChat('slack', digestWithVulns, LINKS) as SlackOut;
    const texts = slack.blocks.map((b) => b.text?.text ?? '');
    const i = texts.findIndex((t) => t.startsWith('*Vulnerabilities in tracked versions*'));
    expect(texts[i - 1]).toMatch(/^\*Projects\*/);
    expect(texts[i + 1]).toMatch(/^\*Top new issues\*/);
    expect(texts[i]).toBe(
      [
        '*Vulnerabilities in tracked versions*',
        '*3* critical · *5* high new vulnerabilities · *1* exploited',
        `• <${VULN_URL(P)}|Payments> — 2 critical, 1 high, 1 exploited · main, release/2.x +3 more`,
        `• <${VULN_URL(PB)}|Billing> — 1 critical, 4 high, 0 exploited · main`,
        '…and 2 more projects',
      ].join('\n'),
    );
  });

  it('Slack: no exploited count without vuln.priority (null)', () => {
    const m: ChatDigestMessage = {
      ...digest,
      vulnerabilities: {
        ...vulnSection,
        exploited: null,
        moreProjects: 0,
        projects: [{ ...vulnSection.projects[1]!, exploited: null }],
      },
    };
    const text = JSON.stringify(formatChat('slack', m, NO_LINKS));
    expect(text).toContain('*3* critical · *5* high new vulnerabilities\\n');
    expect(text).toContain('Billing — 1 critical, 4 high · main');
    expect(text).not.toContain('exploited');
    expect(text).not.toContain('https://');
  });

  it('Teams: a heading and TextBlocks in the same place', () => {
    const card = (
      formatChat('teams', digestWithVulns, LINKS) as {
        attachments: { content: { body: { type: string; text?: string }[] } }[];
      }
    ).attachments[0]!.content.body;
    const i = card.findIndex((b) => b.text === 'Vulnerabilities in tracked versions');
    expect(card[i - 2]!.text).toBe('Projects');
    expect(card[i + 1]!.text).toBe('3 critical · 5 high new vulnerabilities · 1 exploited');
    expect(card[i + 2]!.text).toBe(
      [
        `- [Payments](${VULN_URL(P)}) — 2 critical, 1 high, 1 exploited · main, release/2.x +3 more`,
        `- [Billing](${VULN_URL(PB)}) — 1 critical, 4 high, 0 exploited · main`,
        '- …and 2 more projects',
      ].join('\n'),
    );
    expect(card[i + 3]!.text).toBe('Top new issues');
  });

  it('a 6G digest without the section is unchanged and still parses', () => {
    expect(JSON.stringify(formatChat('slack', digest, LINKS))).not.toContain('Vulnerabilities in');
    expect(JSON.stringify(formatChat('teams', digest, LINKS))).not.toContain('Vulnerabilities in');
    expect(parseChatMessage('digest.weekly', digest)).toEqual(digest);
    expect(parseChatMessage('digest.weekly', digestWithVulns)).toEqual(digestWithVulns);
  });

  it('refuses more projects or targets than the caps', () => {
    const p = vulnSection.projects[0]!;
    const many = { ...vulnSection, projects: Array.from({ length: 11 }, () => p) };
    expect(parseChatMessage('digest.weekly', { ...digest, vulnerabilities: many })).toBeNull();
    const targets = Array.from({ length: MAX_TARGET_NAMES + 1 }, (_, i) => `t${i}`);
    const wide = { ...vulnSection, projects: [{ ...p, targets }] };
    expect(parseChatMessage('digest.weekly', { ...digest, vulnerabilities: wide })).toBeNull();
  });

  it('Slack: lines that do not fit 3000 characters fold into the tail', () => {
    const projects = Array.from({ length: 10 }, (_, i) => ({
      projectId: `0190a6c2-0000-7000-8000-${String(i).padStart(12, '0')}`,
      name: '*'.repeat(500),
      critical: 1,
      high: 1,
      exploited: 1 as number | null,
      targets: Array.from({ length: 5 }, () => '_'.repeat(200)),
      moreTargets: 9,
    }));
    const m: ChatDigestMessage = {
      ...digest,
      rows: [],
      quietProjects: 0,
      top: [],
      vulnerabilities: { ...vulnSection, projects, moreProjects: 7 },
    };
    const slack = formatChat('slack', m, LINKS) as SlackOut;
    for (const b of slack.blocks) {
      expect([...(b.text?.text ?? '')].length).toBeLessThanOrEqual(3000);
    }
    const text = slack.blocks.map((b) => b.text?.text ?? '').find((t) => t.includes('tracked'))!;
    const lines = text.split('\n');
    const shown = lines.filter((l) => l.startsWith('• ')).length;
    const more = Number(/…and (\d+) more projects/.exec(text)?.[1]);
    expect(shown).toBeLessThan(10);
    expect(shown + more).toBe(17);
    const teams = JSON.stringify(formatChat('teams', m, LINKS));
    expect(Buffer.byteLength(teams, 'utf8')).toBeLessThan(28_000);
  });
});

describe('combined worst case', () => {
  const hostileVulns = (): ChatDigestMessage['vulnerabilities'] => ({
    critical: 99,
    high: 99,
    exploited: 99,
    projects: Array.from({ length: 10 }, (_, i) => ({
      projectId: `0190a6c2-0000-7000-8000-${String(i).padStart(12, '0')}`,
      name: '[*_`'.repeat(125),
      critical: 9,
      high: 9,
      exploited: 9 as number | null,
      targets: Array.from({ length: 5 }, () => '[*_`'.repeat(50)),
      moreTargets: 99,
    })),
    moreProjects: 7,
  });
  const full = (): ChatDigestMessage => ({
    ...digest,
    scope: { ...digest.scope, organization: { id: O, name: '*'.repeat(500) } },
    rows: Array.from({ length: 20 }, (_, i) => row(i + 1, { name: '[*_`'.repeat(125) })),
    moreProjects: 7,
    top: Array.from({ length: 3 }, () => ({
      ...digest.top[0]!,
      projectName: '*'.repeat(500),
      ruleName: '_'.repeat(500),
      path: '[]'.repeat(250),
    })),
    vulnerabilities: hostileVulns(),
  });

  it('Teams: a full digest plus a maximal section stays under 28 KB, and counts every project', () => {
    const card = formatChat('teams', full(), LINKS) as {
      attachments: { content: { body: { text?: string }[] } }[];
    };
    expect(Buffer.byteLength(JSON.stringify(card), 'utf8')).toBeLessThan(28_000);
    const body = card.attachments[0]!.content.body;
    const i = body.findIndex((b) => b.text === 'Vulnerabilities in tracked versions');
    const lines = body[i + 2]!.text!.split('\n');
    const shown = lines.filter((l) => !l.startsWith('- …and')).length;
    const more = Number(/…and (\d+) more projects/.exec(lines[lines.length - 1]!)?.[1]);
    expect(shown).toBeLessThan(10);
    expect(shown + more).toBe(17);
  });

  it('Slack: every section of the same digest is within 3000 characters', () => {
    const slack = formatChat('slack', full(), LINKS) as SlackOut;
    expect(slack.blocks.length).toBeLessThanOrEqual(50);
    for (const b of slack.blocks) {
      expect([...(b.text?.text ?? '')].length).toBeLessThanOrEqual(3000);
    }
    const text = slack.blocks.map((b) => b.text?.text ?? '').find((t) => t.includes('tracked'))!;
    const shown = text.split('\n').filter((l) => l.startsWith('• ')).length;
    const more = Number(/…and (\d+) more projects/.exec(text)?.[1]);
    expect(shown + more).toBe(17);
  });
});

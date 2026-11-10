import { describe, expect, it } from 'vitest';
import { sendWebhook } from '../send';
import { chatLinks, formatChat } from './format';
import type {
  ChatDigestMessage,
  ChatExploitedMessage,
  ChatGateMessage,
  ChatMessage,
} from './messages';

/**
 * 6G spec §7: real messages to a real Slack and Teams channel. Never part of `pnpm test` or CI
 * (the unit project excludes `*.live.test.ts`); `pnpm chat:live` with QUALOR_SLACK_WEBHOOK_URL
 * and/or QUALOR_TEAMS_WEBHOOK_URL set. Look at the channel afterwards: the test only sees 2xx.
 */
const MESSAGE: ChatGateMessage = {
  type: 'gate',
  event: 'gate.failed',
  cause: 'analysis',
  project: {
    id: '0190a6c2-0000-7000-8000-0000000000a1',
    key: 'acme/payments',
    name: 'Payments <!here> *test*',
  },
  branch: { id: '0190a6c2-0000-7000-8000-0000000000b1', name: 'main' },
  analysisId: '0190a6c2-0000-7000-8000-0000000000c1',
  revision: '3f9c2e1aa0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5',
  at: new Date().toISOString(),
  gate: { name: 'Qualor way', status: 'failed' },
  failed: [
    { metric: 'new_issues', operator: 'gt', threshold: 0, value: 2 },
    { metric: 'new_coverage', operator: 'lt', threshold: 80, value: 61.5 },
  ],
  failedCount: 2,
  newIssues: { security: 2, reliability: 0, maintainability: 1 },
};

const PROJECT = '0190a6c2-0000-7000-8000-0000000000a1';
const EXPLOITED: ChatExploitedMessage = {
  type: 'exploited',
  projects: [
    {
      id: PROJECT,
      key: 'acme/payments',
      name: 'Payments <!here> *test*',
      rows: [
        {
          vulnerabilityId: 'CVE-2026-1001',
          severity: 'critical',
          title: 'Prototype pollution in lodash',
          packageName: 'lodash',
          installedVersions: ['4.17.20', '4.17.19'],
          fixedVersion: '4.17.21',
          kevDateAdded: '2026-11-03',
          targets: ['main', 'release/2.x'],
        },
        {
          vulnerabilityId: 'CVE-2026-1002',
          severity: 'high',
          title: null,
          packageName: 'axios',
          installedVersions: ['0.21.1'],
          fixedVersion: null,
          kevDateAdded: '2026-11-04',
          targets: ['main'],
        },
      ],
      more: 0,
    },
  ],
  moreProjects: 0,
};
const DIGEST: ChatDigestMessage = {
  type: 'digest',
  week: '2026-W45',
  since: '2026-11-02T08:00:00.000Z',
  until: '2026-11-09T08:00:00.000Z',
  timezone: 'Europe/Berlin',
  scope: {
    organization: { id: '0190a6c2-0000-7000-8000-0000000000f1', name: 'Acme' },
    project: null,
  },
  totals: {
    projects: 3,
    failing: 1,
    newSecurity: 2,
    openSecurity: 9,
    newBySeverity: { blocker: 0, high: 2, medium: 0, low: 0, info: 0 },
  },
  rows: [
    {
      projectId: PROJECT,
      name: 'Payments <!here> *test*',
      gate: 'failed',
      newSecurity: 2,
      newBySeverity: { blocker: 0, high: 2, medium: 0, low: 0, info: 0 },
      openSecurity: 9,
    },
  ],
  moreProjects: 0,
  quietProjects: 2,
  top: [],
  vulnerabilities: {
    critical: 2,
    high: 3,
    exploited: 1,
    projects: [
      {
        projectId: PROJECT,
        name: 'Payments <!here> *test*',
        critical: 2,
        high: 3,
        exploited: 1,
        targets: ['main', 'release/2.x'],
        moreTargets: 0,
      },
    ],
    moreProjects: 0,
  },
};

async function deliverLive(kind: 'slack' | 'teams', url: string, message: ChatMessage = MESSAGE) {
  return sendWebhook(
    {
      url,
      body: JSON.stringify(formatChat(kind, message, chatLinks('https://qualor.example.com'))),
      headers: { 'content-type': 'application/json', 'user-agent': 'Qualor-Webhook/live-test' },
    },
    { allowInternalHosts: false, timeoutMs: 15_000 },
  );
}

describe('live webhooks', () => {
  const targets = {
    slack: process.env.QUALOR_SLACK_WEBHOOK_URL,
    teams: process.env.QUALOR_TEAMS_WEBHOOK_URL,
  };
  const messages = [
    ['a gate message', MESSAGE],
    ['an exploited vulnerability message', EXPLOITED],
    ['a digest with the vulnerability section', DIGEST],
  ] as const;
  for (const kind of ['slack', 'teams'] as const) {
    for (const [name, message] of messages) {
      it(`${kind} accepts ${name}`, async (ctx) => {
        const url = targets[kind];
        if (!url) return ctx.skip();
        const outcome = await deliverLive(kind, url, message);
        expect(outcome.ok, `${outcome.status} ${outcome.excerpt}`).toBe(true);
      });
    }
  }
});

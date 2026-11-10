import { describe, expect, it } from 'vitest';
import { parseInternalHosts } from '../../scm/url';
import { canonicalTimeZone, chatUrlProblem, eventsOf, eventsProblem, maskChatUrl } from './kinds';

const strict = { allowHttp: false, allowInternalHosts: false };
const none = new Set<string>();

describe('chatUrlProblem (6G R1)', () => {
  it.each([
    ['slack', 'https://hooks.slack.com/services/T0001/B0001/abcdEFGHijkl'],
    ['slack', 'https://hooks.slack.com/triggers/T0001/12345/abcdef'],
    [
      'teams',
      'https://default0a1b2c.d1.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=xyz',
    ],
    [
      'teams',
      'https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=xyz',
    ],
  ] as const)('accepts a %s URL %s', (kind, url) => {
    expect(chatUrlProblem(kind, url, strict, none)).toBeNull();
  });

  it.each([
    ['slack', 'https://hooks.slack.com/api/chat.postMessage', /Slack incoming webhook URL/],
    ['slack', 'https://hooks.slack.com.evil.example/services/T/B/x', /Slack incoming webhook URL/],
    ['slack', 'https://evilhooks.slack.com/services/T/B/x', /Slack incoming webhook URL/],
    ['slack', 'https://hooks.slack.com:8443/services/T/B/x', /Slack incoming webhook URL/],
    ['slack', 'http://hooks.slack.com/services/T/B/x', /https/],
    ['teams', 'https://xlogic.azure.com/workflows/x', /Teams Workflows webhook URL/],
    ['teams', 'https://environment.api.powerplatform.com/x', /Teams Workflows webhook URL/],
    ['teams', 'https://acme.webhook.office.com/webhookb2/abc', /Office 365 connectors/],
    ['teams', 'https://outlook.office.com/webhook/abc', /Office 365 connectors/],
    ['teams', 'https://outlook.office365.com/webhook/abc', /Office 365 connectors/],
    ['teams', 'https://acme.outlook.office.com/webhook/abc', /Office 365 connectors/],
    ['teams', 'https://hooks.slack.com/services/T/B/x', /Teams Workflows webhook URL/],
    [
      'slack',
      'https://u:p@hooks.slack.com/services/T/B/x',
      /^The URL must not contain credentials$/,
    ],
    ['slack', 'https://hooks.slack.com./services/T/B/x', /trailing dot/],
    ['slack', 'https://hooks.slack.com@evil.example/services/x', /credentials/],
    ['slack', 'https://hооks.slack.com/services/T/B/x', /Slack incoming webhook URL/],
    ['slack', 'https://hooks.slack.com/services/../api/x', /Slack incoming webhook URL/],
  ] as const)('refuses a %s URL %s', (kind, url, message) => {
    expect(chatUrlProblem(kind, url, strict, none)).toMatch(message);
  });

  it.each(['https://HOOKS.Slack.COM/services/T/B/x', 'https://hooks.slack.com:443/services/T/B/x'])(
    'accepts %s',
    (url) => {
      expect(chatUrlProblem('slack', url, strict, none)).toBeNull();
    },
  );

  it('accepts a listed test host, still under the instance URL settings (R7)', () => {
    const hosts = parseInternalHosts('127.0.0.1:4285');
    const local = { allowHttp: true, allowInternalHosts: true };
    expect(
      chatUrlProblem('slack', 'http://127.0.0.1:4285/services/T/B/x', local, hosts),
    ).toBeNull();
    expect(chatUrlProblem('slack', 'http://127.0.0.1:4285/services/T/B/x', strict, hosts)).toMatch(
      /https/,
    );
    expect(chatUrlProblem('slack', 'http://127.0.0.1:4286/services/T/B/x', local, hosts)).toMatch(
      /Slack incoming webhook URL/,
    );
  });
});

describe('maskChatUrl (6G R3)', () => {
  it('keeps the Slack path kind and the last 4 characters', () => {
    expect(
      maskChatUrl('slack', 'https://hooks.slack.com/services/T0001/B0001/abcdEFGHijklUVWX'),
    ).toBe('https://hooks.slack.com/services/T…/…/UVWX');
    expect(maskChatUrl('slack', 'https://hooks.slack.com/triggers/T0001/123/abcdef')).toBe(
      'https://hooks.slack.com/triggers/T…/…/cdef',
    );
  });

  it('keeps the Teams host and the last 4 characters, never the signature', () => {
    const masked = maskChatUrl(
      'teams',
      'https://default0a.d1.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?api-version=1&sig=SECRETsig9Z',
    );
    expect(masked).toBe('https://default0a.d1.environment.api.powerplatform.com/…ig9Z');
    expect(masked).not.toContain('SECRET');
    expect(new URL(masked).origin).toBe('https://default0a.d1.environment.api.powerplatform.com');
  });
});

describe('events per kind (6G R4)', () => {
  it('lists each kind its events', () => {
    expect(eventsOf('generic')).toEqual([
      'analysis.completed',
      'gate.status_changed',
      'vulnerabilities.found',
    ]);
    expect(eventsOf('slack')).toEqual([
      'gate.failed',
      'gate.recovered',
      'digest.weekly',
      'vulnerabilities.exploited',
    ]);
    expect(eventsOf('teams')).toEqual([
      'gate.failed',
      'gate.recovered',
      'digest.weekly',
      'vulnerabilities.exploited',
    ]);
  });

  it('refuses the other kind events', () => {
    expect(eventsProblem('generic', ['gate.failed'])).toMatch(/analysis.completed/);
    expect(eventsProblem('slack', ['analysis.completed'])).toMatch(/gate.failed/);
    expect(eventsProblem('teams', ['digest.weekly'])).toBeNull();
  });
});

describe('canonicalTimeZone', () => {
  it.each([
    ['UTC', 'UTC'],
    ['utc', 'UTC'],
    ['Europe/Berlin', 'Europe/Berlin'],
    ['europe/berlin', 'Europe/Berlin'],
    ['America/New_York', 'America/New_York'],
  ])('accepts %s as %s', (zone, canonical) => {
    expect(canonicalTimeZone(zone)).toBe(canonical);
  });

  it.each([
    '',
    'Mars/Olympus',
    'Europe/Berlin\u0000',
    'x'.repeat(65),
    '+02:00x',
    '+0200',
    '+02',
    '-05',
    '+02:00',
  ])('refuses %j', (zone) => {
    expect(canonicalTimeZone(zone)).toBeNull();
  });
});

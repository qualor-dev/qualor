import { describe, expect, it } from 'vitest';
import { parseInternalHosts } from '../scm/url';
import { jiraApiUrlProblem, jiraHostAllowed, jiraSiteUrlProblem, normalJiraUrl } from './url';

const none = new Set<string>();
const UUID = '0D2A6C1E-5B7F-4E3A-9C8D-1F2E3A4B5C6D';

describe('Jira Cloud site URLs (spec §6.1)', () => {
  it('accepts https://<name>.atlassian.net and stores it without the trailing slash', () => {
    expect(jiraSiteUrlProblem('https://acme.atlassian.net/', 'cloud', none)).toBeNull();
    expect(jiraSiteUrlProblem('https://acme-eu2.atlassian.net', 'cloud', none)).toBeNull();
    expect(normalJiraUrl('https://acme.atlassian.net/')).toBe('https://acme.atlassian.net');
    expect(normalJiraUrl('https://ACME.atlassian.net')).toBe('https://acme.atlassian.net');
  });

  it.each([
    ['a path', 'https://acme.atlassian.net/jira'],
    ['http', 'http://acme.atlassian.net'],
    ['another host', 'https://evil.example'],
    ['a host that only starts like a site', 'https://acme.atlassian.net.evil.example'],
    ['a nested name', 'https://a.b.atlassian.net'],
    ['a port', 'https://acme.atlassian.net:8443'],
    ['credentials', 'https://user:secret@acme.atlassian.net'],
    ['a query', 'https://acme.atlassian.net/?x=1'],
    ['an empty query', 'https://acme.atlassian.net/?'],
    ['a fragment', 'https://acme.atlassian.net/#f'],
    ['garbage', 'not a url'],
  ])('refuses %s', (_what, raw) => {
    expect(jiraSiteUrlProblem(raw, 'cloud', none)).toEqual(expect.any(String));
  });

  it('refuses more than 2 048 characters, before anything else', () => {
    const raw = `https://acme.atlassian.net/${'a'.repeat(2_049 - 'https://acme.atlassian.net/'.length)}`;
    expect(raw).toHaveLength(2_049);
    expect(jiraSiteUrlProblem(raw, 'cloud', none)).toBe('The URL is too long');
  });

  it('never allows a Cloud site because of QUALOR_JIRA_INTERNAL_HOSTS', () => {
    const listed = parseInternalHosts('acme.atlassian.net, evil.example');
    expect(jiraSiteUrlProblem('https://evil.example', 'cloud', listed)).toEqual(expect.any(String));
    expect(jiraHostAllowed('https://acme.atlassian.net', 'cloud', listed)).toBe(false);
  });
});

describe('Jira Cloud API URLs (spec §6.1)', () => {
  it('accepts the gateway address of a cloud id, in any case, and stores the id in lower case', () => {
    const raw = `https://api.atlassian.com/ex/jira/${UUID}`;
    expect(jiraApiUrlProblem(raw)).toBeNull();
    expect(jiraApiUrlProblem(raw.toLowerCase())).toBeNull();
    expect(normalJiraUrl(raw)).toBe(`https://api.atlassian.com/ex/jira/${UUID.toLowerCase()}`);
  });

  it.each([
    ['another host', `https://api.example.com/ex/jira/${UUID}`],
    ['http', `http://api.atlassian.com/ex/jira/${UUID}`],
    ['a cloud id that is no UUID', 'https://api.atlassian.com/ex/jira/acme'],
    ['a short UUID', `https://api.atlassian.com/ex/jira/${UUID.slice(1)}`],
    ['a path after the id', `https://api.atlassian.com/ex/jira/${UUID}/rest`],
    ['a trailing slash', `https://api.atlassian.com/ex/jira/${UUID}/`],
    ['a query', `https://api.atlassian.com/ex/jira/${UUID}?x=1`],
    ['another product', `https://api.atlassian.com/ex/confluence/${UUID}`],
  ])('refuses %s', (_what, raw) => {
    expect(jiraApiUrlProblem(raw)).toEqual(expect.any(String));
  });

  it('keeps the case of a Data Center path that looks like the gateway path', () => {
    expect(normalJiraUrl(`https://jira.corp.example/ex/jira/${UUID}/`)).toBe(
      `https://jira.corp.example/ex/jira/${UUID}`,
    );
  });
});

describe('Jira Data Center base URLs (spec §6.1, §6.12)', () => {
  it('accepts a context path and stores it without the trailing slash', () => {
    expect(jiraSiteUrlProblem('https://jira.corp.example/jira/', 'data_center', none)).toBeNull();
    expect(normalJiraUrl('https://jira.corp.example/jira/')).toBe('https://jira.corp.example/jira');
  });

  it('allows http only for a listed host and port', () => {
    const raw = 'http://jira.corp:8080';
    expect(jiraSiteUrlProblem(raw, 'data_center', none)).toMatch(/QUALOR_JIRA_INTERNAL_HOSTS/);
    expect(jiraSiteUrlProblem(raw, 'data_center', parseInternalHosts('jira.corp'))).toMatch(
      /QUALOR_JIRA_INTERNAL_HOSTS/,
    );
    const listed = parseInternalHosts('jira.corp:8080');
    expect(jiraSiteUrlProblem(raw, 'data_center', listed)).toBeNull();
    expect(jiraHostAllowed(raw, 'data_center', listed)).toBe(true);
    expect(jiraHostAllowed(raw, 'data_center', none)).toBe(false);
  });

  it('allows a private address only when it is listed', () => {
    expect(jiraSiteUrlProblem('https://10.0.0.5', 'data_center', none)).toMatch(
      /non-public address; list the host in QUALOR_JIRA_INTERNAL_HOSTS/,
    );
    expect(
      jiraSiteUrlProblem('https://10.0.0.5', 'data_center', parseInternalHosts('10.0.0.5')),
    ).toBeNull();
  });

  it('never allows a link-local or cloud metadata address, listed or not', () => {
    const listed = parseInternalHosts('169.254.169.254');
    expect(jiraSiteUrlProblem('https://169.254.169.254', 'data_center', listed)).toBe(
      'The URL points at a link-local or cloud metadata address',
    );
  });

  it('refuses credentials, naming the token', () => {
    expect(jiraSiteUrlProblem('https://u:p@jira.corp.example', 'data_center', none)).toBe(
      'The URL must not contain credentials; use the token',
    );
  });

  it('answers false for a URL that cannot be read', () => {
    expect(jiraHostAllowed('not a url', 'data_center', parseInternalHosts('jira.corp'))).toBe(
      false,
    );
  });
});

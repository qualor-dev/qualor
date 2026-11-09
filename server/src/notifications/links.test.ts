import { describe, expect, it } from 'vitest';
import { vulnerabilityMailLinks, watchLinks, withUnsubscribe } from './links';
import { unsubscribeToken, vulnerabilityUnsubscribeToken } from './unsubscribe';

const KEY = 'test-secret-key-that-is-at-least-32-characters';
const USER = '0190a6c2-0000-7000-8000-00000000000a';
const PROJECT = '0190a6c2-0000-7000-8000-0000000000b1';
const MAIL = { subject: 's', html: '<p>h</p>', text: 't' };

describe('links in notification email (mail E3)', () => {
  it('builds every link from the public URL, keeping its path', () => {
    const token = unsubscribeToken(KEY, USER, PROJECT);
    expect(
      watchLinks({ publicUrl: 'https://qualor.example.com', secretKey: KEY }, USER, PROJECT),
    ).toEqual({
      publicUrl: 'https://qualor.example.com',
      instanceHost: 'qualor.example.com',
      token,
      unsubscribeUrl: `https://qualor.example.com/unsubscribe#t=${token}`,
      settingsUrl: 'https://qualor.example.com/settings/notifications',
    });
    expect(
      watchLinks({ publicUrl: 'https://qualor.example.com:8443/q', secretKey: KEY }, USER, PROJECT),
    ).toMatchObject({
      instanceHost: 'qualor.example.com:8443',
      settingsUrl: 'https://qualor.example.com:8443/q/settings/notifications',
    });
  });

  it('has no links and no host without a public URL (E1 M11)', () => {
    expect(watchLinks({ publicUrl: null, secretKey: KEY }, USER, PROJECT)).toMatchObject({
      publicUrl: null,
      instanceHost: null,
      unsubscribeUrl: null,
      settingsUrl: null,
    });
  });

  it('adds the RFC 8058 headers to a rendered message only with a public URL', () => {
    expect(withUnsubscribe(MAIL, null, 'a.b')).toEqual(MAIL);
    expect(withUnsubscribe(MAIL, 'https://q.example.com', 'a.b').headers).toEqual({
      'List-Unsubscribe': '<https://q.example.com/api/v0/notifications/unsubscribe?t=a.b>',
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
    });
  });

  it('builds the vulnerability email links: its own stop page, the same settings page', () => {
    const token = vulnerabilityUnsubscribeToken(KEY, USER);
    expect(
      vulnerabilityMailLinks({ publicUrl: 'https://qualor.example.com/q', secretKey: KEY }, USER),
    ).toEqual({
      publicUrl: 'https://qualor.example.com/q',
      instanceHost: 'qualor.example.com',
      token,
      unsubscribeUrl: `https://qualor.example.com/q/unsubscribe/vulnerabilities#t=${token}`,
      settingsUrl: 'https://qualor.example.com/q/settings/notifications',
    });
    expect(vulnerabilityMailLinks({ publicUrl: null, secretKey: KEY }, USER)).toMatchObject({
      publicUrl: null,
      instanceHost: null,
      unsubscribeUrl: null,
      settingsUrl: null,
    });
  });

  it('points the headers of a vulnerability email at its own endpoint', () => {
    expect(
      withUnsubscribe(
        MAIL,
        'https://q.example.com',
        'a.b',
        '/api/v0/notifications/unsubscribe/vulnerabilities',
      ).headers,
    ).toEqual({
      'List-Unsubscribe':
        '<https://q.example.com/api/v0/notifications/unsubscribe/vulnerabilities?t=a.b>',
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
    });
  });
});

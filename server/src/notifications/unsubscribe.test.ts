import { describe, expect, it } from 'vitest';
import {
  MAX_TOKEN_LENGTH,
  unsubscribeHeaders,
  unsubscribeToken,
  verifyUnsubscribeToken,
  verifyVulnerabilityUnsubscribeToken,
  vulnerabilityUnsubscribeToken,
} from './unsubscribe';

const KEY = 'test-secret-key-that-is-at-least-32-characters';
const OTHER_KEY = 'another-secret-key-that-is-at-least-32-chars';
const USER = '0190a6c2-0000-7000-8000-00000000000a';
const OTHER_USER = '0190a6c2-0000-7000-8000-00000000000c';
const PROJECT = '0190a6c2-0000-7000-8000-0000000000b1';

/** A token's first part, as the token module writes it: `<user>:<project>` in base64url. */
const payloadOf = (user: string, project: string): string =>
  Buffer.from(`${user}:${project}`).toString('base64url');

describe('unsubscribe tokens (mail E3 N5)', () => {
  it('round-trips a user and a project, URL-safe and short', () => {
    const token = unsubscribeToken(KEY, USER, PROJECT);
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    expect(token.length).toBeLessThanOrEqual(MAX_TOKEN_LENGTH);
    expect(verifyUnsubscribeToken(KEY, token)).toEqual({ userId: USER, projectId: PROJECT });
  });

  it('is the same for the same inputs (nothing stored, nothing random)', () => {
    expect(unsubscribeToken(KEY, USER, PROJECT)).toBe(unsubscribeToken(KEY, USER, PROJECT));
  });

  it('refuses a token made under another secret key', () => {
    expect(verifyUnsubscribeToken(OTHER_KEY, unsubscribeToken(KEY, USER, PROJECT))).toBeNull();
  });

  it('refuses another user put in front of a real tag, and a changed tag', () => {
    const token = unsubscribeToken(KEY, USER, PROJECT);
    const [payload, tag] = token.split('.') as [string, string];
    const forged = `${payloadOf(OTHER_USER, PROJECT)}.${tag}`;
    expect(verifyUnsubscribeToken(KEY, forged)).toBeNull();
    // The tag's first character (its last one holds only padding bits, which decoding ignores).
    const flipped = `${payload}.${tag.startsWith('A') ? 'B' : 'A'}${tag.slice(1)}`;
    expect(verifyUnsubscribeToken(KEY, flipped)).toBeNull();
  });

  it.each([
    '',
    '.',
    'abc',
    'a.b.c',
    `${'a'.repeat(300)}.${'b'.repeat(43)}`,
    `not base64!.${'b'.repeat(43)}`,
    `${payloadOf(USER, PROJECT)}.${'b'.repeat(42)}`,
  ])('refuses the malformed token %j', (token) => {
    expect(verifyUnsubscribeToken(KEY, token)).toBeNull();
  });

  it('names the one-click endpoint in the RFC 8058 headers, only with a public URL', () => {
    const token = unsubscribeToken(KEY, USER, PROJECT);
    expect(unsubscribeHeaders('https://qualor.example.com/q', token)).toEqual({
      'List-Unsubscribe': `<https://qualor.example.com/q/api/v0/notifications/unsubscribe?t=${token}>`,
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
    });
    expect(unsubscribeHeaders(null, token)).toBeUndefined();
  });

  it('never builds a header value that could break a line or the angle brackets', () => {
    const token = unsubscribeToken(KEY, USER, PROJECT);
    for (const url of [
      'https://x.example\r\nBcc: a@b.c',
      'https://x.example\n',
      'https://x>.example',
    ]) {
      expect(unsubscribeHeaders(url, token)).toBeUndefined();
    }
    const headers = unsubscribeHeaders('https://qualor.example.com', token);
    expect(Object.values(headers ?? {}).join('')).not.toMatch(/[\r\n]/);
  });
});

describe('vulnerability unsubscribe tokens (4b)', () => {
  it('round-trips a user, URL-safe and short', () => {
    const token = vulnerabilityUnsubscribeToken(KEY, USER);
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    expect(token.length).toBeLessThanOrEqual(MAX_TOKEN_LENGTH);
    expect(verifyVulnerabilityUnsubscribeToken(KEY, token)).toEqual({ userId: USER });
    expect(vulnerabilityUnsubscribeToken(KEY, USER)).toBe(token);
  });

  it('is not interchangeable with a project token, in either direction', () => {
    const project = unsubscribeToken(KEY, USER, PROJECT);
    const vulnerabilities = vulnerabilityUnsubscribeToken(KEY, USER);
    expect(verifyVulnerabilityUnsubscribeToken(KEY, project)).toBeNull();
    expect(verifyUnsubscribeToken(KEY, vulnerabilities)).toBeNull();
  });

  it('refuses another key, another user in front of a real tag, and malformed tokens', () => {
    const token = vulnerabilityUnsubscribeToken(KEY, USER);
    expect(verifyVulnerabilityUnsubscribeToken(OTHER_KEY, token)).toBeNull();
    const [, tag] = token.split('.') as [string, string];
    const forged = `${Buffer.from(OTHER_USER).toString('base64url')}.${tag}`;
    expect(verifyVulnerabilityUnsubscribeToken(KEY, forged)).toBeNull();
    for (const bad of ['', '.', 'abc', 'a.b.c', `${'a'.repeat(300)}.${'b'.repeat(43)}`]) {
      expect(verifyVulnerabilityUnsubscribeToken(KEY, bad)).toBeNull();
    }
  });

  it('points the one-click header at its own endpoint', () => {
    const token = vulnerabilityUnsubscribeToken(KEY, USER);
    const path = '/api/v0/notifications/unsubscribe/vulnerabilities';
    expect(unsubscribeHeaders('https://q.example.com', token, path)).toEqual({
      'List-Unsubscribe': `<https://q.example.com${path}?t=${token}>`,
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
    });
  });
});

import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

/**
 * mail E3 N5: the token of an email's "Stop watching this project" link and of its
 * `List-Unsubscribe` header: base64url(`<userId>:<projectId>`) `.` base64url(HMAC-SHA256), keyed
 * like the CSRF token (auth/sessions.ts) by HKDF of QUALOR_SECRET_KEY under its own label. Nothing
 * is stored; a new secret key makes every earlier link invalid.
 */

/** base64url of `<uuid>:<uuid>` is 98 characters and the tag 43: anything longer is not a token. */
export const MAX_TOKEN_LENGTH = 200;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PAYLOAD = /^[A-Za-z0-9_-]+$/;
const TAG = /^[A-Za-z0-9_-]{43}$/;

function tag(secretKey: string, payload: string, info = 'unsubscribe v1'): Buffer {
  const key = Buffer.from(hkdfSync('sha256', secretKey, 'qualor', info, 32));
  return createHmac('sha256', key).update(payload).digest();
}

export function unsubscribeToken(secretKey: string, userId: string, projectId: string): string {
  const payload = Buffer.from(`${userId}:${projectId}`, 'utf8').toString('base64url');
  return `${payload}.${tag(secretKey, payload).toString('base64url')}`;
}

/** The user and project of a token this server made, or null for anything else. */
export function verifyUnsubscribeToken(
  secretKey: string,
  token: string,
): { userId: string; projectId: string } | null {
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, given] = parts as [string, string];
  if (!PAYLOAD.test(payload) || !TAG.test(given)) return null;
  const expected = tag(secretKey, payload);
  const actual = Buffer.from(given, 'base64url');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  const ids = Buffer.from(payload, 'base64url').toString('utf8').split(':');
  if (ids.length !== 2) return null;
  const [userId, projectId] = ids as [string, string];
  return UUID.test(userId) && UUID.test(projectId) ? { userId, projectId } : null;
}

const VULNERABILITIES_INFO = 'unsubscribe vulnerabilities v1';

/**
 * 4b: the token of a vulnerability email's "Stop vulnerability emails" link: base64url(`<userId>`)
 * `.` base64url(HMAC-SHA256) under its own HKDF label, so a project token never verifies here
 * and this one never verifies as a project token.
 */
export function vulnerabilityUnsubscribeToken(secretKey: string, userId: string): string {
  const payload = Buffer.from(userId, 'utf8').toString('base64url');
  return `${payload}.${tag(secretKey, payload, VULNERABILITIES_INFO).toString('base64url')}`;
}

/** The user of a token {@link vulnerabilityUnsubscribeToken} made, or null for anything else. */
export function verifyVulnerabilityUnsubscribeToken(
  secretKey: string,
  token: string,
): { userId: string } | null {
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, given] = parts as [string, string];
  if (!PAYLOAD.test(payload) || !TAG.test(given)) return null;
  const expected = tag(secretKey, payload, VULNERABILITIES_INFO);
  const actual = Buffer.from(given, 'base64url');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  const userId = Buffer.from(payload, 'base64url').toString('utf8');
  return UUID.test(userId) ? { userId } : null;
}

export type UnsubscribeHeaders = { 'List-Unsubscribe': string; 'List-Unsubscribe-Post': string };

/** RFC 8058 one-click headers; none without QUALOR_PUBLIC_URL (there is nothing to point at). */
export function unsubscribeHeaders(
  publicUrl: string | null,
  token: string,
  path = '/api/v0/notifications/unsubscribe',
): UnsubscribeHeaders | undefined {
  // A header value stays one line and one `<URL>` (the config already validates the URL).
  if (publicUrl === null || /[\s<>]/.test(publicUrl)) return undefined;
  return {
    'List-Unsubscribe': `<${publicUrl}${path}?t=${encodeURIComponent(token)}>`,
    'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
  };
}

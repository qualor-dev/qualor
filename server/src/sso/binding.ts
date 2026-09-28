import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';

/** sso-scim.md §7.2: ties a flow to the browser that started it (login CSRF, SS4). */
export const SSO_COOKIE = 'qualor_sso';
const PATH = '/api/v0/ee/sso';
/** Seconds: as long as a flow row lives (`FLOW_TTL_MS`). */
const MAX_AGE_SECONDS = 600;
/** 32 random bytes in base64url. */
const COOKIE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;

const hashOf = (cookie: string): string =>
  createHash('sha256').update(cookie, 'utf8').digest('hex');

/** A new cookie value, and the SHA-256 (hex) the flow row stores instead of it. */
export function newBinding(): { cookie: string; hash: string } {
  const cookie = randomBytes(32).toString('base64url');
  return { cookie, hash: hashOf(cookie) };
}

/** HttpOnly, SameSite=Lax (the top-level redirect back from the IdP carries it), Secure on https. */
export function setBindingCookie(
  reply: FastifyReply,
  request: FastifyRequest,
  cookie: string,
): void {
  reply.setCookie(SSO_COOKIE, cookie, {
    path: PATH,
    httpOnly: true,
    sameSite: 'lax',
    secure: request.protocol === 'https',
    maxAge: MAX_AGE_SECONDS,
  });
}

export function clearBindingCookie(reply: FastifyReply): void {
  reply.clearCookie(SSO_COOKIE, { path: PATH, httpOnly: true, sameSite: 'lax' });
}

/** Constant time; a missing or malformed cookie, or a malformed stored hash, never matches. */
export function bindingMatches(cookie: string | undefined, hash: string): boolean {
  if (typeof cookie !== 'string' || !COOKIE_PATTERN.test(cookie)) return false;
  if (typeof hash !== 'string' || !HASH_PATTERN.test(hash)) return false;
  return timingSafeEqual(Buffer.from(hashOf(cookie), 'hex'), Buffer.from(hash, 'hex'));
}

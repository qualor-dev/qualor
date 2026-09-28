import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { and, eq, ne } from 'drizzle-orm';
import type { CookieSerializeOptions } from '@fastify/cookie';
import type { FastifyRequest } from 'fastify';
import type { Executor } from '../db/client';
import { sessions, users } from '../db/schema';

export const SESSION_COOKIE = 'qualor_session';
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/; // 32 random bytes, base64url
const TOUCH_INTERVAL_MS = 60_000;

export type UserRow = typeof users.$inferSelect;

/**
 * The `qualor_session` cookie's options, for a password sign-in and an SSO one alike
 * (sso-scim.md §7.5), so the two cannot drift.
 */
export function sessionCookieOptions(
  request: FastifyRequest,
  expires: Date,
): CookieSerializeOptions {
  return {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: request.protocol === 'https',
    expires,
  };
}

export function sessionIdFor(secret: string): Buffer {
  return createHash('sha256').update(secret, 'utf8').digest();
}

/** Ruling R13: HMAC of the session cookie under an HKDF-derived key; nothing extra stored. */
export function csrfTokenFor(secretKey: string, sessionSecret: string): string {
  const key = Buffer.from(hkdfSync('sha256', secretKey, 'qualor', 'csrf v1', 32));
  return createHmac('sha256', key).update(sessionSecret).digest('base64url');
}

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

export interface NewSession {
  userId: string;
  ttlHours: number;
  ip: string | null;
  userAgent: string | null;
}

export async function createSession(
  db: Executor,
  input: NewSession,
): Promise<{ secret: string; expiresAt: Date }> {
  const secret = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + input.ttlHours * 3_600_000);
  await db.insert(sessions).values({
    id: sessionIdFor(secret),
    userId: input.userId,
    expiresAt,
    ip: input.ip,
    userAgent: input.userAgent?.slice(0, 512) ?? null,
  });
  return { secret, expiresAt };
}

export async function resolveSession(db: Executor, secret: string): Promise<UserRow | null> {
  if (!SECRET_PATTERN.test(secret)) return null;
  const id = sessionIdFor(secret);
  const [row] = await db
    .select({ session: sessions, user: users })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(eq(sessions.id, id));
  if (!row) return null;
  const now = Date.now();
  if (row.session.expiresAt.getTime() <= now) {
    await db.delete(sessions).where(eq(sessions.id, id));
    return null;
  }
  if (!row.user.active) return null;
  if (now - row.session.lastSeenAt.getTime() >= TOUCH_INTERVAL_MS) {
    await db
      .update(sessions)
      .set({ lastSeenAt: new Date(now) })
      .where(eq(sessions.id, id));
  }
  return row.user;
}

export async function deleteSession(db: Executor, secret: string): Promise<void> {
  if (!SECRET_PATTERN.test(secret)) return;
  await db.delete(sessions).where(eq(sessions.id, sessionIdFor(secret)));
}

export async function deleteUserSessions(
  db: Executor,
  userId: string,
  keepSecret?: string,
): Promise<void> {
  await db
    .delete(sessions)
    .where(
      keepSecret === undefined
        ? eq(sessions.userId, userId)
        : and(eq(sessions.userId, userId), ne(sessions.id, sessionIdFor(keepSecret))),
    );
}

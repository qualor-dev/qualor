import { and, eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { apiTokens, users, type TokenScope } from '../db/schema';
import { resolveSession, type UserRow } from './sessions';
import { hashesEqual, hashToken, parseToken } from './tokens';

export type Principal =
  | { kind: 'session'; user: UserRow; sessionSecret: string }
  | { kind: 'personal'; user: UserRow; tokenId: string; scopes: TokenScope[] }
  | { kind: 'project'; tokenId: string; projectId: string };

export type UserPrincipal = Extract<Principal, { user: UserRow }>;

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal | null;
  }
}

const TOUCH_INTERVAL_MS = 60_000;

/**
 * Prefix lookup, then a constant-time SHA-256 comparison against every candidate row sharing that
 * prefix — including revoked ones — with no early exit, so a revoked or expired sibling token can
 * never be distinguished, by timing, from one that was never issued. `revoked_at` / `expires_at` /
 * the owning user's `active` flag are only inspected after a match is found.
 */
export async function resolveToken(db: Executor, token: string): Promise<Principal | null> {
  const parsed = parseToken(token);
  if (!parsed) return null;
  const candidates = await db
    .select({ token: apiTokens, user: users })
    .from(apiTokens)
    .leftJoin(users, eq(users.id, apiTokens.userId))
    .where(and(eq(apiTokens.prefix, parsed.prefix), eq(apiTokens.kind, parsed.kind)));
  const presented = hashToken(token);
  let match: (typeof candidates)[number] | undefined;
  for (const candidate of candidates) {
    if (hashesEqual(candidate.token.secretHash, presented)) match = candidate;
  }
  if (!match) return null;
  const { token: row, user } = match;
  if (row.revokedAt) return null;
  const now = Date.now();
  if (row.expiresAt && row.expiresAt.getTime() <= now) return null;
  // Every rejection (revoked, expired, orphaned project, inactive user) must be decided above
  // before we touch anything: `last_used_at` is evidence the token worked, so a rejected
  // presentation — including one that merely shares a prefix with a live token — must leave it
  // untouched.
  const principal: Principal | null =
    row.kind === 'project'
      ? row.projectId
        ? { kind: 'project', tokenId: row.id, projectId: row.projectId }
        : null
      : user && user.active
        ? { kind: 'personal', user, tokenId: row.id, scopes: row.scopes }
        : null;
  if (!principal) return null;
  if (!row.lastUsedAt || now - row.lastUsedAt.getTime() >= TOUCH_INTERVAL_MS) {
    await db
      .update(apiTokens)
      .set({ lastUsedAt: new Date(now) })
      .where(eq(apiTokens.id, row.id));
  }
  return principal;
}

export async function resolveRequestPrincipal(
  db: Executor,
  authorization: string | undefined,
  sessionSecret: string | undefined,
): Promise<Principal | null> {
  if (authorization !== undefined) {
    const match = /^Bearer\s+(\S+)$/i.exec(authorization);
    return match?.[1] ? resolveToken(db, match[1]) : null;
  }
  if (sessionSecret) {
    const user = await resolveSession(db, sessionSecret);
    return user ? { kind: 'session', user, sessionSecret } : null;
  }
  return null;
}

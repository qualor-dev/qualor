import { and, eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { apiTokens, users, type TokenScope } from '../db/schema';
import { resolveSession, type UserRow } from './sessions';
import type { McpScope } from '../oauth/tokens';
import { hashesEqual, hashToken, parseToken } from './tokens';

export type Principal =
  | { kind: 'session'; user: UserRow; sessionSecret: string }
  | { kind: 'personal'; user: UserRow; tokenId: string; scopes: TokenScope[] }
  | { kind: 'project'; tokenId: string; projectId: string }
  | {
      kind: 'oauth';
      user: UserRow;
      grantId: string;
      clientId: string;
      clientName: string;
      /** What the user granted the client (spec §4.3). */
      mcpScopes: McpScope[];
      /** The REST scopes this one internal call runs with (the tool's, Task 9). */
      scopes: TokenScope[];
    };

export type OAuthPrincipal = Extract<Principal, { kind: 'oauth' }>;

export type UserPrincipal = Extract<Principal, { user: UserRow }>;

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal | null;
  }
}

/** How often a token's `last_used_at` is written at most (PATs here, OAuth grants in grants.ts). */
export const TOUCH_INTERVAL_MS = 60_000;

/**
 * The principal a token row stands for: a project token's project, or a personal token's user
 * while active; null for a project token without a project or an orphaned or inactive user.
 */
function tokenPrincipal(
  row: typeof apiTokens.$inferSelect,
  user: UserRow | null,
): Principal | null {
  if (row.kind === 'project') {
    return row.projectId ? { kind: 'project', tokenId: row.id, projectId: row.projectId } : null;
  }
  return user && user.active
    ? { kind: 'personal', user, tokenId: row.id, scopes: row.scopes }
    : null;
}

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
  const principal = tokenPrincipal(row, user);
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

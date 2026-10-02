import { and, eq, lt, ne } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { memberships, projectMemberships, sessions, users } from '../db/schema';
import type { UserRow } from './sessions';

/**
 * QUALOR_DEMO_USER: a guest account anyone may sign in as from the sign-in page, without a
 * password, to look around. It only ever reads: the authentication hook refuses every change made
 * as it (`DEMO_READ_ONLY`), whatever its role, and the sign-in is offered only while the account
 * can see no more than a viewer does.
 */

/** A demo session never outlives a day, whatever QUALOR_SESSION_TTL_HOURS says. */
export const DEMO_SESSION_MAX_HOURS = 24;

export function isDemoUser(demoUser: string | null, user: Pick<UserRow, 'username'>): boolean {
  return demoUser !== null && user.username === demoUser;
}

/**
 * The demo account, when guests may sign in as it: it exists and is active, is no instance admin,
 * has no forced password change, and holds the viewer role and nothing above it, in every
 * organisation and on every project. Null otherwise, and when QUALOR_DEMO_USER is unset.
 */
export async function demoAccount(db: Executor, demoUser: string | null): Promise<UserRow | null> {
  if (demoUser === null) return null;
  const [user] = await db.select().from(users).where(eq(users.username, demoUser));
  if (!user || !user.active || user.isInstanceAdmin || user.passwordChangeRequired) return null;
  const [aboveViewer] = await db
    .select({ role: memberships.role })
    .from(memberships)
    .where(and(eq(memberships.userId, user.id), ne(memberships.role, 'viewer')))
    .limit(1);
  if (aboveViewer) return null;
  const [grantAboveViewer] = await db
    .select({ role: projectMemberships.role })
    .from(projectMemberships)
    .where(and(eq(projectMemberships.userId, user.id), ne(projectMemberships.role, 'viewer')))
    .limit(1);
  return grantAboveViewer ? null : user;
}

/** Guests sign in many times a day: their expired sessions go before a new one is made. */
export async function deleteExpiredSessions(db: Executor, userId: string): Promise<void> {
  await db
    .delete(sessions)
    .where(and(eq(sessions.userId, userId), lt(sessions.expiresAt, new Date())));
}

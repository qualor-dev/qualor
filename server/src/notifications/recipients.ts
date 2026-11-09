import { and, asc, eq, inArray, isNotNull, ne, sql, type SQL } from 'drizzle-orm';
import { projectVisibleTo } from '../auth/facts';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { notificationPreferences, projects, projectWatches, users } from '../db/schema';

/** mail E3 N2. */
export type NotifyEvent = 'gate.failed' | 'gate.recovered' | 'analysis.failed';

export interface Watcher {
  userId: string;
  email: string;
  username: string;
  displayName: string | null;
}

const EVENT_COLUMN = {
  'gate.failed': projectWatches.gateFailed,
  'gate.recovered': projectWatches.gateRecovered,
  'analysis.failed': projectWatches.analysisFailed,
} as const;

/**
 * mail E3 N3–N4, in one query, when the message is queued: the watchers of the project with the
 * event switched on and a scope that covers the branch (`all`, or `main` on the main branch; an
 * unknown branch, `branchIsMain = null`, matches both), who are active, have an address, have
 * notification email on (no preferences row = on), are not the demo user, and can still see the
 * project. Losing access keeps the watch; it just matches nothing.
 */
export async function watchersFor(
  tx: Executor,
  input: {
    projectId: string;
    event: NotifyEvent;
    branchIsMain: boolean | null;
    demoUser: string | null;
  },
): Promise<Watcher[]> {
  const conditions: SQL[] = [
    eq(projectWatches.projectId, input.projectId),
    eq(EVENT_COLUMN[input.event], true),
    eq(users.active, true),
    isNotNull(users.email),
    sql`${notificationPreferences.email} IS NOT FALSE`,
    projectVisibleTo(users, projects),
  ];
  if (input.branchIsMain === false) conditions.push(eq(projectWatches.branches, 'all'));
  if (input.demoUser !== null) conditions.push(ne(users.username, input.demoUser));
  const rows = await tx
    .select({
      userId: users.id,
      email: users.email,
      username: users.username,
      displayName: users.displayName,
    })
    .from(projectWatches)
    .innerJoin(users, eq(users.id, projectWatches.userId))
    .innerJoin(projects, eq(projects.id, projectWatches.projectId))
    .leftJoin(notificationPreferences, eq(notificationPreferences.userId, users.id))
    .where(and(...conditions))
    .orderBy(asc(users.email), asc(users.id));
  return rows.flatMap((r) => (r.email === null ? [] : [{ ...r, email: r.email }]));
}

/**
 * 4b: the watchers of the given projects with `new_vulnerabilities` on, one row per (watcher,
 * project): active, with an address, notification email on (no preferences row = on), not the demo
 * user, and able to see the project. The watch's branch scope does not matter: vulnerability mail
 * is about tracked branches and versions, not about one branch of an analysis.
 */
export async function vulnerabilityWatchers(
  tx: Executor,
  input: { projectIds: readonly string[]; demoUser: string | null },
): Promise<Array<Watcher & { projectId: string }>> {
  if (input.projectIds.length === 0) return [];
  const conditions: SQL[] = [
    inArray(projectWatches.projectId, uuidList(input.projectIds)),
    eq(projectWatches.newVulnerabilities, true),
    eq(users.active, true),
    isNotNull(users.email),
    sql`${notificationPreferences.email} IS NOT FALSE`,
    projectVisibleTo(users, projects),
  ];
  if (input.demoUser !== null) conditions.push(ne(users.username, input.demoUser));
  const rows = await tx
    .select({
      userId: users.id,
      email: users.email,
      username: users.username,
      displayName: users.displayName,
      projectId: projectWatches.projectId,
    })
    .from(projectWatches)
    .innerJoin(users, eq(users.id, projectWatches.userId))
    .innerJoin(projects, eq(projects.id, projectWatches.projectId))
    .leftJoin(notificationPreferences, eq(notificationPreferences.userId, users.id))
    .where(and(...conditions))
    .orderBy(asc(users.email), asc(users.id), asc(projectWatches.projectId));
  return rows.flatMap((r) => (r.email === null ? [] : [{ ...r, email: r.email }]));
}

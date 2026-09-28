import { and, asc, count, eq, gt, sql } from 'drizzle-orm';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import type { Db, Executor } from '../db/client';
import { isForeignKeyViolation, pgErrorCode } from '../db/errors';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import { projectMemberships, users, type ProjectRole } from '../db/schema';
import { decodeCursor, encodeCursor } from '../http/pagination';
import { conflict, notFound } from '../http/problem';
import { iso } from '../http/schemas';

/**
 * Project grants (rbac-audit.md §2, §7.2, §16): a role of one user on one project. The caller
 * resolves the project and checks `org.members.manage` first (the core routes of
 * routes/project-members.ts do, through the access helpers); this module only reads and writes
 * the rows.
 */

/** rbac-audit.md §7.2: a resource bound, not an edition limit. */
export const PROJECT_GRANT_LIMIT = 1000;

export interface ProjectGrant {
  userId: string;
  username: string;
  displayName: string | null;
  role: ProjectRole;
  createdAt: string;
}

export async function listProjectGrants(
  db: Executor,
  projectId: string,
  page: { limit: number; cursor?: string },
): Promise<{ items: ProjectGrant[]; nextCursor: string | null }> {
  const after = decodeCursor(page.cursor);
  const rows = await db
    .select({
      userId: users.id,
      username: users.username,
      displayName: users.displayName,
      role: projectMemberships.role,
      createdAt: projectMemberships.createdAt,
    })
    .from(projectMemberships)
    .innerJoin(users, eq(users.id, projectMemberships.userId))
    .where(
      and(eq(projectMemberships.projectId, projectId), after ? gt(users.id, after) : undefined),
    )
    .orderBy(asc(users.id))
    .limit(page.limit + 1);
  const items = rows.slice(0, page.limit).map((r) => ({ ...r, createdAt: iso(r.createdAt) }));
  const last = items.at(-1);
  const nextCursor = rows.length > page.limit && last ? encodeCursor(last.userId) : null;
  return { items, nextCursor };
}

/**
 * Who records a grant change, and as whom (rbac-audit.md §8); absent, or while the recorder is
 * inactive (§8.1), nothing is recorded and the audit-only reads are not made.
 */
export interface GrantAudit {
  recorder: AuditRecorder;
  context: AuditActorContext;
}

/**
 * Adds or changes a grant; `previous` is the role it had (null for a new grant). Records
 * `project_member.added` or `.role_changed` in the same transaction, nothing when the role did not
 * change. A project deleted meanwhile (its foreign key refuses the row) is 404 Project.
 */
export async function setProjectGrant(
  db: Db,
  projectId: string,
  userId: string,
  role: ProjectRole,
  audit?: GrantAudit,
): Promise<{ grant: ProjectGrant; previous: ProjectRole | null }> {
  try {
    return await db.transaction(async (tx) => {
      // One writer of a project's grants at a time, so the bound holds under concurrency.
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(${LOCKS.projectGrants}, hashtext(${projectId}))`,
      );
      const [user] = await tx.select().from(users).where(eq(users.id, userId));
      if (!user?.active) throw notFound('User');
      const [existing] = await tx
        .select({ role: projectMemberships.role })
        .from(projectMemberships)
        .where(
          and(eq(projectMemberships.projectId, projectId), eq(projectMemberships.userId, userId)),
        );
      if (!existing) {
        const [row] = await tx
          .select({ n: count() })
          .from(projectMemberships)
          .where(eq(projectMemberships.projectId, projectId));
        if ((row?.n ?? 0) >= PROJECT_GRANT_LIMIT) {
          throw conflict(
            'PROJECT_GRANT_LIMIT_REACHED',
            `A project has at most ${PROJECT_GRANT_LIMIT} role grants`,
          );
        }
      }
      const saved = first(
        await tx
          .insert(projectMemberships)
          .values({ projectId, userId, role })
          .onConflictDoUpdate({
            target: [projectMemberships.projectId, projectMemberships.userId],
            // sso-scim.md §9.3: a hand change takes a grant managed by group sync over;
            // sync leaves it alone from then on.
            set: { role, managedByConnectionId: null, updatedAt: new Date() },
          })
          .returning(),
      );
      if (audit?.recorder.active() && existing?.role !== saved.role) {
        const refs = await projectRefs(tx, projectId);
        const target = { type: 'user' as const, id: userId, label: user.username };
        const scope = { organization: refs.organization, project: refs.project, target };
        await audit.recorder.recordOrSkipWhenAnchorMalformed(tx, audit.context, [
          existing
            ? {
                action: 'project_member.role_changed',
                ...scope,
                details: { from: existing.role, to: saved.role },
              }
            : { action: 'project_member.added', ...scope, details: { role: saved.role } },
        ]);
      }
      return {
        grant: {
          userId,
          username: user.username,
          displayName: user.displayName,
          role: saved.role,
          createdAt: iso(saved.createdAt),
        },
        previous: existing?.role ?? null,
      };
    });
  } catch (err) {
    if (isForeignKeyViolation(pgErrorCode(err))) throw notFound('Project');
    throw err;
  }
}

/**
 * Removes a grant; returns the role it had, or null when there was none. Records
 * `project_member.removed` in the same transaction when a row was removed.
 */
export async function removeProjectGrant(
  db: Db,
  projectId: string,
  userId: string,
  audit?: GrantAudit,
): Promise<ProjectRole | null> {
  return db.transaction(async (tx) => {
    // The lock setProjectGrant takes: a concurrent set and remove run one after the other, so
    // each records the role change it actually made.
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(${LOCKS.projectGrants}, hashtext(${projectId}))`,
    );
    const [removed] = await tx
      .delete(projectMemberships)
      .where(
        and(eq(projectMemberships.projectId, projectId), eq(projectMemberships.userId, userId)),
      )
      .returning({ role: projectMemberships.role });
    if (audit?.recorder.active() && removed) {
      const refs = await projectRefs(tx, projectId);
      const [user] = await tx
        .select({ username: users.username })
        .from(users)
        .where(eq(users.id, userId));
      await audit.recorder.recordOrSkipWhenAnchorMalformed(tx, audit.context, [
        {
          action: 'project_member.removed',
          organization: refs.organization,
          project: refs.project,
          target: { type: 'user', id: userId, label: user?.username ?? null },
          details: { role: removed.role },
        },
      ]);
    }
    return removed?.role ?? null;
  });
}

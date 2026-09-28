import { and, asc, count, eq, inArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { AuditActorContext, AuditEventInput, AuditRecorder } from '../audit/recorder';
import { isStorableText } from '../audit/canonical';
import { SYSTEM_ACTOR } from '../audit/recorder';
import { organizationRef, type AuditRef } from '../audit/refs';
import type { Db, Executor } from '../db/client';
import { isForeignKeyViolation, pgConstraint, pgErrorCode } from '../db/errors';
import { LOCKS } from '../db/locks';
import {
  memberships,
  ORGANIZATION_ROLES,
  organizations,
  PROJECT_ROLES,
  projectMemberships,
  projects,
  ssoConnections,
  ssoGroupMappings,
  type OrganizationRole,
  type ProjectRole,
} from '../db/schema';
import { notFound, validationFailed, type FieldError } from '../http/problem';
import { PROJECT_GRANT_LIMIT } from '../rbac/grants';

/** sso-scim.md §9.2: mappings per connection. */
export const MAX_MAPPINGS = 500;
/** sso-scim.md §9.1: group values of one sign-in or SCIM change; more is refused, never cut. */
export const MAX_GROUP_VALUES = 1_000;
/** sso-scim.md §9.2: the mapping value that matches every person of the connection. */
export const EVERYONE = '*';
const GROUP_MAX = 255;

export interface SsoGroupMappingInput {
  group: string;
  organizationId: string;
  projectId: string | null;
  role: OrganizationRole;
}

export interface SsoGroupMappingView extends SsoGroupMappingInput {
  id: string;
  organizationKey: string;
  projectKey: string | null;
}

export interface SyncResult {
  added: number;
  changed: number;
  removed: number;
  skipped: number;
  keptLastAdmin: number;
}

/** rbac-audit.md §3.2: organisation and project roles, highest first. */
const RANK: Record<OrganizationRole, number> = { admin: 4, project_admin: 3, member: 2, viewer: 1 };
const stronger = <R extends OrganizationRole>(a: R | undefined, b: R): R =>
  a !== undefined && RANK[a] >= RANK[b] ? a : b;

const CONTROL = /\p{Cc}/u;

/**
 * A value a mapping may hold (§9.2): 1–255 code points, well-formed UTF-16 (no lone surrogate,
 * which PostgreSQL cannot store), no control character (U+0000 included). Sync drops every other
 * claim value before it queries: such a value can never equal a stored mapping, so dropping it
 * changes no result, and it never reaches the database as a parameter.
 */
export function isMappableGroup(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > GROUP_MAX * 2) return false;
  if (!isStorableText(value) || CONTROL.test(value)) return false;
  return [...value].length <= GROUP_MAX;
}

/**
 * Serialises member changes of one organisation with the member routes (routes/organizations.ts
 * `lockOrganization`, the same row lock): the last-admin check below and a concurrent hand removal
 * or another sync never both see "another admin".
 */
async function lockOrganizations(tx: Executor, ids: Iterable<string>): Promise<void> {
  // One order everywhere, so two syncs that touch the same organisations never deadlock.
  for (const id of [...new Set(ids)].sort()) {
    await tx
      .select({ id: organizations.id })
      .from(organizations)
      .where(eq(organizations.id, id))
      .for('no key update');
  }
}

/** rbac/grants.ts takes the same lock: one writer of a project's grants at a time (§7.2). */
async function lockProjects(tx: Executor, ids: Iterable<string>): Promise<void> {
  for (const id of [...new Set(ids)].sort()) {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.projectGrants}, hashtext(${id}))`);
  }
}

/** Under lockOrganizations: whether `userId` holds the organisation's only stored `admin` role. */
async function isLastAdmin(tx: Executor, organizationId: string, userId: string): Promise<boolean> {
  const rows = await tx
    .select({ userId: memberships.userId })
    .from(memberships)
    .where(and(eq(memberships.organizationId, organizationId), eq(memberships.role, 'admin')))
    .limit(2);
  return rows.length === 1 && rows[0]?.userId === userId;
}

type PendingEvent =
  | { kind: 'org'; organizationId: string; event: Omit<AuditEventInput, 'organization' | 'target'> }
  | {
      kind: 'project';
      organizationId: string;
      project: AuditRef;
      event: Omit<AuditEventInput, 'organization' | 'project' | 'target'>;
    };

/**
 * sso-scim.md §9.3, ruling SS5: in the caller's transaction, turns the person's group values into
 * memberships through the connection's mappings. Sync creates, changes and removes only rows it
 * manages (`managed_by_connection_id` = this connection): a membership made by hand or managed by
 * another connection is never touched. An organisation's last admin is never removed or demoted
 * (rbac-audit.md §16). Every role and every project-level mapping applies whatever the licence
 * lists besides `sso` (rbac-audit.md §1.3); only a project at its grant limit is skipped. The
 * events are recorded as the system with `details.managedBy`; removals and demotions go through
 * the anchor exemption (§10.2.1).
 */
export async function syncGroupMemberships(
  tx: Executor,
  input: {
    connectionId: string;
    userId: string;
    username: string;
    groups: readonly string[];
    audit: AuditRecorder;
    log: { warn(obj: object, msg: string): void };
  },
): Promise<SyncResult> {
  if (input.groups.length > MAX_GROUP_VALUES) throw new Error('groups.too_many');
  const result: SyncResult = { added: 0, changed: 0, removed: 0, skipped: 0, keptLastAdmin: 0 };
  const values = [...new Set([...input.groups.filter(isMappableGroup), EVERYONE])];
  const mappings = await tx
    .select({
      organizationId: ssoGroupMappings.organizationId,
      projectId: ssoGroupMappings.projectId,
      role: ssoGroupMappings.role,
      projectOrganizationId: projects.organizationId,
    })
    .from(ssoGroupMappings)
    .leftJoin(projects, eq(projects.id, ssoGroupMappings.projectId))
    .where(
      and(
        eq(ssoGroupMappings.connectionId, input.connectionId),
        inArray(ssoGroupMappings.groupValue, values),
      ),
    );
  const keptLastAdmin = (organizationId: string) => {
    input.log.warn(
      { component: 'sso', connectionId: input.connectionId, organizationId },
      'sync kept the last admin',
    );
    result.keptLastAdmin += 1;
  };

  // 1. Desired roles (§9.3 step 1).
  const wantOrg = new Map<string, OrganizationRole>();
  const wantProject = new Map<string, { organizationId: string; role: ProjectRole }>();
  for (const m of mappings) {
    if (m.projectId === null) {
      wantOrg.set(m.organizationId, stronger(wantOrg.get(m.organizationId), m.role));
    } else if (m.projectOrganizationId === m.organizationId) {
      // replaceMappings keeps a project in its organisation; a mismatch is never acted upon.
      const prev = wantProject.get(m.projectId);
      wantProject.set(m.projectId, {
        organizationId: m.organizationId,
        role: stronger(prev?.role, m.role as ProjectRole),
      });
    }
  }

  const pending: PendingEvent[] = [];

  // 2. Organisation level, under the organisations' row locks (read again once locked).
  const before = await tx
    .select({ organizationId: memberships.organizationId })
    .from(memberships)
    .where(
      and(
        eq(memberships.userId, input.userId),
        eq(memberships.managedByConnectionId, input.connectionId),
      ),
    );
  await lockOrganizations(tx, [...wantOrg.keys(), ...before.map((r) => r.organizationId)]);
  const locked = new Set([...wantOrg.keys(), ...before.map((r) => r.organizationId)]);
  // A managed row of an organisation outside the locked set appeared between the two reads (a
  // concurrent sync of this person): it is left alone here rather than locked out of order, and
  // the next sync picks it up.
  const current = (
    await tx.select().from(memberships).where(eq(memberships.userId, input.userId))
  ).filter((r) => locked.has(r.organizationId));

  for (const [organizationId, role] of wantOrg) {
    const row = current.find((m) => m.organizationId === organizationId);
    if (!row) {
      const inserted = await tx
        .insert(memberships)
        .values({
          organizationId,
          userId: input.userId,
          role,
          managedByConnectionId: input.connectionId,
        })
        .onConflictDoNothing()
        .returning({ role: memberships.role });
      if (inserted.length === 0) continue; // added by hand meanwhile: that row is not ours
      pending.push({
        kind: 'org',
        organizationId,
        event: { action: 'member.added', details: { role, managedBy: input.connectionId } },
      });
      result.added += 1;
    } else if (row.managedByConnectionId === input.connectionId && row.role !== role) {
      if (row.role === 'admin' && (await isLastAdmin(tx, organizationId, input.userId))) {
        keptLastAdmin(organizationId);
        continue;
      }
      const updated = await tx
        .update(memberships)
        .set({ role })
        .where(
          and(
            eq(memberships.organizationId, organizationId),
            eq(memberships.userId, input.userId),
            eq(memberships.managedByConnectionId, input.connectionId),
          ),
        )
        .returning({ role: memberships.role });
      if (updated.length === 0) continue; // no longer ours: nothing changed, nothing to record
      pending.push({
        kind: 'org',
        organizationId,
        event: {
          action: 'member.role_changed',
          details: { from: row.role, to: role, managedBy: input.connectionId },
        },
      });
      result.changed += 1;
    }
  }
  for (const row of current) {
    if (row.managedByConnectionId !== input.connectionId) continue;
    if (wantOrg.has(row.organizationId)) continue;
    if (row.role === 'admin' && (await isLastAdmin(tx, row.organizationId, input.userId))) {
      keptLastAdmin(row.organizationId);
      continue;
    }
    const deleted = await tx
      .delete(memberships)
      .where(
        and(
          eq(memberships.organizationId, row.organizationId),
          eq(memberships.userId, input.userId),
          eq(memberships.managedByConnectionId, input.connectionId),
        ),
      )
      .returning({ role: memberships.role });
    if (deleted.length === 0) continue;
    pending.push({
      kind: 'org',
      organizationId: row.organizationId,
      event: {
        action: 'member.removed',
        details: { role: row.role, managedBy: input.connectionId },
      },
    });
    result.removed += 1;
  }

  // 3. Project level, with no last-admin rule. Under the grants' lock, so the 1 000-grant bound
  // holds (rbac-audit.md §7.2); a project at that bound is the only thing `skipped` counts.
  const managedGrants = await tx
    .select({ projectId: projectMemberships.projectId })
    .from(projectMemberships)
    .where(
      and(
        eq(projectMemberships.userId, input.userId),
        eq(projectMemberships.managedByConnectionId, input.connectionId),
      ),
    );
  const lockedProjects = new Set([...wantProject.keys(), ...managedGrants.map((g) => g.projectId)]);
  await lockProjects(tx, lockedProjects);
  // As above: a grant of a project outside the locked set is left to the next sync.
  const grants = (
    await tx
      .select({
        grant: projectMemberships,
        organizationId: projects.organizationId,
        projectKey: projects.key,
      })
      .from(projectMemberships)
      .innerJoin(projects, eq(projects.id, projectMemberships.projectId))
      .where(eq(projectMemberships.userId, input.userId))
  ).filter((g) => lockedProjects.has(g.grant.projectId));
  const projectKeys = new Map(
    (wantProject.size === 0
      ? []
      : await tx
          .select({ id: projects.id, key: projects.key })
          .from(projects)
          .where(inArray(projects.id, [...wantProject.keys()]))
    ).map((p) => [p.id, p.key]),
  );
  for (const [projectId, want] of wantProject) {
    const row = grants.find((g) => g.grant.projectId === projectId);
    const projectKey = projectKeys.get(projectId);
    // The project was deleted meanwhile: nothing to grant, and no event with an empty key.
    if (projectKey === undefined) continue;
    const project = { id: projectId, key: projectKey };
    if (!row) {
      const [n] = await tx
        .select({ n: count() })
        .from(projectMemberships)
        .where(eq(projectMemberships.projectId, projectId));
      if ((n?.n ?? 0) >= PROJECT_GRANT_LIMIT) {
        input.log.warn(
          { component: 'sso', connectionId: input.connectionId, projectId },
          'sync skipped a project at its grant limit',
        );
        result.skipped += 1;
        continue;
      }
      const inserted = await tx
        .insert(projectMemberships)
        .values({
          projectId,
          userId: input.userId,
          role: want.role,
          managedByConnectionId: input.connectionId,
        })
        .onConflictDoNothing()
        .returning({ role: projectMemberships.role });
      if (inserted.length === 0) continue;
      pending.push({
        kind: 'project',
        organizationId: want.organizationId,
        project,
        event: {
          action: 'project_member.added',
          details: { role: want.role, managedBy: input.connectionId },
        },
      });
      result.added += 1;
    } else if (
      row.grant.managedByConnectionId === input.connectionId &&
      row.grant.role !== want.role
    ) {
      const updated = await tx
        .update(projectMemberships)
        .set({ role: want.role, updatedAt: new Date() })
        .where(
          and(
            eq(projectMemberships.projectId, projectId),
            eq(projectMemberships.userId, input.userId),
            eq(projectMemberships.managedByConnectionId, input.connectionId),
          ),
        )
        .returning({ role: projectMemberships.role });
      if (updated.length === 0) continue;
      pending.push({
        kind: 'project',
        organizationId: want.organizationId,
        project,
        event: {
          action: 'project_member.role_changed',
          details: { from: row.grant.role, to: want.role, managedBy: input.connectionId },
        },
      });
      result.changed += 1;
    }
  }
  for (const row of grants) {
    if (row.grant.managedByConnectionId !== input.connectionId) continue;
    if (wantProject.has(row.grant.projectId)) continue;
    const deleted = await tx
      .delete(projectMemberships)
      .where(
        and(
          eq(projectMemberships.projectId, row.grant.projectId),
          eq(projectMemberships.userId, input.userId),
          eq(projectMemberships.managedByConnectionId, input.connectionId),
        ),
      )
      .returning({ role: projectMemberships.role });
    if (deleted.length === 0) continue;
    pending.push({
      kind: 'project',
      organizationId: row.organizationId,
      project: { id: row.grant.projectId, key: row.projectKey },
      event: {
        action: 'project_member.removed',
        details: { role: row.grant.role, managedBy: input.connectionId },
      },
    });
    result.removed += 1;
  }

  // 4. Recorded as the system (§9.3 step 4); the refs are audit-only reads (rbac-audit.md §8.1).
  // Removals and demotions go through the anchor exemption (§10.2.1); the recorder records a
  // batch holding anything else exactly as `record` does.
  if (pending.length > 0 && input.audit.active()) {
    const target = { type: 'user' as const, id: input.userId, label: input.username };
    const refs = new Map<string, AuditRef>();
    const ref = async (id: string) => {
      const known = refs.get(id);
      if (known) return known;
      const loaded = await organizationRef(tx, id);
      refs.set(id, loaded);
      return loaded;
    };
    const events: AuditEventInput[] = [];
    for (const p of pending) {
      const organization = await ref(p.organizationId);
      events.push(
        p.kind === 'org'
          ? ({ ...p.event, organization, target } as AuditEventInput)
          : ({ ...p.event, organization, project: p.project, target } as AuditEventInput),
      );
    }
    // A batch mixing additions or promotions with removals fails closed on a malformed anchor as a
    // whole (the recorder exempts only a batch where every event removes access, §10.2.1).
    await input.audit.recordOrSkipWhenAnchorMalformed(tx, SYSTEM_ACTOR, events);
  }
  return result;
}

const uuid = z.uuid();

/** §9.2: the connection's mappings with their keys, by group, then organisation and project key. */
export async function listMappings(
  db: Executor,
  connectionId: string,
): Promise<SsoGroupMappingView[]> {
  const rows = await db
    .select({
      id: ssoGroupMappings.id,
      group: ssoGroupMappings.groupValue,
      organizationId: ssoGroupMappings.organizationId,
      organizationKey: organizations.key,
      projectId: ssoGroupMappings.projectId,
      projectKey: projects.key,
      role: ssoGroupMappings.role,
    })
    .from(ssoGroupMappings)
    .innerJoin(organizations, eq(organizations.id, ssoGroupMappings.organizationId))
    .leftJoin(projects, eq(projects.id, ssoGroupMappings.projectId))
    .where(eq(ssoGroupMappings.connectionId, connectionId))
    .orderBy(
      asc(ssoGroupMappings.groupValue),
      asc(organizations.key),
      sql`${projects.key} ASC NULLS FIRST`,
      asc(ssoGroupMappings.id),
    );
  return rows.map((r) => ({
    id: r.id,
    group: r.group,
    organizationId: r.organizationId,
    organizationKey: r.organizationKey,
    projectId: r.projectId,
    projectKey: r.projectKey,
    role: r.role,
  }));
}

const tupleOf = (m: {
  group: string;
  organizationId: string;
  projectId: string | null;
  role: string;
}) => JSON.stringify([m.group, m.organizationId, m.projectId, m.role]);

/**
 * §9.2, §17: replaces the connection's whole mapping list in one transaction, under the
 * connections' lock. 422 on `body.<i>.<field>` for a bad group, organisation, project or role (a
 * project must belong to the mapping's organisation), 422 on `body` beyond 500. Every role and
 * every project-level mapping is accepted whenever the caller reached it (`sso` active, checked by
 * the service; rbac-audit.md §1.3). Records `sso.group_mappings_replaced` with the counts of
 * `(group, organisation, project, role)` tuples added and removed.
 */
export async function replaceMappings(
  deps: { db: Db; audit: AuditRecorder },
  actor: AuditActorContext,
  connectionId: string,
  input: SsoGroupMappingInput[],
): Promise<SsoGroupMappingView[]> {
  if (input.length > MAX_MAPPINGS) {
    throw validationFailed([{ path: 'body', message: `At most ${MAX_MAPPINGS} mappings` }]);
  }
  const errors: FieldError[] = [];
  const seen = new Set<string>();
  input.forEach((m, i) => {
    if (!isMappableGroup(m.group)) {
      errors.push({
        path: `body.${i}.group`,
        message: `1–${GROUP_MAX} characters, without control characters`,
      });
    }
    if (!uuid.safeParse(m.organizationId).success) {
      errors.push({ path: `body.${i}.organizationId`, message: 'Must be an organization id' });
    }
    if (m.projectId !== null && !uuid.safeParse(m.projectId).success) {
      errors.push({ path: `body.${i}.projectId`, message: 'Must be a project id or null' });
    }
    const roles: readonly string[] = m.projectId === null ? ORGANIZATION_ROLES : PROJECT_ROLES;
    if (!roles.includes(m.role)) {
      errors.push({ path: `body.${i}.role`, message: `One of ${roles.join(', ')}` });
    }
    const key = JSON.stringify([m.group, m.organizationId, m.projectId]);
    if (seen.has(key)) {
      errors.push({
        path: `body.${i}.group`,
        message: 'This group already maps to this organization or project',
      });
    }
    seen.add(key);
  });
  if (errors.length > 0) throw validationFailed(errors);

  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.ssoConnections})`);
    const [connection] = await tx
      .select({ id: ssoConnections.id, name: ssoConnections.name })
      .from(ssoConnections)
      .where(eq(ssoConnections.id, connectionId));
    if (!connection) throw notFound('SSO connection');

    const organizationIds = [...new Set(input.map((m) => m.organizationId))];
    const projectIds = [
      ...new Set(input.flatMap((m) => (m.projectId === null ? [] : [m.projectId]))),
    ];
    const knownOrganizations = new Set(
      organizationIds.length === 0
        ? []
        : (
            await tx
              .select({ id: organizations.id })
              .from(organizations)
              .where(inArray(organizations.id, organizationIds))
          ).map((o) => o.id),
    );
    const projectOrganization = new Map(
      (projectIds.length === 0
        ? []
        : await tx
            .select({ id: projects.id, organizationId: projects.organizationId })
            .from(projects)
            .where(inArray(projects.id, projectIds))
      ).map((p) => [p.id, p.organizationId]),
    );
    input.forEach((m, i) => {
      if (!knownOrganizations.has(m.organizationId)) {
        errors.push({ path: `body.${i}.organizationId`, message: 'No such organization' });
      } else if (
        m.projectId !== null &&
        projectOrganization.get(m.projectId) !== m.organizationId
      ) {
        errors.push({
          path: `body.${i}.projectId`,
          message: 'Must be a project of this organization',
        });
      }
    });
    if (errors.length > 0) throw validationFailed(errors);

    const previous = await tx
      .delete(ssoGroupMappings)
      .where(eq(ssoGroupMappings.connectionId, connectionId))
      .returning();
    if (input.length > 0) {
      try {
        await tx.insert(ssoGroupMappings).values(
          input.map((m) => ({
            connectionId,
            groupValue: m.group,
            organizationId: m.organizationId,
            projectId: m.projectId,
            role: m.role,
          })),
        );
      } catch (err) {
        // An organisation or project deleted between the checks above and the insert.
        if (!isForeignKeyViolation(pgErrorCode(err))) throw err;
        const field = pgConstraint(err)?.includes('project') ? 'projectId' : 'organizationId';
        throw validationFailed([
          {
            path: 'body',
            message: `A mapping's ${field} names an organization or project that no longer exists`,
          },
        ]);
      }
    }
    const oldTuples = new Set(previous.map((p) => tupleOf({ ...p, group: p.groupValue })));
    const newTuples = new Set(input.map(tupleOf));
    await deps.audit.record(tx, actor, [
      {
        action: 'sso.group_mappings_replaced',
        target: { type: 'sso_connection', id: connection.id, label: connection.name },
        details: {
          count: input.length,
          added: [...newTuples].filter((t) => !oldTuples.has(t)).length,
          removed: [...oldTuples].filter((t) => !newTuples.has(t)).length,
        },
      },
    ]);
    return listMappings(tx, connectionId);
  });
}

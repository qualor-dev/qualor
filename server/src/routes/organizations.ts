import { and, asc, eq, gt, ne } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import {
  accessOf,
  requireInstanceAdmin,
  requireOrganizationAccess,
  requireUser,
} from '../auth/access';
import { actorOf } from '../audit/recorder';
import { organizationRef } from '../audit/refs';
import { visibleOrganizationsCondition } from '../auth/facts';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import {
  memberships,
  ORGANIZATION_ROLES,
  organizations,
  ssoConnections,
  users,
} from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, notFound } from '../http/problem';
import { iso, idParams, noContent, text, timestamp } from '../http/schemas';
import { createOrganization, type OrganizationRow } from '../orgs/service';
import { ORGANIZATION_KEY_PATTERN } from '../patterns';

// rbac-audit.md §3.2, §6.1, §16: the four organisation roles, in every edition.
const role = z.enum(ORGANIZATION_ROLES);
const organizationSchema = z.object({
  id: z.uuid(),
  key: z.string(),
  name: z.string(),
  createdAt: timestamp,
  updatedAt: timestamp,
});
const memberSchema = z.object({
  userId: z.uuid(),
  username: z.string(),
  displayName: z.string().nullable(),
  role,
  createdAt: timestamp,
  /**
   * sso-scim.md §9.3, §16.2: the SSO connection whose group sync manages this membership, or null
   * for one made by hand. A hand change (PUT) takes a managed membership over, so it answers null.
   */
  managedBy: z.object({ connectionId: z.uuid(), connectionName: z.string() }).nullable(),
});
const memberParams = z.strictObject({ id: z.uuid(), userId: z.uuid() });

/**
 * Serialises the member changes of one organisation: the row lock (FOR NO KEY UPDATE, so inserts
 * that reference the organisation are not blocked) is held until commit, so two changes never
 * both read the same "before" (a doubled member.added) or both see another admin (LAST_ADMIN).
 */
async function lockOrganization(tx: Executor, organizationId: string): Promise<void> {
  await tx
    .select({ id: organizations.id })
    .from(organizations)
    .where(eq(organizations.id, organizationId))
    .for('no key update');
}

/**
 * api.md §2.1: 409 LAST_ADMIN when `userId` is the organisation's last member whose stored role
 * is `admin` (an instance admin counts only when it holds that role). Under lockOrganization.
 */
async function assertAnotherAdmin(
  tx: Executor,
  organizationId: string,
  userId: string,
): Promise<void> {
  const [other] = await tx
    .select({ userId: memberships.userId })
    .from(memberships)
    .where(
      and(
        eq(memberships.organizationId, organizationId),
        eq(memberships.role, 'admin'),
        ne(memberships.userId, userId),
      ),
    )
    .limit(1);
  if (!other) throw conflict('LAST_ADMIN', 'An organization keeps at least one admin');
}

function organizationDto(org: OrganizationRow): z.infer<typeof organizationSchema> {
  return {
    id: org.id,
    key: org.key,
    name: org.name,
    createdAt: iso(org.createdAt),
    updatedAt: iso(org.updatedAt),
  };
}

export const organizationRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  app.get(
    '/organizations',
    {
      schema: {
        tags: ['organizations'],
        summary: 'Organisations you belong to (all, for instance admins)',
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(organizationSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const after = decodeCursor(request.query.cursor);
      const cursor = after ? gt(organizations.id, after) : undefined;
      const limit = request.query.limit + 1;
      const rows = await deps.db
        .select()
        .from(organizations)
        .where(and(cursor, visibleOrganizationsCondition(accessOf(deps), principal.user)))
        .orderBy(asc(organizations.id))
        .limit(limit);
      const page = toPage(rows, request.query.limit);
      return {
        items: page.items.map((o) => organizationDto(o)),
        nextCursor: page.nextCursor,
      };
    },
  );

  app.post(
    '/organizations',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['organizations'],
        summary:
          'Create an organisation (409 ORG_KEY_TAKEN for a key already taken; no limit on the number of organisations)',
        body: z.strictObject({
          key: z.string().regex(ORGANIZATION_KEY_PATTERN),
          name: text(255),
        }),
        response: { 201: organizationSchema },
      },
    },
    async (request, reply) => {
      const principal = requireInstanceAdmin(request);
      const org = await createOrganization(
        deps.db,
        {
          ...request.body,
          creatorId: principal.user.id,
        },
        { recorder: deps.audit, context: actorOf(request) },
      );
      return reply.code(201).send(organizationDto(org));
    },
  );

  app.get(
    '/organizations/:id/members',
    {
      schema: {
        tags: ['organizations'],
        summary:
          'Members of an organisation; managedBy names the SSO connection whose group sync manages a membership',
        params: idParams,
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(memberSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        request.params.id,
        'org.members.read',
      );
      const after = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select({
          id: users.id,
          username: users.username,
          displayName: users.displayName,
          role: memberships.role,
          createdAt: memberships.createdAt,
          connectionId: ssoConnections.id,
          connectionName: ssoConnections.name,
        })
        .from(memberships)
        .innerJoin(users, eq(users.id, memberships.userId))
        .leftJoin(ssoConnections, eq(ssoConnections.id, memberships.managedByConnectionId))
        .where(
          and(
            eq(memberships.organizationId, request.params.id),
            after ? gt(users.id, after) : undefined,
          ),
        )
        .orderBy(asc(users.id))
        .limit(request.query.limit + 1);
      const page = toPage(rows, request.query.limit);
      return {
        items: page.items.map((m) => ({
          userId: m.id,
          username: m.username,
          displayName: m.displayName,
          role: m.role,
          createdAt: iso(m.createdAt),
          managedBy:
            m.connectionId === null || m.connectionName === null
              ? null
              : { connectionId: m.connectionId, connectionName: m.connectionName },
        })),
        nextCursor: page.nextCursor,
      };
    },
  );

  app.put(
    '/organizations/:id/members/:userId',
    {
      config: {
        openapi: {
          problems: [403, 404, 409],
          problemDescriptions: {
            409: "LAST_ADMIN (it would demote the organization's last admin)",
          },
        },
      },
      schema: {
        tags: ['organizations'],
        summary:
          'Add a member or change their role (admin, project_admin, member or viewer); a membership managed by SSO group sync becomes manual',
        params: memberParams,
        body: z.strictObject({ role }),
        response: { 200: memberSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      const { id, userId } = request.params;
      const access = accessOf(deps);
      await requireOrganizationAccess(access, principal, id, 'org.members.manage');
      const [user] = await deps.db.select().from(users).where(eq(users.id, userId));
      if (!user) throw notFound('User');
      const membership = await deps.db.transaction(async (tx) => {
        await lockOrganization(tx, id);
        const [before] = await tx
          .select({ role: memberships.role })
          .from(memberships)
          .where(and(eq(memberships.organizationId, id), eq(memberships.userId, userId)));
        if (before?.role === 'admin' && request.body.role !== 'admin') {
          await assertAnotherAdmin(tx, id, userId);
        }
        // The refs below are audit-only reads: none while audit-log is inactive (§8.1).
        const audited = deps.audit.active();
        const row = first(
          await tx
            .insert(memberships)
            .values({ organizationId: id, userId, role: request.body.role })
            .onConflictDoUpdate({
              target: [memberships.organizationId, memberships.userId],
              // sso-scim.md §9.3: a hand change takes a managed membership over; sync leaves it
              // alone from then on.
              set: { role: request.body.role, managedByConnectionId: null },
            })
            .returning(),
        );
        // No event for a PUT that changed nothing (the same role again).
        if (audited && before?.role !== row.role) {
          const organization = await organizationRef(tx, id);
          const target = { type: 'user' as const, id: userId, label: user.username };
          // rbac-audit.md §10.2.1: a demotion is never blocked by a malformed audit anchor (the
          // recorder decides; an addition or a promotion still fails closed).
          await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
            before
              ? {
                  action: 'member.role_changed',
                  organization,
                  target,
                  details: { from: before.role, to: row.role },
                }
              : { action: 'member.added', organization, target, details: { role: row.role } },
          ]);
        }
        return row;
      });
      return {
        userId,
        username: user.username,
        displayName: user.displayName,
        role: membership.role,
        createdAt: iso(membership.createdAt),
        managedBy: null,
      };
    },
  );

  app.delete(
    '/organizations/:id/members/:userId',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: { 409: "LAST_ADMIN (the organization's last admin)" },
        },
      },
      schema: {
        tags: ['organizations'],
        summary: 'Remove a member',
        params: memberParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { id, userId } = request.params;
      await requireOrganizationAccess(accessOf(deps), principal, id, 'org.members.manage');
      const removed = await deps.db.transaction(async (tx) => {
        await lockOrganization(tx, id);
        const [current] = await tx
          .select({ role: memberships.role })
          .from(memberships)
          .where(and(eq(memberships.organizationId, id), eq(memberships.userId, userId)));
        if (current?.role === 'admin') await assertAnotherAdmin(tx, id, userId);
        const rows = await tx
          .delete(memberships)
          .where(and(eq(memberships.organizationId, id), eq(memberships.userId, userId)))
          .returning({ userId: memberships.userId, role: memberships.role });
        const [row] = rows;
        // The name and the refs are audit-only reads: none while audit-log is inactive (§8.1).
        if (row && deps.audit.active()) {
          const [user] = await tx
            .select({ username: users.username })
            .from(users)
            .where(eq(users.id, userId));
          // rbac-audit.md §10.2.1: a removal is never blocked by a malformed audit anchor.
          await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
            {
              action: 'member.removed',
              organization: await organizationRef(tx, id),
              target: { type: 'user', id: userId, label: user?.username ?? null },
              details: { role: row.role },
            },
          ]);
        }
        return rows;
      });
      if (removed.length === 0) throw notFound('Membership');
      return reply.code(204).send();
    },
  );
};

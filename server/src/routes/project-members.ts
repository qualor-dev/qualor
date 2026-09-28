import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireOrganizationAccess, requireUser } from '../auth/access';
import { actorOf } from '../audit/recorder';
import { PROJECT_ROLES } from '../db/schema';
import { pageQuery, pageSchema } from '../http/pagination';
import { notFound } from '../http/problem';
import { idParams, noContent, timestamp } from '../http/schemas';
import { projectForUser } from '../projects/access';
import { listProjectGrants, removeProjectGrant, setProjectGrant } from '../rbac/grants';

// rbac-audit.md §2, §16: a grant's role is one of the three project roles; `admin` is an
// organisation role only, so a body naming it is 422 on body.role.
const role = z.enum(PROJECT_ROLES);
const grantSchema = z.object({
  userId: z.uuid(),
  username: z.string(),
  displayName: z.string().nullable(),
  role,
  createdAt: timestamp,
});
const grantParams = z.strictObject({ id: z.uuid(), userId: z.uuid() });

/**
 * rbac-audit.md §16: a project's role grants, in every edition. They follow the organisation
 * members routes: each resolves the project with `project.read` (404 when the caller cannot see
 * it), then asks for the organisation permission on the project's organisation (403 FORBIDDEN,
 * then 403 INSUFFICIENT_SCOPE, §3.3). So only an organisation admin manages grants; a project
 * admin, by role or by grant, does not. The grants service (rbac/grants.ts) takes the per-project
 * lock, keeps the bound of 1 000 grants, refuses an unknown or inactive user with 404, and records
 * the change through `deps.audit` in its transaction (nothing while audit-log is inactive; a
 * demotion or removal through recordOrSkipWhenAnchorMalformed, §10.2.1).
 */
export const projectMemberRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  app.get(
    '/projects/:id/members',
    {
      schema: {
        tags: ['projects'],
        summary: "A project's role grants",
        params: idParams,
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(grantSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const access = accessOf(deps);
      const project = await projectForUser(access, principal, request.params.id, 'project.read');
      await requireOrganizationAccess(
        access,
        principal,
        project.organizationId,
        'org.members.read',
      );
      const { limit, cursor } = request.query;
      return listProjectGrants(deps.db, project.id, {
        limit,
        ...(cursor === undefined ? {} : { cursor }),
      });
    },
  );

  app.put(
    '/projects/:id/members/:userId',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            409: 'PROJECT_GRANT_LIMIT_REACHED (the project has 1 000 grants)',
          },
        },
      },
      schema: {
        tags: ['projects'],
        summary: 'Grant a role on a project, or change it',
        description:
          'The role is project_admin, member or viewer, added to the organisation role. 404 for an unknown or inactive user. A grant managed by SSO group sync becomes manual.',
        params: grantParams,
        body: z.strictObject({ role }),
        response: { 200: grantSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      const { id, userId } = request.params;
      const access = accessOf(deps);
      const project = await projectForUser(access, principal, id, 'project.read');
      await requireOrganizationAccess(
        access,
        principal,
        project.organizationId,
        'org.members.manage',
      );
      const { grant } = await setProjectGrant(deps.db, project.id, userId, request.body.role, {
        recorder: deps.audit,
        context: actorOf(request),
      });
      return grant;
    },
  );

  app.delete(
    '/projects/:id/members/:userId',
    {
      schema: {
        tags: ['projects'],
        summary: 'Remove a role grant',
        params: grantParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { id, userId } = request.params;
      const access = accessOf(deps);
      const project = await projectForUser(access, principal, id, 'project.read');
      await requireOrganizationAccess(
        access,
        principal,
        project.organizationId,
        'org.members.manage',
      );
      const removed = await removeProjectGrant(deps.db, project.id, userId, {
        recorder: deps.audit,
        context: actorOf(request),
      });
      if (removed === null) throw notFound('Grant');
      return reply.code(204).send();
    },
  );
};

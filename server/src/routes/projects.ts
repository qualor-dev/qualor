import { and, asc, eq, gt, ilike, inArray, isNull, or } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import {
  accessOf,
  requireOrganizationAccess,
  requireUser,
  type AccessContext,
} from '../auth/access';
import { canonicalJson } from '../audit/canonical';
import { PROJECT_CHANGE_FIELDS } from '../audit/catalogue';
import { actorOf } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import { projectFacts, visibleProjectsCondition } from '../auth/facts';
import { PROJECT_PERMISSIONS, projectPermissions } from '../auth/policy';
import type { UserRow } from '../auth/sessions';
import { generateToken } from '../auth/tokens';
import type { Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgErrorCode } from '../db/errors';
import { first } from '../db/rows';
import {
  analyses,
  apiTokens,
  branches,
  memberships,
  projectMemberships,
  projects,
  qualityGates,
  scmConnections,
  type OrganizationRole,
  type ProjectRole,
} from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, notFound, validationFailed } from '../http/problem';
import {
  createdTokenSchema,
  expiresAtFrom,
  gateStatusSchema,
  idParams,
  iso,
  isoOrNull,
  noContent,
  text,
  timestamp,
  tokenDto,
  tokenSchema,
} from '../http/schemas';
import { headlineMeasures } from '../measures/read';
import { containsPattern } from '../issues/query';
import { PROJECT_KEY_PATTERN } from '../patterns';
import { projectForUser, type ProjectRow } from '../projects/access';
import { forgetForeignMergeRequestUrls } from '../scm/connections';
import { projectRefProblem, scmProjectRef } from './scm-connections';

export const newCodeDefinitionSchema = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('days'), value: z.number().int().min(1).max(3_650) }),
  z.strictObject({ type: z.literal('previous_version') }),
  z.strictObject({ type: z.literal('analysis'), analysisId: z.uuid() }),
]);

export const branchSummarySchema = z.object({
  id: z.uuid(),
  name: z.string(),
  gateStatus: gateStatusSchema.nullable(),
  /** The last succeeded analysis (`GET /analyses/{id}` has its gate result); null before one. */
  lastAnalysisId: z.uuid().nullable(),
  lastAnalyzedAt: timestamp.nullable(),
  /** Headline measures of the last analysis (measures/read.ts HEADLINE_METRICS). */
  measures: z.record(z.string(), z.number().nullable()),
});

export const projectSchema = z.object({
  id: z.uuid(),
  organizationId: z.uuid(),
  key: z.string(),
  name: z.string(),
  mainBranchName: z.string(),
  qualityGateId: z.uuid().nullable(),
  newCodeDefinition: newCodeDefinitionSchema.nullable(),
  /** scm.md §2.2: the GitLab connection and project that decorate this project, or null. */
  scmConnectionId: z.uuid().nullable(),
  scmProjectRef: z.string().nullable(),
  createdAt: timestamp,
  updatedAt: timestamp,
  mainBranch: branchSummarySchema.nullable(),
  /** rbac-audit.md §16: the caller's effective permissions on the project (the UI hides the rest). */
  permissions: z.array(z.enum(PROJECT_PERMISSIONS)),
});
export type ProjectDto = z.infer<typeof projectSchema>;

const projectKey = z.string().regex(PROJECT_KEY_PATTERN);
const projectTokenParams = z.strictObject({ id: z.uuid(), tokenId: z.uuid() });

/** Who reads the DTOs: its permissions go into each one. */
export interface ProjectViewer {
  access: AccessContext;
  user: UserRow;
}

/** The viewer's organisation roles and project grants for `rows`: two queries, none for an admin. */
async function viewerRoles(
  db: Executor,
  rows: readonly ProjectRow[],
  viewer: ProjectViewer,
): Promise<{
  organizationRoles: Map<string, OrganizationRole>;
  projectRoles: Map<string, ProjectRole>;
}> {
  if (viewer.user.isInstanceAdmin) return { organizationRoles: new Map(), projectRoles: new Map() };
  const organizationIds = [...new Set(rows.map((r) => r.organizationId))];
  const [orgRows, grantRows] = await Promise.all([
    db
      .select({ organizationId: memberships.organizationId, role: memberships.role })
      .from(memberships)
      .where(
        and(
          eq(memberships.userId, viewer.user.id),
          inArray(memberships.organizationId, organizationIds),
        ),
      ),
    db
      .select({ projectId: projectMemberships.projectId, role: projectMemberships.role })
      .from(projectMemberships)
      .where(
        and(
          eq(projectMemberships.userId, viewer.user.id),
          inArray(
            projectMemberships.projectId,
            rows.map((r) => r.id),
          ),
        ),
      ),
  ]);
  return {
    organizationRoles: new Map(orgRows.map((r) => [r.organizationId, r.role])),
    projectRoles: new Map(grantRows.map((r) => [r.projectId, r.role])),
  };
}

export async function projectDtos(
  db: Executor,
  rows: readonly ProjectRow[],
  viewer: ProjectViewer,
): Promise<ProjectDto[]> {
  if (rows.length === 0) return [];
  const roles = await viewerRoles(db, rows, viewer);
  const mains = await db
    .select({ branch: branches, gateStatus: analyses.gateStatus })
    .from(branches)
    .leftJoin(analyses, eq(analyses.id, branches.lastAnalysisId))
    .where(
      and(
        inArray(
          branches.projectId,
          rows.map((r) => r.id),
        ),
        eq(branches.isMain, true),
      ),
    );
  const byProject = new Map(mains.map((m) => [m.branch.projectId, m]));
  const headlines = await headlineMeasures(
    db,
    mains.flatMap((m) => (m.branch.lastAnalysisId ? [m.branch.lastAnalysisId] : [])),
  );
  return rows.map((p) => {
    const main = byProject.get(p.id);
    return {
      id: p.id,
      organizationId: p.organizationId,
      key: p.key,
      name: p.name,
      mainBranchName: p.mainBranchName,
      qualityGateId: p.qualityGateId,
      newCodeDefinition: p.newCodeDefinition,
      scmConnectionId: p.scmConnectionId,
      scmProjectRef: p.scmProjectRef,
      createdAt: iso(p.createdAt),
      updatedAt: iso(p.updatedAt),
      mainBranch: main
        ? {
            id: main.branch.id,
            name: main.branch.name,
            gateStatus: main.gateStatus,
            lastAnalysisId: main.branch.lastAnalysisId,
            lastAnalyzedAt: isoOrNull(main.branch.lastAnalyzedAt),
            measures: main.branch.lastAnalysisId
              ? (headlines.get(main.branch.lastAnalysisId) ?? {})
              : {},
          }
        : null,
      permissions: [
        ...projectPermissions(
          projectFacts(viewer.user, {
            organizationRole: roles.organizationRoles.get(p.organizationId) ?? null,
            projectRole: roles.projectRoles.get(p.id) ?? null,
          }),
        ),
      ].sort(),
    };
  });
}

export const projectRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  const one = async (row: ProjectRow, viewer: ProjectViewer): Promise<ProjectDto> =>
    first(await projectDtos(deps.db, [row], viewer));

  app.get(
    '/projects',
    {
      schema: {
        tags: ['projects'],
        summary: 'Projects you can see',
        querystring: z.strictObject({
          ...pageQuery,
          organizationId: z.uuid().optional(),
          q: text(255).optional(),
        }),
        response: { 200: pageSchema(projectSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const { limit, cursor, organizationId, q } = request.query;
      const after = decodeCursor(cursor);
      const access = accessOf(deps);
      const rows = await deps.db
        .select()
        .from(projects)
        .where(
          and(
            after ? gt(projects.id, after) : undefined,
            organizationId ? eq(projects.organizationId, organizationId) : undefined,
            q
              ? or(
                  ilike(projects.name, containsPattern(q)),
                  ilike(projects.key, containsPattern(q)),
                )
              : undefined,
            visibleProjectsCondition(access, principal.user),
          ),
        )
        .orderBy(asc(projects.id))
        .limit(limit + 1);
      const page = toPage(rows, limit);
      return {
        items: await projectDtos(deps.db, page.items, { access, user: principal.user }),
        nextCursor: page.nextCursor,
      };
    },
  );

  app.post(
    '/projects',
    {
      config: { openapi: { problems: [404, 409] } },
      schema: {
        tags: ['projects'],
        summary: 'Create a project and its main branch',
        body: z.strictObject({
          organizationId: z.uuid(),
          key: projectKey,
          name: text(255),
          mainBranchName: text(255).optional(),
        }),
        response: { 201: projectSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request);
      const body = request.body;
      const access = accessOf(deps);
      await requireOrganizationAccess(
        access,
        principal,
        body.organizationId,
        'org.projects.create',
      );
      let project: ProjectRow;
      try {
        project = await deps.db.transaction(async (tx) => {
          const created = first(
            await tx
              .insert(projects)
              .values({
                organizationId: body.organizationId,
                key: body.key,
                name: body.name,
                mainBranchName: body.mainBranchName ?? 'main',
              })
              .returning(),
          );
          await tx.insert(branches).values({
            projectId: created.id,
            kind: 'branch',
            name: created.mainBranchName,
            isMain: true,
          });
          // The refs are an audit-only read: none while audit-log is inactive (§8.1).
          if (deps.audit.active()) {
            const refs = await projectRefs(tx, created.id);
            await deps.audit.record(tx, actorOf(request), [
              {
                action: 'project.created',
                organization: refs.organization,
                project: refs.project,
                target: { type: 'project', id: created.id, label: created.name },
                details: {
                  key: created.key,
                  name: created.name,
                  mainBranchName: created.mainBranchName,
                },
              },
            ]);
          }
          return created;
        });
      } catch (err) {
        if (pgErrorCode(err) === PG_UNIQUE_VIOLATION)
          throw conflict('PROJECT_KEY_TAKEN', 'That project key is already taken');
        throw err;
      }
      return reply.code(201).send(await one(project, { access, user: principal.user }));
    },
  );

  app.get(
    '/projects/by-key',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['projects'],
        summary: 'Find a project by key',
        querystring: z.strictObject({ key: projectKey }),
        response: { 200: projectSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const [row] = await deps.db
        .select({ id: projects.id })
        .from(projects)
        .where(eq(projects.key, request.query.key));
      if (!row) throw notFound('Project');
      const access = accessOf(deps);
      return one(await projectForUser(access, principal, row.id, 'project.read'), {
        access,
        user: principal.user,
      });
    },
  );

  app.get(
    '/projects/:id',
    {
      schema: {
        tags: ['projects'],
        summary: 'A project',
        params: idParams,
        response: { 200: projectSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const access = accessOf(deps);
      return one(await projectForUser(access, principal, request.params.id, 'project.read'), {
        access,
        user: principal.user,
      });
    },
  );

  app.patch(
    '/projects/:id',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['projects'],
        summary:
          'Update name, main branch, new-code definition, quality gate or SCM mapping (GitLab project or GitHub owner/repo; the mapping needs an organization admin)',
        params: idParams,
        body: z
          .strictObject({
            name: text(255).optional(),
            mainBranchName: text(255).optional(),
            newCodeDefinition: newCodeDefinitionSchema.nullable().optional(),
            qualityGateId: z.uuid().nullable().optional(),
            scmConnectionId: z.uuid().nullable().optional(),
            scmProjectRef: scmProjectRef.nullable().optional(),
          })
          .refine((b) => Object.keys(b).length > 0, { message: 'At least one field is required' }),
        response: { 200: projectSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const body = request.body;
      const access = accessOf(deps);
      const project = await projectForUser(
        access,
        principal,
        request.params.id,
        'project.settings',
      );
      // rbac-audit.md §3.4 notes: the SCM mapping aims the organisation's credentials at a
      // repository, so it also needs org.scm.manage (403 FORBIDDEN for a project admin).
      if (body.scmConnectionId !== undefined || body.scmProjectRef !== undefined) {
        await requireOrganizationAccess(
          access,
          principal,
          project.organizationId,
          'org.scm.manage',
        );
      }
      if (body.qualityGateId) {
        const [gate] = await deps.db
          .select({ id: qualityGates.id })
          .from(qualityGates)
          .where(
            and(
              eq(qualityGates.id, body.qualityGateId),
              eq(qualityGates.organizationId, project.organizationId),
            ),
          );
        if (!gate)
          throw validationFailed([{ path: 'body.qualityGateId', message: 'Unknown quality gate' }]);
      }
      let updated: ProjectRow;
      try {
        updated = await deps.db.transaction(async (tx) => {
          let provider: 'gitlab' | 'github' | null = null;
          if (body.scmConnectionId) {
            // scm.md §2.2: only a connection of the project's own organisation (a project never
            // changes organisation). Locked FOR KEY SHARE so a concurrent DELETE waits for this
            // update instead of racing it, and locked before the project row: a DELETE locks the
            // connection, then (ON DELETE SET NULL) the projects that reference it, so taking the
            // two in the same order means one waits for the other instead of a deadlock.
            const [connection] = await tx
              .select({ id: scmConnections.id, provider: scmConnections.provider })
              .from(scmConnections)
              .where(
                and(
                  eq(scmConnections.id, body.scmConnectionId),
                  eq(scmConnections.organizationId, project.organizationId),
                ),
              )
              .for('key share');
            if (!connection) {
              throw validationFailed([
                { path: 'body.scmConnectionId', message: 'Unknown SCM connection' },
              ]);
            }
            provider = connection.provider;
          }
          // Lock the project row before deciding anything: reading mainBranchName outside a
          // lock (as above) lets two concurrent switches both see the old name, both clear it
          // and both insert a new is_main branch, tripping branches_one_main — a non-deferrable
          // unique index, so Postgres checks it per row as each insert/update happens, not once
          // per statement. Locking here serialises the two requests so the second sees the
          // first's committed mainBranchName before it decides whether to switch at all.
          // FOR NO KEY UPDATE (not FOR UPDATE): it still conflicts with itself, but not with the
          // FOR KEY SHARE locks that inserts referencing the project (uploads, tokens, branches)
          // take, so those are not blocked for the length of this transaction.
          const locked = first(
            await tx
              .select()
              .from(projects)
              .where(eq(projects.id, project.id))
              .for('no key update'),
          );
          // scm.md §2.2, github.md §2.3: the reference is the mapped connection's own kind (a
          // GitLab project id or path, a GitHub owner/repo), checked whenever either changes.
          if (body.scmConnectionId !== undefined || body.scmProjectRef !== undefined) {
            const connectionId =
              body.scmConnectionId !== undefined ? body.scmConnectionId : locked.scmConnectionId;
            const ref =
              body.scmProjectRef !== undefined ? body.scmProjectRef : locked.scmProjectRef;
            if (provider === null && connectionId !== null && ref !== null) {
              const [current] = await tx
                .select({ provider: scmConnections.provider })
                .from(scmConnections)
                .where(eq(scmConnections.id, connectionId));
              provider = current?.provider ?? null;
            }
            const problem =
              provider === null || ref === null ? null : projectRefProblem(provider, ref);
            if (problem) throw validationFailed([{ path: 'body.scmProjectRef', message: problem }]);
          }
          const changes: Partial<typeof projects.$inferInsert> = { updatedAt: new Date() };
          if (body.name !== undefined) changes.name = body.name;
          if (body.newCodeDefinition !== undefined)
            changes.newCodeDefinition = body.newCodeDefinition;
          if (body.qualityGateId !== undefined) changes.qualityGateId = body.qualityGateId;
          if (body.scmConnectionId !== undefined) changes.scmConnectionId = body.scmConnectionId;
          if (body.scmProjectRef !== undefined) changes.scmProjectRef = body.scmProjectRef;
          if (body.mainBranchName !== undefined && body.mainBranchName !== locked.mainBranchName) {
            changes.mainBranchName = body.mainBranchName;
            await tx
              .update(branches)
              .set({ isMain: false })
              .where(and(eq(branches.projectId, locked.id), eq(branches.isMain, true)));
            await tx
              .insert(branches)
              .values({
                projectId: locked.id,
                kind: 'branch',
                name: body.mainBranchName,
                isMain: true,
              })
              .onConflictDoUpdate({
                target: [branches.projectId, branches.kind, branches.name],
                set: { isMain: true },
              });
          }
          if (body.newCodeDefinition?.type === 'analysis') {
            // gates.md §5: a newCodeDefinition of type 'analysis' is a main-branch baseline. This
            // must run inside the lock, after any switch above, against whichever branch is main
            // *after* this request — never the pre-switch main — so a single PATCH that both
            // moves mainBranchName and sets newCodeDefinition can't leave the baseline pointing
            // at a branch that is no longer main. If the (possibly just-promoted) main branch has
            // no matching succeeded analysis yet, this fails, rolling back the whole request.
            const [mainBranch] = await tx
              .select({ id: branches.id })
              .from(branches)
              .where(and(eq(branches.projectId, locked.id), eq(branches.isMain, true)));
            const [analysis] = mainBranch
              ? await tx
                  .select({ id: analyses.id })
                  .from(analyses)
                  .where(
                    and(
                      eq(analyses.id, body.newCodeDefinition.analysisId),
                      eq(analyses.projectId, locked.id),
                      eq(analyses.status, 'succeeded'),
                      eq(analyses.branchId, mainBranch.id),
                    ),
                  )
              : [];
            if (!analysis) {
              throw validationFailed([
                {
                  path: 'body.newCodeDefinition.analysisId',
                  message: 'Must be a succeeded analysis on the main branch',
                },
              ]);
            }
          }
          const saved = first(
            await tx.update(projects).set(changes).where(eq(projects.id, locked.id)).returning(),
          );
          // scm.md §8: merge request links are kept only on the mapped connection's address.
          if (saved.scmConnectionId !== null && saved.scmConnectionId !== locked.scmConnectionId) {
            await forgetForeignMergeRequestUrls(tx, { projectId: saved.id });
          }
          // rbac-audit.md §8: only the fields whose value changed.
          const fieldChanges = PROJECT_CHANGE_FIELDS.filter(
            (field) => canonicalJson(locked[field]) !== canonicalJson(saved[field]),
          ).map((field) => ({ field, from: locked[field], to: saved[field] }));
          if (fieldChanges.length > 0 && deps.audit.active()) {
            const refs = await projectRefs(tx, saved.id);
            await deps.audit.record(tx, actorOf(request), [
              {
                action: 'project.updated',
                organization: refs.organization,
                project: refs.project,
                target: { type: 'project', id: saved.id, label: saved.name },
                details: { changes: fieldChanges },
              },
            ]);
          }
          return saved;
        });
      } catch (err) {
        // Defence in depth: the row lock above should make this unreachable, but a residual
        // unique violation must still be a 409, never an unhandled 500.
        if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) {
          throw conflict('MAIN_BRANCH_CONFLICT', 'The main branch changed concurrently; retry');
        }
        throw err;
      }
      return one(updated, { access, user: principal.user });
    },
  );

  app.delete(
    '/projects/:id',
    {
      schema: {
        tags: ['projects'],
        summary: 'Delete a project (?confirm must equal its key)',
        params: idParams,
        querystring: z.strictObject({ confirm: z.string().max(255) }),
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.delete',
      );
      if (request.query.confirm !== project.key) {
        throw validationFailed([{ path: 'query.confirm', message: 'Must equal the project key' }]);
      }
      await deps.db.transaction(async (tx) => {
        // The refs are read before the delete: the event outlives the project (§7.3). They are
        // an audit-only read: none while audit-log is inactive (§8.1).
        const refs = deps.audit.active() ? await projectRefs(tx, project.id) : null;
        const deleted = await tx
          .delete(projects)
          .where(eq(projects.id, project.id))
          .returning({ id: projects.id, key: projects.key, name: projects.name });
        const [row] = deleted;
        if (row && refs) {
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'project.deleted',
              organization: refs.organization,
              project: refs.project,
              target: { type: 'project', id: row.id, label: row.name },
              details: { key: row.key },
            },
          ]);
        }
      });
      return reply.code(204).send();
    },
  );

  app.get(
    '/projects/:id/tokens',
    {
      schema: {
        tags: ['projects'],
        summary: 'Live analysis tokens of a project',
        params: idParams,
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(tokenSchema) },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.tokens.manage',
      );
      const after = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select()
        .from(apiTokens)
        .where(
          and(
            eq(apiTokens.projectId, project.id),
            isNull(apiTokens.revokedAt),
            after ? gt(apiTokens.id, after) : undefined,
          ),
        )
        .orderBy(asc(apiTokens.id))
        .limit(request.query.limit + 1);
      const page = toPage(rows, request.query.limit);
      return { items: page.items.map(tokenDto), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/projects/:id/tokens',
    {
      schema: {
        tags: ['projects'],
        summary: 'Create a project analysis token (returned once)',
        params: idParams,
        body: z.strictObject({
          name: text(100),
          expiresInDays: z.number().int().min(1).max(3_650).optional(),
        }),
        response: { 201: createdTokenSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request);
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.tokens.manage',
      );
      const generated = generateToken('project');
      const row = await deps.db.transaction(async (tx) => {
        const created = first(
          await tx
            .insert(apiTokens)
            .values({
              kind: 'project',
              projectId: project.id,
              name: request.body.name,
              prefix: generated.prefix,
              secretHash: generated.secretHash,
              scopes: ['analysis:write'],
              expiresAt: expiresAtFrom(request.body.expiresInDays),
              createdBy: principal.user.id,
            })
            .returning(),
        );
        if (deps.audit.active()) {
          const refs = await projectRefs(tx, project.id);
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'project_token.created',
              organization: refs.organization,
              project: refs.project,
              target: { type: 'token', id: created.id, label: created.name },
              details: {
                name: created.name,
                prefix: created.prefix,
                expiresAt: created.expiresAt?.toISOString() ?? null,
              },
            },
          ]);
        }
        return created;
      });
      return reply.code(201).send({ ...tokenDto(row), token: generated.token });
    },
  );

  app.delete(
    '/projects/:id/tokens/:tokenId',
    {
      schema: {
        tags: ['projects'],
        summary: 'Revoke a project analysis token',
        params: projectTokenParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.tokens.manage',
      );
      const revoked = await deps.db.transaction(async (tx) => {
        const rows = await tx
          .update(apiTokens)
          .set({ revokedAt: new Date() })
          .where(
            and(
              eq(apiTokens.id, request.params.tokenId),
              eq(apiTokens.projectId, project.id),
              isNull(apiTokens.revokedAt),
            ),
          )
          .returning({ id: apiTokens.id, name: apiTokens.name, prefix: apiTokens.prefix });
        const [token] = rows;
        if (token && deps.audit.active()) {
          const refs = await projectRefs(tx, project.id);
          // rbac-audit.md §10.2.1: a revocation is never blocked by a malformed audit anchor.
          await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
            {
              action: 'project_token.revoked',
              organization: refs.organization,
              project: refs.project,
              target: { type: 'token', id: token.id, label: token.name },
              details: { name: token.name, prefix: token.prefix },
            },
          ]);
        }
        return rows;
      });
      if (revoked.length === 0) throw notFound('Token');
      return reply.code(204).send();
    },
  );
};

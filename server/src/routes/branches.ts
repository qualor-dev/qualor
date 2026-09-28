import { and, asc, eq, gt } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import { accessOf, requireUser } from '../auth/access';
import { analyses, branches, projects, type GateStatus } from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, notFound } from '../http/problem';
import { gateStatusSchema, idParams, isoOrNull, noContent, timestamp } from '../http/schemas';
import { headlineMeasures } from '../measures/read';
import { projectForUser } from '../projects/access';

type BranchRow = typeof branches.$inferSelect;

export const branchSchema = z.object({
  id: z.uuid(),
  projectId: z.uuid(),
  kind: z.enum(['branch', 'merge_request']),
  name: z.string(),
  isMain: z.boolean(),
  mrSourceBranch: z.string().nullable(),
  mrTargetBranch: z.string().nullable(),
  mrTitle: z.string().nullable(),
  mrUrl: z.string().nullable(),
  lastAnalysisId: z.uuid().nullable(),
  lastAnalyzedAt: timestamp.nullable(),
  gateStatus: gateStatusSchema.nullable(),
  measures: z.record(z.string(), z.number().nullable()),
});

export function branchDto(
  branch: BranchRow,
  gateStatus: GateStatus | null,
  measures: Record<string, number | null> = {},
): z.infer<typeof branchSchema> {
  return {
    id: branch.id,
    projectId: branch.projectId,
    kind: branch.kind,
    name: branch.name,
    isMain: branch.isMain,
    mrSourceBranch: branch.mrSourceBranch,
    mrTargetBranch: branch.mrTargetBranch,
    mrTitle: branch.mrTitle,
    mrUrl: branch.mrUrl,
    lastAnalysisId: branch.lastAnalysisId,
    lastAnalyzedAt: isoOrNull(branch.lastAnalyzedAt),
    gateStatus,
    measures,
  };
}

export const branchRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/projects/:id/branches',
    {
      schema: {
        tags: ['branches'],
        summary: 'Branches and merge requests of a project',
        params: idParams,
        querystring: z.strictObject({
          ...pageQuery,
          kind: z.enum(['branch', 'merge_request']).optional(),
        }),
        response: { 200: pageSchema(branchSchema) },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const after = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select({ branch: branches, gateStatus: analyses.gateStatus })
        .from(branches)
        .leftJoin(analyses, eq(analyses.id, branches.lastAnalysisId))
        .where(
          and(
            eq(branches.projectId, project.id),
            request.query.kind ? eq(branches.kind, request.query.kind) : undefined,
            after ? gt(branches.id, after) : undefined,
          ),
        )
        .orderBy(asc(branches.id))
        .limit(request.query.limit + 1);
      const page = toPage(
        rows.map((r) => ({ id: r.branch.id, ...r })),
        request.query.limit,
      );
      const headlines = await headlineMeasures(
        deps.db,
        page.items.flatMap((r) => (r.branch.lastAnalysisId ? [r.branch.lastAnalysisId] : [])),
      );
      return {
        items: page.items.map((r) =>
          branchDto(
            r.branch,
            r.gateStatus,
            r.branch.lastAnalysisId ? headlines.get(r.branch.lastAnalysisId) : undefined,
          ),
        ),
        nextCursor: page.nextCursor,
      };
    },
  );

  app.delete(
    '/branches/:id',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['branches'],
        summary: 'Delete a branch or merge request (not the main branch)',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      // DELETE /branches/{id} is 🛡 (api.md §3): 'write' is only the cheap pre-check; the
      // projectForUser(…, 'admin') below requires the org admin role (else 403 FORBIDDEN) and a
      // token with the 'admin' scope (else 403 INSUFFICIENT_SCOPE).
      const principal = requireUser(request, 'write');
      const [branch] = await deps.db
        .select()
        .from(branches)
        .where(eq(branches.id, request.params.id));
      if (!branch) throw notFound('Branch');
      await projectForUser(accessOf(deps), principal, branch.projectId, 'project.branches.delete');
      await deps.db.transaction(async (tx) => {
        // Same lock order as PATCH /projects/{id} (project row first): a concurrent main-branch
        // switch and a concurrent delete of the same branch then can never interleave, so this
        // can never delete a branch that a racing PATCH just promoted to main. Re-read is_main
        // fresh under the lock — the outer read above is stale by the time we get here.
        // FOR NO KEY UPDATE: see PATCH /projects/{id}; it does not block FK inserts.
        await tx
          .select({ id: projects.id })
          .from(projects)
          .where(eq(projects.id, branch.projectId))
          .for('no key update');
        const [current] = await tx.select().from(branches).where(eq(branches.id, branch.id));
        if (!current) throw notFound('Branch');
        if (current.isMain) throw conflict('MAIN_BRANCH', 'The main branch cannot be deleted');
        // An audit-only read: none while audit-log is inactive (§8.1).
        const refs = deps.audit.active() ? await projectRefs(tx, current.projectId) : null;
        await tx.delete(branches).where(eq(branches.id, current.id));
        if (refs) {
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'branch.deleted',
              organization: refs.organization,
              project: refs.project,
              target: { type: 'branch', id: current.id, label: current.name },
              details: { kind: current.kind, name: current.name },
            },
          ]);
        }
      });
      return reply.code(204).send();
    },
  );
};

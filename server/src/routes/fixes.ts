import { familyOfEcosystem, type FixFamily } from '@qualor/shared/fix';
import { and, desc, eq, sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { recordProjectEvent } from '../audit/refs';
import { accessOf, requireUser } from '../auth/access';
import type { Executor } from '../db/client';
import { dependencyFixes, FIX_STATES } from '../db/schema';
import { dependencyFixFor } from '../fixes/access';
import { fixProblem, isGoStdlib, mainVulnerabilities } from '../fixes/eligibility';
import {
  activeFixCount,
  cancelFix,
  isActiveFix,
  lockFix,
  lockPackageFix,
  lockProject,
  rearmFix,
  requestFix,
  requireCancellable,
} from '../fixes/requests';
import { fixListItem, fixListItemSchema } from '../fixes/rows';
import { requireFixesUsable } from '../fixes/settings';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, notFound, ProblemError } from '../http/problem';
import { idParams, noContent, noNul } from '../http/schemas';
import { projectForUser, type ProjectRow } from '../projects/access';

const requestBody = z.strictObject({
  ecosystem: z
    .string()
    .regex(/^[a-z0-9-]{1,32}$/)
    .meta({
      description:
        "The vulnerability item's ecosystem (Trivy's package type: npm, pnpm, yarn, gomod, pom, uv, poetry); its family names the fix",
    }),
  packageName: noNul(z.string().min(1).max(512)),
});

const listQuery = z.strictObject({
  ...pageQuery,
  state: z.enum(FIX_STATES).optional(),
});

/** The 409s of `requireFixesUsable`, in its order. */
const PRECONDITIONS =
  'FIXES_DISABLED: fix merge requests are switched off for the project; SCM_NOT_BOUND: the project is not mapped to a repository; FIX_MRS_NOT_ALLOWED: an organisation admin has not allowed fix merge requests on the connection; MONITORING_OFF: vulnerability monitoring is off';
const LIMIT_REACHED =
  "FIX_LIMIT_REACHED: the project's fixes in flight (requested, preparing, committing, open) fill its cap";
const NOT_FIXABLE =
  "NOT_FIXABLE: no open, not ignored vulnerability of the package on the main branch has a fixed version, or it is Go's standard library";

/** The project row, locked for the request's transaction; 404 when it was deleted meanwhile. */
async function requireLockedProject(tx: Executor, projectId: string): Promise<ProjectRow> {
  const project = await lockProject(tx, projectId);
  if (!project) throw notFound('Project');
  return project;
}

/** R9: 409 when the project's fixes in flight fill its cap. */
async function requireUnderCap(tx: Executor, projectId: string, maxOpen: number): Promise<void> {
  const active = await activeFixCount(tx, projectId);
  if (active >= maxOpen) {
    throw conflict(
      'FIX_LIMIT_REACHED',
      `${active} of ${maxOpen} fix merge requests are open or in progress`,
    );
  }
}

/** spec §6.2, B7: the family of the request's Trivy type; 422 when it has none. */
function requireFamily(ecosystem: string): FixFamily {
  const family = familyOfEcosystem(ecosystem);
  if (family === null) {
    throw new ProblemError(
      422,
      'FIX_ECOSYSTEM_UNSUPPORTED',
      `No automatic fix for ${ecosystem} yet`,
    );
  }
  return family;
}

/** spec §6.2, R3: 422 unless the package has something to fix on main (`fixProblem`). */
async function requireFixable(
  tx: Executor,
  projectId: string,
  family: FixFamily,
  packageName: string,
): Promise<void> {
  const rows = await mainVulnerabilities(tx, projectId, family, packageName);
  if (fixProblem(family, packageName, rows) === null) return;
  throw new ProblemError(
    422,
    'NOT_FIXABLE',
    isGoStdlib(family, packageName)
      ? "Go's standard library is fixed by the Go version, not by a module update"
      : 'No open vulnerability of the package on the main branch has a fixed version',
  );
}

/** R11: 409 for a fix in flight. */
function notRetryable(): never {
  throw conflict(
    'FIX_NOT_RETRYABLE',
    'The fix is still in flight; only an ended fix can be retried',
  );
}

/**
 * spec §6.3, §6.4, §6.8: the project's fixes, requesting a fix MR for a vulnerable package of
 * main, retrying an ended one and cancelling one in flight (`issue.triage`). The fix job of the
 * customer's CI claims a request; nothing is queued here but the close of a cancelled open MR.
 */
export const fixRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/projects/:id/fixes',
    {
      schema: {
        tags: ['fixes'],
        summary: "The project's fixes, newest first, in keyset pages; `state` keeps one state",
        params: idParams,
        querystring: listQuery,
        response: { 200: pageSchema(fixListItemSchema) },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const { state, limit } = request.query;
      const before = decodeCursor(request.query.cursor);
      const f = dependencyFixes;
      const rows = await deps.db
        .select()
        .from(f)
        .where(
          and(
            eq(f.projectId, project.id),
            state === undefined ? undefined : eq(f.state, state),
            before === undefined
              ? undefined
              : sql`(${f.createdAt}, ${f.id}) < (SELECT c.created_at, c.id FROM dependency_fixes c WHERE c.id = ${before})`,
          ),
        )
        .orderBy(desc(f.createdAt), desc(f.id))
        .limit(limit + 1);
      const page = toPage(rows, limit);
      return { items: page.items.map((row) => fixListItem(row)), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/projects/:id/fixes',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            409: `${PRECONDITIONS}; ${LIMIT_REACHED}`,
            422: `Validation failed (VALIDATION_FAILED); ${NOT_FIXABLE}; FIX_ECOSYSTEM_UNSUPPORTED: the ecosystem has no automatic fix (npm, pnpm, Yarn, Go modules, Maven, uv and Poetry have)`,
          },
        },
      },
      schema: {
        tags: ['fixes'],
        summary:
          "Request a fix MR for a vulnerable package of the main branch: the fix of the package's family (js, go, maven, python) becomes `requested` for the fix job of the project's CI. A fix in flight is answered as it is; an ended one is re-armed (a taken-over one on a new branch). Checked in this order: the preconditions, a fix in flight, the cap, the package",
        params: idParams,
        body: requestBody,
        response: { 202: fixListItemSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      const { ecosystem, packageName } = request.body;
      const family = familyOfEcosystem(ecosystem);
      const row = await deps.db.transaction(async (tx) => {
        // Requests of a project run one at a time (ruling T2a: the branch names, the cap) and read
        // the switch and the cap as the settings save, which takes the same lock, left them.
        const locked = await requireLockedProject(tx, project.id);
        const settings = await requireFixesUsable(tx, locked);
        const current =
          family === null ? null : await lockPackageFix(tx, locked.id, family, packageName);
        if (current && isActiveFix(current.state)) return current;
        await requireUnderCap(tx, locked.id, settings.maxOpen);
        const fixFamily = requireFamily(ecosystem);
        await requireFixable(tx, locked.id, fixFamily, packageName);
        const made = await requestFix(tx, {
          project: locked,
          family: fixFamily,
          packageName,
          userId: principal.user.id,
          origin: 'manual',
          current,
        });
        if (made.outcome !== 'active') {
          await recordProjectEvent(deps.audit, tx, request, locked, 'dependency_fix.requested', {
            family: made.row.family,
            packageName: made.row.packageName,
          });
        }
        return made.row;
      });
      return reply.code(202).send(fixListItem(row));
    },
  );

  app.post(
    '/fixes/:id/retry',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            409: `${PRECONDITIONS}; FIX_NOT_RETRYABLE: the fix is in flight (requested, preparing, committing, open); ${LIMIT_REACHED}`,
            422: `Validation failed (VALIDATION_FAILED); ${NOT_FIXABLE}`,
          },
        },
      },
      schema: {
        tags: ['fixes'],
        summary:
          'Retry an ended fix (failed, no fix, merged, fixed, declined, taken over or cancelled): it goes back to `requested` with a new generation, its failure and MR cleared; a taken-over fix gets the next branch. Checked as a request: the preconditions, the state, the cap, the package',
        params: idParams,
        response: { 202: fixListItemSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { fix, project } = await dependencyFixFor(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      const row = await deps.db.transaction(async (tx) => {
        const locked = await requireLockedProject(tx, project.id);
        const settings = await requireFixesUsable(tx, locked);
        const current = await lockFix(tx, fix.id);
        if (!current) throw notFound('Fix');
        if (isActiveFix(current.state)) notRetryable();
        await requireUnderCap(tx, locked.id, settings.maxOpen);
        await requireFixable(tx, locked.id, current.family, current.packageName);
        const rearmed = await rearmFix(tx, current, {
          userId: principal.user.id,
          origin: 'manual',
        });
        await recordProjectEvent(deps.audit, tx, request, locked, 'dependency_fix.retried', {
          family: rearmed.family,
          packageName: rearmed.packageName,
        });
        return rearmed;
      });
      return reply.code(202).send(fixListItem(row));
    },
  );

  app.delete(
    '/fixes/:id',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            409: "FIX_BUSY: the server is writing the fix's branch and MR (committing); cancel again in a few seconds",
          },
        },
      },
      schema: {
        tags: ['fixes'],
        summary:
          'Cancel a fix in flight: it becomes `cancelled` with a new generation (an upload in flight is refused). When it has an MR (open, or being refreshed), a background job closes the MR with a comment and deletes its branch, unless a person pushed to it. Cancelling an ended fix changes nothing',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { fix, project } = await dependencyFixFor(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      await deps.db.transaction(async (tx) => {
        const current = await lockFix(tx, fix.id);
        if (!current || !isActiveFix(current.state)) return;
        requireCancellable(current);
        // The audit chain before the job schedule (cancelFix queues the close): the order of the
        // settings save, so the two never deadlock.
        await recordProjectEvent(deps.audit, tx, request, project, 'dependency_fix.cancelled', {
          family: current.family,
          packageName: current.packageName,
        });
        await cancelFix(tx, current);
      });
      return reply.code(204).send();
    },
  );
};

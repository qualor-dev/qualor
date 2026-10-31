import { and, eq, sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { accessOf, requireUser } from '../auth/access';
import type { Executor } from '../db/client';
import { branches, projectVersions } from '../db/schema';
import { notFound, ProblemError, validationFailed } from '../http/problem';
import { idParams, noNul } from '../http/schemas';
import { issueChangeCharge, type ChargeIssueChanges } from '../issues/rate-limit';
import { setLockTimeout, TRANSITION_LOCK_TIMEOUT_MS } from '../issues/transitions';
import { projectForUser } from '../projects/access';
import {
  DECISION_STATUSES,
  VEX_JUSTIFICATIONS,
  writeDecision,
  type TargetScope,
} from '../vulnerabilities/decisions';
import { decisionsOf, listVulnerabilities } from '../vulnerabilities/list';
import { readTargetSummary, SEVERITIES } from '../vulnerabilities/summary';
import { PRIORITY_FEATURE, priorityNotLicensed } from '../vulndb/priority/feature';
import { transitionComment } from './issues';

const TRACKING_REASONS = [
  'pinned',
  'unsupported',
  'prerelease',
  'newest_in_line',
  'replaced',
  'older_line',
  'recent',
  'older',
  'rule_all',
  'rule_none',
] as const;

const severitySchema = z.enum(SEVERITIES);
const decisionStatusSchema = z.enum(DECISION_STATUSES);
const trackingSchema = z.enum(['auto', 'pinned', 'unsupported']);

const countsSchema = z.object({
  critical: z.number().int(),
  high: z.number().int(),
  medium: z.number().int(),
  low: z.number().int(),
  unknown: z.number().int(),
});

const targetSchema = z.object({
  kind: z.enum(['branch', 'version']),
  id: z.uuid(),
  /** The branch name or the version label. */
  name: z.string(),
  isMain: z.boolean(),
  /** A version's override; null for a branch. */
  tracking: trackingSchema.nullable(),
  /** Whether a dependency list exists to read the vulnerabilities from. */
  hasInventory: z.boolean(),
  /** Open, not ignored rows (a decision that is not Open takes a row out). */
  counts: countsSchema,
  /** Open, not ignored rows in the KEV catalog; null without the vuln.priority feature. */
  exploited: z.number().int().nullable(),
  /** Open, not ignored rows first seen after the target's last scan was checked. */
  new: z.number().int(),
  checkedAt: z.iso.datetime().nullable(),
});

const untrackedSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  tracking: trackingSchema,
  trackingReason: z.enum(TRACKING_REASONS),
  /** The rows the version kept when it stopped being tracked. */
  counts: countsSchema,
  exploited: z.number().int().nullable(),
  checkedAt: z.iso.datetime().nullable(),
});

const targetsAnswerSchema = z.object({
  /** Whether the vuln.priority feature (KEV and EPSS) is licensed. */
  priority: z.boolean(),
  /** Off while the instance or the project switch is off; the lists are then empty. */
  monitoring: z.enum(['on', 'off']),
  /** The vulnerability database in use; null when there is none. */
  data: z.object({ builtAt: z.iso.datetime().nullable() }).nullable(),
  /** The latest check over the tracked targets. */
  checkedAt: z.iso.datetime().nullable(),
  versionCount: z.number().int(),
  targets: z.array(targetSchema),
  untracked: z.array(untrackedSchema),
});

const targetRefSchema = z.object({
  kind: z.enum(['branch', 'version']),
  id: z.uuid(),
  name: z.string(),
});

const decisionSchema = z.object({
  id: z.uuid(),
  scope: z.enum(['project', 'branch', 'version']),
  status: decisionStatusSchema,
  reason: z.enum(VEX_JUSTIFICATIONS).nullable(),
  comment: z.string().nullable(),
  decidedAt: z.iso.datetime(),
  decidedBy: z.object({ id: z.uuid(), name: z.string() }).nullable(),
});

const itemSchema = z.object({
  vulnerabilityId: z.string(),
  packageName: z.string(),
  ecosystem: z.string(),
  severity: severitySchema,
  title: z.string().nullable(),
  primaryUrl: z.string().nullable(),
  installedVersions: z.array(z.string()),
  fixedVersion: z.string().nullable(),
  /** The targets in scope that have it. */
  in: z.array(targetRefSchema),
  /** The tracked targets in scope that do not; empty when the list is for one target. */
  notIn: z.array(targetRefSchema),
  foundAt: z.iso.datetime(),
  /** A row appeared after the target's last scan: the database changed, the code did not. */
  withoutScan: z.boolean(),
  new: z.boolean(),
  /** Every row in scope is ignored in .trivyignore. */
  ignored: z.boolean(),
  /** The decision in force: the viewed target's, or the project-wide one without `target`. */
  status: decisionStatusSchema,
  decision: decisionSchema.nullable(),
  /** In the CISA KEV catalog. Null without the vuln.priority feature or when not listed. */
  exploited: z.object({ dateAdded: z.iso.date(), ransomware: z.boolean() }).nullable(),
  /** The EPSS score. Null without the vuln.priority feature or when not scored. */
  epss: z.object({ score: z.number(), percentile: z.number() }).nullable(),
});

const TARGET_PATTERN =
  /^(branch|version):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const listQuerySchema = z.strictObject({
  /** `branch:<id>` or `version:<id>`, tracked or not; without it, every tracked target. */
  target: z.string().regex(TARGET_PATTERN).optional(),
  status: z.enum(['all', ...DECISION_STATUSES]).default('all'),
  severity: severitySchema.optional(),
  /** Only the exploited (KEV) rows; 403 FEATURE_NOT_LICENSED without vuln.priority when true. */
  exploited: z.enum(['true', 'false']).optional(),
  page: z.coerce.number().int().min(1).max(100_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(50),
});

const targetScopeSchema = z.strictObject({ kind: z.enum(['branch', 'version']), id: z.uuid() });

const decisionBodySchema = z.strictObject({
  packageName: noNul(z.string().min(1).max(512)),
  vulnerabilityId: noNul(z.string().min(1).max(128)),
  scope: z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.literal('project') }),
    targetScopeSchema,
  ]),
  status: decisionStatusSchema,
  /** Required for Not affected, and only then. */
  reason: z.enum(VEX_JUSTIFICATIONS).optional(),
  /** At most 2 000 characters; required for Not affected and Won't fix. */
  comment: noNul(z.string().max(2_000)).optional(),
  /** A project-wide write only: the override of this target is removed in the same transaction. */
  replaceOverrideOf: targetScopeSchema.optional(),
});

/** 404 for a target that is not the project's, 422 for a merge request (it has no decisions). */
async function requireTarget(
  db: Executor,
  projectId: string,
  target: TargetScope,
  path: string,
): Promise<void> {
  if (target.kind === 'version') {
    const [row] = await db
      .select({ id: projectVersions.id })
      .from(projectVersions)
      .where(and(eq(projectVersions.id, target.id), eq(projectVersions.projectId, projectId)));
    if (!row) throw notFound();
    return;
  }
  const [row] = await db
    .select({ kind: branches.kind })
    .from(branches)
    .where(and(eq(branches.id, target.id), eq(branches.projectId, projectId)));
  if (!row) throw notFound();
  if (row.kind === 'merge_request') {
    throw validationFailed([{ path, message: 'A merge request has no vulnerability decisions' }]);
  }
}

/** Whether the project has a vulnerability row, or a Trivy issue, for the pair. */
async function pairExists(
  db: Executor,
  projectId: string,
  packageName: string,
  vulnerabilityId: string,
): Promise<boolean> {
  const found = await db.execute(sql`
    SELECT 1 WHERE EXISTS (
      SELECT 1 FROM target_vulnerabilities
       WHERE project_id = ${projectId} AND package_name = ${packageName}
         AND vulnerability_id = ${vulnerabilityId})
    OR EXISTS (
      SELECT 1 FROM issues i JOIN rules r ON r.id = i.rule_id
       WHERE i.project_id = ${projectId} AND i.package_name = ${packageName}
         AND r.engine_id = 'trivy' AND r.engine_rule_id = ${vulnerabilityId})`);
  return found.rows.length > 0;
}

export const vulnerabilityRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** The app's G7 bound, shared with the issue routes (routes/index.ts). */
  chargeIssueChanges?: ChargeIssueChanges;
}> = async (app, { deps, chargeIssueChanges }) => {
  const chargeChanges = chargeIssueChanges ?? issueChangeCharge();

  app.get(
    '/projects/:id/vulnerabilities/targets',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['vulnerabilities'],
        summary: 'The tracked branches and versions with their vulnerability counts',
        params: idParams,
        response: { 200: targetsAnswerSchema },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      return readTargetSummary(deps.db, project.id, {
        priority: deps.edition.limits().vulnerabilities.priority,
      });
    },
  );

  app.get(
    '/projects/:id/vulnerabilities',
    {
      config: {
        openapi: {
          problems: [404],
          problemDescriptions: {
            403: `FEATURE_NOT_LICENSED (\`exploited=true\` needs the enterprise feature ${PRIORITY_FEATURE}), FORBIDDEN or INSUFFICIENT_SCOPE`,
          },
        },
      },
      schema: {
        tags: ['vulnerabilities'],
        summary:
          'The vulnerabilities of the tracked targets, or of one target, by package and vulnerability',
        params: idParams,
        querystring: listQuerySchema,
        response: { 200: z.object({ items: z.array(itemSchema), total: z.number().int() }) },
      },
    },
    async (request) => {
      const { target, exploited, ...query } = request.query;
      const priority = deps.edition.limits().vulnerabilities.priority;
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      if (exploited === 'true' && !priority) throw priorityNotLicensed();
      const [kind, id] = target?.split(':') ?? [];
      return listVulnerabilities(
        deps.db,
        project.id,
        {
          ...query,
          ...(exploited === 'true' && { exploited: true }),
          ...(kind !== undefined &&
            id !== undefined && {
              target: { kind: kind as 'branch' | 'version', id: id.toLowerCase() },
            }),
        },
        { priority },
      );
    },
  );

  app.put(
    '/projects/:id/vulnerability-decisions',
    {
      config: {
        openapi: {
          problems: [404, 429, 503],
          problemDescriptions: {
            404: 'The project, a scope target or the (package, vulnerability) pair is not found (NOT_FOUND)',
            422: 'Validation failed (VALIDATION_FAILED; also a reason with a status other than false_positive, a replaceOverrideOf with a target scope, or a merge-request branch), a required comment is missing (COMMENT_REQUIRED), or a false positive has no reason (REASON_REQUIRED)',
            429: 'Too many issue changes by this user (RATE_LIMITED); see Retry-After',
            503: 'The decision stayed locked by a concurrent change (CONCURRENCY_CONFLICT); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['vulnerabilities'],
        summary:
          "Change a vulnerability's status for the whole project or for one branch or version; applied to the matching Trivy issues",
        params: idParams,
        body: decisionBodySchema,
        response: {
          200: z.object({ decision: decisionSchema, appliedIssues: z.number().int() }),
        },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      const { packageName, vulnerabilityId, scope, status, replaceOverrideOf } = request.body;
      if (request.body.reason !== undefined && status !== 'false_positive') {
        throw validationFailed([
          { path: 'body.reason', message: 'Only a false positive takes a reason' },
        ]);
      }
      if (replaceOverrideOf && scope.kind !== 'project') {
        throw validationFailed([
          {
            path: 'body.replaceOverrideOf',
            message: 'Only a project-wide decision replaces an override',
          },
        ]);
      }
      const comment = transitionComment(status, request.body.comment);
      if (status === 'false_positive' && request.body.reason === undefined) {
        throw new ProblemError(422, 'REASON_REQUIRED', 'A reason is required for false_positive', {
          errors: [{ path: 'body.reason', message: 'Required for false_positive' }],
        });
      }
      chargeChanges(principal.user.id, 1);
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'issue.triage',
      );
      if (scope.kind !== 'project') {
        await requireTarget(deps.db, project.id, scope, 'body.scope');
      }
      if (replaceOverrideOf) {
        await requireTarget(deps.db, project.id, replaceOverrideOf, 'body.replaceOverrideOf');
      }
      if (!(await pairExists(deps.db, project.id, packageName, vulnerabilityId))) {
        throw notFound('Vulnerability');
      }

      return deps.db.transaction(async (tx) => {
        await setLockTimeout(tx, TRANSITION_LOCK_TIMEOUT_MS);
        // writeDecision takes the pair's lock first; nothing above it locks anything.
        const { decision, appliedIssueIds } = await writeDecision(
          tx,
          {
            projectId: project.id,
            packageName,
            vulnerabilityId,
            scope,
            status,
            reason: request.body.reason ?? null,
            comment,
            userId: principal.user.id,
            source: 'tab',
            ...(replaceOverrideOf && { replaceOverrideOf }),
          },
          { recorder: deps.audit, context: actorOf(request) },
        );
        // The request paid for one change; each issue the decision changed costs one more, and a
        // refusal rolls the decision back.
        if (appliedIssueIds.length > 0) chargeChanges(principal.user.id, appliedIssueIds.length);
        const dto = (await decisionsOf(tx, [decision.id])).get(decision.id);
        if (!dto) throw new Error('The decision just written is missing');
        return { decision: dto, appliedIssues: appliedIssueIds.length };
      });
    },
  );
};

import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireUser } from '../auth/access';
import { idParams } from '../http/schemas';
import { projectForUser } from '../projects/access';
import { DECISION_STATUSES, VEX_JUSTIFICATIONS } from '../vulnerabilities/decisions';
import { listVulnerabilities } from '../vulnerabilities/list';
import { readTargetSummary, SEVERITIES } from '../vulnerabilities/summary';

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
  checkedAt: z.iso.datetime().nullable(),
});

const targetsAnswerSchema = z.object({
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
});

const TARGET_PATTERN =
  /^(branch|version):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const listQuerySchema = z.strictObject({
  /** `branch:<id>` or `version:<id>`, tracked or not; without it, every tracked target. */
  target: z.string().regex(TARGET_PATTERN).optional(),
  status: z.enum(['all', ...DECISION_STATUSES]).default('all'),
  severity: severitySchema.optional(),
  page: z.coerce.number().int().min(1).max(100_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(50),
});

export const vulnerabilityRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
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
      return readTargetSummary(deps.db, project.id);
    },
  );

  app.get(
    '/projects/:id/vulnerabilities',
    {
      config: { openapi: { problems: [404] } },
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
      const { target, ...query } = request.query;
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const [kind, id] = target?.split(':') ?? [];
      return listVulnerabilities(deps.db, project.id, {
        ...query,
        ...(kind !== undefined &&
          id !== undefined && {
            target: { kind: kind as 'branch' | 'version', id: id.toLowerCase() },
          }),
      });
    },
  );
};

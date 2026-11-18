import { eq, sql, type SQL } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import type { PROJECT_FIXES_CHANGED_FIELDS } from '../audit/catalogue';
import { recordProjectEvent } from '../audit/refs';
import { accessOf, requireUser } from '../auth/access';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import { projectFixSettings, projects, type FixAutoSeverity } from '../db/schema';
import { syncFixesNow } from '../fixes/jobs';
import { fixCounts, fixPreconditions, fixSettingsOf, type FixSettingsRow } from '../fixes/settings';
import { idParams } from '../http/schemas';
import { projectForUser, type ProjectRow } from '../projects/access';
import { priorityNotLicensed } from '../vulndb/priority/feature';

const DEFAULT_MAX_OPEN = 5;
const severity = z.enum(['critical', 'high', 'medium', 'low']);

const answerSchema = z.object({
  settings: z.object({
    enabled: z.boolean(),
    autoCreate: z.object({
      minSeverity: severity.nullable(),
      exploited: z.boolean(),
      since: z.iso.datetime().nullable(),
    }),
    maxOpen: z.number().int(),
    updatedAt: z.iso.datetime().nullable(),
  }),
  preconditions: z.object({
    scmBound: z.boolean().meta({ description: 'The project is mapped to a repository' }),
    provider: z.enum(['gitlab', 'github']).nullable(),
    fixMrsAllowed: z.boolean().meta({
      description: "An organisation admin allowed fix merge requests on the project's connection",
    }),
    monitoringOn: z.boolean(),
    lastClaimAt: z.iso.datetime().nullable(),
  }),
  counts: z.object({
    requested: z.number().int(),
    preparing: z.number().int(),
    committing: z.number().int(),
    open: z.number().int(),
  }),
  /** Whether `autoCreate.exploited` may be turned on (the `vuln.priority` licence). */
  exploitedAvailable: z.boolean(),
});

const putBody = z.strictObject({
  enabled: z.boolean(),
  autoCreate: z.strictObject({
    minSeverity: severity.nullable(),
    exploited: z.boolean().meta({
      description: 'Turning it on needs the `vuln.priority` licence (403 FEATURE_NOT_LICENSED)',
    }),
  }),
  maxOpen: z.number().int().min(1).max(20),
});

type FixesChanged = (typeof PROJECT_FIXES_CHANGED_FIELDS)[number];

/** The names, among those of PROJECT_FIXES_CHANGED_FIELDS, of what the save changes. */
function changedFields(
  before: FixSettingsRow | null,
  next: z.infer<typeof putBody>,
): FixesChanged[] {
  const changed: FixesChanged[] = [];
  if ((before?.enabled ?? false) !== next.enabled) changed.push('enabled');
  if (
    (before?.autoMinSeverity ?? null) !== next.autoCreate.minSeverity ||
    (before?.autoExploited ?? false) !== next.autoCreate.exploited
  ) {
    changed.push('autoCreate');
  }
  if ((before?.maxOpen ?? DEFAULT_MAX_OPEN) !== next.maxOpen) changed.push('maxOpen');
  return changed;
}

/** spec §6.3: the rule's `since`, now whenever the rule changes, else kept; null while it is off. */
function autoSinceOf(
  rule: { minSeverity: FixAutoSeverity | null; exploited: boolean },
  before: FixSettingsRow | null,
): SQL | Date | null {
  if (rule.minSeverity === null && !rule.exploited) return null;
  const changed =
    before === null ||
    before.autoMinSeverity !== rule.minSeverity ||
    before.autoExploited !== rule.exploited;
  return changed ? sql`now()` : (before?.autoSince ?? null);
}

/**
 * spec §6.1, §6.3: a project's fix MR settings, the preconditions that decide whether a request
 * can be made (R19: no live permission probe) and how many fixes are in flight (project admins
 * save; everyone with access reads).
 */
export const fixSettingsRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const answer = async (db: Executor, project: ProjectRow) => {
    const [settings, preconditions, counts] = await Promise.all([
      fixSettingsOf(db, project.id),
      fixPreconditions(db, project),
      fixCounts(db, project.id),
    ]);
    return {
      settings: {
        enabled: settings?.enabled ?? false,
        autoCreate: {
          minSeverity: settings?.autoMinSeverity ?? null,
          exploited: settings?.autoExploited ?? false,
          since: settings?.autoSince?.toISOString() ?? null,
        },
        maxOpen: settings?.maxOpen ?? DEFAULT_MAX_OPEN,
        updatedAt: settings?.updatedAt.toISOString() ?? null,
      },
      preconditions,
      counts,
      exploitedAvailable: deps.edition.limits().vulnerabilities.priority,
    };
  };

  app.get(
    '/projects/:id/fixes/settings',
    {
      schema: {
        tags: ['fixes'],
        summary:
          "The project's fix MR settings (defaults while none are saved: off, at most 5 open), the preconditions of a request (repository mapped, the connection's switch, monitoring, the last claim), the counts of fixes in flight and whether `exploited` of the automatic rule is licensed",
        params: idParams,
        response: { 200: answerSchema },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      return answer(deps.db, project);
    },
  );

  app.put(
    '/projects/:id/fixes/settings',
    {
      config: {
        openapi: {
          problems: [403],
          problemDescriptions: {
            403: 'FEATURE_NOT_LICENSED: `autoCreate.exploited` is turned on without the `vuln.priority` licence',
          },
        },
      },
      schema: {
        tags: ['fixes'],
        summary:
          'Save the fix MR settings (project admins): the switch, the automatic rule and the cap of fixes in flight (1-20). `autoCreate.since` is set whenever the rule changes and cleared when it goes off. Turning the switch on queues a pass of the organisation',
        params: idParams,
        body: putBody,
        response: { 200: answerSchema },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.settings',
      );
      const { body } = request;
      const { minSeverity, exploited } = body.autoCreate;
      await deps.db.transaction(async (tx) => {
        await tx
          .select({ id: projects.id })
          .from(projects)
          .where(eq(projects.id, project.id))
          .for('no key update');
        const before = await fixSettingsOf(tx, project.id);
        // Like the Jira rule (R10): only turning it on needs the licence; a stored true is kept.
        if (
          exploited &&
          before?.autoExploited !== true &&
          !deps.edition.limits().vulnerabilities.priority
        ) {
          throw priorityNotLicensed();
        }
        const values = {
          enabled: body.enabled,
          autoMinSeverity: minSeverity,
          autoExploited: exploited,
          autoSince: autoSinceOf(body.autoCreate, before),
          maxOpen: body.maxOpen,
          updatedAt: sql`now()`,
        };
        first(
          await tx
            .insert(projectFixSettings)
            .values({ projectId: project.id, ...values })
            .onConflictDoUpdate({ target: projectFixSettings.projectId, set: values })
            .returning({ projectId: projectFixSettings.projectId }),
        );
        const changed = changedFields(before, body);
        if (changed.length > 0) {
          await recordProjectEvent(deps.audit, tx, request, project, 'project.fixes_updated', {
            changed,
          });
        }
        // Switching on gives the organisation a pass now (its next one may be 15 minutes away).
        if (body.enabled && before?.enabled !== true)
          await syncFixesNow(tx, project.organizationId);
      });
      return answer(deps.db, project);
    },
  );
};

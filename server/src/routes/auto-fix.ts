import { eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import { accessOf, requireOrganizationAccess, requireUser } from '../auth/access';
import { organizations } from '../db/schema';
import { conflict, ProblemError } from '../http/problem';
import { idParams } from '../http/schemas';
import {
  AUTO_FIX_FEATURE,
  fixSuggestionsEnabled,
  lockLlmSettings,
  projectAutoFixEnabled,
  withOrganizationAutoFix,
  withProjectAutoFix,
} from '../llm/auto-fix-settings';
import {
  autoFixSettingsSchema,
  MAX_ORGANIZATION_PROJECT_IDS,
  organizationSettings,
  projectOwners,
  readLlmSettings,
  writeLlmSettings,
  type AutoFixSettings,
} from '../llm/settings';
import { projectForUser } from '../projects/access';

/** 4E-3a §2: `available` is the licence's seam, `limits.llm.automaticFixSuggestions`. */
export const autoFixStateSchema = z.object({
  /** The enterprise feature `llm.auto-fix` is active. */
  available: z.boolean(),
  /** The project is not opted out of its organisation's automatic fix suggestions. */
  enabled: z.boolean(),
});

/**
 * The project DTO's `autoFix` (4E-3a §4): the state, and whether the organisation has them on, so
 * the project settings can explain an opt-out that would change nothing.
 */
export const projectAutoFixSchema = autoFixStateSchema.extend({
  /**
   * The organisation has them on: the assistant configured, the organisation enabled with fix
   * suggestions, and its automatic fix suggestions switched on.
   */
  organizationEnabled: z.boolean(),
  /**
   * The organisation excludes the project from the AI assistant, so it gets no automatic fix
   * suggestions whatever its own switch says.
   */
  excludedFromAi: z.boolean(),
});

const organizationAutoFixSchema = autoFixSettingsSchema.extend({ available: z.boolean() });

const notLicensed = (): ProblemError =>
  new ProblemError(
    403,
    'FEATURE_NOT_LICENSED',
    `The enterprise feature "${AUTO_FIX_FEATURE}" is not licensed`,
  );

const sameAutoFix = (a: AutoFixSettings, b: AutoFixSettings): boolean =>
  a.enabled === b.enabled &&
  a.minSeverity === b.minSeverity &&
  a.maxPerAnalysis === b.maxPerAnalysis;

/**
 * 4E-3a §2: an organisation admin switches automatic fix suggestions on for the organisation, and
 * a project admin opts one project out. Every other AI setting stays the instance admin's
 * (`/system/llm`, llm.md §3.1).
 */
export const autoFixRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  const available = (): boolean => deps.edition.limits().llm.automaticFixSuggestions;

  app.get(
    '/organizations/:id/ai/auto-fix',
    {
      schema: {
        tags: ['ai'],
        summary:
          "The organisation's automatic fix suggestion settings (org.ai.manage); `available` is false without the enterprise feature llm.auto-fix",
        params: idParams,
        response: { 200: organizationAutoFixSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.ai.manage');
      const settings = await readLlmSettings(deps.db);
      return { available: available(), ...organizationSettings(settings, organizationId).autoFix };
    },
  );

  app.put(
    '/organizations/:id/ai/auto-fix',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            403: 'FEATURE_NOT_LICENSED: switching it on, from off, needs the enterprise feature llm.auto-fix',
            409: 'AI_DISABLED (switching it on, from off, needs the AI provider configured, in an organisation that may use AI with Suggest a fix on)',
          },
        },
      },
      schema: {
        tags: ['ai'],
        summary:
          "Set the organisation's automatic fix suggestions (org.ai.manage): posted to merge requests for new findings at or above minSeverity, at most maxPerAnalysis per analysis",
        params: idParams,
        body: autoFixSettingsSchema,
        response: { 200: organizationAutoFixSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      const organization = await requireOrganizationAccess(
        accessOf(deps),
        principal,
        organizationId,
        'org.ai.manage',
      );
      const next: AutoFixSettings = request.body;
      const saved = await deps.db.transaction(async (tx) => {
        const settings = await lockLlmSettings(tx);
        const current = organizationSettings(settings, organizationId).autoFix;
        // Only switching it on (stored off) needs the licence and the organisation's fix
        // suggestions: a switch-on saved before keeps its threshold editable, as on /system/llm,
        // and without the licence the stored values are kept.
        if (next.enabled && !current.enabled) {
          if (!available()) throw notLicensed();
          if (!fixSuggestionsEnabled(settings, organizationId)) {
            throw conflict(
              'AI_DISABLED',
              'The AI fix suggestions are not enabled for this organisation',
            );
          }
        }
        if (sameAutoFix(current, next)) return current;
        await writeLlmSettings(tx, withOrganizationAutoFix(settings, organizationId, next));
        if (deps.audit.active()) {
          const [row] = await tx
            .select({ name: organizations.name })
            .from(organizations)
            .where(eq(organizations.id, organizationId));
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'organization.auto_fix_changed',
              organization: { id: organizationId, key: organization.organizationKey },
              target: { type: 'organization', id: organizationId, label: row?.name ?? null },
              details: {
                enabled: next.enabled,
                minSeverity: next.minSeverity,
                maxPerAnalysis: next.maxPerAnalysis,
              },
            },
          ]);
        }
        return next;
      });
      return { available: available(), ...saved };
    },
  );

  app.put(
    '/projects/:id/ai/auto-fix',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            403: 'FEATURE_NOT_LICENSED: the enterprise feature llm.auto-fix is not active',
            409: 'AUTO_FIX_OPT_OUT_LIMIT_REACHED (the organisation has 1 000 projects opted out)',
          },
        },
      },
      schema: {
        tags: ['ai'],
        summary:
          "Opt the project out of its organisation's automatic fix suggestions (enabled: false), or back in (project.settings)",
        params: idParams,
        body: z.strictObject({ enabled: z.boolean() }),
        response: { 200: autoFixStateSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.settings',
      );
      if (!available()) throw notLicensed();
      const { enabled } = request.body;
      const organizationId = project.organizationId;
      await deps.db.transaction(async (tx) => {
        const settings = await lockLlmSettings(tx);
        if (projectAutoFixEnabled(settings, project) === enabled) return;
        // llm.md §3.3: the ids of projects deleted since are dropped silently.
        const listed = organizationSettings(settings, organizationId).autoFixDisabledProjectIds;
        const owners = await projectOwners(tx, listed);
        const next = withProjectAutoFix(
          settings,
          organizationId,
          project.id,
          enabled,
          (id) => owners.get(id) === organizationId,
        );
        const optedOut = organizationSettings(next, organizationId).autoFixDisabledProjectIds;
        if (optedOut.length > MAX_ORGANIZATION_PROJECT_IDS) {
          throw conflict(
            'AUTO_FIX_OPT_OUT_LIMIT_REACHED',
            `At most ${MAX_ORGANIZATION_PROJECT_IDS} projects of an organisation can be opted out`,
          );
        }
        await writeLlmSettings(tx, next);
        if (deps.audit.active()) {
          const refs = await projectRefs(tx, project.id);
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'project.auto_fix_changed',
              organization: refs.organization,
              project: refs.project,
              target: { type: 'project', id: project.id, label: project.name },
              details: { enabled },
            },
          ]);
        }
      });
      return { available: true, enabled };
    },
  );
};

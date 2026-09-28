import { LLM_DATA_FIELDS, LLM_FEATURES } from '@qualor/shared';
import { desc, eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { accessOf, requireOrganizationAccess, requireUser } from '../auth/access';
import { llmRequests } from '../db/schema';
import { conflict, ProblemError } from '../http/problem';
import { idParams } from '../http/schemas';
import { issueChangeCharge, type ChargeIssueChanges } from '../issues/rate-limit';
import { aiRequestDto, aiRequestSchema } from '../llm/dto';
import { queueFixPost } from '../llm/post';
import { PROVIDER_KINDS } from '../llm/providers';
import { AiUserLimits, effectiveBudgets, requestAi, todayUsage } from '../llm/service';
import { budgetsSchema, organizationSettings, readLlmSettings } from '../llm/settings';
import { aiRequestFor, issueForUser } from '../projects/access';

/** How soon a client polls a request in flight again (llm.md §16). */
const POLL_SECONDS = '2';

const orgAiSchema = z.object({
  enabled: z.boolean(),
  features: z.object({ explain: z.boolean(), triage: z.boolean(), fix: z.boolean() }),
  provider: z
    .object({ kind: z.enum(PROVIDER_KINDS), host: z.string(), model: z.string() })
    .nullable(),
  dataSent: z.array(z.enum(LLM_DATA_FIELDS)),
  usage: z.object({
    explain: z.number().int(),
    triage: z.number().int(),
    fix: z.number().int(),
    tokens: z.number().int(),
    costUsd: z.number().nullable(),
  }),
  budgets: budgetsSchema,
});

const latestSchema = z.object({
  explain: aiRequestSchema.nullable(),
  triage: aiRequestSchema.nullable(),
  fix: aiRequestSchema.nullable(),
});

/** llm.md §16: asking the AI assistant about one issue, and reading the answers. */
export const aiRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** The app's G7 bound, shared with the issue routes (routes/index.ts). */
  chargeIssueChanges?: ChargeIssueChanges;
}> = async (app, { deps, chargeIssueChanges }) => {
  // The per-user bound (llm.md §12.1) of this app, in its process's memory.
  const users = new AiUserLimits();
  const chargeChanges = chargeIssueChanges ?? issueChangeCharge();

  app.post(
    '/issues/:id/ai/:feature',
    {
      config: {
        openapi: {
          problems: [409, 429],
          problemDescriptions: {
            409: 'AI_DISABLED (no provider, or the organisation or feature is off), or AI_NOT_ELIGIBLE (detail: the reason)',
            429: "AI_QUOTA_EXCEEDED (the organisation's budget for today; Retry-After is the next UTC midnight), or RATE_LIMITED (this user's hourly bound); see Retry-After",
          },
        },
      },
      schema: {
        tags: ['ai'],
        summary:
          'Ask the AI assistant about one issue: 200 with a cached answer, or 202 with the request queued (or already in flight)',
        params: z.strictObject({ id: z.uuid(), feature: z.enum(LLM_FEATURES) }),
        body: z.strictObject({ refresh: z.boolean().default(false) }),
        response: { 200: aiRequestSchema, 202: aiRequestSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const { kind, row } = await requestAi(
        {
          db: deps.db,
          limits: deps.edition.limits(),
          users,
          audit: { recorder: deps.audit, context: actorOf(request) },
        },
        principal,
        request.params.id,
        request.params.feature,
        { refresh: request.body.refresh },
      );
      return reply.code(kind === 'cached' ? 200 : 202).send(aiRequestDto(row));
    },
  );

  app.get(
    '/ai-requests/:id',
    {
      schema: {
        tags: ['ai'],
        summary: 'One AI request; Retry-After: 2 while it is queued or running',
        params: idParams,
        response: { 200: aiRequestSchema },
      },
    },
    async (request, reply) => {
      const row = await aiRequestFor(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      if (row.status === 'queued' || row.status === 'running') {
        void reply.header('retry-after', POLL_SECONDS);
      }
      return aiRequestDto(row);
    },
  );

  app.post(
    '/ai-requests/:id/post',
    {
      config: {
        openapi: {
          problems: [409, 429],
          problemDescriptions: {
            409: 'AI_DISABLED (the assistant or its fix feature is off, or the project or path excluded), or AI_POST_NOT_POSSIBLE (detail: not_fix, not_applicable, not_open, not_merge_request, not_mapped, not_latest, no_scm_context or already_posted)',
            429: "RATE_LIMITED (this user's bound on issue changes); see Retry-After",
          },
        },
      },
      schema: {
        tags: ['ai'],
        summary:
          'Post a fix suggestion to its merge request (a GitLab suggestion, a GitHub suggested change): 202 with the post queued',
        params: idParams,
        body: z.strictObject({}),
        response: { 202: aiRequestSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      // Missing and invisible alike; a viewer reads but does not post (403).
      const row = await aiRequestFor(accessOf(deps), principal, request.params.id, 'ai.use');
      // Ruling G7: a post acts on the merge request like an issue change; one per click that
      // queues a post (a refused click costs nothing).
      const queued = await queueFixPost(
        deps.db,
        row,
        () => {
          chargeChanges(principal.user.id, 1);
        },
        { recorder: deps.audit, context: actorOf(request) },
      );
      if (!queued.ok && queued.refusal === 'ai_disabled') {
        throw conflict('AI_DISABLED', 'The AI fix suggestions are not enabled for this project');
      }
      if (!queued.ok) {
        throw new ProblemError(
          409,
          'AI_POST_NOT_POSSIBLE',
          'This suggestion cannot be posted to the merge request',
          { detail: queued.refusal },
        );
      }
      return reply.code(202).send(aiRequestDto(queued.row));
    },
  );

  app.get(
    '/issues/:id/ai',
    {
      schema: {
        tags: ['ai'],
        summary: 'The latest AI request of each feature for the issue',
        params: idParams,
        response: { 200: latestSchema },
      },
    },
    async (request) => {
      const issue = await issueForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const rows = await deps.db
        .selectDistinctOn([llmRequests.feature])
        .from(llmRequests)
        .where(eq(llmRequests.issueId, issue.id))
        .orderBy(llmRequests.feature, desc(llmRequests.createdAt));
      const of = (feature: string) => {
        const row = rows.find((r) => r.feature === feature);
        return row ? aiRequestDto(row) : null;
      };
      return { explain: of('explain'), triage: of('triage'), fix: of('fix') };
    },
  );

  app.get(
    '/organizations/:id/ai',
    {
      schema: {
        tags: ['ai'],
        summary:
          "The AI assistant for the organisation: whether it is on, what is sent where, today's use (UTC) and the budgets",
        params: idParams,
        response: { 200: orgAiSchema },
      },
    },
    async (request): Promise<z.infer<typeof orgAiSchema>> => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.read');
      const settings = await readLlmSettings(deps.db);
      const org = organizationSettings(settings, organizationId);
      const enabled = settings.provider !== null && org.enabled;
      const usage = await todayUsage(deps.db, organizationId);
      return {
        enabled,
        features: enabled ? org.features : { explain: false, triage: false, fix: false },
        provider: settings.provider
          ? {
              kind: settings.provider.kind,
              host: new URL(settings.provider.baseUrl).host,
              model: settings.provider.model,
            }
          : null,
        dataSent: [...LLM_DATA_FIELDS],
        usage: {
          explain: usage.explain,
          triage: usage.triage,
          fix: usage.fix,
          tokens: usage.tokens,
          costUsd: settings.pricing === null ? null : usage.costMicroUsd / 1e6,
        },
        budgets: effectiveBudgets(settings, deps.edition.limits()),
      };
    },
  );
};

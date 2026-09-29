import { llmIneligibility, PROMPT_VERSIONS, type LlmFeature } from '@qualor/shared';
import { and, desc, eq, gt, inArray, sql } from 'drizzle-orm';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import type { UserPrincipal } from '../auth/principal';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import { llmRequests, projects, type LlmRequestRow } from '../db/schema';
import { conflict, notFound, ProblemError } from '../http/problem';
import { IssueChangeLimiter } from '../issues/rate-limit';
import type { Limits } from '../limits';
import { issueForUser } from '../projects/access';
import { enqueue } from '../queue/queue';
import type { LlmErrorCode } from './errors';
import { baseUrlHash, buildIssueInput, cacheKeyOf } from './input';
import type { LlmJobPayload } from './job';
import {
  organizationSettings,
  pathExcluded,
  readLlmSettings,
  type Budgets,
  type StoredLlmSettings,
} from './settings';

export const LLM_QUEUE = 'llm';
/** llm.md §10.2: a succeeded answer is reused for this many days. */
export const LLM_CACHE_DAYS = 30;
/**
 * A heuristic, not a guarantee: a `queued` or `running` row younger than this is taken for the
 * request in flight for the same key, and is answered again instead of a new one. It bounds the
 * lookup (the issue index, by `created_at`) and outlasts a job's three attempts at the longest
 * timeout (3 × (2 × 600 s + 60 s) plus the retry delays, llm.md §12.3, §14). A row stuck longer
 * (a request waiting behind a long backlog, or one the sweep has not failed yet) is not waited
 * for: the person's next click queues a new request.
 */
export const LLM_IN_FLIGHT_MINUTES = 90;

/**
 * The per-user bound (llm.md §12.1): a token bucket per user in this process's memory (the G7
 * limiter), one limiter per configured rate so a changed rate starts from a full bucket.
 * `take` is synchronous, so concurrent requests of one user cannot both take the last token.
 */
export class AiUserLimits {
  private readonly byRate = new Map<number, IssueChangeLimiter>();

  private limiter(perHour: number): IssueChangeLimiter {
    let limiter = this.byRate.get(perHour);
    if (!limiter) {
      limiter = new IssueChangeLimiter({ perMinute: perHour / 60, burst: perHour });
      this.byRate.set(perHour, limiter);
    }
    return limiter;
  }

  /** Null when the user may ask now, else the seconds to wait; takes nothing. */
  peek(userId: string, perHour: number): number | null {
    return this.limiter(perHour).peek(userId, 1);
  }

  /** Null when the user may ask now (one token taken), else the seconds to wait. */
  take(userId: string, perHour: number): number | null {
    return this.limiter(perHour).take(userId, 1);
  }

  /** Gives back the token of a request that was not queued after all. */
  refund(userId: string, perHour: number): void {
    this.limiter(perHour).refund(userId, 1);
  }
}

const userRateLimited = (wait: number) =>
  new ProblemError(429, 'RATE_LIMITED', 'Too many AI requests by this user', {
    headers: { 'retry-after': String(wait) },
  });

export interface AiRequestDeps {
  db: Db;
  limits: Limits;
  users: AiUserLimits;
  /**
   * rbac-audit.md §8: `ai.requested` for a new request (a new `llm_requests` row), in the insert's
   * transaction; never for a cached answer or the request in flight. No prompt, answer or key.
   */
  audit?: { recorder: AuditRecorder; context: AuditActorContext };
}

export function secondsToUtcMidnight(now: Date = new Date()): number {
  const midnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((midnight - now.getTime()) / 1_000));
}

/** llm.md §12.1, §13: the admin's budgets with the community ceiling on fix suggestions. */
export function effectiveBudgets(settings: StoredLlmSettings, limits: Limits): Budgets {
  return {
    ...settings.budgets,
    fixPerDay: Math.min(settings.budgets.fixPerDay, limits.llm.maxFixPerOrganizationPerDay),
  };
}

export interface AiUsage {
  explain: number;
  triage: number;
  fix: number;
  tokens: number;
  costMicroUsd: number;
}

/**
 * Failed requests the organisation's daily counts leave out, when no token was used: the job's
 * own checks refused them before anything was sent, or the provider refused the key (401, 403)
 * before doing any work. Every other failure counts (a timeout or an unavailable provider may
 * still have used the provider; a refused request may follow from what was sent). The per-user
 * hourly bound counts every request, so leaving these out cannot be used to send more.
 */
export const UNCOUNTED_FAILURES = [
  'PROVIDER_REFUSED_KEY',
  'URL_NOT_ALLOWED',
  'KEY_UNDECRYPTABLE',
  'AI_DISABLED',
  'SETTINGS_CHANGED',
  'ISSUE_CHANGED',
  'ISSUE_GONE',
] as const satisfies readonly LlmErrorCode[];

/**
 * llm.md §12.1: the organisation's requests, tokens and estimated cost of the current UTC day.
 * A request queued or running counts (it holds its unit of the budget); a failed one that used
 * nothing does not (UNCOUNTED_FAILURES).
 */
export async function todayUsage(db: Executor, organizationId: string): Promise<AiUsage> {
  const uncounted = sql.join(
    UNCOUNTED_FAILURES.map((code) => sql`${code}`),
    sql`, `,
  );
  const counted = sql`NOT (status = 'failed'
             AND coalesce(error_code, '') IN (${uncounted})
             AND coalesce(input_tokens, 0) = 0
             AND coalesce(output_tokens, 0) = 0)`;
  const { rows } = await db.execute<{
    explain: number;
    triage: number;
    fix: number;
    tokens: string;
    cost: string;
  }>(sql`
    SELECT count(*) FILTER (WHERE feature = 'explain' AND ${counted})::int AS explain,
           count(*) FILTER (WHERE feature = 'triage' AND ${counted})::int AS triage,
           count(*) FILTER (WHERE feature = 'fix' AND ${counted})::int AS fix,
           coalesce(sum(coalesce(input_tokens, 0) + coalesce(output_tokens, 0)), 0)::bigint AS tokens,
           coalesce(sum(cost_micro_usd), 0)::bigint AS cost
      FROM llm_requests
     WHERE organization_id = ${organizationId}
       AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`);
  const u = first(rows);
  return {
    explain: u.explain,
    triage: u.triage,
    fix: u.fix,
    tokens: Number(u.tokens),
    costMicroUsd: Number(u.cost),
  };
}

const notEligible = (reason: string) =>
  new ProblemError(409, 'AI_NOT_ELIGIBLE', 'This issue is not sent to the AI assistant', {
    detail: reason,
  });

/**
 * llm.md §16 `POST /issues/{id}/ai/{feature}`: a cached answer, the request in flight, or a new
 * queued one. One person, one issue: there is no bulk form (§13). Everything is read again from
 * the database: the issue's organisation comes from its project row, and eligibility and
 * redaction from the stored issue and rule.
 */
export async function requestAi(
  deps: AiRequestDeps,
  principal: UserPrincipal,
  issueId: string,
  feature: LlmFeature,
  options: { refresh: boolean },
): Promise<{ kind: 'cached' | 'queued'; row: LlmRequestRow }> {
  const visible = await issueForUser({ db: deps.db }, principal, issueId, 'ai.use');
  const project = first(
    await deps.db.select().from(projects).where(eq(projects.id, visible.projectId)),
  );
  const orgId = project.organizationId;
  const settings = await readLlmSettings(deps.db);
  const provider = settings.provider;
  if (provider === null) throw conflict('AI_DISABLED', 'No LLM provider is configured');
  const org = organizationSettings(settings, orgId);
  if (!org.enabled || !org.features[feature]) {
    throw conflict('AI_DISABLED', 'This AI feature is not enabled for the organisation');
  }
  const built = await buildIssueInput(deps.db, issueId, feature);
  if (!built) throw notFound('Issue');
  const { issue, rule } = built;
  const reason =
    llmIneligibility(
      feature,
      {
        status: issue.status,
        path: issue.path,
        startLine: issue.startLine,
        hasSnippet: built.input.snippet !== null,
      },
      { engineId: rule.engineId, cwe: rule.cwe, tags: rule.tags },
    ) ??
    (org.excludedProjectIds.includes(project.id) ? 'excluded_project' : null) ??
    (pathExcluded(settings, issue.path) ? 'excluded_path' : null);
  if (reason) throw notEligible(reason);

  const cacheKey = cacheKeyOf(
    orgId,
    feature,
    provider,
    rule.key,
    issue.fingerprint,
    built.inputSha256,
  );
  // Per issue (llm.md §10.2): the twin of an issue on another branch (same organisation,
  // rule, fingerprint and code) has its own requests, so a triage accepted on one issue or a fix
  // posted to one merge request is never another issue's. The issue index serves the lookups.
  const sameKey = and(
    eq(llmRequests.issueId, issue.id),
    eq(llmRequests.organizationId, orgId),
    eq(llmRequests.feature, feature),
    eq(llmRequests.cacheKey, cacheKey),
  );
  // The cache (llm.md §10.2): the issue's succeeded rows only.
  const cached = async (db: Executor) => {
    const [hit] = await db
      .select()
      .from(llmRequests)
      .where(
        and(
          sameKey,
          eq(llmRequests.status, 'succeeded'),
          gt(llmRequests.createdAt, sql`now() - make_interval(days => ${LLM_CACHE_DAYS})`),
        ),
      )
      .orderBy(desc(llmRequests.createdAt))
      .limit(1);
    return hit;
  };
  if (!options.refresh) {
    const hit = await cached(deps.db);
    if (hit) return { kind: 'cached', row: hit };
  }

  const budgets = effectiveBudgets(settings, deps.limits);
  const userId = principal.user.id;
  // A user over their bound is refused before waiting for the organisation's lock; the token is
  // still taken under the lock, so this only saves them the wait (and the lock the traffic).
  const early = deps.users.peek(userId, budgets.perUserPerHour);
  if (early !== null) throw userRateLimited(early);
  let charged = false;
  try {
    return await deps.db.transaction(async (tx) => {
      // One organisation's check-and-insert at a time (llm.md §12.1): concurrent requests can
      // neither both take the last unit of a budget nor both queue the same question.
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.llmQuota}, hashtext(${orgId}))`);
      if (!options.refresh) {
        // Again under the lock: the request in flight may have succeeded since the first look.
        const hit = await cached(tx);
        if (hit) return { kind: 'cached' as const, row: hit };
        const [inFlight] = await tx
          .select()
          .from(llmRequests)
          .where(
            and(
              sameKey,
              inArray(llmRequests.status, ['queued', 'running']),
              gt(
                llmRequests.createdAt,
                sql`now() - make_interval(mins => ${LLM_IN_FLIGHT_MINUTES})`,
              ),
            ),
          )
          .orderBy(desc(llmRequests.createdAt))
          .limit(1);
        if (inFlight) return { kind: 'queued' as const, row: inFlight };
      }
      const used = await todayUsage(tx, orgId);
      const perDay = {
        explain: budgets.explainPerDay,
        triage: budgets.triagePerDay,
        fix: budgets.fixPerDay,
      }[feature];
      const overCost =
        budgets.costPerDayUsd !== null && used.costMicroUsd >= budgets.costPerDayUsd * 1_000_000;
      if (used[feature] >= perDay || used.tokens >= budgets.tokensPerDay || overCost) {
        throw new ProblemError(
          429,
          'AI_QUOTA_EXCEEDED',
          "The organisation's AI budget for today is used up",
          { headers: { 'retry-after': String(secondsToUtcMidnight()) } },
        );
      }
      // Charged only for a request that will be queued (under the lock, so a refused budget costs
      // the user nothing); a refusal rolls the transaction back, and a failure after the charge
      // (the insert, the enqueue, the commit) gives the token back.
      const wait = deps.users.take(userId, budgets.perUserPerHour);
      if (wait !== null) throw userRateLimited(wait);
      charged = true;
      const inserted = first(
        await tx
          .insert(llmRequests)
          .values({
            organizationId: orgId,
            projectId: project.id,
            issueId: issue.id,
            userId,
            feature,
            cacheKey,
            provider: provider.kind,
            providerHost: new URL(provider.baseUrl).host,
            model: provider.model,
            promptVersion: PROMPT_VERSIONS[feature],
            inputSha256: built.inputSha256,
            inputBytes: Buffer.byteLength(built.data, 'utf8'),
            fields: built.fields,
            redactions: built.redactions,
            prompt: settings.storePrompts ? (JSON.parse(built.data) as unknown) : null,
          })
          .returning(),
      );
      // The job's own retries are off: the handler (Task 11) schedules its retries itself.
      await enqueue(tx, {
        queue: LLM_QUEUE,
        payload: {
          requestId: inserted.id,
          attempt: 0,
          baseUrl: baseUrlHash(provider.baseUrl),
        } satisfies LlmJobPayload,
        maxAttempts: 1,
      });
      if (deps.audit?.recorder.active()) {
        const refs = await projectRefs(tx, project.id);
        await deps.audit.recorder.record(tx, deps.audit.context, [
          {
            action: 'ai.requested',
            organization: refs.organization,
            project: refs.project,
            target: { type: 'issue', id: issue.id, label: null },
            details: {
              requestId: inserted.id,
              feature,
              providerHost: inserted.providerHost,
              model: inserted.model,
            },
          },
        ]);
      }
      return { kind: 'queued' as const, row: inserted };
    });
  } catch (err) {
    if (charged) deps.users.refund(userId, budgets.perUserPerHour);
    throw err;
  }
}

import { randomBytes } from 'node:crypto';
import {
  buildPrompt,
  checkFix,
  llmIneligibility,
  MAX_OUTPUT_TOKENS,
  parseAnswer,
  REDACTED,
} from '@qualor/shared';
import { and, eq, inArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Db, Executor } from '../db/client';
import { llmRequests, type LlmRequestRow } from '../db/schema';
import type { Resolver } from '../http/outbound';
import { enqueue } from '../queue/queue';
import type { JobHandlers, WorkerLogger } from '../queue/worker';
import { inSeconds } from '../scm/queue';
import { CircuitBreaker, OrganizationSlots } from '../scm/runtime';
import { errorCodeOf, TRANSIENT_FAILURES, type LlmErrorCode } from './errors';
import { baseUrlHash, buildIssueInput, cacheKeyOf } from './input';
import { callProvider, LlmError, type LlmAnswer } from './providers';
import { LLM_QUEUE } from './service';
import {
  organizationSettings,
  pathExcluded,
  providerApiKey,
  providerConfig,
  readLlmSettings,
} from './settings';

export const LLM_WORKER_CONCURRENCY = 2;
export const LLM_MAX_ATTEMPTS = 3;
/** Delays before the second and third attempts (llm.md §14), unless Retry-After says longer. */
export const LLM_RETRY_SECONDS = [5, 30] as const;
/** A job whose organisation already has a request in flight in this process waits this long. */
export const LLM_BUSY_DEFER_SECONDS = 2;
/** llm.md §14, plan 3B ruling LL4: a provider's `Retry-After` is honoured within 1 s – 2 min. */
const MIN_RETRY_AFTER = 1;
const MAX_RETRY_AFTER = 120;
/**
 * The worker's job lease (llm.md §12.3: `2 × timeoutSeconds + 60 s`), at the longest timeout the
 * settings allow; the heartbeat keeps a live call's lease anyway.
 */
export const LLM_LEASE_MS = 2 * 600_000 + 60_000;
/**
 * The stored answer's bound, as PostgreSQL measures it (`octet_length(result::text)`, the CHECK
 * `llm_requests_result_size` of 16 384 bytes), with a margin.
 */
export const LLM_RESULT_MAX_BYTES = 15 * 1024;

export const llmJobPayload = z.strictObject({
  requestId: z.uuid(),
  attempt: z.number().int().min(0).max(10),
  /**
   * The SHA-256 of the provider base URL when the person asked (`baseUrlHash`): the row keeps
   * only the host, and a base URL changed on the same host (another path or port) is
   * `SETTINGS_CHANGED` too (llm.md §14). Never the URL itself.
   */
  baseUrl: z.string().regex(/^[0-9a-f]{64}$/),
});
export type LlmJobPayload = z.infer<typeof llmJobPayload>;

/**
 * The per-process state of the `llm` worker: a circuit per provider base URL (llm.md §14) and one
 * request in flight per organisation (§12.3). Nothing of it is shown through the API.
 */
export interface LlmRuntime {
  circuit: CircuitBreaker;
  slots: OrganizationSlots;
}
export function createLlmRuntime(now: () => number = Date.now): LlmRuntime {
  return { circuit: new CircuitBreaker(now), slots: new OrganizationSlots(1) };
}

export interface LlmJobDeps {
  db: Db;
  secretKey: string;
  internalHosts: ReadonlySet<string>;
  runtime: LlmRuntime;
  logger?: WorkerLogger | undefined;
  version: string;
  resolve?: Resolver;
  /**
   * The prompt's nonce; default 16 random bytes in hex.
   * @internal Tests only: main.ts never sets it, and nothing else may.
   */
  nonce?: () => string;
}

/**
 * The byte length of `value` as PostgreSQL writes a jsonb value as text (`jsonb::text`): the
 * escapes of `JSON.stringify` (the same set: `"`, `\`, and the C0 controls), with a space after
 * every `:` and `,` between members and elements.
 */
export function jsonbTextBytes(value: unknown): number {
  if (Array.isArray(value)) {
    const items = value as unknown[];
    if (items.length === 0) return 2;
    return 2 + 2 * (items.length - 1) + items.reduce<number>((n, v) => n + jsonbTextBytes(v), 0);
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) return 2;
    return (
      2 +
      2 * (entries.length - 1) +
      entries.reduce<number>(
        (n, [k, v]) => n + Buffer.byteLength(JSON.stringify(k), 'utf8') + 2 + jsonbTextBytes(v),
        0,
      )
    );
  }
  return Buffer.byteLength(JSON.stringify(value) ?? 'null', 'utf8');
}

function scrub(text: string, key: string | null): string {
  return key !== null && key.length >= 8 ? text.split(key).join(REDACTED) : text;
}

/**
 * Every string of a parsed answer with the key scrubbed (llm.md §9.3): the answer text may spell
 * the key with JSON escapes (`\u0073k-…`), which the scrub of the raw text cannot see.
 */
function scrubStrings<T>(value: T, key: string | null): T {
  if (typeof value === 'string') return scrub(value, key) as T;
  if (Array.isArray(value)) return value.map((v: unknown) => scrubStrings(v, key)) as T;
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, scrubStrings(v, key)]),
    ) as T;
  }
  return value;
}

/**
 * llm.md §10.1: the estimated cost in micro-USD whenever prices are set and both token counts are
 * known, whatever became of the answer (the tokens were spent).
 */
export function costOf(
  pricing: { inputUsdPerMTok: number; outputUsdPerMTok: number } | null,
  tokens: { inputTokens: number | null; outputTokens: number | null },
): number | null {
  if (pricing === null || tokens.inputTokens === null || tokens.outputTokens === null) return null;
  return Math.round(
    tokens.inputTokens * pricing.inputUsdPerMTok + tokens.outputTokens * pricing.outputUsdPerMTok,
  );
}

type Outcome =
  | {
      ok: true;
      result: unknown;
      inputTokens: number | null;
      outputTokens: number | null;
      costMicroUsd: number | null;
    }
  | {
      ok: false;
      code: LlmErrorCode | `OUTPUT_REFUSED:${string}`;
      inputTokens?: number | null;
      outputTokens?: number | null;
      costMicroUsd?: number | null;
      /** The provider's HTTP status of a failed call, for the log (401 and 403 read apart). */
      providerStatus?: number | null;
    };

/**
 * Records the request's end (llm.md §10.1) and writes its one log line: metadata only, never the
 * data sent, the answer, the base URL or the key. Only a row still `running` is finished: when the
 * job lost its lease meanwhile (the sweep failed the row with `REQUEST_ABANDONED`), nothing
 * changes.
 */
async function finish(
  deps: LlmJobDeps,
  row: LlmRequestRow,
  started: number,
  outcome: Outcome,
): Promise<void> {
  const durationMs = Date.now() - started;
  const finished = await deps.db
    .update(llmRequests)
    .set({
      status: outcome.ok ? 'succeeded' : 'failed',
      result: outcome.ok ? outcome.result : null,
      errorCode: outcome.ok ? null : outcome.code,
      inputTokens: outcome.inputTokens ?? null,
      outputTokens: outcome.outputTokens ?? null,
      costMicroUsd: outcome.costMicroUsd ?? null,
      durationMs,
      finishedAt: sql`now()`,
      updatedAt: sql`now()`,
    })
    .where(and(eq(llmRequests.id, row.id), eq(llmRequests.status, 'running')))
    .returning({ id: llmRequests.id });
  if (finished.length === 0) {
    deps.logger?.warn(
      { requestId: row.id, organizationId: row.organizationId },
      'AI request no longer running (its job lost its lease); its outcome is not recorded',
    );
    return;
  }
  deps.logger?.info(
    {
      requestId: row.id,
      organizationId: row.organizationId,
      feature: row.feature,
      provider: row.provider,
      providerHost: row.providerHost,
      model: row.model,
      promptVersion: row.promptVersion,
      status: outcome.ok ? 'succeeded' : 'failed',
      errorCode: outcome.ok ? null : outcome.code,
      providerStatus: outcome.ok ? null : (outcome.providerStatus ?? null),
      inputBytes: row.inputBytes,
      inputSha256: row.inputSha256,
      redactions: row.redactions,
      inputTokens: outcome.inputTokens ?? null,
      outputTokens: outcome.outputTokens ?? null,
      durationMs,
    },
    'AI request finished',
  );
}

/**
 * llm.md §9.3–§9.5, §10.1: the answer parsed, a fix checked, the key scrubbed and the result
 * bounded; what is stored, or why nothing is. None of these failures is retried.
 */
function validate(
  feature: LlmRequestRow['feature'],
  answer: LlmAnswer,
  key: string | null,
  input: Parameters<typeof checkFix>[1],
): { ok: true; result: unknown } | { ok: false; code: Extract<Outcome, { ok: false }>['code'] } {
  const parsed = parseAnswer(feature, {
    text: scrub(answer.text, key),
    finishReason: answer.finishReason,
  });
  if (!parsed.ok) return { ok: false, code: parsed.code };
  // Scrubbed again once parsed: the final strings are what is stored, shown and posted.
  const value = scrubStrings(parsed.value, key);
  let result: unknown = value;
  if (feature === 'fix') {
    if ('kind' in value) return { ok: false, code: 'MALFORMED_OUTPUT' };
    const checked = checkFix(value, input);
    if (!checked.ok) return { ok: false, code: `OUTPUT_REFUSED:${checked.problem}` };
    result = checked.value;
  }
  // A fix may hold 15 original and 30 replacement lines of 400 characters: more than the column
  // holds in the widest scripts. Refused here rather than by the CHECK (a database error).
  if (jsonbTextBytes(result) > LLM_RESULT_MAX_BYTES) {
    return { ok: false, code: feature === 'fix' ? 'OUTPUT_REFUSED:size' : 'MALFORMED_OUTPUT' };
  }
  return { ok: true, result };
}

async function runLlmJob(deps: LlmJobDeps, payload: LlmJobPayload): Promise<void> {
  const [row] = await deps.db
    .select()
    .from(llmRequests)
    .where(eq(llmRequests.id, payload.requestId));
  if (!row || row.status === 'succeeded' || row.status === 'failed') return;
  if (!deps.runtime.slots.tryTake(row.organizationId)) {
    // llm.md §12.3: one request per organisation per process; this one waits its turn.
    await enqueue(deps.db, {
      queue: LLM_QUEUE,
      payload,
      runAt: inSeconds(LLM_BUSY_DEFER_SECONDS),
      maxAttempts: 1,
    });
    return;
  }
  const started = Date.now();
  try {
    const claimed = await deps.db
      .update(llmRequests)
      .set({ status: 'running', attempts: payload.attempt + 1, updatedAt: sql`now()` })
      .where(and(eq(llmRequests.id, row.id), inArray(llmRequests.status, ['queued', 'running'])))
      .returning({ id: llmRequests.id });
    // Finished meanwhile (the sweep failed it): nothing to send.
    if (claimed.length === 0) return;
    // Everything is read again (llm.md §14): the admin or the analysis may have changed it all
    // since the click, and then nothing is sent.
    const settings = await readLlmSettings(deps.db);
    const provider = settings.provider;
    const org = organizationSettings(settings, row.organizationId);
    if (
      provider === null ||
      !org.enabled ||
      !org.features[row.feature] ||
      org.excludedProjectIds.includes(row.projectId)
    ) {
      return await finish(deps, row, started, { ok: false, code: 'AI_DISABLED' });
    }
    if (
      provider.kind !== row.provider ||
      provider.model !== row.model ||
      new URL(provider.baseUrl).host !== row.providerHost ||
      baseUrlHash(provider.baseUrl) !== payload.baseUrl
    ) {
      return await finish(deps, row, started, { ok: false, code: 'SETTINGS_CHANGED' });
    }
    const key = providerApiKey(settings, deps.secretKey);
    if (!key.ok) return await finish(deps, row, started, { ok: false, code: 'KEY_UNDECRYPTABLE' });
    if (row.issueId === null) {
      return await finish(deps, row, started, { ok: false, code: 'ISSUE_GONE' });
    }
    const built = await buildIssueInput(deps.db, row.issueId, row.feature);
    if (!built) return await finish(deps, row, started, { ok: false, code: 'ISSUE_GONE' });
    if (pathExcluded(settings, built.issue.path)) {
      return await finish(deps, row, started, { ok: false, code: 'AI_DISABLED' });
    }
    const ineligible = llmIneligibility(
      row.feature,
      {
        status: built.issue.status,
        path: built.issue.path,
        startLine: built.issue.startLine,
        hasSnippet: built.input.snippet !== null,
      },
      { engineId: built.rule.engineId, cwe: built.rule.cwe, tags: built.rule.tags },
    );
    const cacheKey = cacheKeyOf(
      row.organizationId,
      row.feature,
      provider,
      built.rule.key,
      built.issue.fingerprint,
      built.inputSha256,
    );
    if (ineligible !== null || cacheKey !== row.cacheKey) {
      return await finish(deps, row, started, { ok: false, code: 'ISSUE_CHANGED' });
    }
    // Built before the circuit is asked: a prompt that cannot be built must not hold a probe.
    const prompt = buildPrompt(
      row.feature,
      built.input,
      deps.nonce?.() ?? randomBytes(16).toString('hex'),
    );
    const circuitKey = provider.baseUrl;
    if (!deps.runtime.circuit.tryPass(circuitKey)) {
      // llm.md §14: an open circuit sends nothing, and the request fails at once.
      return await finish(deps, row, started, { ok: false, code: 'PROVIDER_UNAVAILABLE' });
    }
    let answer: LlmAnswer;
    try {
      answer = await callProvider(
        providerConfig(provider),
        key.key,
        {
          system: prompt.system,
          user: prompt.user,
          maxOutputTokens: MAX_OUTPUT_TOKENS[row.feature],
        },
        {
          internalHosts: deps.internalHosts,
          version: deps.version,
          ...(deps.resolve ? { resolve: deps.resolve } : {}),
        },
      );
      deps.runtime.circuit.success(circuitKey);
    } catch (err) {
      if (!(err instanceof LlmError)) {
        deps.runtime.circuit.release(circuitKey);
        throw err;
      }
      const transient = TRANSIENT_FAILURES.has(err.failure);
      if (transient) deps.runtime.circuit.failure(circuitKey);
      else if (err.status !== null) deps.runtime.circuit.success(circuitKey);
      else deps.runtime.circuit.release(circuitKey);
      return await retryOrFail(deps, row, payload, started, err, transient);
    }
    const tokens = {
      inputTokens: answer.usage.inputTokens,
      outputTokens: answer.usage.outputTokens,
    };
    const costMicroUsd = costOf(settings.pricing, tokens);
    const checked = validate(row.feature, answer, key.key, built.input);
    if (!checked.ok) {
      return await finish(deps, row, started, {
        ok: false,
        code: checked.code,
        ...tokens,
        costMicroUsd,
      });
    }
    await finish(deps, row, started, {
      ok: true,
      result: checked.result,
      ...tokens,
      costMicroUsd,
    });
  } finally {
    deps.runtime.slots.release(row.organizationId);
  }
}

/**
 * llm.md §14: a transient failure is tried again (3 attempts in all), after the backoff or the
 * provider's `Retry-After` (clamped to 1 s – 2 min) when that is longer; anything else fails the
 * request now.
 */
async function retryOrFail(
  deps: LlmJobDeps,
  row: LlmRequestRow,
  payload: LlmJobPayload,
  started: number,
  err: LlmError,
  transient: boolean,
): Promise<void> {
  const next = payload.attempt + 1;
  if (transient && next < LLM_MAX_ATTEMPTS) {
    const base = LLM_RETRY_SECONDS[Math.min(payload.attempt, LLM_RETRY_SECONDS.length - 1)] ?? 30;
    const asked =
      err.retryAfterSeconds === null
        ? 0
        : Math.min(MAX_RETRY_AFTER, Math.max(MIN_RETRY_AFTER, err.retryAfterSeconds));
    const wait = Math.max(base, asked);
    // The row goes back to queued with its next job in one transaction: the stuck-row sweep
    // never sees one without the other. Only a row still running: a job that lost its lease (the
    // sweep failed the row) neither requeues it nor enqueues anything.
    const requeued = await deps.db.transaction(async (tx) => {
      const updated = await tx
        .update(llmRequests)
        .set({ status: 'queued', updatedAt: sql`now()` })
        .where(and(eq(llmRequests.id, row.id), eq(llmRequests.status, 'running')))
        .returning({ id: llmRequests.id });
      if (updated.length === 0) return false;
      await enqueue(tx, {
        queue: LLM_QUEUE,
        payload: { ...payload, attempt: next } satisfies LlmJobPayload,
        runAt: inSeconds(wait),
        maxAttempts: 1,
      });
      return true;
    });
    if (!requeued) return;
    deps.logger?.info(
      {
        requestId: row.id,
        attempt: next,
        waitSeconds: wait,
        errorCode: errorCodeOf(err),
        providerStatus: err.status,
      },
      'AI request retried',
    );
    return;
  }
  await finish(deps, row, started, {
    ok: false,
    code: errorCodeOf(err),
    providerStatus: err.status,
  });
}

/**
 * Fails every `queued` or `running` request that no live `llm` job (queued or running) will ever
 * finish: its worker died and the reaper made the job dead, or its handler threw. Decided by the
 * jobs alone, never by the row's age (a request may wait long behind its organisation's backlog).
 * Run after every reap cycle of the `llm` worker, like `reconcileDeadAnalyses`.
 */
export async function reconcileStuckLlmRequests(db: Executor): Promise<number> {
  const result = await db.execute(sql`
    UPDATE llm_requests r
       SET status = 'failed', error_code = 'REQUEST_ABANDONED', result = NULL,
           finished_at = now(), updated_at = now()
     WHERE r.status IN ('queued', 'running')
       AND NOT EXISTS (
             SELECT 1 FROM jobs j
              WHERE j.queue = ${LLM_QUEUE} AND j.status IN ('queued', 'running')
                -- Compared as text: a malformed payload must not make the sweep fail.
                AND j.payload ->> 'requestId' = r.id::text)`);
  return result.rowCount ?? 0;
}

/** The `llm` queue's handler (llm.md §12.3, §14); its own worker runs it (main.ts). */
export function llmHandlers(deps: LlmJobDeps): JobHandlers {
  return {
    [LLM_QUEUE]: async (job) => {
      const parsed = llmJobPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed AI job payload; completing');
        return;
      }
      await runLlmJob(deps, parsed.data);
    },
  };
}

import { eq, sql } from 'drizzle-orm';
import { encryptionKey, encryptSecret } from '../src/crypto/secrets';
import type { Db } from '../src/db/client';
import { jobs } from '../src/db/schema';
import { createLlmRuntime, llmHandlers, type LlmJobDeps } from '../src/llm/job';
import type { ProviderKind } from '../src/llm/providers';
import { LLM_QUEUE } from '../src/llm/service';
import {
  DEFAULT_LLM_SETTINGS,
  LLM_API_KEY_AAD,
  writeLlmSettings,
  type StoredLlmSettings,
  type StoredProvider,
} from '../src/llm/settings';
import { runUntilIdle } from '../src/queue/worker';
import type { FakeLlm } from './fake-llm';
import type { IngestHarness } from './ingest';
import { silentLogger } from './scm';

/** The fake as a stored provider, model `fake-model`, its key encrypted. */
export function configuredProvider(
  secretKey: string,
  fake: FakeLlm,
  kind: ProviderKind = 'openai',
): StoredProvider {
  return {
    kind,
    baseUrl: kind === 'openai' ? fake.openAiBaseUrl : fake.anthropicBaseUrl,
    model: 'fake-model',
    auth: 'bearer',
    jsonMode: 'json_object',
    maxTokensField: 'max_tokens',
    temperature: null,
    timeoutSeconds: 5,
    apiKeyEnc:
      fake.apiKey === ''
        ? null
        : encryptSecret(encryptionKey(secretKey), fake.apiKey, LLM_API_KEY_AAD),
  };
}

/** Turns the AI assistant on for one organisation against the fake, every feature enabled. */
export async function configureLlm(
  db: Db,
  secretKey: string,
  fake: FakeLlm,
  organizationId: string,
  over: Partial<StoredLlmSettings> & { kind?: ProviderKind } = {},
): Promise<void> {
  const { kind = 'openai', ...rest } = over;
  await writeLlmSettings(db, {
    ...DEFAULT_LLM_SETTINGS,
    provider: configuredProvider(secretKey, fake, kind),
    organizations: {
      [organizationId]: {
        enabled: true,
        features: { explain: true, triage: true, fix: true },
        excludedProjectIds: [],
      },
    },
    ...rest,
  });
}

/** The `llm` worker's dependencies against the harness (a fresh circuit and slots). */
export function llmJobDeps(h: IngestHarness, over: Partial<LlmJobDeps> = {}): LlmJobDeps {
  return {
    db: h.ctx.db,
    secretKey: h.ctx.config.secretKey,
    internalHosts: h.ctx.config.llmInternalHosts,
    runtime: createLlmRuntime(),
    logger: h.ctx.app.log,
    version: '0.0.0',
    ...over,
  };
}

/** Makes every queued `llm` job due now, then runs the queue until idle. */
export async function runLlmJobs(h: IngestHarness, deps: LlmJobDeps): Promise<number> {
  await h.ctx.db
    .update(jobs)
    .set({ runAt: sql`now()` })
    .where(eq(jobs.queue, LLM_QUEUE));
  return runUntilIdle(h.ctx.db, llmHandlers(deps), silentLogger);
}

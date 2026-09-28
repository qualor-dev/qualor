import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildPrompt,
  checkFix,
  LLM_FEATURES,
  llmIssueInputSchema,
  MAX_OUTPUT_TOKENS,
  parseAnswer,
  parseModelJson,
  type FixAnswer,
  type LlmFeature,
  type LlmIssueInput,
} from '@qualor/shared';
import type { Resolver } from '../../server/src/http/outbound';
import { llmBaseUrlProblem } from '../../server/src/llm/url';
import { callProvider, LlmError, type ProviderConfig } from '../../server/src/llm/providers';
import {
  isInternalHostAllowed,
  isLoopbackHost,
  parseInternalHosts,
} from '../../server/src/scm/url';

/**
 * Plan 3B Task 20, llm.md §17: the opt-in live check of the `openai` adapter against a local
 * Ollama's `/v1`, run only by hand through `pnpm llm:live` (`ollama.live.test.ts`). It sends the
 * three prompts of the `llm-prompts` fixture's synthetic cases (never repository content), with no
 * API key, to a loopback URL (or a host listed in `QUALOR_LIVE_LLM_ALLOWED_HOSTS`), and prints
 * aggregates only: calls, valid JSON, finish reasons, `<think>` blocks, outcomes, latency and
 * tokens. Never a prompt, an answer or a line of code. Checked against the fake by
 * `ollama-live.test.ts`.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** The only input: the synthetic cases of the llm-prompts fixture (Task 17). */
export const LIVE_FIXTURE = 'fixtures/llm-prompts/llm/expected.json';

export interface LiveOptions {
  /** The OpenAI-compatible base URL, e.g. `http://localhost:11434/v1`, without a trailing slash. */
  url: string;
  model: string;
  /** Calls per feature and case. */
  runs: number;
  timeoutSeconds: number;
  jsonMode: 'json_object' | 'none';
  /** `QUALOR_LIVE_LLM_ALLOWED_HOSTS`, in `QUALOR_LLM_INTERNAL_HOSTS` syntax; '' for none. */
  allowedHosts: string;
}

type Env = Readonly<Record<string, string | undefined>>;

/** The project `llm-live` exists (vitest.config.ts) only with both variables set. */
export function liveEnabled(env: Env): boolean {
  return (env.QUALOR_LIVE_LLM_URL ?? '') !== '' && (env.QUALOR_LIVE_LLM_MODEL ?? '') !== '';
}

function intIn(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

export function readLiveEnv(env: Env): LiveOptions {
  const url = env.QUALOR_LIVE_LLM_URL ?? '';
  const model = env.QUALOR_LIVE_LLM_MODEL ?? '';
  if (url === '') throw new Error('Set QUALOR_LIVE_LLM_URL (e.g. http://localhost:11434/v1)');
  if (model === '') throw new Error('Set QUALOR_LIVE_LLM_MODEL (e.g. qwen2.5-coder:7b)');
  const jsonMode = env.QUALOR_LIVE_LLM_JSON_MODE ?? 'json_object';
  if (jsonMode !== 'json_object' && jsonMode !== 'none') {
    throw new Error('QUALOR_LIVE_LLM_JSON_MODE must be json_object or none');
  }
  return {
    url: url.replace(/\/+$/, ''),
    model,
    runs: intIn(env, 'QUALOR_LIVE_LLM_RUNS', 3, 1, 10),
    // The settings' own bounds (llm.md §3.2).
    timeoutSeconds: intIn(env, 'QUALOR_LIVE_LLM_TIMEOUT_SECONDS', 300, 5, 600),
    jsonMode,
    allowedHosts: env.QUALOR_LIVE_LLM_ALLOWED_HOSTS ?? '',
  };
}

/**
 * The live check contacts a loopback host (`localhost`, `127.0.0.0/8`, `::1`) or a host listed in
 * `QUALOR_LIVE_LLM_ALLOWED_HOSTS`, nothing else; then the server's own base URL rules apply.
 * Returns the internal-hosts list the adapter gets.
 */
export function liveTarget(
  raw: string,
  allowedHosts: string,
): { ok: true; internalHosts: ReadonlySet<string> } | { ok: false; problem: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, problem: 'QUALOR_LIVE_LLM_URL is not a valid URL' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, problem: 'QUALOR_LIVE_LLM_URL must be an http or https URL' };
  }
  let listed: ReadonlySet<string>;
  try {
    listed = parseInternalHosts(allowedHosts);
  } catch (err) {
    return { ok: false, problem: `QUALOR_LIVE_LLM_ALLOWED_HOSTS: ${(err as Error).message}` };
  }
  let internalHosts: ReadonlySet<string>;
  if (isInternalHostAllowed(url, listed)) internalHosts = listed;
  else if (isLoopbackHost(url)) internalHosts = parseInternalHosts(url.host);
  else {
    return {
      ok: false,
      problem: `${url.host} is not a loopback host; list it in QUALOR_LIVE_LLM_ALLOWED_HOSTS to use it`,
    };
  }
  const problem = llmBaseUrlProblem(raw, internalHosts);
  return problem === null ? { ok: true, internalHosts } : { ok: false, problem };
}

/** The fixture's eligible cases, validated as the server's input shape. */
export function loadLiveCases(): LlmIssueInput[] {
  const expected = JSON.parse(readFileSync(path.join(root, LIVE_FIXTURE), 'utf8')) as {
    eligible: { data: { explain: { issue: unknown } } }[];
  };
  return expected.eligible.map((c) => llmIssueInputSchema.parse(c.data.explain.issue));
}

export interface FeatureSummary {
  calls: number;
  /** Calls that returned an answer (no provider error). */
  answered: number;
  /** Answers holding one JSON object as llm.md §9.3 accepts it (fence and `<think>` allowed). */
  jsonValid: number;
  /** Answers that start with a `<think>` block. */
  thinkBlock: number;
  finishReasons: Record<string, number>;
  /** `ok`, `ok:<fix status>`, a parse code, `OUTPUT_REFUSED:<problem>` or `error:<failure>`. */
  outcomes: Record<string, number>;
  latencyMs: { min: number; median: number; max: number } | null;
  outputTokens: number;
}

export interface LiveSummary {
  model: string;
  runs: number;
  cases: number;
  jsonMode: LiveOptions['jsonMode'];
  features: Record<LlmFeature, FeatureSummary>;
}

function bump(map: Record<string, number>, key: string): void {
  map[key] = (map[key] ?? 0) + 1;
}

function spread(values: number[]): FeatureSummary['latencyMs'] {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return {
    min: sorted[0] ?? 0,
    median: sorted[Math.floor((sorted.length - 1) / 2)] ?? 0,
    max: sorted[sorted.length - 1] ?? 0,
  };
}

/** A fixed nonce: nothing but the model reads it here; the server draws a fresh one per request. */
const NONCE = 'a'.repeat(32);

/**
 * Runs `runs` calls per feature and case, in order, and returns the aggregates and their JSON text.
 * Throws before any request when the URL is not allowed, and refuses to return a text that holds
 * an answer or a line of the fixture.
 */
export async function runLiveCheck(
  o: LiveOptions,
  seams: { resolve?: Resolver } = {},
): Promise<{ summary: LiveSummary; text: string }> {
  const target = liveTarget(o.url, o.allowedHosts);
  if (!target.ok) throw new Error(target.problem);
  const cases = loadLiveCases();
  const config: ProviderConfig = {
    kind: 'openai',
    baseUrl: o.url,
    model: o.model,
    auth: 'bearer',
    jsonMode: o.jsonMode,
    maxTokensField: 'max_tokens',
    temperature: null,
    timeoutSeconds: o.timeoutSeconds,
  };
  const http = {
    internalHosts: target.internalHosts,
    version: 'live-check',
    resolve: seams.resolve,
  };
  const answers: string[] = [];
  const features = {} as Record<LlmFeature, FeatureSummary>;
  for (const feature of LLM_FEATURES) {
    const s: FeatureSummary = {
      calls: 0,
      answered: 0,
      jsonValid: 0,
      thinkBlock: 0,
      finishReasons: {},
      outcomes: {},
      latencyMs: null,
      outputTokens: 0,
    };
    const latencies: number[] = [];
    for (const input of cases) {
      const prompt = buildPrompt(feature, input, NONCE);
      for (let i = 0; i < o.runs; i += 1) {
        s.calls += 1;
        const started = performance.now();
        try {
          const answer = await callProvider(
            config,
            null,
            {
              system: prompt.system,
              user: prompt.user,
              maxOutputTokens: MAX_OUTPUT_TOKENS[feature],
            },
            http,
          );
          latencies.push(Math.round(performance.now() - started));
          answers.push(answer.text);
          s.answered += 1;
          s.outputTokens += answer.usage.outputTokens ?? 0;
          bump(s.finishReasons, answer.finishReason);
          if (answer.text.trim().startsWith('<think>')) s.thinkBlock += 1;
          if (parseModelJson(answer.text) !== undefined) s.jsonValid += 1;
          const parsed = parseAnswer(feature, answer);
          if (!parsed.ok) bump(s.outcomes, parsed.code);
          else if (feature === 'fix') {
            const checked = checkFix(parsed.value as FixAnswer, input);
            bump(
              s.outcomes,
              checked.ok ? `ok:${checked.value.status}` : `OUTPUT_REFUSED:${checked.problem}`,
            );
          } else bump(s.outcomes, 'ok');
        } catch (err) {
          bump(s.outcomes, err instanceof LlmError ? `error:${err.failure}` : 'error:other');
        }
      }
    }
    s.latencyMs = spread(latencies);
    features[feature] = s;
  }
  const summary: LiveSummary = {
    model: o.model,
    runs: o.runs,
    cases: cases.length,
    jsonMode: o.jsonMode,
    features,
  };
  const text = JSON.stringify(summary, null, 2);
  // Aggregates only: the text holds no answer, no prompt and no line of the fixture.
  const forbidden = [
    ...answers.map((a) => a.trim()),
    ...cases.flatMap((c) => [c.message, ...(c.snippet?.lines ?? [])]),
  ].filter((s) => s.trim().length >= 8);
  if (text.includes('QUALOR-DATA') || forbidden.some((s) => text.includes(s))) {
    throw new Error('The live summary would hold model or fixture text; not printed');
  }
  return { summary, text };
}

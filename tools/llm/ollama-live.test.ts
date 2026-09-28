import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  createFakeLlm,
  openAiAnswer,
  type FakeLlm,
  type RecordedLlmRequest,
} from '../../server/test/fake-llm';
import {
  LIVE_FIXTURE,
  liveEnabled,
  liveTarget,
  loadLiveCases,
  readLiveEnv,
  runLiveCheck,
} from './ollama-live';

/**
 * Plan 3B Task 20: the opt-in live check (`ollama.live.test.ts`), exercised here against the fake
 * LLM only. Nothing in this file contacts a model.
 */

describe('readLiveEnv and liveEnabled', () => {
  it('is enabled only with both the URL and the model', () => {
    expect(liveEnabled({})).toBe(false);
    expect(liveEnabled({ QUALOR_LIVE_LLM_URL: 'http://localhost:11434/v1' })).toBe(false);
    expect(liveEnabled({ QUALOR_LIVE_LLM_MODEL: 'qwen2.5-coder:7b' })).toBe(false);
    expect(
      liveEnabled({
        QUALOR_LIVE_LLM_URL: 'http://localhost:11434/v1',
        QUALOR_LIVE_LLM_MODEL: 'qwen2.5-coder:7b',
      }),
    ).toBe(true);
  });

  it('reads the defaults and refuses out-of-range values', () => {
    const base = { QUALOR_LIVE_LLM_URL: 'http://localhost:11434/v1/', QUALOR_LIVE_LLM_MODEL: 'm' };
    expect(readLiveEnv(base)).toEqual({
      url: 'http://localhost:11434/v1',
      model: 'm',
      runs: 3,
      timeoutSeconds: 300,
      jsonMode: 'json_object',
      allowedHosts: '',
    });
    expect(
      readLiveEnv({
        ...base,
        QUALOR_LIVE_LLM_RUNS: '1',
        QUALOR_LIVE_LLM_TIMEOUT_SECONDS: '600',
        QUALOR_LIVE_LLM_JSON_MODE: 'none',
        QUALOR_LIVE_LLM_ALLOWED_HOSTS: 'ollama:11434',
      }),
    ).toMatchObject({
      runs: 1,
      timeoutSeconds: 600,
      jsonMode: 'none',
      allowedHosts: 'ollama:11434',
    });
    for (const [name, value] of [
      ['QUALOR_LIVE_LLM_RUNS', '0'],
      ['QUALOR_LIVE_LLM_RUNS', '11'],
      ['QUALOR_LIVE_LLM_RUNS', '2.5'],
      ['QUALOR_LIVE_LLM_TIMEOUT_SECONDS', '4'],
      ['QUALOR_LIVE_LLM_TIMEOUT_SECONDS', '601'],
      ['QUALOR_LIVE_LLM_JSON_MODE', 'json_schema'],
    ] as const) {
      expect(() => readLiveEnv({ ...base, [name]: value }), `${name}=${value}`).toThrow(name);
    }
    expect(() => readLiveEnv({ QUALOR_LIVE_LLM_URL: 'http://localhost/v1' })).toThrow(
      'QUALOR_LIVE_LLM_MODEL',
    );
  });
});

describe('liveTarget: loopback only, unless the host is listed', () => {
  it.each([
    'http://localhost:11434/v1',
    'http://127.0.0.1:11434/v1',
    'http://[::1]:11434/v1',
    'http://127.0.0.2:8080/v1',
  ])('accepts the loopback URL %s', (url) => {
    const target = liveTarget(url, '');
    expect(target.ok, JSON.stringify(target)).toBe(true);
  });

  it.each([
    ['http://ollama:11434/v1', /not a loopback host/],
    ['http://10.0.0.5:11434/v1', /not a loopback host/],
    ['https://api.openai.com/v1', /not a loopback host/],
    ['https://api.anthropic.com', /not a loopback host/],
    ['http://user:pw@localhost:11434/v1', /credentials/],
    ['http://localhost:11434/v1?x=1', /query/],
    ['ftp://localhost/v1', /http/],
    ['not a url', /valid URL/],
  ])('refuses %s', (url, problem) => {
    const target = liveTarget(url, '');
    expect(target.ok).toBe(false);
    if (!target.ok) expect(target.problem).toMatch(problem);
  });

  it('accepts a non-loopback host only when QUALOR_LIVE_LLM_ALLOWED_HOSTS lists it', () => {
    expect(liveTarget('http://ollama:11434/v1', 'ollama:11434').ok).toBe(true);
    expect(liveTarget('http://ollama:11434/v1', 'ollama:8080').ok).toBe(false);
    expect(liveTarget('http://10.0.0.5:11434/v1', 'ollama:11434').ok).toBe(false);
    // Listing never opens link-local or cloud metadata addresses.
    const metadata = liveTarget('http://169.254.169.254/v1', '169.254.169.254');
    expect(metadata.ok).toBe(false);
    if (!metadata.ok) expect(metadata.problem).toMatch(/link-local|metadata|not a host/);
  });
});

describe('loadLiveCases', () => {
  it('reads the synthetic cases of the llm-prompts fixture, and nothing else', () => {
    expect(LIVE_FIXTURE).toBe('fixtures/llm-prompts/llm/expected.json');
    const cases = loadLiveCases();
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) expect(c.path).toMatch(/^src\//);
  });
});

/** The data line of the request's prompt (between the nonce markers). */
function dataOf(request: RecordedLlmRequest): unknown {
  const messages = (request.json as { messages: { role: string; content: string }[] }).messages;
  const user = messages.find((m) => m.role === 'user')?.content ?? '';
  const match = /<<<QUALOR-DATA-[0-9a-f]{32}\n(.*)\nQUALOR-DATA-[0-9a-f]{32}>>>/.exec(user);
  return match ? JSON.parse(match[1] ?? '') : undefined;
}

describe('runLiveCheck against the fake LLM', () => {
  let fake: FakeLlm;
  beforeAll(async () => {
    // A local model takes no key: the fake answers 400 to any key header.
    fake = await createFakeLlm({ apiKey: null });
  });
  afterAll(async () => {
    await fake.close();
  });
  beforeEach(() => {
    fake.requests.length = 0;
  });

  const SECRET_ANSWER = 'This answer text must never reach the summary 7f3a9c';

  it('sends every feature of every fixture case, and prints aggregates only', async () => {
    const cases = loadLiveCases();
    const runs = 2;
    // The runner goes feature by feature, then case by case, then run by run.
    const replies = {
      explain: [
        // A reasoning model's <think> block, then a valid answer.
        {
          status: 200,
          body: openAiAnswer(
            `<think>${SECRET_ANSWER}</think>\n{"summary":"s","explanation":"e","howToFix":"h"}`,
          ),
        },
        // Prose around the object (malformed).
        { status: 200, body: openAiAnswer(`${SECRET_ANSWER} {"summary":"s"}`) },
      ],
      triage: [
        // Valid, in a fence.
        {
          status: 200,
          body: openAiAnswer(
            '```json\n{"verdict":"likely_false_positive","confidence":"low","reasons":["r"]}\n```',
          ),
        },
        // Cut off.
        { status: 200, body: openAiAnswer('{"verdict":', { finishReason: 'length' }) },
      ],
      fix: [
        {
          status: 200,
          body: openAiAnswer(
            '{"status":"not_applicable","startLine":1,"endLine":1,"replacement":[],"explanation":"x"}',
          ),
        },
        // The provider fails.
        { status: 503, body: { error: { message: SECRET_ANSWER } } },
      ],
    };
    for (const feature of ['explain', 'triage', 'fix'] as const) {
      for (let i = 0; i < cases.length; i += 1) fake.enqueue(...replies[feature]);
    }
    const { summary, text } = await runLiveCheck({
      url: fake.openAiBaseUrl,
      model: 'fake-model',
      runs,
      timeoutSeconds: 30,
      jsonMode: 'json_object',
      allowedHosts: '',
    });

    expect(fake.requests).toHaveLength(cases.length * 3 * runs);
    for (const request of fake.requests) {
      expect(request.path).toBe('/v1/chat/completions');
      for (const h of ['authorization', 'api-key', 'x-api-key'])
        expect(request.headers).not.toHaveProperty(h);
      // Only the fixture's synthetic data object is sent.
      const data = dataOf(request) as { issue: unknown };
      expect(cases).toContainEqual(data.issue);
    }

    const n = cases.length;
    expect(summary.model).toBe('fake-model');
    expect(summary.cases).toBe(n);
    expect(summary.features.explain).toMatchObject({
      calls: 2 * n,
      answered: 2 * n,
      jsonValid: n,
      thinkBlock: n,
      finishReasons: { stop: 2 * n },
      outcomes: { ok: n, MALFORMED_OUTPUT: n },
    });
    expect(summary.features.triage).toMatchObject({
      calls: 2 * n,
      answered: 2 * n,
      jsonValid: n,
      thinkBlock: 0,
      finishReasons: { stop: n, length: n },
      outcomes: { ok: n, OUTPUT_TRUNCATED: n },
    });
    expect(summary.features.fix).toMatchObject({
      calls: 2 * n,
      answered: n,
      jsonValid: n,
      finishReasons: { stop: n },
      outcomes: { 'ok:not_applicable': n, 'error:unavailable': n },
    });
    const latency = summary.features.explain.latencyMs;
    expect(latency).not.toBeNull();
    expect(latency!.min).toBeLessThanOrEqual(latency!.median);
    expect(latency!.median).toBeLessThanOrEqual(latency!.max);
    expect(summary.features.explain.outputTokens).toBeGreaterThan(0);

    // Aggregates only: no answer text, no prompt, no line of the fixture.
    expect(text).not.toContain(SECRET_ANSWER);
    expect(text).not.toContain('QUALOR-DATA');
    for (const c of cases) {
      expect(text).not.toContain(c.message);
      for (const line of c.snippet?.lines ?? [])
        if (line.trim().length >= 8) expect(text).not.toContain(line);
    }
    expect(JSON.parse(text)).toEqual(summary);
  });

  it('answers with the fake canned answers: fixes checked by checkFix', async () => {
    const { summary } = await runLiveCheck({
      url: fake.openAiBaseUrl,
      model: 'fake-model',
      runs: 1,
      timeoutSeconds: 30,
      jsonMode: 'none',
      allowedHosts: '',
    });
    expect(summary.features.explain.outcomes).toEqual({ ok: summary.cases });
    expect(summary.features.triage.outcomes).toEqual({ ok: summary.cases });
    const fixes = Object.keys(summary.features.fix.outcomes);
    for (const k of fixes) expect(k).toMatch(/^(ok:|OUTPUT_REFUSED:)/);
    // jsonMode none: no response_format sent.
    for (const r of fake.requests) expect(r.json).not.toHaveProperty('response_format');
  });

  it('refuses a URL that is not loopback or listed before sending anything', async () => {
    await expect(
      runLiveCheck({
        url: 'https://api.openai.com/v1',
        model: 'gpt',
        runs: 1,
        timeoutSeconds: 30,
        jsonMode: 'json_object',
        allowedHosts: '',
      }),
    ).rejects.toThrow(/not a loopback host/);
    expect(fake.requests).toHaveLength(0);
  });

  it('refuses a listed name that resolves to a loopback address (outbound defence in depth)', async () => {
    const { summary } = await runLiveCheck(
      {
        url: `http://ollama.test:${new URL(fake.url).port}/v1`,
        model: 'fake-model',
        runs: 1,
        timeoutSeconds: 30,
        jsonMode: 'json_object',
        allowedHosts: `ollama.test:${new URL(fake.url).port}`,
      },
      { resolve: () => Promise.resolve([{ address: '127.0.0.1', family: 4 }]) },
    );
    expect(summary.features.explain.outcomes).toEqual({ 'error:url_not_allowed': summary.cases });
    expect(fake.requests).toHaveLength(0);
  });
});

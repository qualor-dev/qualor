import { inspect } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  anthropicAnswer,
  createFakeLlm,
  llmShape,
  openAiAnswer,
  type FakeLlm,
} from '../../../test/fake-llm';
import { loadConfig } from '../../config';
import { parseInternalHosts } from '../../scm/url';
import {
  callProvider,
  LLM_MAX_ANSWER_BYTES,
  LlmError,
  MAX_TOKEN_COUNT,
  retryAfterSeconds,
  type ProviderConfig,
} from './index';

const call = { system: 'S', user: 'U', maxOutputTokens: 50 };

describe('callProvider (llm.md §2, §4, §14)', () => {
  let fake: FakeLlm;
  let http: { internalHosts: ReadonlySet<string>; version: string };
  let openai: ProviderConfig;
  let anthropic: ProviderConfig;
  beforeAll(async () => {
    fake = await createFakeLlm();
    http = { internalHosts: parseInternalHosts(fake.host), version: '0.0.0' };
  });
  afterAll(async () => {
    await fake.close();
  });
  beforeEach(() => {
    fake.requests.length = 0;
    const base = {
      model: 'm-1',
      auth: 'bearer',
      jsonMode: 'json_object',
      maxTokensField: 'max_tokens',
      temperature: null,
      timeoutSeconds: 5,
    } as const;
    openai = { kind: 'openai', baseUrl: fake.openAiBaseUrl, ...base };
    anthropic = { kind: 'anthropic', baseUrl: fake.anthropicBaseUrl, ...base };
  });

  it('sends exactly the documented OpenAI body and headers, and reads the answer', async () => {
    fake.say('{"a":1}');
    const answer = await callProvider(openai, fake.apiKey, call, http);
    expect(answer).toEqual({
      text: '{"a":1}',
      finishReason: 'stop',
      usage: { inputTokens: 412, outputTokens: 96 },
      model: 'fake-openai-model',
    });
    const sent = fake.requests[0]!;
    expect(sent.json).toEqual({
      model: 'm-1',
      messages: [
        { role: 'system', content: 'S' },
        { role: 'user', content: 'U' },
      ],
      max_tokens: 50,
      response_format: { type: 'json_object' },
    });
    expect(sent.headers.authorization).toBe(`Bearer ${fake.apiKey}`);
    expect(sent.headers['user-agent']).toBe('Qualor/0.0.0');
  });

  it.each([
    ['negative', -1],
    ['fractional', 1.5],
    ['over the ceiling', MAX_TOKEN_COUNT + 1],
    ['huge', 1e300],
    ['a string', '412'],
    ['null', null],
  ])(
    'stores a %s token count as unknown, and still reads the answer (both shapes)',
    async (_name, count) => {
      fake.enqueue(
        {
          status: 200,
          body: {
            ...(openAiAnswer('{"a":1}') as object),
            usage: { prompt_tokens: count, completion_tokens: 7 },
          },
        },
        {
          status: 200,
          body: {
            ...(anthropicAnswer('{"a":1}') as object),
            usage: { input_tokens: 9, output_tokens: count },
          },
        },
      );
      const a = await callProvider(openai, fake.apiKey, call, http);
      expect([a.text, a.usage]).toEqual(['{"a":1}', { inputTokens: null, outputTokens: 7 }]);
      const b = await callProvider(anthropic, fake.apiKey, call, http);
      expect([b.text, b.usage]).toEqual(['{"a":1}', { inputTokens: 9, outputTokens: null }]);
    },
  );

  it('keeps a token count at the ceiling, and reads a usage that is not an object as unknown', async () => {
    fake.enqueue(
      {
        status: 200,
        body: {
          ...(openAiAnswer('{}') as object),
          usage: { prompt_tokens: MAX_TOKEN_COUNT, completion_tokens: 0 },
        },
      },
      { status: 200, body: { ...(openAiAnswer('{}') as object), usage: 'lots' } },
    );
    expect((await callProvider(openai, fake.apiKey, call, http)).usage).toEqual({
      inputTokens: MAX_TOKEN_COUNT,
      outputTokens: 0,
    });
    expect((await callProvider(openai, fake.apiKey, call, http)).usage).toEqual({
      inputTokens: null,
      outputTokens: null,
    });
  });

  it('honours auth, jsonMode, maxTokensField and temperature', async () => {
    const config = {
      ...openai,
      auth: 'api-key',
      jsonMode: 'none',
      maxTokensField: 'max_completion_tokens',
      temperature: 0,
    } as const;
    await callProvider(config, fake.apiKey, call, http);
    const sent = fake.requests[0]!;
    expect(sent.headers['api-key']).toBe(fake.apiKey);
    expect(sent.headers.authorization).toBeUndefined();
    expect(sent.json).toMatchObject({ max_completion_tokens: 50, temperature: 0 });
    expect(sent.json).not.toHaveProperty('response_format');
    expect(sent.json).not.toHaveProperty('max_tokens');
  });

  it('sends no auth header without a key', async () => {
    const open = await createFakeLlm({ apiKey: null });
    try {
      await callProvider({ ...openai, baseUrl: open.openAiBaseUrl }, null, call, {
        ...http,
        internalHosts: parseInternalHosts(open.host),
      });
      expect(open.requests[0]!.headers.authorization).toBeUndefined();
    } finally {
      await open.close();
    }
  });

  it('sends the documented Anthropic body and headers, and joins the text blocks', async () => {
    const two = {
      ...(anthropicAnswer('') as object),
      content: [
        { type: 'text', text: '{"a"' },
        { type: 'text', text: ':1}' },
      ],
    };
    fake.enqueue({ status: 200, body: two });
    const answer = await callProvider(anthropic, fake.apiKey, call, http);
    expect(answer.text).toBe('{"a":1}');
    expect(answer.usage).toEqual({ inputTokens: 431, outputTokens: 102 });
    const sent = fake.requests[0]!;
    expect(sent.path).toBe('/v1/messages');
    expect(sent.headers['x-api-key']).toBe(fake.apiKey);
    expect(sent.headers['anthropic-version']).toBe('2023-06-01');
    expect(sent.json).toEqual({
      model: 'm-1',
      max_tokens: 50,
      system: 'S',
      messages: [{ role: 'user', content: 'U' }],
    });
  });

  it.each([
    ['openai', openAiAnswer('x', { finishReason: 'length' }), 'length'],
    ['openai', openAiAnswer('x', { finishReason: 'content_filter' }), 'refusal'],
    ['openai', openAiAnswer('x', { toolCalls: true }), 'tool'],
    ['anthropic', anthropicAnswer('x', { stopReason: 'max_tokens' }), 'length'],
    ['anthropic', anthropicAnswer('x', { stopReason: 'refusal' }), 'refusal'],
    ['anthropic', anthropicAnswer('x', { toolUse: true }), 'tool'],
  ])('maps the finish reason of %s (%#)', async (kind, body, reason) => {
    fake.enqueue({ status: 200, body });
    const config = kind === 'anthropic' ? anthropic : openai;
    expect((await callProvider(config, fake.apiKey, call, http)).finishReason).toBe(reason);
  });

  it.each([
    [429, { 'retry-after': '7' }, 'rate_limited', 7],
    [401, {}, 'refused_key', null],
    [403, {}, 'refused_key', null],
    [404, {}, 'rejected', null],
    [400, {}, 'rejected', null],
    [302, { location: 'https://elsewhere.example' }, 'rejected', null],
    [307, { location: '/v1/chat/completions' }, 'rejected', null],
    [500, {}, 'unavailable', null],
    [529, {}, 'unavailable', null],
  ])('classifies HTTP %i', async (status, headers, failure, retryAfter) => {
    fake.enqueue({ status, headers, body: llmShape('openai-error') });
    const err = await callProvider(openai, fake.apiKey, call, http).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LlmError);
    expect(err).toMatchObject({ failure, status, retryAfterSeconds: retryAfter });
    expect((err as Error).message).not.toContain('Fake error text');
    expect(fake.requests).toHaveLength(1);
  });

  it.each([
    ['openai', 401, 'The provider refused the API key (HTTP 401)'],
    ['anthropic', 401, 'The provider refused the API key (HTTP 401)'],
    [
      'openai',
      403,
      'The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit',
    ],
    [
      'anthropic',
      403,
      'The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit',
    ],
  ])('names the status of a refused %s key (HTTP %i)', async (kind, status, message) => {
    fake.enqueue({ status, body: llmShape('openai-error') });
    const config = kind === 'anthropic' ? anthropic : openai;
    const err = await callProvider(config, fake.apiKey, call, http).catch((e: unknown) => e);
    expect(err).toMatchObject({ failure: 'refused_key', status, message });
  });

  it('refuses an answer that is not the provider shape', async () => {
    fake.enqueue({ status: 200, body: { choices: [] } });
    await expect(callProvider(openai, fake.apiKey, call, http)).rejects.toMatchObject({
      failure: 'bad_answer',
    });
    fake.enqueue({ status: 200, body: 'not json' });
    await expect(callProvider(openai, fake.apiKey, call, http)).rejects.toMatchObject({
      failure: 'bad_answer',
    });
  });

  it('fails with timeout, naming the seconds, when the model is slower than timeoutSeconds', async () => {
    fake.enqueue({ status: 200, body: openAiAnswer('{}'), delayMs: 1_500 });
    const err = await callProvider({ ...openai, timeoutSeconds: 1 }, fake.apiKey, call, http).catch(
      (e: unknown) => e,
    );
    expect(err).toMatchObject({ failure: 'timeout' });
    expect((err as Error).message).toBe(
      'The model did not answer within 1 s; raise the timeout in the AI assistant settings',
    );
  });

  it('never contacts an address that is not listed', async () => {
    const err = await callProvider(openai, fake.apiKey, call, {
      ...http,
      internalHosts: new Set(),
    }).catch((e: unknown) => e);
    expect(err).toMatchObject({ failure: 'url_not_allowed' });
    expect(fake.requests).toHaveLength(0);
  });

  it('never puts the API key in an error, its inspection or its JSON', async () => {
    const errors: unknown[] = [];
    for (const reply of [
      { status: 401, body: llmShape('openai-error') },
      { status: 500, body: llmShape('openai-error') },
      { status: 200, body: 'not json' },
      { status: 200, body: openAiAnswer('{}'), delayMs: 1_500 },
    ]) {
      fake.enqueue(reply);
      errors.push(
        await callProvider({ ...openai, timeoutSeconds: 1 }, fake.apiKey, call, http).catch(
          (e: unknown) => e,
        ),
      );
    }
    errors.push(
      await callProvider(anthropic, fake.apiKey, call, { ...http, internalHosts: new Set() }).catch(
        (e: unknown) => e,
      ),
    );
    for (const err of errors) {
      expect(err).toBeInstanceOf(LlmError);
      const text = [
        inspect(err, { depth: 10, showHidden: true }),
        JSON.stringify(err),
        String(err),
        (err as Error).stack,
      ].join('\n');
      expect(text).not.toContain(fake.apiKey);
    }
  });

  it('follows no redirect to the fake itself', async () => {
    fake.enqueue({
      status: 302,
      headers: { location: `${fake.url}/v1/chat/completions` },
      body: '',
    });
    await expect(callProvider(openai, fake.apiKey, call, http)).rejects.toMatchObject({
      failure: 'rejected',
      status: 302,
    });
    expect(fake.requests).toHaveLength(1);
  });

  it('is unavailable on a 500 with an HTML body, never reading it', async () => {
    fake.enqueue({
      status: 500,
      headers: { 'content-type': 'text/html' },
      body: '<html><body>Fake error text</body></html>',
    });
    const err = await callProvider(openai, fake.apiKey, call, http).catch((e: unknown) => e);
    expect(err).toMatchObject({
      failure: 'unavailable',
      message: 'The model provider could not be reached',
    });
    expect((err as Error).message).not.toContain('Fake error text');
  });

  it('refuses an answer over 1 MiB as bad_answer', async () => {
    fake.enqueue({ status: 200, body: openAiAnswer('x'.repeat(LLM_MAX_ANSWER_BYTES + 10)) });
    await expect(callProvider(openai, fake.apiKey, call, http)).rejects.toMatchObject({
      failure: 'bad_answer',
    });
  });

  it('refuses an OpenAI answer whose content is null or absent (no refusal, no tool call)', async () => {
    const nullContent = openAiAnswer('x') as { choices: { message: Record<string, unknown> }[] };
    nullContent.choices[0]!.message.content = null;
    fake.enqueue({ status: 200, body: nullContent });
    await expect(callProvider(openai, fake.apiKey, call, http)).rejects.toMatchObject({
      failure: 'bad_answer',
    });
    const absent = openAiAnswer('x') as { choices: { message: Record<string, unknown> }[] };
    delete absent.choices[0]!.message.content;
    fake.enqueue({ status: 200, body: absent });
    await expect(callProvider(openai, fake.apiKey, call, http)).rejects.toMatchObject({
      failure: 'bad_answer',
    });
  });

  it('reads an OpenAI refusal (content null) as refusal', async () => {
    const refused = openAiAnswer('x') as { choices: { message: Record<string, unknown> }[] };
    refused.choices[0]!.message.content = null;
    refused.choices[0]!.message.refusal = 'I cannot help with that.';
    fake.enqueue({ status: 200, body: refused });
    const answer = await callProvider(openai, fake.apiKey, call, http);
    expect(answer).toMatchObject({ text: '', finishReason: 'refusal' });
  });

  it('refuses an Anthropic answer without type "message"', async () => {
    const other = { ...(anthropicAnswer('{}') as object), type: 'error' };
    fake.enqueue({ status: 200, body: other });
    await expect(callProvider(anthropic, fake.apiKey, call, http)).rejects.toMatchObject({
      failure: 'bad_answer',
    });
    const untyped = anthropicAnswer('{}') as Record<string, unknown>;
    delete untyped.type;
    fake.enqueue({ status: 200, body: untyped });
    await expect(callProvider(anthropic, fake.apiKey, call, http)).rejects.toMatchObject({
      failure: 'bad_answer',
    });
  });

  it('sends the Anthropic temperature when configured', async () => {
    await callProvider({ ...anthropic, temperature: 0.5 }, fake.apiKey, call, http);
    expect(fake.requests[0]!.json).toMatchObject({ temperature: 0.5 });
  });

  it('sends no key header to Anthropic without a key, and the fake refuses one it does not expect', async () => {
    const open = await createFakeLlm({ apiKey: null });
    const openHttp = { ...http, internalHosts: parseInternalHosts(open.host) };
    try {
      const answer = await callProvider(
        { ...anthropic, baseUrl: open.anthropicBaseUrl },
        null,
        call,
        openHttp,
      );
      expect(answer.finishReason).toBe('stop');
      expect(open.requests[0]!.headers['x-api-key']).toBeUndefined();
      expect(open.requests[0]!.headers['anthropic-version']).toBe('2023-06-01');
      await expect(
        callProvider({ ...anthropic, baseUrl: open.anthropicBaseUrl }, 'k-1', call, openHttp),
      ).rejects.toMatchObject({ failure: 'rejected', status: 400 });
      await expect(
        callProvider(
          { ...openai, baseUrl: open.openAiBaseUrl, auth: 'api-key' },
          'k-1',
          call,
          openHttp,
        ),
      ).rejects.toMatchObject({ failure: 'rejected', status: 400 });
    } finally {
      await open.close();
    }
  });

  it('ignores a trailing slash on the base URL', async () => {
    await callProvider({ ...openai, baseUrl: `${fake.openAiBaseUrl}/` }, fake.apiKey, call, http);
    await callProvider(
      { ...anthropic, baseUrl: `${fake.anthropicBaseUrl}/` },
      fake.apiKey,
      call,
      http,
    );
    expect(fake.requests.map((r) => r.path)).toEqual(['/v1/chat/completions', '/v1/messages']);
  });

  it('is rejected, not unavailable, when the request cannot be made (a bad header value)', async () => {
    const err = await callProvider(openai, 'bad\nkey-value', call, http).catch((e: unknown) => e);
    expect(err).toMatchObject({ failure: 'rejected', status: null });
    expect((err as Error).message).not.toContain('key-value');
    expect(fake.requests).toHaveLength(0);
  });

  it('is unavailable (not timeout) when no connection is made within 3 s', async () => {
    const err = await callProvider(
      { ...openai, baseUrl: 'https://slow-dns.example/v1', timeoutSeconds: 30 },
      fake.apiKey,
      call,
      { ...http, resolve: () => new Promise(() => undefined) },
    ).catch((e: unknown) => e);
    expect(err).toMatchObject({
      failure: 'unavailable',
      message: 'The model provider could not be reached',
    });
  });

  describe('SSRF: every resolved address is checked (llm.md §4)', () => {
    it('refuses a public name that resolves to a private address', async () => {
      const err = await callProvider(
        { ...openai, baseUrl: 'https://llm.example.com/v1' },
        fake.apiKey,
        call,
        { ...http, resolve: () => Promise.resolve([{ address: '10.0.0.5', family: 4 }]) },
      ).catch((e: unknown) => e);
      expect(err).toMatchObject({ failure: 'url_not_allowed' });
      expect(fake.requests).toHaveLength(0);
    });

    it('refuses a listed name that resolves to the cloud metadata address', async () => {
      const port = new URL(fake.url).port;
      const err = await callProvider(
        { ...openai, baseUrl: `http://llm.corp:${port}/v1` },
        fake.apiKey,
        call,
        {
          ...http,
          internalHosts: parseInternalHosts(`llm.corp:${port}`),
          resolve: () => Promise.resolve([{ address: '169.254.169.254', family: 4 }]),
        },
      ).catch((e: unknown) => e);
      expect(err).toMatchObject({ failure: 'url_not_allowed' });
      expect(fake.requests).toHaveLength(0);
    });

    it('refuses a listed non-loopback name that resolves to 127.0.0.1, where the fake listens', async () => {
      const port = new URL(fake.url).port;
      const err = await callProvider(
        { ...openai, baseUrl: `http://llm.corp:${port}/v1` },
        fake.apiKey,
        call,
        {
          ...http,
          internalHosts: parseInternalHosts(`llm.corp:${port}`),
          resolve: () => Promise.resolve([{ address: '127.0.0.1', family: 4 }]),
        },
      ).catch((e: unknown) => e);
      expect(err).toMatchObject({ failure: 'url_not_allowed' });
      expect(fake.requests).toHaveLength(0);
    });
  });

  it('is reached through QUALOR_LLM_INTERNAL_HOSTS only, never through the SCM list', async () => {
    const env = {
      DATABASE_URL: 'postgres://q:q@localhost:5432/qualor',
      QUALOR_SECRET_KEY: 'k'.repeat(32),
    };
    const scmOnly = loadConfig({ ...env, QUALOR_SCM_INTERNAL_HOSTS: fake.host });
    const err = await callProvider(openai, fake.apiKey, call, {
      ...http,
      internalHosts: scmOnly.llmInternalHosts,
    }).catch((e: unknown) => e);
    expect(err).toMatchObject({ failure: 'url_not_allowed' });
    expect(fake.requests).toHaveLength(0);
    const llm = loadConfig({ ...env, QUALOR_LLM_INTERNAL_HOSTS: fake.host });
    expect(llm.scmInternalHosts.size).toBe(0);
    await callProvider(openai, fake.apiKey, call, { ...http, internalHosts: llm.llmInternalHosts });
    expect(fake.requests).toHaveLength(1);
  });

  it('reads Retry-After as seconds or an HTTP date, and retry-after-ms', () => {
    expect(retryAfterSeconds({ 'retry-after': '12' })).toBe(12);
    expect(retryAfterSeconds({ 'retry-after-ms': '1500' })).toBe(2);
    expect(retryAfterSeconds({ 'retry-after': new Date(10_000).toUTCString() }, () => 4_000)).toBe(
      6,
    );
    expect(retryAfterSeconds({ 'retry-after': 'soon' })).toBeNull();
    // llm.md §14: Retry-After first, else retry-after-ms.
    expect(retryAfterSeconds({ 'retry-after': '9', 'retry-after-ms': '1500' })).toBe(9);
    expect(retryAfterSeconds({ 'retry-after': 'soon', 'retry-after-ms': '1500' })).toBe(2);
    expect(retryAfterSeconds({})).toBeNull();
  });
});

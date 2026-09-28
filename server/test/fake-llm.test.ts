import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildPrompt } from '@qualor/shared';
import { sampleInput } from '../../packages/shared/test/llm';
import { cannedModelText, createFakeLlm, type FakeLlm } from './fake-llm';

const NONCE = 'f'.repeat(32);

describe('fake LLM', () => {
  let fake: FakeLlm;
  beforeAll(async () => {
    fake = await createFakeLlm();
  });
  afterAll(async () => {
    await fake.close();
  });

  const post = (path: string, headers: Record<string, string>, body: unknown) =>
    fetch(`${fake.url}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });

  it('answers the OpenAI shape with a canned answer for the task in the data block', async () => {
    const p = buildPrompt('fix', sampleInput(), NONCE);
    const res = await post(
      '/v1/chat/completions',
      { authorization: `Bearer ${fake.apiKey}` },
      {
        model: 'm',
        messages: [
          { role: 'system', content: p.system },
          { role: 'user', content: p.user },
        ],
      },
    );
    expect(res.status).toBe(200);
    const json = (await res.json()) as { choices: { message: { content: string } }[] };
    expect(JSON.parse(json.choices[0]!.message.content)).toEqual({
      status: 'fixed',
      startLine: 2,
      endLine: 2,
      replacement: ['if (a === 1) {}'],
      explanation: 'Use strict equality.',
    });
    expect(fake.requests.at(-1)?.path).toBe('/v1/chat/completions');
  });

  it('answers the Anthropic shape and checks its version header', async () => {
    const p = buildPrompt('triage', sampleInput(), NONCE);
    const body = {
      model: 'm',
      max_tokens: 10,
      system: p.system,
      messages: [{ role: 'user', content: p.user }],
    };
    expect((await post('/v1/messages', { 'x-api-key': fake.apiKey }, body)).status).toBe(400);
    const res = await post(
      '/v1/messages',
      { 'x-api-key': fake.apiKey, 'anthropic-version': '2023-06-01' },
      body,
    );
    const json = (await res.json()) as { content: { text: string }[] };
    expect(JSON.parse(json.content[0]!.text).verdict).toBe('likely_true_positive');
  });

  it('refuses a wrong key with 401 and serves scripted replies first', async () => {
    expect((await post('/v1/chat/completions', { authorization: 'Bearer nope' }, {})).status).toBe(
      401,
    );
    fake.enqueue({
      status: 429,
      headers: { 'retry-after': '7' },
      body: { error: { message: 'x' } },
    });
    fake.say('not json');
    const auth = { authorization: `Bearer ${fake.apiKey}` };
    const first = await post('/v1/chat/completions', auth, { messages: [] });
    expect([first.status, first.headers.get('retry-after')]).toEqual([429, '7']);
    const second = (await (await post('/v1/chat/completions', auth, { messages: [] })).json()) as {
      choices: { message: { content: string } }[];
    };
    expect(second.choices[0]!.message.content).toBe('not json');
  });

  it('survives a malformed data block and a throwing responder, and keeps serving', async () => {
    const auth = { authorization: `Bearer ${fake.apiKey}` };
    const block = (inner: string) => ({
      messages: [
        {
          role: 'user',
          content: `<<<QUALOR-DATA-${NONCE}\n${inner}\nQUALOR-DATA-${NONCE}>>>`,
        },
      ],
    });
    for (const inner of ['{not json', '{"task":"fix"}', 'null']) {
      const res = await post('/v1/chat/completions', auth, block(inner));
      expect(res.status).toBe(200);
      const json = (await res.json()) as { choices: { message: { content: string } }[] };
      expect(json.choices[0]!.message.content).toBe('{"ok": true}');
    }
    fake.enqueue(() => {
      throw new Error('scripted failure');
    });
    expect((await post('/v1/chat/completions', auth, { messages: [] })).status).toBe(500);
    expect((await post('/v1/chat/completions', auth, { messages: [] })).status).toBe(200);
  });

  it('refuses a key header when it expects none', async () => {
    const open = await createFakeLlm({ apiKey: null });
    try {
      const send = (headers: Record<string, string>, path = '/v1/chat/completions') =>
        fetch(`${open.url}${path}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'anthropic-version': '2023-06-01',
            ...headers,
          },
          body: '{}',
        });
      expect((await send({})).status).toBe(200);
      expect((await send({ authorization: 'Bearer x' })).status).toBe(400);
      expect((await send({ 'api-key': 'x' })).status).toBe(400);
      expect((await send({ 'x-api-key': 'x' }, '/v1/messages')).status).toBe(400);
      expect((await send({}, '/v1/messages')).status).toBe(200);
    } finally {
      await open.close();
    }
  });

  it('says {"ok": true} to a request without a data block', () => {
    const request = {
      method: 'POST',
      path: '/v1/messages',
      headers: {},
      body: '',
      json: { messages: [{ role: 'user', content: 'ping' }] },
    };
    expect(cannedModelText(request)).toBe('{"ok": true}');
  });
});

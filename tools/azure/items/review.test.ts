import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  aiInProgress,
  aiSection,
  commandRefusal,
  commandWaitMs,
  deliveries,
  isAiNote,
  isReplyNote,
  notificationsRecording,
  ownSubscriptions,
  QualorApi,
  reviewSource,
  withoutProvider,
} from './21-review.js';

const ID = '11111111-2222-4333-8444-555555555555';

describe('isReplyNote', () => {
  it('knows the reply marker on the first line only', () => {
    expect(isReplyNote(`<!-- qualor:reply ${ID} -->\n**AI review** · reply\n\nText`)).toBe(true);
    expect(isReplyNote(`<!-- qualor:issue ${ID} -->\ntext`)).toBe(false);
    expect(isReplyNote(`text\n<!-- qualor:reply ${ID} -->`)).toBe(false);
    expect(isReplyNote(undefined)).toBe(false);
  });
});

describe('isAiNote', () => {
  it('tells an AI thread from an analyzer thread by the header line', () => {
    expect(isAiNote(`<!-- qualor:issue ${ID} -->\n**AI review** · High · Security`)).toBe(true);
    expect(isAiNote(`<!-- qualor:issue ${ID} -->\n**High** · Bug · \`S1186\``)).toBe(false);
    expect(isAiNote(`<!-- qualor:reply ${ID} -->\n**AI review** · reply`)).toBe(false);
  });
});

describe('reviewSource', () => {
  it('has the analyzer finding on line 2 and the inverted admin check on line 6', () => {
    const lines = reviewSource('x').split('\n');
    expect(lines[1]).toBe('export function emptyHandler() {');
    expect(lines[5]).toBe('export const canDeleteAccount = (user) => !user.isAdmin;');
    expect(lines.join('\n')).not.toContain('eval(');
  });
});

describe('aiSection', () => {
  it('cuts the AI review section of a summary', () => {
    const text = 'Summary\n\n#### AI review\nAI review in progress…\n';
    expect(aiSection(text)).toContain('AI review in progress');
    expect(aiInProgress(text)).toBe(true);
    expect(aiInProgress('Summary\n\n#### AI review\n2 findings')).toBe(false);
    expect(aiSection('no section')).toBe('');
  });
});

describe('ownSubscriptions', () => {
  const sub = (over: Record<string, unknown>) => ({
    id: 's',
    status: 'enabled',
    eventType: 'git.pullrequest.updated',
    publisherInputs: { projectId: 'AAAA' },
    consumerInputs: { url: 'https://q.example/api/v0/azure-devops/webhooks/c1' },
    ...over,
  });
  it("keeps the subscriptions that deliver to Qualor's webhook path in the project", () => {
    const own = ownSubscriptions(
      {
        value: [
          sub({ id: 'a' }),
          sub({ id: 'b', publisherInputs: { projectId: 'other' } }),
          sub({ id: 'c', consumerInputs: { url: 'https://elsewhere.example/hook' } }),
        ],
      },
      'aaaa',
    );
    expect(own.map((s) => s.id)).toEqual(['a']);
    expect(ownSubscriptions('nonsense', 'aaaa')).toEqual([]);
  });
});

describe('withoutProvider', () => {
  it('keeps the settings, drops the provider and the read-only fields', () => {
    const body = withoutProvider({
      provider: { kind: 'openai', apiKeySet: true },
      organizations: {
        o1: { enabled: true, features: {}, excludedProjectIds: [], reviewStatus: {} },
      },
      excludePaths: ['x'],
      budgets: { tokensPerDay: 1 },
      pricing: null,
      storePrompts: false,
      promptRetentionDays: 7,
      lastTest: { at: 'now' },
    });
    expect(body['provider']).toBeNull();
    expect(body['organizations']).toEqual({
      o1: { enabled: true, features: {}, excludedProjectIds: [] },
    });
    expect(body['budgets']).toEqual({ tokensPerDay: 1 });
    expect(body).not.toHaveProperty('lastTest');
    expect(JSON.stringify(body)).not.toContain('apiKey');
  });
});

describe('deliveries', () => {
  it('counts the succeeded notifications, and those since a time', () => {
    const json = {
      value: [
        { status: 'completed', result: 'succeeded', createdDate: '2026-11-23T10:00:10Z' },
        { status: 'completed', result: 'succeeded', createdDate: '2026-11-23T09:00:00Z' },
        { status: 'completed', result: 'failed', createdDate: '2026-11-23T10:00:20Z' },
      ],
    };
    expect(deliveries(json, Date.parse('2026-11-23T10:00:00Z'))).toEqual({
      total: 3,
      succeeded: 2,
      since: 1,
      readable: true,
    });
    expect(deliveries('nonsense', 0).readable).toBe(false);
  });
});

describe('QualorApi.login', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('accepts the 204 of the login and keeps the session cookie for the next call', async () => {
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(url);
      if (url.endsWith('/api/v0/auth/login')) {
        return new Response(null, {
          status: 204,
          headers: { 'set-cookie': 'qualor_session=s1; Path=/; HttpOnly' },
        });
      }
      return new Response(JSON.stringify({ csrfToken: 'csrf-1' }), { status: 200 });
    });
    await expect(
      new QualorApi('https://qualor.example/').login('test-password'),
    ).resolves.toBeUndefined();
    expect(urls).toEqual([
      'https://qualor.example/api/v0/auth/login',
      'https://qualor.example/api/v0/auth/me',
    ]);
  });
});

describe('QualorApi.send, call and all', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('answers any status from send, and throws from call only on a non-2xx', async () => {
    vi.stubGlobal(
      'fetch',
      async () => new Response(JSON.stringify({ code: 'FIX_BUSY' }), { status: 409 }),
    );
    const api = new QualorApi('https://qualor.example');
    await expect(api.send('DELETE', '/api/v0/fixes/f1')).resolves.toMatchObject({
      status: 409,
      json: { code: 'FIX_BUSY' },
    });
    await expect(api.call('DELETE', '/api/v0/fixes/f1')).rejects.toThrow(
      'DELETE /api/v0/fixes/f1 -> 409: {"code":"FIX_BUSY"}',
    );
  });

  it('reads a body that is not JSON as null, with its text', async () => {
    vi.stubGlobal('fetch', async () => new Response('<html>', { status: 502 }));
    await expect(new QualorApi('https://qualor.example').send('GET', '/x')).resolves.toEqual({
      status: 502,
      json: null,
      text: '<html>',
    });
  });

  it('follows nextCursor through every page', async () => {
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(url);
      const second = url.includes('cursor=c%2F1');
      return new Response(
        JSON.stringify(
          second
            ? { items: [{ id: 'b' }], nextCursor: null }
            : { items: [{ id: 'a' }], nextCursor: 'c/1' },
        ),
        { status: 200 },
      );
    });
    const all = await new QualorApi('https://qualor.example').all(
      '/api/v0/projects/p/branches?kind=branch',
      z.object({ id: z.string() }),
    );
    expect(all.map((b) => b.id)).toEqual(['a', 'b']);
    expect(urls).toEqual([
      'https://qualor.example/api/v0/projects/p/branches?kind=branch&limit=100',
      'https://qualor.example/api/v0/projects/p/branches?kind=branch&limit=100&cursor=c%2F1',
    ]);
  });
});

describe('notificationsRecording', () => {
  it('keeps only the id, status, result and date of each notification, never its details', () => {
    const basic = `Basic ${Buffer.from('qualor:hook-password-value-0123456789').toString('base64')}`;
    const json = {
      count: 2,
      value: [
        {
          id: 41,
          subscriptionId: ID,
          status: 'completed',
          result: 'succeeded',
          createdDate: '2026-11-23T10:00:10Z',
          details: {
            request: `POST https://qualor.example.com/api/v0/azure-devops/webhooks/${ID}\nAuthorization: ${basic}`,
            requestAttempts: 1,
            messages: { authorization: basic },
          },
        },
        { id: 42, status: 'processing', details: { request: basic } },
      ],
    };
    const recorded = notificationsRecording(json);
    expect(recorded).toEqual({
      count: 2,
      value: [
        { id: 41, status: 'completed', result: 'succeeded', createdDate: '2026-11-23T10:00:10Z' },
        { id: 42, status: 'processing' },
      ],
    });
    expect(JSON.stringify(recorded)).not.toContain('Basic');
    expect(JSON.stringify(recorded)).not.toContain(basic.slice(6));
  });

  it('records nothing of an answer it does not read', () => {
    expect(notificationsRecording({ message: 'Basic abc' })).toEqual({ value: [] });
    expect(notificationsRecording('Basic abc')).toEqual({ value: [] });
  });
});

describe('commandWaitMs', () => {
  it('is 5 minutes unless AZURE_PROBE_COMMAND_WAIT_MINUTES names 1 to 30', () => {
    expect(commandWaitMs(undefined)).toBe(5 * 60_000);
    expect(commandWaitMs('')).toBe(5 * 60_000);
    expect(commandWaitMs('17')).toBe(17 * 60_000);
    for (const bad of ['0', '31', '2.5', 'x']) expect(() => commandWaitMs(bad)).toThrow(/1 to 30/);
  });
});

describe('commandRefusal', () => {
  it('finds the refusal Qualor writes for a command it does not take', () => {
    const answer = `<!-- qualor:reply ${ID} -->\n**AI review** · reply\n\nOnly project members can ask for an AI review.`;
    expect(commandRefusal(answer)).toBe('Only project members can ask for an AI review.');
    expect(
      commandRefusal('This commit (` abc `) has been reviewed. Push a new commit to review again.'),
    ).toBeUndefined();
    expect(commandRefusal(undefined)).toBeUndefined();
  });
});

import { describe, expect, it } from 'vitest';
import {
  aiInProgress,
  aiSection,
  isAiNote,
  isReplyNote,
  ownSubscriptions,
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
  it('has the analyzer finding on line 2 and eval on line 6', () => {
    const lines = reviewSource('x').split('\n');
    expect(lines[1]).toBe('export function emptyHandler() {');
    expect(lines[5]).toContain('eval(input)');
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

import { readFile } from 'node:fs/promises';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { engine, file, reportWith } from '../../test/reports';
import { instanceSettings, organizations } from '../db/schema';
import { DEFAULT_LLM_SETTINGS, DISABLED_ORGANIZATION, writeLlmSettings } from '../llm/settings';
import { VERSION } from '../index';
import {
  AI_USE_NOT_COUNTED,
  USAGE_NOT_COUNTED,
  collectTelemetry,
  type CollectDeps,
  type TelemetryPayload,
  type TelemetryPayloadV3,
} from './collect';
import { installationId, TELEMETRY_SETTING_KEY } from './installation-id';

const GUIDE = 'docs/guide/telemetry.md';

/**
 * Every field of a report at every depth, as `path: kind` (`counts.users: number`), sorted. A list
 * is one field: its items are not fields.
 */
function fieldsOf(value: unknown, prefix = ''): string[] {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return [];
  return Object.entries(value)
    .flatMap(([key, field]) => {
      const path = prefix === '' ? key : `${prefix}.${key}`;
      let kind: string = typeof field;
      if (Array.isArray(field)) kind = 'list';
      else if (field === null) kind = 'null';
      return [`${path}: ${kind}`, ...fieldsOf(field, path)];
    })
    .sort();
}

/** The report as schema 3, which it is whenever the server could count everything. */
function schemaThree(payload: TelemetryPayload): TelemetryPayloadV3 {
  if (payload.schema !== 3) throw new Error(`a report of schema ${payload.schema}`);
  return payload;
}

describe('telemetry payload (telemetry.md)', () => {
  let h: IngestHarness;
  let p: Awaited<ReturnType<IngestHarness['project']>>;
  const collect = async (over: Partial<CollectDeps> = {}) =>
    collectTelemetry({
      db: h.ctx.db,
      edition: { edition: () => 'community' },
      installationId: await installationId(h.ctx.db),
      database: 'external',
      env: {},
      dockerEnvExists: false,
      ...over,
    });

  beforeAll(async () => {
    h = await createIngestHarness();
    p = await h.project('secret-team/secret-project');
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('semgrep'), engine('eslint', [], 'failed')],
        files: [file('src/a.ts'), file('src/B.java', { language: 'java' })],
        findings: [],
      }),
    );
  });
  afterAll(async () => {
    await h.close();
  });

  it('creates one installation id and keeps it', async () => {
    const a = await installationId(h.ctx.db);
    const b = await installationId(h.ctx.db);
    expect(a).toMatch(/^[0-9a-f-]{36}$/);
    expect(b).toBe(a);
  });

  it('replaces a malformed stored id', async () => {
    await h.ctx.db
      .update(instanceSettings)
      .set({ value: { installationId: 'nope' } })
      .where(eq(instanceSettings.key, TELEMETRY_SETTING_KEY));
    expect(await installationId(h.ctx.db)).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('counts and lists, with no names, URLs or keys anywhere', async () => {
    const id = await installationId(h.ctx.db);
    const payload = await collectTelemetry({
      db: h.ctx.db,
      edition: { edition: () => 'community' },
      installationId: id,
      database: 'external',
      env: {},
      dockerEnvExists: false,
    });
    expect(payload).toMatchObject({
      schema: 3,
      installationId: id,
      version: VERSION,
      edition: 'community',
      platform: { runtime: 'node', node: process.versions.node },
      database: 'external',
      languages: ['java', 'typescript'],
      engines: ['semgrep'],
      scm: [],
      features: {
        sso: false,
        scim: false,
        aiAssistant: false,
        aiReview: false,
        autoFix: false,
        mcp: false,
        chat: false,
        email: false,
        licensePolicy: false,
      },
      aiReview: { provider: 'none', organizations: 0, projects: 0 },
      assistant30d: { explain: 0, triage: 0, fix: 0 },
    });
    expect(payload.counts.organizations).toBeGreaterThanOrEqual(1);
    expect(payload.counts.users).toBeGreaterThanOrEqual(1);
    expect(payload.counts.projects).toBe(1);
    expect(payload.counts.analyses30d).toBe(1);
    const json = JSON.stringify(payload);
    expect(json).not.toMatch(/secret-team|secret-project|src\/|http/);
  });

  it('sends a user-chosen external engine id only as `external`', async () => {
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('semgrep'), engine('acme-secret-tool')],
        files: [file('src/a.ts')],
        findings: [],
      }),
    );
    const payload = await collect();
    expect(payload.engines).toEqual(['external', 'semgrep']);
    expect(JSON.stringify(payload)).not.toContain('acme');
  });

  it('reports the AI assistant when a provider is set and an organisation has it on', async () => {
    const [org] = await h.ctx.db.select({ id: organizations.id }).from(organizations).limit(1);
    const provider = {
      kind: 'openai' as const,
      baseUrl: 'https://llm.example.test/v1',
      model: 'gpt-test',
      strongModel: 'gpt-test-strong',
      fastModel: 'gpt-test-fast',
      auth: 'bearer' as const,
      jsonMode: 'json_object' as const,
      maxTokensField: 'max_tokens' as const,
      temperature: null,
      api: 'chat_completions' as const,
      workspaceId: null,
      timeoutSeconds: 60,
      contextWindowTokens: null,
      apiKeyEnc: null,
    };
    await writeLlmSettings(h.ctx.db, {
      ...DEFAULT_LLM_SETTINGS,
      provider,
      organizations: { [org!.id]: DISABLED_ORGANIZATION },
    });
    expect((await collect()).features.aiAssistant).toBe(false);
    await writeLlmSettings(h.ctx.db, {
      ...DEFAULT_LLM_SETTINGS,
      provider,
      organizations: { [org!.id]: { ...DISABLED_ORGANIZATION, enabled: true } },
    });
    const payload = schemaThree(await collect());
    expect(payload.features.aiAssistant).toBe(true);
    // The provider is named by its kind and API alone; AI review is not switched on.
    expect(payload.features.aiReview).toBe(false);
    expect(payload.aiReview).toMatchObject({
      provider: 'openai_chat_completions',
      organizations: 0,
      tiers: { strong: true, fast: true },
    });
    expect(JSON.stringify(payload)).not.toMatch(/example\.test|gpt-test/);
    await writeLlmSettings(h.ctx.db, DEFAULT_LLM_SETTINGS);
  });

  it('sends schema 1, every schema-1 field intact, on a day it cannot count its AI use', async () => {
    const whole = schemaThree(await collect());
    const debug = vi.fn();
    // A query of each collector fails: AI review's (review_replies), then the assistant's.
    for (const table of ['review_replies', 'llm_requests']) {
      await h.ctx.db.execute(sql.raw(`ALTER TABLE ${table} RENAME TO ${table}_away`));
      let payload: TelemetryPayload;
      try {
        payload = await collect({ logger: { debug } });
      } finally {
        await h.ctx.db.execute(sql.raw(`ALTER TABLE ${table}_away RENAME TO ${table}`));
      }
      // Never zeros, which would read as no reviews: the day's report is the schema-1 one.
      expect(payload).toEqual({
        schema: 1,
        installationId: whole.installationId,
        version: whole.version,
        edition: whole.edition,
        platform: whole.platform,
        database: whole.database,
        counts: whole.counts,
        languages: whole.languages,
        engines: whole.engines,
        scm: whole.scm,
        features: {
          sso: whole.features.sso,
          scim: whole.features.scim,
          aiAssistant: whole.features.aiAssistant,
        },
      });
    }
    // Once for each report, at debug, with the error's class and nothing of its text. The
    // assistant's table is also the auto-fix count's, so that report's usage fails as well.
    const logged = (message: string) => debug.mock.calls.filter((c) => c[1] === message);
    expect(logged(AI_USE_NOT_COUNTED)).toEqual([
      [{ component: 'telemetry', errorClass: expect.any(String) }, AI_USE_NOT_COUNTED],
      [{ component: 'telemetry', errorClass: expect.any(String) }, AI_USE_NOT_COUNTED],
    ]);
    expect(logged(USAGE_NOT_COUNTED)).toHaveLength(1);
    expect(schemaThree(await collect()).aiReview).toEqual(whole.aiReview);
  });

  it('sends schema 2, every schema-2 field intact, on a day it cannot count its feature use', async () => {
    const whole = schemaThree(await collect());
    const debug = vi.fn();
    await h.ctx.db.execute(sql`ALTER TABLE mail_messages RENAME TO mail_messages_away`);
    let payload: TelemetryPayload;
    try {
      payload = await collect({ logger: { debug } });
    } finally {
      await h.ctx.db.execute(sql`ALTER TABLE mail_messages_away RENAME TO mail_messages`);
    }
    // The blocks are left out, never zeroed; what schema 2 has is the same.
    expect(payload).toEqual({
      schema: 2,
      installationId: whole.installationId,
      version: whole.version,
      edition: whole.edition,
      platform: whole.platform,
      database: whole.database,
      counts: whole.counts,
      languages: whole.languages,
      engines: whole.engines,
      scm: whole.scm,
      aiReview: whole.aiReview,
      assistant30d: whole.assistant30d,
      features: {
        sso: whole.features.sso,
        scim: whole.features.scim,
        aiAssistant: whole.features.aiAssistant,
        aiReview: whole.features.aiReview,
      },
    });
    expect(debug.mock.calls).toEqual([
      [{ component: 'telemetry', errorClass: expect.any(String) }, USAGE_NOT_COUNTED],
    ]);
  });

  it("the guide's example names every field the report has, and no other", async () => {
    const guide = await readFile(GUIDE, 'utf8');
    const block = /```json\r?\n([\s\S]*?)\r?\n```/.exec(guide);
    expect(block, `${GUIDE} has a \`\`\`json block`).not.toBeNull();
    const example: unknown = JSON.parse(block![1]!);
    expect(fieldsOf(example)).toEqual(fieldsOf(await collect()));
  });

  it('counts only the last 30 days of analyses', async () => {
    await h.ctx.db.execute(sql`UPDATE analyses SET queued_at = now() - interval '31 days'`);
    const payload = await collectTelemetry({
      db: h.ctx.db,
      edition: { edition: () => 'enterprise' },
      installationId: await installationId(h.ctx.db),
      database: 'embedded',
    });
    expect(payload.counts.analyses30d).toBe(0);
    expect(payload.engines).toEqual([]);
    expect(payload.edition).toBe('enterprise');
  });
});

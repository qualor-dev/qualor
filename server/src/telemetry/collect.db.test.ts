import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { engine, file, reportWith } from '../../test/reports';
import { instanceSettings, organizations } from '../db/schema';
import { DEFAULT_LLM_SETTINGS, DISABLED_ORGANIZATION, writeLlmSettings } from '../llm/settings';
import { VERSION } from '../index';
import { collectTelemetry } from './collect';
import { installationId, TELEMETRY_SETTING_KEY } from './installation-id';

describe('telemetry payload (telemetry.md)', () => {
  let h: IngestHarness;
  let p: Awaited<ReturnType<IngestHarness['project']>>;
  const collect = async () =>
    collectTelemetry({
      db: h.ctx.db,
      edition: { edition: () => 'community' },
      installationId: await installationId(h.ctx.db),
      database: 'external',
      env: {},
      dockerEnvExists: false,
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
      schema: 1,
      installationId: id,
      version: VERSION,
      edition: 'community',
      platform: { runtime: 'node', node: process.versions.node },
      database: 'external',
      languages: ['java', 'typescript'],
      engines: ['semgrep'],
      scm: [],
      features: { sso: false, scim: false, aiAssistant: false },
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
      auth: 'bearer' as const,
      jsonMode: 'json_object' as const,
      maxTokensField: 'max_tokens' as const,
      temperature: null,
      timeoutSeconds: 60,
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
    const payload = await collect();
    expect(payload.features.aiAssistant).toBe(true);
    expect(JSON.stringify(payload)).not.toMatch(/example\.test|gpt-test/);
    await writeLlmSettings(h.ctx.db, DEFAULT_LLM_SETTINGS);
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

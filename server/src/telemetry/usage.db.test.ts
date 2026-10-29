import { randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { configuredProvider } from '../../test/llm';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { uuidv7 } from '../db/ids';
import { first } from '../db/rows';
import { instanceSettings, llmRequests, mailMessages, oauthClients, users } from '../db/schema';
import { writeLicensePolicy } from '../licenses/settings';
import { DEFAULT_LLM_SETTINGS, DISABLED_ORGANIZATION, writeLlmSettings } from '../llm/settings';
import { MAIL_SETTINGS_KEY } from '../mail/settings';
import { collectTelemetry, type TelemetryPayloadV3 } from './collect';
import { installationId } from './installation-id';

const OLD = sql`now() - interval '31 days'`;
const NAMED =
  /secret-agent|secret-host|secret-user|ops@|secret-subject|Europe\/Helsinki|hooks\.|secret-kind/;

describe('telemetry schema 3: feature use (telemetry.md, 0.13)', () => {
  let h: IngestHarness;
  let fake: FakeLlm;
  let projectId: string;

  const collect = async (): Promise<TelemetryPayloadV3> => {
    const payload = await collectTelemetry({
      db: h.ctx.db,
      edition: { edition: () => 'community' },
      installationId: await installationId(h.ctx.db),
      database: 'external',
      env: {},
      dockerEnvExists: false,
    });
    if (payload.schema !== 3) throw new Error(`a report of schema ${payload.schema}`);
    return payload;
  };
  /** A webhook subscription of a kind, with a host and a time zone the report must not carry. */
  const hook = (kind: 'slack' | 'teams', over: Record<string, unknown> = {}) =>
    h.ctx.db.execute(sql`
      INSERT INTO webhook_subscriptions
        (id, organization_id, kind, url, url_enc, events, active, timezone, digest_last_week)
      VALUES (${uuidv7()}, ${h.organizationId}, ${kind}, 'https://hooks.secret-host.test/x',
              '{"v":1,"iv":"a","ct":"b","tag":"c"}'::jsonb, '{}', ${over.active ?? true},
              'Europe/Helsinki', ${over.digest ?? null})`);
  const mail = async (kind: string, status: 'sent' | 'failed', at = sql`now()`) => {
    const row = first(
      await h.ctx.db
        .insert(mailMessages)
        .values({ kind, toAddress: 'ops@secret-host.test', subject: 'secret-subject', status })
        .returning({ id: mailMessages.id }),
    );
    await h.ctx.db.execute(sql`UPDATE mail_messages SET sent_at = ${at} WHERE id = ${row.id}`);
  };
  const fix = async (userId: string | null, at = sql`now()`, post: object | null = null) => {
    const row = first(
      await h.ctx.db
        .insert(llmRequests)
        .values({
          organizationId: h.organizationId,
          userId,
          projectId,
          feature: 'fix',
          cacheKey: 'c'.repeat(64),
          provider: 'openai',
          providerHost: 'llm.secret-host.test',
          model: 'secret-model',
          promptVersion: 'test-1',
          status: 'succeeded',
          inputSha256: 'd'.repeat(64),
          inputBytes: 10,
          fields: ['message'],
          post: post as never,
        })
        .returning({ id: llmRequests.id }),
    );
    await h.ctx.db.execute(sql`UPDATE llm_requests SET created_at = ${at} WHERE id = ${row.id}`);
  };
  const audit = (action: string, at = sql`now()`) =>
    h.ctx.db.execute(sql`
      INSERT INTO audit_events (id, seq, created_at, action, outcome, actor_type, details, prev_hash, hash)
      VALUES (${uuidv7()}, (SELECT coalesce(max(seq), 0) + 1 FROM audit_events), ${at}, ${action}, 'success',
              'system', '{}'::jsonb, ${'0'.repeat(64)}, ${'1'.repeat(64)})`);

  beforeAll(async () => {
    fake = await createFakeLlm();
    h = await createIngestHarness();
    projectId = (await h.project('secret-team/usage')).id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    await h.ctx.db.execute(sql`DELETE FROM mail_messages`);
    await h.ctx.db.execute(sql`DELETE FROM webhook_subscriptions`);
    await h.ctx.db.execute(sql`DELETE FROM llm_requests`);
    await h.ctx.db.execute(sql`DELETE FROM compliance_reports`);
    await h.ctx.db.execute(sql`DELETE FROM oauth_grants`);
    await h.ctx.db.execute(sql`DELETE FROM oauth_clients`);
  });

  it('is all zeros and false on a server that uses none of it', async () => {
    const p = await collect();
    expect(p.autoFix30d).toEqual({ made: 0, posted: 0 });
    expect(p.integrations.mcp).toEqual({ clients30d: 0, users30d: 0 });
    expect(p.integrations.chat).toEqual({ slack: 0, teams: 0, withDigest: 0 });
    expect(p.integrations.email.sent30d).toBe(0);
    expect(p.reports30d).toEqual({ complianceReady: 0, complianceFailed: 0, sonarImport: 0 });
    expect(p.licensePolicyOrgs).toBe(0);
    expect(p.features).toMatchObject({
      autoFix: false,
      mcp: false,
      chat: false,
      email: false,
      licensePolicy: false,
    });
  });

  it('counts automatic fixes made and posted in the last 30 days, not the people', async () => {
    await fix(null, sql`now()`, { status: 'posted', at: new Date().toISOString() });
    await fix(null, sql`now()`, { status: 'failed', at: new Date().toISOString() });
    await fix(null, OLD, { status: 'posted', at: new Date().toISOString() });
    await fix(h.ctx.adminId);
    expect((await collect()).autoFix30d).toEqual({ made: 2, posted: 1 });
  });

  it('flags auto-fix only with a provider and an organisation that has it on', async () => {
    await writeLlmSettings(h.ctx.db, {
      ...DEFAULT_LLM_SETTINGS,
      provider: configuredProvider(h.ctx.config.secretKey, fake),
      organizations: {
        [h.organizationId]: {
          ...DISABLED_ORGANIZATION,
          enabled: true,
          autoFix: { ...DISABLED_ORGANIZATION.autoFix, enabled: true },
        },
      },
    });
    try {
      expect((await collect()).features.autoFix).toBe(true);
    } finally {
      await writeLlmSettings(h.ctx.db, DEFAULT_LLM_SETTINGS);
    }
    expect((await collect()).features.autoFix).toBe(false);
  });

  it('counts MCP clients and people with a live grant used in 30 days, never a revoked one', async () => {
    const client = async (name: string) =>
      first(
        await h.ctx.db
          .insert(oauthClients)
          .values({
            clientId: `https://${name}.secret-host.test/c.json`,
            source: 'cimd',
            name,
            redirectUris: ['http://127.0.0.1/cb'],
            metadata: {},
          })
          .returning({ id: oauthClients.id }),
      );
    const user = async () =>
      first(
        await h.ctx.db
          .insert(users)
          .values({ username: `secret-user-${randomUUID().slice(0, 8)}`, displayName: 'x' })
          .returning({ id: users.id }),
      );
    const [a, b, c] = [
      await client('secret-agent-a'),
      await client('secret-agent-b'),
      await client('c'),
    ];
    const [u1, u2] = [await user(), await user()];
    const grant = (userId: string, clientRowId: string, used: string, revoked = false) =>
      h.ctx.db.execute(sql`
        INSERT INTO oauth_grants (id, user_id, client_row_id, scopes, last_used_at, revoked_at)
        VALUES (${uuidv7()}, ${userId}, ${clientRowId}, '{mcp:read}', ${sql.raw(used)},
                ${revoked ? sql`now()` : null})`);
    await grant(u1.id, a.id, 'now()');
    await grant(u2.id, a.id, 'now()');
    await grant(u1.id, b.id, "now() - interval '31 days'");
    await grant(u2.id, c.id, 'now()', true);
    const p = await collect();
    expect(p.integrations.mcp).toEqual({ clients30d: 1, users30d: 2 });
    expect(p.features.mcp).toBe(true);
    expect(JSON.stringify(p)).not.toMatch(NAMED);
    await h.ctx.db.execute(sql`DELETE FROM oauth_grants`);
    expect((await collect()).features.mcp).toBe(false);
  });

  it('counts active Slack and Teams subscriptions and their digests, no host or time zone', async () => {
    const week = (
      await h.ctx.db.execute<{ w: string }>(sql`SELECT to_char(now(), 'IYYY-"W"IW') AS w`)
    ).rows[0]!.w;
    await hook('slack', { digest: week });
    await hook('slack', { digest: '2020-W01' });
    await hook('teams');
    await hook('teams', { active: false, digest: week });
    const p = await collect();
    expect(p.integrations.chat).toEqual({ slack: 2, teams: 1, withDigest: 1 });
    expect(p.features.chat).toBe(true);
    expect(JSON.stringify(p)).not.toMatch(NAMED);
  });

  it('counts mails sent in 30 days by template, an unknown one as other, no address', async () => {
    await mail('test', 'sent');
    await mail('test', 'sent');
    await mail('notify.gate-failed', 'sent');
    await mail('secret-kind', 'sent');
    await mail('test', 'failed');
    await mail('test', 'sent', OLD);
    const p = await collect();
    expect(p.integrations.email.sent30d).toBe(4);
    expect(p.integrations.email.byKind).toMatchObject({
      test: 2,
      'notify.gate-failed': 1,
      other: 1,
      'license.expiry': 0,
    });
    expect(p.features.email).toBe(true);
    expect(JSON.stringify(p)).not.toMatch(NAMED);
  });

  it('flags e-mail when the environment configures SMTP though nothing was sent', async () => {
    const payload = await collectTelemetry({
      db: h.ctx.db,
      edition: { edition: () => 'community' },
      installationId: await installationId(h.ctx.db),
      database: 'external',
      env: {},
      dockerEnvExists: false,
      smtpConfigured: true,
    });
    if (payload.schema !== 3) throw new Error(`a report of schema ${payload.schema}`);
    expect(payload.features.email).toBe(true);
    expect(payload.integrations.email.sent30d).toBe(0);
  });

  it('flags e-mail when a server is configured though nothing was sent', async () => {
    await h.ctx.db.insert(instanceSettings).values({
      key: MAIL_SETTINGS_KEY,
      value: {
        server: {
          host: 'smtp.secret-host.test',
          port: 587,
          security: 'starttls',
          username: null,
          passwordEnc: null,
          fromName: 'Qualor',
          fromAddress: 'ops@secret-host.test',
          replyTo: null,
        },
        alerts: { licenseExpiry: true, webhookFailures: true },
      },
    });
    try {
      const p = await collect();
      expect(p.features.email).toBe(true);
      expect(JSON.stringify(p)).not.toMatch(NAMED);
    } finally {
      await h.ctx.db.execute(sql`DELETE FROM instance_settings WHERE key = ${MAIL_SETTINGS_KEY}`);
    }
  });

  it('counts compliance exports and SonarQube imports in 30 days', async () => {
    const report = (
      status: 'ready' | 'failed' | 'pending',
      scope: 'organization' | 'project',
      old = false,
    ) =>
      h.ctx.db.execute(sql`
        INSERT INTO compliance_reports
          (id, organization_id, project_id, scope, status, created_by_name, standards, created_at,
           data, sha256, summary, completed_at, size_bytes)
        VALUES (${uuidv7()}, ${h.organizationId}, ${scope === 'project' ? projectId : null}, ${scope},
                ${status}, 'Secret Admin', '[]'::jsonb, ${old ? OLD : sql`now()`},
                ${status === 'ready' ? sql`decode('00', 'hex'), ${'a'.repeat(64)}, '{}'::jsonb, now(), 1` : sql`NULL, NULL, NULL, NULL, NULL`})`);
    await report('ready', 'organization');
    await report('ready', 'project');
    await report('ready', 'project', true);
    await report('failed', 'organization');
    await audit('issue.statuses_imported');
    await audit('issue.statuses_imported');
    await audit('issue.statuses_imported', OLD);
    expect((await collect()).reports30d).toEqual({
      complianceReady: 2,
      complianceFailed: 1,
      sonarImport: 2,
    });
  });

  it('counts the organisations with a licence policy', async () => {
    await h.ctx.db.transaction((tx) =>
      writeLicensePolicy(tx, h.organizationId, {
        mode: 'denylist',
        forbiddenGroups: [],
        forbidden: ['GPL-3.0-only'],
        allowed: [],
        warnUnknown: false,
      }),
    );
    try {
      const p = await collect();
      expect(p.licensePolicyOrgs).toBe(1);
      expect(p.features.licensePolicy).toBe(true);
      expect(JSON.stringify(p)).not.toContain('GPL');
    } finally {
      await h.ctx.db.transaction((tx) => writeLicensePolicy(tx, h.organizationId, null));
    }
    expect((await collect()).licensePolicyOrgs).toBe(0);
  });

  it('counts merge request analyses by provider and analyses by CI context in 30 days', async () => {
    await h.ctx.db.execute(sql`DELETE FROM analyses WHERE project_id = ${projectId}`);
    const analysis = (ctx: object | null, old = false) =>
      h.ctx.db.execute(sql`
        INSERT INTO analyses (id, project_id, scm_context, queued_at)
        VALUES (${uuidv7()}, ${projectId}, ${ctx === null ? null : JSON.stringify(ctx)}::jsonb,
                ${old ? OLD : sql`now()`})`);
    const gl = {
      provider: 'gitlab',
      mergeRequestId: '7',
      gitlab: { projectId: '1' },
      github: null,
    };
    const gh = { provider: 'github', mergeRequestId: '8', gitlab: null, github: { runId: '2' } };
    await analysis(gl);
    await analysis({ ...gl, mergeRequestId: null });
    await analysis(gh);
    await analysis(gh);
    await analysis(gh, true);
    await analysis({ provider: 'none', mergeRequestId: null, gitlab: null });
    await analysis(null);
    const p = await collect();
    expect(p.mergeRequests30d).toEqual({ gitlab: 1, github: 2 });
    expect(p.ci).toEqual({ gitlab: 2, github: 2, other: 2 });
  });
});

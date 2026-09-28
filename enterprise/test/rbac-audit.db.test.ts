// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  type Session,
  type TestContext,
} from '../../server/test/app';
import {
  runAuditScenario,
  startAuditScenarioEnv,
  type AuditScenarioEnv,
} from '../../server/test/audit-scenario';
import { testConfig } from '../../server/test/config';
import { createTestDatabase, type TestDatabase } from '../../server/test/db';
import {
  BUSINESS_FEATURES,
  ENTERPRISE_FEATURES,
  signTest,
  testPayload,
  testSigner,
  verifyWith,
  type TestSigner,
} from '../../server/test/license';
import { AFTER_GRACE, LICENSE_EXPIRES } from '../../server/test/rbac';
import { buildApp } from '../../server/src/app';
import { bootstrap } from '../../server/src/auth/bootstrap';
import { eventHash } from '../../server/src/audit/chain';
import { createAuditRecorder, type AuditRecorder } from '../../server/src/audit/recorder';
import { pruneAuditEvents } from '../../server/src/audit/retention';
import { users } from '../../server/src/db/schema';
import { createLogger } from '../../server/src/http/logger';
import { createEdition, type Edition } from '../../server/src/license/edition';
import { licenseState } from '../../server/src/license/state';
import { verifyLicenseKey } from '../../server/src/license/verify';
import { bootEnterprise } from '../../server/src/plugins/boot';
import { loadPlugins } from '../../server/src/plugins/loader';
import { dropPluginsThatFailToMount, pluginJobHandlers } from '../../server/src/plugins/mount';
import { ensurePluginScheduled } from '../../server/src/plugins/schedule';
import { createPluginServices } from '../../server/src/plugins/services';
import { runUntilIdle } from '../../server/src/queue/worker';
import { buildEnterprise } from '../scripts/bundle';

// Under enterprise/, so the bundle resolves its external zod from enterprise/node_modules, as the
// image's /app/enterprise/plugin.js resolves it from /app/node_modules.
const OUT = fileURLToPath(new URL('../.tmp/rbac-audit-test/plugin.js', import.meta.url));
const LICENSED = new Date('2027-01-01T00:00:00Z');
const FEATURES = ['llm.fix-quota', 'audit-log', 'audit-log.stream'];

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

/** A SIEM receiver on the loopback address: every body it was sent. */
async function startReceiver(): Promise<{ server: Server; port: number; bodies: string[] }> {
  const bodies: string[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      bodies.push(Buffer.concat(chunks).toString());
      res.statusCode = 204;
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: (server.address() as AddressInfo).port, bodies };
}

/**
 * The built plugin through the real loader (as enterprise.db.test.ts boots it), under an uploaded
 * key the edition trusts (so the scenario's licence steps run), with the services and the one
 * recorder bound to the edition as bootEnterprise binds them. Everything runs on `clock`.
 */
async function bootEnterpriseTest(
  env: AuditScenarioEnv,
  clock: () => Date,
  features: readonly string[] = FEATURES,
): Promise<TestContext> {
  const verifyOptions = (at: Date) => verifyWith(env.signer, at);
  const verification = verifyLicenseKey(
    signTest(env.signer, testPayload({ features: [...features], expires: LICENSE_EXPIRES })),
    verifyOptions(clock()),
  );
  const boot = { source: 'uploaded' as const, keyHash: 'h', verification };
  return createTestContext({
    config: env.config,
    pluginsFor: async (db, config, logger) => {
      let edition: Edition | undefined;
      const isFeatureActive = (f: string): boolean => edition?.isFeatureActive(f) ?? false;
      const audit = createAuditRecorder({
        isActive: () => isFeatureActive('audit-log'),
        now: clock,
        log: logger,
      });
      const services = createPluginServices({
        db,
        isFeatureActive,
        secretKey: config.secretKey,
        version: '0.0.0',
        recorder: audit,
        now: clock,
      });
      const plugins = await loadPlugins({
        paths: [OUT],
        state: licenseState(verification, clock()),
        base: { serverVersion: '0.0.0', db, logger: quietLogger(), services },
      });
      await dropPluginsThatFailToMount(plugins, quietLogger());
      return {
        plugins,
        edition: (frozen) => {
          edition = createEdition({ boot, plugins: frozen, now: clock, verifyOptions });
          return edition;
        },
        audit,
      };
    },
  });
}

const allowLoopbackReceivers = (ctx: TestContext) =>
  ctx.db.execute(sql`
    INSERT INTO instance_settings (key, value)
    VALUES ('webhooks', ${JSON.stringify({ allowHttp: true, allowInternalHosts: true })}::jsonb)
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`);

type EventItem = {
  action: string;
  organization: { id: string } | null;
  prevHash: string;
  hash: string;
};

beforeAll(async () => {
  await buildEnterprise({ outfile: OUT });
}, 60_000);

describe('Qualor Enterprise: audit-log, and the grant routes in core (rbac-audit.md §12–§16)', () => {
  let now = LICENSED;
  let env: AuditScenarioEnv;
  let receiver: Awaited<ReturnType<typeof startReceiver>>;
  let ctx: TestContext;
  let admin: Session;
  let orgAdmin: Session;
  let orgMember: Session;
  let orgB_admin: Session;
  let org: string;
  let orgB: string;
  let project: { id: string; key: string };
  let userId: string;
  let betaId: string;
  let orgBAdminId: string;
  const streamSecrets: string[] = [];

  const req = (
    method: 'GET' | 'PUT' | 'POST' | 'DELETE',
    url: string,
    session: Session,
    payload?: unknown,
  ) =>
    ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const exportLines = (body: string) =>
    body
      .trim()
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => JSON.parse(l) as EventItem);
  const handlers = () =>
    pluginJobHandlers(ctx.plugins!, ctx.edition!, quietLogger(), { db: ctx.db });

  beforeAll(async () => {
    env = await startAuditScenarioEnv();
    receiver = await startReceiver();
    ctx = await bootEnterpriseTest(env, () => now);
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const created: string[] = [];
    for (const key of ['org-a', 'org-b']) {
      const res = await req('POST', '/organizations', admin, { key, name: key });
      expect(res.statusCode).toBe(201);
      created.push((res.json() as { id: string }).id);
    }
    [org, orgB] = created as [string, string];
    project = await createProject(ctx, admin, { organizationId: org, key: 'alpha' });
    betaId = (await createProject(ctx, admin, { organizationId: orgB, key: 'beta' })).id;
    const a = await createUser(ctx, { username: 'org-a-admin' });
    await addMember(ctx, org, a.id, 'admin');
    orgAdmin = await login(ctx, a.username, a.password);
    const m = await createUser(ctx, { username: 'org-a-member' });
    await addMember(ctx, org, m.id, 'member');
    orgMember = await login(ctx, m.username, m.password);
    const b = await createUser(ctx, { username: 'org-b-admin' });
    await addMember(ctx, orgB, b.id, 'admin');
    orgB_admin = await login(ctx, b.username, b.password);
    orgBAdminId = b.id;
    // A user who acts in org B only: its events name it as the actor.
    await createProject(ctx, orgB_admin, { organizationId: orgB, key: 'gamma' });
    userId = (await createUser(ctx, { username: 'viewer-one' })).id;
  }, 120_000);
  afterAll(async () => {
    receiver?.server.closeAllConnections();
    await new Promise<void>((resolve) => receiver?.server.close(() => resolve()));
    await ctx?.close();
    await env?.close();
  });

  it('loads with llm.fix-quota, audit-log and audit-log.stream, the stream schedule and the two settings entries', async () => {
    expect(ctx.edition!.plugins()).toEqual([
      {
        name: 'qualor-enterprise',
        state: 'loaded',
        // The plugin declares sso, sso.multi and scim too; this key does not list them.
        features: ['llm.fix-quota', 'audit-log', 'audit-log.stream', 'sso', 'sso.multi', 'scim'],
        error: null,
      },
    ]);
    expect(ctx.plugins!.schedules).toEqual([
      {
        plugin: 'qualor-enterprise',
        feature: 'audit-log.stream',
        queue: 'ee.audit.stream',
        everySeconds: 10,
      },
    ]);
    const info = (await req('GET', '/system/info', admin)).json() as {
      features: string[];
      extensions: unknown[];
    };
    expect([...info.features].sort()).toEqual([...FEATURES].sort());
    expect(info.extensions).toEqual([
      {
        point: 'settings.nav',
        id: 'audit-log',
        label: 'Audit log',
        path: '/settings/ee/audit-log',
      },
      {
        point: 'settings.nav',
        id: 'audit-settings',
        label: 'Audit settings',
        path: '/settings/ee/audit-settings',
      },
    ]);
  });

  it('the removed /ee/rbac paths answer 404', async () => {
    // rbac-audit.md §16: removed with the plugin's grant routes, not redirected or aliased.
    const old = `/ee/rbac/projects/${project.id}/members`;
    for (const [method, url, payload] of [
      ['GET', old, undefined],
      ['PUT', `${old}/${userId}`, { role: 'viewer' }],
      ['DELETE', `${old}/${userId}`, undefined],
    ] as const) {
      const res = await req(method, url, orgAdmin, payload);
      expect(res.statusCode, `${method} ${url}`).toBe(404);
    }
    expect(await ctx.db.execute(sql`SELECT 1 FROM project_memberships`)).toMatchObject({
      rows: [],
    });
    // The same grant through the core route, recorded while audit-log is active.
    const res = await req('PUT', `/projects/${project.id}/members/${userId}`, orgAdmin, {
      role: 'viewer',
    });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({ userId, role: 'viewer' });
    const events = await req('GET', '/ee/audit/events?action=project_member.*', admin);
    expect((events.json() as { items: { action: string }[] }).items[0]).toMatchObject({
      action: 'project_member.added',
    });
  });

  it('records a grant change and removal made through the core routes', async () => {
    const grant = `/projects/${project.id}/members/${userId}`;
    const changed = await req('PUT', grant, orgAdmin, { role: 'project_admin' });
    expect(changed.json()).toMatchObject({ userId, role: 'project_admin' });
    expect((await req('DELETE', grant, orgAdmin)).statusCode).toBe(204);
    const events = await req('GET', '/ee/audit/events?action=project_member.*', admin);
    expect((events.json() as { items: { action: string }[] }).items.map((e) => e.action)).toEqual([
      'project_member.removed',
      'project_member.role_changed',
      'project_member.added',
    ]);
    // Put the viewer back for the tests below.
    expect((await req('PUT', grant, orgAdmin, { role: 'viewer' })).statusCode).toBe(200);
  });

  it('exports JSON Lines of a period, records the export, and each line verifies', async () => {
    const from = '2026-12-01T00:00:00Z'; // the context's clock is 2027-01-01
    const to = '2027-02-01T00:00:00Z';
    const res = await req('GET', `/ee/audit/export?from=${from}&to=${to}`, admin);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toMatch(/^application\/x-ndjson/);
    // §12: no proxy or browser cache keeps a copy.
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['content-disposition']).toBe(
      'attachment; filename="qualor-audit-2026-12-01T00-00-00Z-2027-02-01T00-00-00Z.jsonl"',
    );
    const lines = res.body
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { prevHash: string; hash: string; action: string });
    expect(lines.at(-1)).toMatchObject({ action: 'audit.exported' });
    for (const line of lines) {
      const { prevHash, hash, ...record } = line;
      expect(eventHash(prevHash, record as never)).toBe(hash);
    }
    // An export without filters is the chain itself.
    for (let i = 1; i < lines.length; i += 1) expect(lines[i]!.prevHash).toBe(lines[i - 1]!.hash);
  });

  it('refuses a period over 366 days, or one that ends before it starts', async () => {
    for (const [from, to] of [
      ['2025-01-01T00:00:00Z', '2026-06-01T00:00:00Z'],
      ['2027-01-02T00:00:00Z', '2027-01-01T00:00:00Z'],
    ]) {
      const res = await req('GET', `/ee/audit/export?from=${from}&to=${to}`, admin);
      expect(res.statusCode).toBe(422);
      expect(res.json()).toMatchObject({
        code: 'VALIDATION_FAILED',
        errors: [expect.objectContaining({ path: 'query.to' })],
      });
    }
    const missing = await req('GET', '/ee/audit/export?from=2027-01-01T00:00:00Z', admin);
    expect(missing.statusCode).toBe(422);
  });

  it('refuses a targetType or targetId holding NUL with 422 on the field, never a 500 (§13)', async () => {
    const period = 'from=2027-01-01T00:00:00Z&to=2027-01-02T00:00:00Z';
    for (const route of ['/ee/audit/events?', `/ee/audit/export?${period}&`]) {
      for (const field of ['targetType', 'targetId']) {
        const res = await req('GET', `${route}${field}=a%00b`, admin);
        expect(res.statusCode, `${route} ${field} ${res.body}`).toBe(422);
        expect(res.json()).toMatchObject({
          code: 'VALIDATION_FAILED',
          errors: [{ path: `query.${field}`, message: 'Must not contain NUL characters' }],
        });
      }
    }
    // UTF-8 cannot encode a lone surrogate: its CESU-8 bytes reach the route as the raw text,
    // which is storable, so the filter simply matches nothing (the route unit test covers the
    // surrogate itself).
    const cesu = await req('GET', '/ee/audit/events?targetId=a%ED%A0%80b', admin);
    expect(cesu.statusCode, cesu.body).toBe(200);
    expect(cesu.json()).toMatchObject({ items: [] });
  });

  it('refuses an action filter that is not a name or a prefix, such as .* (match-all)', async () => {
    for (const action of ['.*', '*', '%', 'project.%', 'Project.*', 'a..b', 'issue.*.*']) {
      const res = await req('GET', `/ee/audit/events?action=${encodeURIComponent(action)}`, admin);
      expect(res.statusCode, action).toBe(422);
    }
    const many = Array.from({ length: 21 }, (_, i) => `action=a${'b'.repeat(i)}`).join('&');
    expect((await req('GET', `/ee/audit/events?${many}`, admin)).statusCode).toBe(422);
    const two = await req(
      'GET',
      '/ee/audit/events?action=project.created&action=project_member.*',
      admin,
    );
    expect(two.statusCode).toBe(200);
    const actions = new Set((two.json() as { items: EventItem[] }).items.map((e) => e.action));
    expect([...actions].sort()).toEqual([
      'project.created',
      'project_member.added',
      'project_member.removed',
      'project_member.role_changed',
    ]);
  });

  it('shows an org admin its organisation’s events only, and nothing without organizationId', async () => {
    expect((await req('GET', '/ee/audit/events', orgAdmin)).statusCode).toBe(403);
    const own = await req('GET', `/ee/audit/events?organizationId=${org}`, orgAdmin);
    const items = (own.json() as { items: { organization: { id: string } | null }[] }).items;
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((e) => e.organization?.id === org)).toBe(true);
  });

  it("never shows org A's admin a row of org B or an instance event, in events or the export", async () => {
    // org B has events of its own, which its admin sees.
    const b = await req('GET', `/ee/audit/events?organizationId=${orgB}`, orgB_admin);
    expect((b.json() as { items: EventItem[] }).items.length).toBeGreaterThan(0);
    // org A's admin: org B is invisible (404), and every filter keeps to its own organisation.
    expect((await req('GET', `/ee/audit/events?organizationId=${orgB}`, orgAdmin)).statusCode).toBe(
      404,
    );
    const period = 'from=2026-12-01T00:00:00Z&to=2027-02-01T00:00:00Z';
    expect((await req('GET', `/ee/audit/export?${period}`, orgAdmin)).statusCode).toBe(403);
    expect(
      (await req('GET', `/ee/audit/export?${period}&organizationId=${orgB}`, orgAdmin)).statusCode,
    ).toBe(404);
    const events = await req('GET', `/ee/audit/events?organizationId=${org}&limit=500`, orgAdmin);
    const exported = await req('GET', `/ee/audit/export?${period}&organizationId=${org}`, orgAdmin);
    expect(exported.statusCode).toBe(200);
    const lines = exportLines(exported.body);
    const rows = [...(events.json() as { items: EventItem[] }).items, ...lines];
    expect(lines.length).toBeGreaterThan(0);
    expect(rows.every((e) => e.organization?.id === org)).toBe(true);
    // Its view is exactly its organisation's rows: the database agrees, instance rows excluded.
    const [{ n }] = (
      await ctx.db.execute<{ n: number }>(
        sql`SELECT count(*)::int AS n FROM audit_events WHERE organization_id = ${org}`,
      )
    ).rows as [{ n: number }];
    expect(lines).toHaveLength(n);
    // A maintainer of org A may not read its audit log.
    const member = await req('GET', `/ee/audit/events?organizationId=${org}`, orgMember);
    expect(member.statusCode).toBe(403);
    expect(member.json()).toMatchObject({ code: 'FORBIDDEN' });
    // head, verify and the settings are the instance admin's only.
    for (const url of ['/ee/audit/head', '/ee/audit/verify', '/ee/audit/settings']) {
      expect((await req('GET', url, orgAdmin)).statusCode, url).toBe(403);
    }
  });

  it("gives org A's admin nothing of org B through projectId or actorUserId filters", async () => {
    const period = 'from=2026-12-01T00:00:00Z&to=2027-02-01T00:00:00Z';
    for (const filter of [`projectId=${betaId}`, `actorUserId=${orgBAdminId}`]) {
      // Positive control: those filters do match rows, in org B.
      const inB = await req('GET', `/ee/audit/events?organizationId=${orgB}&${filter}`, admin);
      expect((inB.json() as { items: EventItem[] }).items.length, filter).toBeGreaterThan(0);
      const events = await req('GET', `/ee/audit/events?organizationId=${org}&${filter}`, orgAdmin);
      expect(events.statusCode, filter).toBe(200);
      expect((events.json() as { items: EventItem[] }).items, filter).toEqual([]);
      const exported = await req(
        'GET',
        `/ee/audit/export?${period}&organizationId=${org}&${filter}`,
        orgAdmin,
      );
      expect(exported.statusCode, filter).toBe(200);
      expect(exportLines(exported.body), filter).toEqual([]);
    }
  });

  it('records a scoped export in its organisation, where its admins see it (§8)', async () => {
    const period = 'from=2026-12-01T00:00:00Z&to=2027-02-01T00:00:00Z';
    const own = await req('GET', `/ee/audit/export?${period}&organizationId=${org}`, orgAdmin);
    const last = exportLines(own.body).at(-1) as unknown as {
      action: string;
      organization: { id: string; key: string };
      actor: { username: string };
    };
    expect(last).toMatchObject({
      action: 'audit.exported',
      organization: { id: org, key: 'org-a' },
      actor: { username: 'org-a-admin' },
    });
    const events = await req(
      'GET',
      `/ee/audit/events?organizationId=${org}&action=audit.exported`,
      orgAdmin,
    );
    expect((events.json() as { items: unknown[] }).items[0]).toMatchObject({
      action: 'audit.exported',
      organization: { id: org, key: 'org-a' },
    });
    // An instance admin's scoped export belongs to that organisation too; an unscoped one to none.
    await req('GET', `/ee/audit/export?${period}&organizationId=${orgB}`, admin);
    await req('GET', `/ee/audit/export?${period}`, admin);
    const exports = await req('GET', '/ee/audit/events?action=audit.exported&limit=2', admin);
    expect(
      (exports.json() as { items: { organization: { key: string } | null }[] }).items.map(
        (e) => e.organization?.key ?? null,
      ),
    ).toEqual([null, 'org-b']);
    // An organisation that does not exist is 404, for an instance admin too.
    const missing = await req(
      'GET',
      `/ee/audit/export?${period}&organizationId=00000000-0000-4000-8000-000000000000`,
      admin,
    );
    expect(missing.statusCode).toBe(404);
  });

  it('answers the head and a verification to an instance admin', async () => {
    const head = await req('GET', '/ee/audit/head', admin);
    expect(head.json()).toMatchObject({
      seq: expect.any(String),
      hash: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    const verify = await req('GET', '/ee/audit/verify', admin);
    expect(verify.json()).toMatchObject({ ok: true, break: null });
    const bad = await req('GET', '/ee/audit/verify?fromSeq=01', admin);
    expect(bad.statusCode).toBe(422);
  });

  it('answers 409 AUDIT_CHAIN_ANCHOR_MALFORMED, never a 500, while the anchor row is malformed', async () => {
    await ctx.db.execute(sql`
      INSERT INTO instance_settings (key, value) VALUES ('audit-chain', '{"throughSeq":1}'::jsonb)`);
    try {
      const head = await req('GET', '/ee/audit/head', admin);
      expect(head.statusCode).toBe(409);
      expect(head.json()).toMatchObject({ code: 'AUDIT_CHAIN_ANCHOR_MALFORMED' });
    } finally {
      await ctx.db.execute(sql`DELETE FROM instance_settings WHERE key = 'audit-chain'`);
    }
  });

  it('configures the stream, returns its secret once, and never shows it again', async () => {
    await allowLoopbackReceivers(ctx);
    const put = await req('PUT', '/ee/audit/settings', admin, {
      retentionDays: 400,
      stream: { url: `http://127.0.0.1:${receiver.port}/siem` },
    });
    expect(put.statusCode).toBe(200);
    const secret = (put.json() as { stream: { secret: string } }).stream.secret;
    expect(secret).toMatch(/^whsec_/);
    streamSecrets.push(secret);
    const get = await req('GET', '/ee/audit/settings', admin);
    expect(get.body).not.toContain(secret);
    expect(get.json()).toMatchObject({ retentionDays: 400, stream: { secretSet: true } });

    const regenerated = await req('POST', '/ee/audit/settings/stream/regenerate-secret', admin);
    expect(regenerated.statusCode).toBe(200);
    const next = (regenerated.json() as { secret: string }).secret;
    expect(next).toMatch(/^whsec_/);
    expect(next).not.toBe(secret);
    streamSecrets.push(next);
    expect((await req('GET', '/ee/audit/settings', admin)).body).not.toContain(next);

    const test = await req('POST', '/ee/audit/settings/stream/test', admin);
    expect(test.statusCode).toBe(200);
    expect(test.json()).toMatchObject({ ok: true, status: 204 });
    expect(JSON.parse(receiver.bodies.at(-1)!)).toMatchObject({ test: true, events: [] });

    const invalid = await req('PUT', '/ee/audit/settings', admin, {
      stream: { url: 'ftp://127.0.0.1/siem' },
    });
    expect(invalid.statusCode).toBe(422);
    expect(invalid.json()).toMatchObject({
      errors: [expect.objectContaining({ path: 'body.stream.url' })],
    });
  });

  it('sends at most 10 stream tests a minute per caller (429 RATE_LIMITED)', async () => {
    // One test was sent above; nine more are allowed this minute, the eleventh is refused.
    for (let i = 0; i < 9; i += 1) {
      expect((await req('POST', '/ee/audit/settings/stream/test', admin)).statusCode).toBe(200);
    }
    const refused = await req('POST', '/ee/audit/settings/stream/test', admin);
    expect(refused.statusCode).toBe(429);
    expect(refused.json()).toMatchObject({ code: 'RATE_LIMITED' });
  });

  it('keeps the SIEM and the database free of every secret of the scenario', async () => {
    // runAuditScenario (Task 10) through the real plugin, then an export and one stream run.
    const { secrets } = await runAuditScenario(ctx, env);
    secrets.push(...streamSecrets);
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const before = receiver.bodies.length;
    // The scenario's webhook step rewrote the row; the receiver needs both settings again.
    await allowLoopbackReceivers(ctx);
    await ensurePluginScheduled(ctx.db, 'ee.audit.stream', 0);
    await runUntilIdle(ctx.db, handlers(), quietLogger());
    const batches = receiver.bodies.slice(before);
    expect(batches.length).toBeGreaterThan(0);
    const streamedActions = batches.flatMap((b) =>
      (JSON.parse(b) as { events: { action: string }[] }).events.map((e) => e.action),
    );
    expect(streamedActions).toContain('project.deleted');

    const exported = await req(
      'GET',
      '/ee/audit/export?from=2026-12-01T00:00:00Z&to=2027-11-30T00:00:00Z',
      admin,
    );
    expect(exported.statusCode).toBe(200);
    const rows = await ctx.db.execute<{ row: string }>(
      sql`SELECT row_to_json(a)::text AS row FROM audit_events a`,
    );
    const columns = rows.rows.map((r) => r.row).join('\n');
    const streamed = batches.join('\n');
    expect(secrets.length).toBeGreaterThan(8);
    for (const s of secrets) {
      expect(exported.body.includes(s), `a secret of length ${s.length} is in the export`).toBe(
        false,
      );
      expect(streamed.includes(s), `a secret of length ${s.length} was streamed`).toBe(false);
      expect(columns.includes(s), `a secret of length ${s.length} is in a column`).toBe(false);
    }
    const verify = await req('GET', '/ee/audit/verify', admin);
    expect(verify.json()).toMatchObject({ ok: true, break: null });
  }, 180_000);

  it('answers 403 FEATURE_NOT_LICENSED on every route after a lapse, and streams nothing', async () => {
    // One event the stream has not sent yet, so a run after the lapse would have something to send.
    const pending = await req('PUT', `/projects/${project.id}/members/${userId}`, admin, {
      role: 'member',
    });
    expect(pending.statusCode).toBe(200);
    now = AFTER_GRACE;
    const period = 'from=2027-01-01T00:00:00Z&to=2027-02-01T00:00:00Z';
    const routes: ['GET' | 'PUT' | 'POST' | 'DELETE', string][] = [
      ['GET', '/ee/audit/events'],
      ['GET', `/ee/audit/export?${period}`],
      ['GET', '/ee/audit/head'],
      ['GET', '/ee/audit/verify'],
      ['GET', '/ee/audit/settings'],
      ['PUT', '/ee/audit/settings'],
      ['POST', '/ee/audit/settings/stream/regenerate-secret'],
      ['POST', '/ee/audit/settings/stream/test'],
    ];
    for (const [method, url] of routes) {
      const res = await req(method, url, admin, method === 'PUT' ? { role: 'viewer' } : undefined);
      expect(res.statusCode, `${method} ${url}`).toBe(403);
      expect(res.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
    }
    // Grants are core since 5B (§16): they do not lapse; nothing is recorded any more.
    const events = (await ctx.db.execute(sql`SELECT count(*)::int AS n FROM audit_events`)).rows;
    const kept = await req('PUT', `/projects/${project.id}/members/${userId}`, admin, {
      role: 'viewer',
    });
    expect([kept.statusCode, kept.json().role]).toEqual([200, 'viewer']);
    expect((await ctx.db.execute(sql`SELECT count(*)::int AS n FROM audit_events`)).rows).toEqual(
      events,
    );
    // The schedule still runs, and sends nothing while the feature is inactive (§15).
    const before = receiver.bodies.length;
    await ctx.db.execute(sql`UPDATE jobs SET run_at = now() WHERE queue = 'ee.audit.stream'`);
    await ensurePluginScheduled(ctx.db, 'ee.audit.stream', 0);
    await runUntilIdle(ctx.db, handlers(), quietLogger());
    expect(receiver.bodies.length).toBe(before);
  });
});

/** A server on `database`, booted as main.ts boots it: bootEnterprise reads a real signed key. */
async function bootOn(
  database: TestDatabase,
  signer: TestSigner,
  features: readonly string[],
  clock: () => Date,
): Promise<TestContext & { audit: AuditRecorder }> {
  const key = signTest(signer, testPayload({ features: [...features], expires: LICENSE_EXPIRES }));
  const config = testConfig({
    databaseUrl: database.url,
    license: { text: key, file: null },
    pluginPaths: [OUT],
  });
  const logs: string[] = [];
  const logger = createLogger('info', { write: (line: string) => void logs.push(line) });
  const booted = await bootEnterprise({
    config,
    db: database.db,
    logger,
    serverVersion: '0.0.0',
    verifyOptions: (at) => verifyWith(signer, at),
    now: clock,
  });
  const app = await buildApp({
    config,
    db: database.db,
    logger,
    edition: booted.edition,
    plugins: booted.plugins,
    audit: booted.audit,
    checkReady: async () => true,
  });
  await app.ready();
  const [admin] = await database.db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, 'admin'));
  return {
    app,
    db: database.db,
    database,
    config,
    logs,
    adminId: admin!.id,
    plugins: booted.plugins,
    edition: booted.edition,
    audit: booted.audit,
    // The database outlives the app: the next boot uses it.
    close: () => app.close(),
  };
}

describe('audit-log.stream (rbac-audit.md §14.4)', () => {
  const STREAM_TITLE = 'The enterprise feature "audit-log.stream" is not licensed';
  let receiver: Awaited<ReturnType<typeof startReceiver>>;

  const call = (
    ctx: TestContext,
    session: Session,
    method: 'GET' | 'PUT' | 'POST',
    url: string,
    payload?: unknown,
  ) =>
    ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const settingsRows = async (ctx: TestContext) =>
    (
      await ctx.db.execute<{ key: string; value: string }>(sql`
        SELECT key, value::text AS value FROM instance_settings
         WHERE key IN ('audit', 'audit-stream') ORDER BY key`)
    ).rows;
  const eventCount = async (ctx: TestContext) =>
    (await ctx.db.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM audit_events`)).rows[0]!
      .n;
  const seqs = async (ctx: TestContext, after = 0) =>
    (
      await ctx.db.execute<{ seq: string }>(
        // Ordered by the bigint column, not the text alias.
        sql`SELECT seq::text AS seq FROM audit_events a WHERE a.seq > ${after} ORDER BY a.seq`,
      )
    ).rows.map((r) => Number(r.seq));
  const receivedSeqs = (from: number) =>
    receiver.bodies
      .slice(from)
      .flatMap((b) => (JSON.parse(b) as { events: { seq: string }[] }).events)
      .map((e) => Number(e.seq));
  const createOrganizations = async (ctx: TestContext, admin: Session, keys: string[]) => {
    for (const key of keys) {
      const res = await call(ctx, admin, 'POST', '/organizations', { key, name: key });
      expect(res.statusCode, res.body).toBe(201);
    }
  };
  /** The plugin's scheduled job through core's worker, as the server runs it. */
  const runStreamJob = async (ctx: TestContext) => {
    await ctx.db.execute(sql`UPDATE jobs SET run_at = now() WHERE queue = 'ee.audit.stream'`);
    await ensurePluginScheduled(ctx.db, 'ee.audit.stream', 0);
    const handlers = pluginJobHandlers(ctx.plugins!, ctx.edition!, quietLogger(), { db: ctx.db });
    await runUntilIdle(ctx.db, handlers, quietLogger());
  };
  /** Core's own guard: `ctx.audit.streamOnce` of services bound to this edition. */
  const coreStreamOnce = async (ctx: TestContext & { audit: AuditRecorder }, clock: () => Date) =>
    createPluginServices({
      db: ctx.db,
      isFeatureActive: (f) => ctx.edition!.isFeatureActive(f),
      secretKey: ctx.config.secretKey,
      version: '0.0.0',
      recorder: ctx.audit,
      now: clock,
    }).audit.streamOnce(new AbortController().signal);

  beforeAll(async () => {
    receiver = await startReceiver();
  });
  afterAll(async () => {
    receiver?.server.closeAllConnections();
    await new Promise<void>((resolve) => receiver?.server.close(() => resolve()));
  });

  it('a Business key keeps retention and refuses the stream', async () => {
    // Review Focus 1: Business lists sso, audit-log and llm.fix-quota.
    const env = await startAuditScenarioEnv();
    const ctx = await bootEnterpriseTest(env, () => LICENSED, BUSINESS_FEATURES);
    try {
      await allowLoopbackReceivers(ctx);
      const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
      const url = `http://127.0.0.1:${receiver.port}/siem`;
      for (const path of ['stream/test', 'stream/regenerate-secret']) {
        const res = await call(ctx, admin, 'POST', `/ee/audit/settings/${path}`);
        expect(res.statusCode, path).toBe(403);
        expect(res.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED', title: STREAM_TITLE });
      }
      // One request, one answer: the retention in the same body is not saved.
      const both = await call(ctx, admin, 'PUT', '/ee/audit/settings', {
        retentionDays: 90,
        stream: { url },
      });
      expect(both.statusCode).toBe(403);
      expect(both.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED', title: STREAM_TITLE });
      expect((await call(ctx, admin, 'GET', '/ee/audit/settings')).json()).toEqual({
        retentionDays: 365,
        stream: null,
      });
      const retention = await call(ctx, admin, 'PUT', '/ee/audit/settings', { retentionDays: 90 });
      expect(retention.statusCode, retention.body).toBe(200);
      expect(retention.json()).toEqual({ retentionDays: 90, stream: null });
      const removed = await call(ctx, admin, 'PUT', '/ee/audit/settings', { stream: null });
      expect(removed.statusCode, removed.body).toBe(200);
      expect((await call(ctx, admin, 'GET', '/ee/audit/settings')).json()).toEqual({
        retentionDays: 90,
        stream: null,
      });
      const info = (await call(ctx, admin, 'GET', '/system/info')).json() as {
        features: string[];
      };
      expect([...info.features].sort()).toEqual([...BUSINESS_FEATURES].sort());
      expect(info.features).not.toContain('audit-log.stream');
      // No stream could be configured here, so nothing to send: the pause of a kept stream is the
      // next describe's case.
    } finally {
      await ctx.close();
      await env.close();
    }
  });

  describe('one database across keys', () => {
    const signer = testSigner();
    // Enterprise, then Business (two moments), then the clock past retention, then Enterprise.
    const ENTERPRISE_AT = new Date('2027-01-01T00:00:00Z');
    const BUSINESS_AT = new Date('2027-01-02T00:00:00Z');
    const BUSINESS_LATER = new Date('2027-03-01T00:00:00Z');
    const RETURN_AT = new Date('2027-03-15T00:00:00Z');
    const RETENTION_DAYS = 30; // cutoff 2027-02-13: January's events go, March's stay
    let now = ENTERPRISE_AT;
    const clock = () => now;
    let database: TestDatabase;
    let ctx: (TestContext & { audit: AuditRecorder }) | undefined;

    const boot = async (features: readonly string[]) => {
      await ctx?.close();
      ctx = await bootOn(database, signer, features, clock);
      return { ctx, admin: await login(ctx, 'admin', ADMIN_PASSWORD) };
    };

    beforeAll(async () => {
      database = await createTestDatabase();
      await bootstrap(database.db, { username: 'admin', password: ADMIN_PASSWORD });
    });
    afterAll(async () => {
      await ctx?.close();
      await database?.close();
    });

    it('a stream kept across Enterprise → Business → Enterprise pauses and catches up, bounded by retention', async () => {
      // Review Focus 2. Enterprise: configure, record, send.
      const e1 = await boot(ENTERPRISE_FEATURES);
      await allowLoopbackReceivers(e1.ctx);
      const put = await call(e1.ctx, e1.admin, 'PUT', '/ee/audit/settings', {
        stream: { url: `http://127.0.0.1:${receiver.port}/siem` },
      });
      expect(put.statusCode, put.body).toBe(200);
      await createOrganizations(e1.ctx, e1.admin, ['ent-one', 'ent-two']);
      const sentBefore = receiver.bodies.length;
      await runStreamJob(e1.ctx);
      expect(receivedSeqs(sentBefore).length).toBeGreaterThan(0);
      const status = (await call(e1.ctx, e1.admin, 'GET', '/ee/audit/settings')).json() as {
        stream: { status: { cursorSeq: string; pending: number; skipped: number } };
      };
      expect(status.stream.status).toMatchObject({ pending: 0, skipped: 0 });
      const cursor = Number(status.stream.status.cursorSeq);
      expect(cursor).toBe(Math.max(...(await seqs(e1.ctx))));

      // Business: events are recorded (audit-log), nothing is sent, nothing of the stream changes.
      now = BUSINESS_AT;
      const b = await boot(BUSINESS_FEATURES);
      const kept = await settingsRows(b.ctx);
      expect(kept.map((r) => r.key)).toEqual(['audit', 'audit-stream']);
      const paused = receiver.bodies.length;
      await createOrganizations(b.ctx, b.admin, ['biz-one', 'biz-two']);
      now = BUSINESS_LATER;
      await createOrganizations(b.ctx, b.admin, ['biz-three', 'biz-four']);
      await runStreamJob(b.ctx);
      await coreStreamOnce(b.ctx, clock);
      expect(receiver.bodies.length).toBe(paused);
      expect(await settingsRows(b.ctx)).toEqual(kept);
      const view = (await call(b.ctx, b.admin, 'GET', '/ee/audit/settings')).json() as {
        stream: { active: boolean; secretSet: boolean; status: Record<string, unknown> };
      };
      expect(view.stream).toMatchObject({ active: true, secretSet: true });
      expect(view.stream.status).toMatchObject({ cursorSeq: String(cursor), skipped: 0 });
      expect(view.stream.status['pending']).toBe((await seqs(b.ctx, cursor)).length);

      // Retention removes the oldest events, sent or not; the stream rows are untouched.
      now = RETURN_AT;
      const before = await seqs(b.ctx);
      const deleted = await pruneAuditEvents(b.ctx.db, {
        retentionDays: RETENTION_DAYS,
        now: clock(),
      });
      const after = new Set(await seqs(b.ctx));
      expect(deleted).toBe(before.filter((s) => !after.has(s)).length);
      const prunedUnsent = before.filter((s) => s > cursor && !after.has(s)).length;
      expect(prunedUnsent).toBeGreaterThan(0);
      expect(before.filter((s) => s > cursor && after.has(s)).length).toBeGreaterThan(0);
      expect(await settingsRows(b.ctx)).toEqual(kept);

      // Enterprise again: the retained events after the cursor, in seq order; the rest skipped.
      const e2 = await boot(ENTERPRISE_FEATURES);
      const expected = await seqs(e2.ctx, cursor);
      const resumed = receiver.bodies.length;
      await runStreamJob(e2.ctx);
      expect(receivedSeqs(resumed)).toEqual(expected);
      const caughtUp = (await call(e2.ctx, e2.admin, 'GET', '/ee/audit/settings')).json() as {
        stream: { status: Record<string, unknown> };
      };
      expect(caughtUp.stream.status).toMatchObject({
        cursorSeq: String(expected.at(-1)),
        pending: 0,
        skipped: prunedUnsent,
      });
    }, 120_000);

    it('a key listing audit-log.stream without audit-log streams and records nothing', async () => {
      // Review Focus 3: a key made by hand; it verifies, boots, and switches nothing on. Its own
      // database, with a stream configured and events waiting under an Enterprise key first, so
      // "sends nothing" has something it could have sent.
      const own = await createTestDatabase();
      let current: (TestContext & { audit: AuditRecorder }) | undefined;
      try {
        await bootstrap(own.db, { username: 'admin', password: ADMIN_PASSWORD });
        now = ENTERPRISE_AT;
        current = await bootOn(own, signer, ENTERPRISE_FEATURES, clock);
        await allowLoopbackReceivers(current);
        const e = await login(current, 'admin', ADMIN_PASSWORD);
        const put = await call(current, e, 'PUT', '/ee/audit/settings', {
          stream: { url: `http://127.0.0.1:${receiver.port}/siem` },
        });
        expect(put.statusCode, put.body).toBe(200);
        await createOrganizations(current, e, ['waiting-one']);
        const waiting = (await call(current, e, 'GET', '/ee/audit/settings')).json() as {
          stream: { status: { pending: number } };
        };
        expect(waiting.stream.status.pending).toBeGreaterThan(0);
        await current.close();

        current = await bootOn(own, signer, ['audit-log.stream'], clock);
        const s = { ctx: current, admin: await login(current, 'admin', ADMIN_PASSWORD) };
        expect(s.ctx.edition!.state().state).toBe('active');
        const info = (await call(s.ctx, s.admin, 'GET', '/system/info')).json() as {
          features: string[];
        };
        expect(info.features).toEqual([]);
        const rows = await settingsRows(s.ctx);
        expect(rows.map((r) => r.key)).toEqual(['audit', 'audit-stream']);
        const events = await eventCount(s.ctx);
        await createOrganizations(s.ctx, s.admin, ['orphan-one']);
        expect(await eventCount(s.ctx)).toBe(events);
        for (const [method, url, feature] of [
          ['POST', '/ee/audit/settings/stream/test', 'audit-log.stream'],
          ['POST', '/ee/audit/settings/stream/regenerate-secret', 'audit-log.stream'],
          ['GET', '/ee/audit/settings', 'audit-log'],
          ['GET', '/ee/audit/events', 'audit-log'],
        ] as const) {
          const res = await call(s.ctx, s.admin, method, url);
          expect(res.statusCode, url).toBe(403);
          expect(res.json()).toMatchObject({
            code: 'FEATURE_NOT_LICENSED',
            title: `The enterprise feature "${feature}" is not licensed`,
          });
        }
        const before = receiver.bodies.length;
        await runStreamJob(s.ctx);
        await coreStreamOnce(s.ctx, clock);
        expect(receiver.bodies.length).toBe(before);
        expect(await settingsRows(s.ctx)).toEqual(rows);
      } finally {
        await current?.close();
        await own.close();
      }
    }, 120_000);
  });
});

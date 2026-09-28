import { randomUUID } from 'node:crypto';
import { count, desc, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createProject,
  createTestContext,
  createUser,
  login,
  nextIp,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { signTest, testPayload, testSigner, verifyWith, type TestSigner } from '../../test/license';
import { RBAC_FIXTURE } from '../../test/rbac';
import { LOGIN_ATTEMPTS_PER_MINUTE } from '../routes/auth';
import { auditEvents, branches, memberships, type AuditEventRow } from '../db/schema';
import { ProblemError } from '../http/problem';
import { createEdition } from '../license/edition';
import { licenseState } from '../license/state';
import { verifyLicenseKey } from '../license/verify';
import { loadPlugins } from '../plugins/loader';
import { setProjectGrant } from '../rbac/grants';
import { createAuditRecorder, type AuditActorContext } from './recorder';
import { verifyAuditChain } from './verify';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

/**
 * A licensed server as `rbacContext` builds it, but with an uploaded boot key and `signer`
 * trusted by `PUT /license`, so the licence routes run (rbac-audit.md §8, enterprise.md §9).
 */
async function licensedContext(options: {
  features: string[];
  now: () => Date;
  signer: TestSigner;
}): Promise<TestContext> {
  const verification = verifyLicenseKey(
    signTest(options.signer, testPayload({ features: options.features })),
    verifyWith(options.signer, options.now()),
  );
  const boot = { source: 'uploaded' as const, keyHash: 'h', verification };
  return createTestContext({
    pluginsFor: async (db) => ({
      plugins: await loadPlugins({
        paths: ['/virtual/rbac-fixture.js'],
        state: licenseState(verification, options.now()),
        base: { serverVersion: '0.0.0', db, logger: quietLogger() },
        checkFile: async (path) => ({ ok: true, realPath: path }),
        importModule: async () => ({ default: RBAC_FIXTURE }),
      }),
      edition: (frozen) =>
        createEdition({
          boot,
          plugins: frozen,
          now: options.now,
          verifyOptions: (now) => verifyWith(options.signer, now),
        }),
    }),
  });
}

describe('recorded events, part A (rbac-audit.md §8)', () => {
  const now = new Date('2027-01-01T00:00:00Z');
  const signer = testSigner();
  // A fake key, split so no scanner mistakes it for a real one.
  const apiKey = ['sk', 'audit', 'test', '0123456789'].join('-');
  let ctx: TestContext;
  let root: Session;
  let org: string;

  beforeAll(async () => {
    ctx = await licensedContext({ features: ['audit-log'], now: () => now, signer });
    root = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
  });
  afterAll(async () => {
    expect((await verifyAuditChain(ctx.db)).ok).toBe(true);
    await ctx.close();
  });

  const latest = async (action: string): Promise<AuditEventRow> => {
    const [row] = await ctx.db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.action, action))
      .orderBy(desc(auditEvents.seq))
      .limit(1);
    expect(row, `no ${action} event`).toBeDefined();
    return row!;
  };
  const total = async (): Promise<number> => {
    const [row] = await ctx.db.select({ n: count() }).from(auditEvents);
    return row!.n;
  };
  const loginAs = (username: string, password: string) =>
    ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/login',
      payload: { username, password },
      remoteAddress: nextIp(),
    });

  it('records a sign-in with the user and the client', async () => {
    await login(ctx, 'admin', ADMIN_PASSWORD);
    const e = await latest('auth.sign_in');
    expect(e).toMatchObject({
      actorType: 'user',
      actorUsername: 'admin',
      targetType: 'user',
      targetId: ctx.adminId,
      organizationId: null,
      details: { method: 'password' },
    });
    expect(e.ip).toMatch(/^10\./);
  });

  it('a failed sign-in with an unknown name stores no name', async () => {
    const typed = 'correct horse battery staple!';
    const res = await loginAs(typed, 'x');
    expect(res.statusCode).toBe(401);
    const e = await latest('auth.sign_in_failed');
    expect(e).toMatchObject({
      outcome: 'failure',
      actorType: 'anonymous',
      actorUserId: null,
      actorUsername: null,
      targetType: null,
      targetId: null,
      targetLabel: null,
      details: { reason: 'invalid_credentials', knownUser: false },
    });
    expect(JSON.stringify(e)).not.toContain(typed);
  });

  it('a failed sign-in of a known user names the user, never the password', async () => {
    const res = await loginAs('admin', 'wrong password 123');
    expect(res.statusCode).toBe(401);
    const e = await latest('auth.sign_in_failed');
    expect(e).toMatchObject({
      actorType: 'anonymous',
      actorUserId: ctx.adminId,
      actorUsername: 'admin',
      targetId: ctx.adminId,
      details: { reason: 'invalid_credentials', knownUser: true },
    });
    expect(JSON.stringify(e)).not.toContain('wrong password 123');
  });

  it('an inactive user is logged as such while the answer stays 401 INVALID_CREDENTIALS', async () => {
    const u = await createUser(ctx, { username: 'idle', active: false });
    const res = await loginAs('idle', u.password);
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ code: 'INVALID_CREDENTIALS' });
    const e = await latest('auth.sign_in_failed');
    expect(e).toMatchObject({
      actorUserId: u.id,
      details: { reason: 'inactive_user', knownUser: true },
    });
    expect(JSON.stringify(e)).not.toContain(u.password);
  });

  it('a throttled sign-in is recorded as rate_limited, without the typed name', async () => {
    const typed = 'nobody-at-all-here';
    for (let i = 0; i < LOGIN_ATTEMPTS_PER_MINUTE; i++) await loginAs(typed, 'x');
    const res = await loginAs(typed, 'x');
    expect(res.statusCode).toBe(429);
    const e = await latest('auth.sign_in_failed');
    expect(e).toMatchObject({
      actorUserId: null,
      actorUsername: null,
      details: { reason: 'rate_limited', knownUser: false },
    });
    expect(JSON.stringify(e)).not.toContain(typed);
  });

  it('records a sign-out and a password change', async () => {
    const u = await createUser(ctx, { username: 'pat' });
    const s = await login(ctx, u.username, u.password);
    const newPassword = 'another perfectly fine passphrase';
    const changed = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/auth/me/password',
      headers: s.headers,
      payload: { currentPassword: u.password, newPassword },
    });
    expect(changed.statusCode).toBe(204);
    const pw = await latest('auth.password_changed');
    expect(pw).toMatchObject({ actorUserId: u.id, targetId: u.id, details: {} });
    expect(JSON.stringify(pw)).not.toContain(newPassword);
    const out = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/logout',
      headers: s.headers,
    });
    expect(out.statusCode).toBe(204);
    expect(await latest('auth.sign_out')).toMatchObject({
      actorUserId: u.id,
      targetType: 'user',
      targetId: u.id,
      details: {},
    });
  });

  it('records a new user and only the user fields that changed', async () => {
    const password = 'a brand new passphrase 1';
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/users',
      headers: root.headers,
      payload: { username: 'uma', password, isInstanceAdmin: false },
    });
    expect(created.statusCode).toBe(201);
    const id = (created.json() as { id: string }).id;
    const c = await latest('user.created');
    expect(c).toMatchObject({
      actorUsername: 'admin',
      targetType: 'user',
      targetId: id,
      targetLabel: 'uma',
      details: { instanceAdmin: false, passwordChangeRequired: true },
    });
    expect(JSON.stringify(c)).not.toContain(password);

    const reset = 'a reset passphrase here 2';
    const patch = (payload: object) =>
      ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/users/${id}`,
        headers: root.headers,
        payload,
      });
    expect((await patch({ displayName: 'Uma', active: true, password: reset })).statusCode).toBe(
      200,
    );
    const u = await latest('user.updated');
    expect(u).toMatchObject({
      targetId: id,
      details: {
        changes: [{ field: 'displayName', from: null, to: 'Uma' }],
        passwordReset: true,
      },
    });
    expect(JSON.stringify(u)).not.toContain(reset);
    const before = await total();
    expect((await patch({ displayName: 'Uma' })).statusCode).toBe(200);
    expect(await total()).toBe(before);
  });

  it('records a personal token created and revoked, never the token', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: root.headers,
      payload: { name: 'laptop', scopes: ['read'], expiresInDays: 30 },
    });
    expect(res.statusCode).toBe(201);
    const token = res.json() as { id: string; prefix: string; token: string };
    const c = await latest('token.created');
    expect(c).toMatchObject({
      targetType: 'token',
      targetId: token.id,
      targetLabel: 'laptop',
      details: { name: 'laptop', prefix: token.prefix, scopes: ['read'] },
    });
    expect((c.details as { expiresAt: string }).expiresAt).toMatch(/^\d{4}-/);
    expect(JSON.stringify(c)).not.toContain(token.token);
    const del = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/tokens/${token.id}`,
      headers: root.headers,
    });
    expect(del.statusCode).toBe(204);
    expect(await latest('token.revoked')).toMatchObject({
      targetId: token.id,
      details: { name: 'laptop', prefix: token.prefix },
    });
    const before = await total();
    const again = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/tokens/${token.id}`,
      headers: root.headers,
    });
    expect(again.statusCode).toBe(404);
    expect(await total()).toBe(before);
  });

  it('records a new organisation', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: root.headers,
      payload: { key: 'audited-org', name: 'Audited' },
    });
    expect(res.statusCode).toBe(201);
    const id = (res.json() as { id: string }).id;
    expect(await latest('organization.created')).toMatchObject({
      organizationId: id,
      organizationKey: 'audited-org',
      targetType: 'organization',
      targetId: id,
      details: { key: 'audited-org', name: 'Audited' },
    });
  });

  it('records a role change with from and to, and nothing for the same role again', async () => {
    const u = await createUser(ctx, { username: 'rick' });
    const put = (role: string) =>
      ctx.app.inject({
        method: 'PUT',
        url: `/api/v0/organizations/${org}/members/${u.id}`,
        headers: root.headers,
        payload: { role },
      });
    await put('member');
    expect(await latest('member.added')).toMatchObject({
      organizationKey: 'default',
      targetId: u.id,
      targetLabel: 'rick',
      details: { role: 'member' },
    });
    await put('viewer');
    expect(await latest('member.role_changed')).toMatchObject({
      details: { from: 'member', to: 'viewer' },
    });
    const before = await total();
    await put('viewer');
    expect(await total()).toBe(before);
    const del = () =>
      ctx.app.inject({
        method: 'DELETE',
        url: `/api/v0/organizations/${org}/members/${u.id}`,
        headers: root.headers,
      });
    expect((await del()).statusCode).toBe(204);
    expect(await latest('member.removed')).toMatchObject({
      organizationKey: 'default',
      targetId: u.id,
      details: { role: 'viewer' },
    });
    const after = await total();
    expect((await del()).statusCode).toBe(404);
    expect(await total()).toBe(after);
  });

  it('records a project change with only the fields that changed', async () => {
    const p = await createProject(ctx, root, { organizationId: org, key: 'aud-a' });
    expect(await latest('project.created')).toMatchObject({
      organizationKey: 'default',
      projectId: p.id,
      projectKey: 'aud-a',
      targetType: 'project',
      targetId: p.id,
      details: { key: 'aud-a', name: 'aud-a', mainBranchName: 'main' },
    });
    await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${p.id}`,
      headers: root.headers,
      payload: { name: 'Renamed', mainBranchName: 'main' },
    });
    expect(await latest('project.updated')).toMatchObject({
      projectKey: 'aud-a',
      details: { changes: [{ field: 'name', from: 'aud-a', to: 'Renamed' }] },
    });
    await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${p.id}`,
      headers: root.headers,
      payload: { newCodeDefinition: { type: 'days', value: 14 } },
    });
    expect(await latest('project.updated')).toMatchObject({
      details: {
        changes: [{ field: 'newCodeDefinition', from: null, to: { type: 'days', value: 14 } }],
      },
    });
    const before = await total();
    await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${p.id}`,
      headers: root.headers,
      payload: { name: 'Renamed', newCodeDefinition: { value: 14, type: 'days' } },
    });
    expect(await total()).toBe(before);
  });

  it('records project tokens, a deleted branch and a deleted project with refs read first', async () => {
    const p = await createProject(ctx, root, { organizationId: org, key: 'aud-del' });
    const res = await ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${p.id}/tokens`,
      headers: root.headers,
      payload: { name: 'ci' },
    });
    expect(res.statusCode).toBe(201);
    const token = res.json() as { id: string; prefix: string; token: string };
    const c = await latest('project_token.created');
    expect(c).toMatchObject({
      organizationKey: 'default',
      projectKey: 'aud-del',
      targetType: 'token',
      targetId: token.id,
      details: { name: 'ci', prefix: token.prefix, expiresAt: null },
    });
    expect(JSON.stringify(c)).not.toContain(token.token);
    const revoked = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${p.id}/tokens/${token.id}`,
      headers: root.headers,
    });
    expect(revoked.statusCode).toBe(204);
    expect(await latest('project_token.revoked')).toMatchObject({
      projectKey: 'aud-del',
      targetId: token.id,
      details: { name: 'ci', prefix: token.prefix },
    });

    const [branch] = await ctx.db
      .insert(branches)
      .values({ projectId: p.id, kind: 'merge_request', name: '42', isMain: false })
      .returning();
    const delBranch = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/branches/${branch!.id}`,
      headers: root.headers,
    });
    expect(delBranch.statusCode).toBe(204);
    expect(await latest('branch.deleted')).toMatchObject({
      organizationKey: 'default',
      projectKey: 'aud-del',
      targetType: 'branch',
      targetId: branch!.id,
      targetLabel: '42',
      details: { kind: 'merge_request', name: '42' },
    });

    const del = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${p.id}?confirm=aud-del`,
      headers: root.headers,
    });
    expect(del.statusCode).toBe(204);
    expect(await latest('project.deleted')).toMatchObject({
      organizationId: org,
      organizationKey: 'default',
      projectId: p.id,
      projectKey: 'aud-del',
      targetId: p.id,
      details: { key: 'aud-del' },
    });
  });

  it('records a licence upload from the verified payload and its removal, never the key', async () => {
    const payload = testPayload({ features: ['audit-log'] });
    const key = signTest(signer, payload);
    const put = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/license',
      headers: root.headers,
      payload: { key },
    });
    expect(put.statusCode).toBe(200);
    const e = await latest('license.uploaded');
    expect(e).toMatchObject({
      organizationId: null,
      targetType: 'license',
      targetId: payload.id,
      details: {
        licenseId: payload.id,
        keyId: signer.kid,
        expires: new Date(payload.expires).toISOString(),
        features: ['audit-log'],
      },
    });
    expect(JSON.stringify(e)).not.toContain(key.slice(0, 40));
    const del = () =>
      ctx.app.inject({ method: 'DELETE', url: '/api/v0/license', headers: root.headers });
    expect((await del()).statusCode).toBe(200);
    expect(await latest('license.removed')).toMatchObject({
      targetType: 'license',
      details: {},
    });
    const before = await total();
    expect((await del()).statusCode).toBe(200);
    expect(await total()).toBe(before);
  });

  it('records AI settings as the names that changed and what became of the key', async () => {
    const body = (provider: object | null, over: object = {}) => ({
      provider,
      organizations: {},
      excludePaths: [],
      budgets: {
        explainPerDay: 200,
        triagePerDay: 100,
        fixPerDay: 25,
        tokensPerDay: 1_000_000,
        costPerDayUsd: null,
        perUserPerHour: 30,
      },
      pricing: null,
      storePrompts: false,
      promptRetentionDays: 7,
      ...over,
    });
    const provider = { kind: 'openai', baseUrl: 'https://llm.example.com/v1', model: 'm-1' };
    const put = (payload: object) =>
      ctx.app.inject({
        method: 'PUT',
        url: '/api/v0/system/llm',
        headers: root.headers,
        payload,
      });
    const set = await put(body({ ...provider, apiKey }));
    expect(set.statusCode, set.body).toBe(200);
    const first = await latest('ai.settings_updated');
    expect(first).toMatchObject({
      targetType: 'ai_settings',
      details: { changed: ['provider'], apiKey: 'set' },
    });
    expect(JSON.stringify(first)).not.toContain(apiKey);

    expect((await put(body(provider, { promptRetentionDays: 9 }))).statusCode).toBe(200);
    expect(await latest('ai.settings_updated')).toMatchObject({
      details: { changed: ['promptRetentionDays'], apiKey: 'kept' },
    });

    expect((await put(body(null, { promptRetentionDays: 9 }))).statusCode).toBe(200);
    expect(await latest('ai.settings_updated')).toMatchObject({
      details: { changed: ['provider'], apiKey: 'removed' },
    });
  });

  describe('project grants (rbac-audit.md §8, §16)', () => {
    let project: { id: string; key: string };
    let context: AuditActorContext;

    beforeAll(async () => {
      project = await createProject(ctx, root, { organizationId: org, key: 'aud-grants' });
      context = {
        ip: '10.9.9.9',
        userAgent: null,
        actor: { type: 'user', userId: ctx.adminId, username: 'admin', tokenId: null },
      };
    });

    const grant = (method: 'PUT' | 'DELETE', userId: string, role?: string) =>
      ctx.app.inject({
        method,
        url: `/api/v0/projects/${project.id}/members/${userId}`,
        headers: root.headers,
        ...(role === undefined ? {} : { payload: { role } }),
      });

    it('records added, role_changed and removed through the core routes, and nothing for the same role', async () => {
      const u = await createUser(ctx, { username: 'gina' });
      expect((await grant('PUT', u.id, 'viewer')).statusCode).toBe(200);
      expect(await latest('project_member.added')).toMatchObject({
        actorUsername: 'admin',
        organizationKey: 'default',
        projectKey: 'aud-grants',
        targetType: 'user',
        targetId: u.id,
        targetLabel: 'gina',
        details: { role: 'viewer' },
      });
      expect((await grant('PUT', u.id, 'project_admin')).statusCode).toBe(200);
      expect(await latest('project_member.role_changed')).toMatchObject({
        projectKey: 'aud-grants',
        details: { from: 'viewer', to: 'project_admin' },
      });
      const before = await total();
      expect((await grant('PUT', u.id, 'project_admin')).statusCode).toBe(200);
      expect(await total()).toBe(before);
      expect((await grant('DELETE', u.id)).statusCode).toBe(204);
      expect(await latest('project_member.removed')).toMatchObject({
        projectKey: 'aud-grants',
        targetId: u.id,
        details: { role: 'project_admin' },
      });
      const after = await total();
      expect((await grant('DELETE', u.id)).statusCode).toBe(404);
      expect(await total()).toBe(after);
    });

    it('answers 404 Project when the project is gone (its foreign key refuses the grant)', async () => {
      const u = await createUser(ctx, { username: 'hal' });
      const before = await total();
      const err = await setProjectGrant(ctx.db, randomUUID(), u.id, 'viewer', {
        recorder: auditRecorder(),
        context,
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ProblemError);
      expect(err).toMatchObject({ status: 404, code: 'NOT_FOUND' });
      expect(await total()).toBe(before);
    });
  });

  /** A recorder as buildApp builds it: active exactly while the edition lists audit-log. */
  const auditRecorder = () =>
    createAuditRecorder({
      log: QUIET_AUDIT_LOG,
      isActive: () => ctx.edition!.isFeatureActive('audit-log'),
    });

  describe('one transaction with the change (rbac-audit.md §8, §10.2)', () => {
    const put = (userId: string, role: string) =>
      ctx.app.inject({
        method: 'PUT',
        url: `/api/v0/organizations/${org}/members/${userId}`,
        headers: root.headers,
        payload: { role },
      });
    const membershipOf = async (userId: string) =>
      ctx.db.select().from(memberships).where(eq(memberships.userId, userId));

    it('an event that fails to record rolls the change back', async () => {
      const u = await createUser(ctx, { username: 'vic' });
      await ctx.db.execute(sql`
        CREATE FUNCTION audit_test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.action = 'member.added' THEN RAISE EXCEPTION 'refused by the test'; END IF;
          RETURN NEW;
        END $$`);
      await ctx.db.execute(sql`
        CREATE TRIGGER audit_test_refuse BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_test_refuse()`);
      try {
        const before = await total();
        expect((await put(u.id, 'member')).statusCode).toBe(500);
        expect(await membershipOf(u.id)).toEqual([]);
        expect(await total()).toBe(before);
      } finally {
        await ctx.db.execute(sql`DROP TRIGGER audit_test_refuse ON audit_events`);
        await ctx.db.execute(sql`DROP FUNCTION audit_test_refuse()`);
      }
    });

    it('a change that rolls back leaves no event', async () => {
      const u = await createUser(ctx, { username: 'wes' });
      // Fails at commit, after the membership and its event were both written.
      await ctx.db.execute(sql`
        CREATE FUNCTION membership_test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'refused at commit by the test'; END $$`);
      await ctx.db.execute(sql`
        CREATE CONSTRAINT TRIGGER membership_test_refuse AFTER INSERT ON memberships
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION membership_test_refuse()`);
      try {
        const before = await total();
        expect((await put(u.id, 'member')).statusCode).toBe(500);
        expect(await membershipOf(u.id)).toEqual([]);
        expect(await total()).toBe(before);
      } finally {
        await ctx.db.execute(sql`DROP TRIGGER membership_test_refuse ON memberships`);
        await ctx.db.execute(sql`DROP FUNCTION membership_test_refuse()`);
      }
      expect((await put(u.id, 'member')).statusCode).toBe(200);
      expect(await latest('member.added')).toMatchObject({ targetId: u.id });
    });
  });

  it('never stores a secret used above in any column', async () => {
    const rows = JSON.stringify(await ctx.db.select().from(auditEvents));
    for (const secret of [
      ADMIN_PASSWORD,
      'wrong password 123',
      'correct horse battery staple!',
      'a brand new passphrase 1',
      'a reset passphrase here 2',
      'another perfectly fine passphrase',
      apiKey,
      'nobody-at-all-here',
    ]) {
      expect(rows).not.toContain(secret);
    }
  });
});

describe('nothing is recorded without audit-log (rbac-audit.md §8.1)', () => {
  const now = new Date('2027-01-01T00:00:00Z');
  const signer = testSigner();
  let ctx: TestContext;

  beforeAll(async () => {
    // rbac is retired (enterprise.md §1.4): no feature is licensed, so none can be active.
    ctx = await licensedContext({ features: [], now: () => now, signer });
  });
  afterAll(async () => ctx.close());

  it('signs in, fails, changes members, grants, projects and the licence without a row', async () => {
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    const org = await organizationId(ctx, 'default');
    await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/login',
      payload: { username: 'admin', password: 'nope' },
      remoteAddress: nextIp(),
    });
    const u = await createUser(ctx, { username: 'quiet' });
    await ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/organizations/${org}/members/${u.id}`,
      headers: root.headers,
      payload: { role: 'member' },
    });
    const quiet = await createProject(ctx, root, { organizationId: org, key: 'quiet' });
    for (const [method, payload, status] of [
      ['PUT', { role: 'viewer' }, 200],
      ['PUT', { role: 'member' }, 200],
      ['DELETE', undefined, 204],
    ] as const) {
      const res = await ctx.app.inject({
        method,
        url: `/api/v0/projects/${quiet.id}/members/${u.id}`,
        headers: root.headers,
        ...(payload === undefined ? {} : { payload }),
      });
      expect(res.statusCode).toBe(status);
    }
    // A key that lists audit-log is stored, but applies only at the next start.
    const put = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/license',
      headers: root.headers,
      payload: { key: signTest(signer, testPayload({ features: ['audit-log'] })) },
    });
    expect(put.statusCode).toBe(200);
    expect(await ctx.db.select().from(auditEvents)).toEqual([]);
  });
});

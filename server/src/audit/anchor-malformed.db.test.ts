import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createUser,
  login,
  nextIp,
  organizationId,
  type CreatedUser,
  type Session,
  type TestContext,
} from '../../test/app';
import { grantProject, rbacContext } from '../../test/rbac';
import { SESSION_COOKIE } from '../auth/sessions';

const LICENSED = new Date('2027-01-01T00:00:00Z');

/**
 * rbac-audit.md §10.2, api.md §2.1: while the `audit-chain` row is malformed and no event is
 * stored, every audited change of a core route answers 409 AUDIT_CHAIN_ANCHOR_MALFORMED (the
 * central error handler), never a 500, and writes nothing; sign-in is refused too, while the
 * sessions and tokens that exist keep working.
 */
describe('a malformed audit-chain row on core routes', () => {
  let ctx: TestContext;
  let admin: Session;
  let token: string;
  let org: string;

  beforeAll(async () => {
    ctx = await rbacContext({ now: () => LICENSED });
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: admin.headers,
      payload: { name: 'ops', scopes: ['admin'] },
    });
    expect(created.statusCode).toBe(201);
    token = (created.json() as { token: string }).token;
    // An empty table (as after every event aged out) and a row that does not parse.
    await ctx.db.transaction(async (tx) => {
      await tx.execute(sql`ALTER TABLE audit_events DISABLE TRIGGER audit_events_guard`);
      await tx.execute(sql`DELETE FROM audit_events`);
      await tx.execute(sql`ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard`);
    });
    await ctx.db.execute(sql`
      INSERT INTO instance_settings (key, value) VALUES ('audit-chain', '{"throughSeq":1}'::jsonb)`);
  });
  afterAll(async () => ctx.close());

  const count = async (table: 'audit_events' | 'quality_gates' | 'sessions') =>
    (await ctx.db.execute<{ n: number }>(sql.raw(`SELECT count(*)::int AS n FROM ${table}`)))
      .rows[0]!.n;
  const signIn = (password: string, cookie?: string) =>
    ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/login',
      payload: { username: 'admin', password },
      remoteAddress: nextIp(),
      ...(cookie ? { cookies: { [SESSION_COOKIE]: cookie } } : {}),
    });

  it('refuses a sign-in, right or wrong, and keeps the session the client had', async () => {
    const sessions = await count('sessions');
    for (const res of [
      await signIn(ADMIN_PASSWORD, admin.cookie),
      await signIn(ADMIN_PASSWORD),
      await signIn('not the password'),
    ]) {
      expect(res.statusCode, res.body).toBe(409);
      expect(res.json()).toMatchObject({
        code: 'AUDIT_CHAIN_ANCHOR_MALFORMED',
        type: 'urn:qualor:problem:audit-chain-anchor-malformed',
      });
      expect(res.cookies.find((c) => c.name === SESSION_COOKIE)).toBeUndefined();
    }
    expect(await count('sessions')).toBe(sessions);
    expect(await count('audit_events')).toBe(0);
  });

  it('keeps existing sessions and tokens working for reads', async () => {
    const me = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      headers: admin.headers,
    });
    expect(me.statusCode).toBe(200);
    const projects = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/projects',
      headers: bearer(token),
    });
    expect(projects.statusCode).toBe(200);
  });

  it('refuses an audited change with 409 and rolls it back (a gate route)', async () => {
    const gates = await count('quality_gates');
    for (const headers of [admin.headers, bearer(token)]) {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/quality-gates',
        headers,
        payload: { organizationId: org, name: 'Refused while the anchor is malformed' },
      });
      expect(res.statusCode, res.body).toBe(409);
      expect(res.json()).toMatchObject({ code: 'AUDIT_CHAIN_ANCHOR_MALFORMED' });
    }
    expect(await count('quality_gates')).toBe(gates);
    expect(await count('audit_events')).toBe(0);
  });

  it('works again once the row is restored', async () => {
    await ctx.db.execute(sql`
      UPDATE instance_settings
         SET value = ${JSON.stringify({ throughSeq: '7', throughHash: 'a'.repeat(64), prunedAt: '2026-12-01T00:00:00.000Z' })}::jsonb
       WHERE key = 'audit-chain'`);
    expect((await signIn(ADMIN_PASSWORD)).statusCode).toBe(204);
    const [first] = (
      await ctx.db.execute<{ seq: string; prev_hash: string }>(
        sql`SELECT seq::text, prev_hash FROM audit_events ORDER BY seq LIMIT 1`,
      )
    ).rows;
    expect(first).toEqual({ seq: '8', prev_hash: 'a'.repeat(64) });
  });
});

/**
 * rbac-audit.md §10.2.1: a broken audit trail never blocks removing access. While the anchor is
 * malformed (and the table empty), sign-out, token revocation, deactivation, removal and demotion
 * go through, write no event, and log one line naming the action, the actor and the target; every
 * other audited change still answers 409.
 */
describe('removing access while the audit-chain row is malformed', () => {
  let ctx: TestContext;
  let admin: Session;
  let bobSession: Session;
  let org: string;
  let project: { id: string; key: string };
  let personalTokenId: string;
  let projectTokenId: string;
  let bob: CreatedUser;
  let carol: CreatedUser;
  let dave: CreatedUser;
  let erin: CreatedUser;
  let frank: CreatedUser;

  beforeAll(async () => {
    ctx = await rbacContext({ now: () => LICENSED });
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    bob = await createUser(ctx, { username: 'bob' });
    carol = await createUser(ctx, { username: 'carol' });
    dave = await createUser(ctx, { username: 'dave' });
    erin = await createUser(ctx, { username: 'erin' });
    frank = await createUser(ctx, { username: 'frank' });
    await addMember(ctx, org, bob.id, 'member');
    await addMember(ctx, org, carol.id, 'member');
    await addMember(ctx, org, dave.id, 'member');
    bobSession = await login(ctx, 'bob', bob.password);
    project = await createProject(ctx, admin, { organizationId: org, key: 'removal' });
    await grantProject(ctx, project.id, erin.id, 'member');
    await grantProject(ctx, project.id, frank.id, 'project_admin');
    const personal = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: admin.headers,
      payload: { name: 'leaked', scopes: ['read'] },
    });
    expect(personal.statusCode).toBe(201);
    personalTokenId = (personal.json() as { id: string }).id;
    await createProjectToken(ctx, admin, project.id);
    const [row] = (
      await ctx.db.execute<{ id: string }>(
        sql`SELECT id FROM api_tokens WHERE project_id = ${project.id}`,
      )
    ).rows;
    projectTokenId = row!.id;
    await ctx.db.transaction(async (tx) => {
      await tx.execute(sql`ALTER TABLE audit_events DISABLE TRIGGER audit_events_guard`);
      await tx.execute(sql`DELETE FROM audit_events`);
      await tx.execute(sql`ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard`);
    });
    await ctx.db.execute(sql`
      INSERT INTO instance_settings (key, value) VALUES ('audit-chain', '{"throughSeq":1}'::jsonb)`);
  });
  afterAll(async () => ctx.close());

  const events = async () =>
    (await ctx.db.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM audit_events`)).rows[0]!
      .n;
  const SKIP_MESSAGE = 'audit event skipped: the audit-chain anchor is malformed';
  /** The skip lines logged since `from`, parsed. */
  const skipped = (from: number) =>
    ctx.logs
      .slice(from)
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((l) => l.msg === SKIP_MESSAGE);

  /** Runs `change`, expects `status`, no event, and exactly one skip line naming the ids. */
  async function expectSkipped(
    change: () => Promise<{ statusCode: number; body: string }>,
    status: number,
    line: { action: string; actorId: string; targetId: string },
  ) {
    const from = ctx.logs.length;
    const res = await change();
    expect(res.statusCode, res.body).toBe(status);
    expect(await events()).toBe(0);
    const lines = skipped(from);
    expect(lines).toHaveLength(1);
    const [logged] = lines;
    expect(logged).toMatchObject({ level: 50, component: 'audit', ...line });
    // Ids only: no name, token, prefix or address.
    const { level, time, pid, hostname, msg, component, action, actorId, targetId, ...rest } =
      logged!;
    void [level, time, pid, hostname, msg, component, action, actorId, targetId];
    expect(rest).toEqual({});
  }

  it('signs out, deleting the session', async () => {
    await expectSkipped(
      () =>
        ctx.app.inject({ method: 'POST', url: '/api/v0/auth/logout', headers: bobSession.headers }),
      204,
      { action: 'auth.sign_out', actorId: bob.id, targetId: bob.id },
    );
    const me = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      headers: bobSession.headers,
    });
    expect(me.statusCode).toBe(401);
  });

  it('revokes a personal token', async () => {
    await expectSkipped(
      () =>
        ctx.app.inject({
          method: 'DELETE',
          url: `/api/v0/tokens/${personalTokenId}`,
          headers: admin.headers,
        }),
      204,
      { action: 'token.revoked', actorId: ctx.adminId, targetId: personalTokenId },
    );
  });

  it('revokes a project token', async () => {
    await expectSkipped(
      () =>
        ctx.app.inject({
          method: 'DELETE',
          url: `/api/v0/projects/${project.id}/tokens/${projectTokenId}`,
          headers: admin.headers,
        }),
      204,
      { action: 'project_token.revoked', actorId: ctx.adminId, targetId: projectTokenId },
    );
  });

  it('deactivates a user', async () => {
    await expectSkipped(
      () =>
        ctx.app.inject({
          method: 'PATCH',
          url: `/api/v0/users/${dave.id}`,
          headers: admin.headers,
          payload: { active: false },
        }),
      200,
      { action: 'user.updated', actorId: ctx.adminId, targetId: dave.id },
    );
  });

  it('removes an organization member', async () => {
    await expectSkipped(
      () =>
        ctx.app.inject({
          method: 'DELETE',
          url: `/api/v0/organizations/${org}/members/${carol.id}`,
          headers: admin.headers,
        }),
      204,
      { action: 'member.removed', actorId: ctx.adminId, targetId: carol.id },
    );
  });

  it('demotes an organization role', async () => {
    await expectSkipped(
      () =>
        ctx.app.inject({
          method: 'PUT',
          url: `/api/v0/organizations/${org}/members/${bob.id}`,
          headers: admin.headers,
          payload: { role: 'viewer' },
        }),
      200,
      { action: 'member.role_changed', actorId: ctx.adminId, targetId: bob.id },
    );
  });

  const grantUrl = (userId: string) => `/api/v0/projects/${project.id}/members/${userId}`;

  it('DELETE /projects/:id/members/:userId goes through a malformed anchor', async () => {
    await expectSkipped(
      () => ctx.app.inject({ method: 'DELETE', url: grantUrl(erin.id), headers: admin.headers }),
      204,
      { action: 'project_member.removed', actorId: ctx.adminId, targetId: erin.id },
    );
    const again = await ctx.app.inject({
      method: 'DELETE',
      url: grantUrl(erin.id),
      headers: admin.headers,
    });
    expect(again.statusCode).toBe(404);
  });

  it('demotes a project grant', async () => {
    await expectSkipped(
      () =>
        ctx.app.inject({
          method: 'PUT',
          url: grantUrl(frank.id),
          headers: admin.headers,
          payload: { role: 'viewer' },
        }),
      200,
      { action: 'project_member.role_changed', actorId: ctx.adminId, targetId: frank.id },
    );
  });

  it('still refuses every other audited change with 409, logging no skip', async () => {
    const from = ctx.logs.length;
    const refused = [
      {
        method: 'POST' as const,
        url: '/api/v0/quality-gates',
        payload: { organizationId: org, name: 'Refused' },
      },
      // A promotion.
      {
        method: 'PUT' as const,
        url: `/api/v0/organizations/${org}/members/${bob.id}`,
        payload: { role: 'member' },
      },
      // Reactivating, and a deactivation that changes something else too.
      { method: 'PATCH' as const, url: `/api/v0/users/${dave.id}`, payload: { active: true } },
      {
        method: 'PATCH' as const,
        url: `/api/v0/users/${erin.id}`,
        payload: { active: false, displayName: 'Erin' },
      },
      // A new member.
      {
        method: 'PUT' as const,
        url: `/api/v0/organizations/${org}/members/${carol.id}`,
        payload: { role: 'viewer' },
      },
      // A promotion of a project grant, and a new one.
      { method: 'PUT' as const, url: grantUrl(frank.id), payload: { role: 'member' } },
      { method: 'PUT' as const, url: grantUrl(erin.id), payload: { role: 'viewer' } },
    ];
    for (const r of refused) {
      const res = await ctx.app.inject({ ...r, headers: admin.headers });
      expect(res.statusCode, `${r.method} ${r.url} ${res.body}`).toBe(409);
      expect(res.json()).toMatchObject({ code: 'AUDIT_CHAIN_ANCHOR_MALFORMED' });
    }
    const roles = (
      await ctx.db.execute<{ user_id: string; role: string }>(
        sql`SELECT user_id, role FROM project_memberships WHERE project_id = ${project.id}`,
      )
    ).rows;
    expect(roles).toEqual([{ user_id: frank.id, role: 'viewer' }]);
    expect(await events()).toBe(0);
    expect(skipped(from)).toEqual([]);
    const [state] = (
      await ctx.db.execute<{ active: boolean; name: string | null }>(
        sql`SELECT active, display_name AS name FROM users WHERE id = ${erin.id}`,
      )
    ).rows;
    expect(state).toEqual({ active: true, name: null });
  });
});

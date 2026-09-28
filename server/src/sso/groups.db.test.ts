import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  createProject,
  createUser,
  login,
  organizationId,
  type TestContext,
} from '../../test/app';
import { adminHeaders, auditRows, oidcConnection, ssoContext } from '../../test/sso';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { createDatabase, type Database } from '../db/client';
import { memberships, organizations, projectMemberships } from '../db/schema';
import { setProjectGrant } from '../rbac/grants';
import {
  listMappings,
  MAX_MAPPINGS,
  replaceMappings,
  syncGroupMemberships,
  type SsoGroupMappingInput,
} from './groups';
import { createSsoService } from './service';

describe('group sync (sso-scim.md §9)', () => {
  let ctx: TestContext;
  let conn: string;
  let other: string;
  let org: string;
  let project: string;
  let userId: string;
  const audit = createAuditRecorder({ isActive: () => true, log: { error() {} } });
  const warnings: { obj: object; msg: string }[] = [];
  const log = { warn: (obj: object, msg: string) => void warnings.push({ obj, msg }) };
  const sync = (groups: readonly string[], connectionId = conn) =>
    ctx.db.transaction((tx) =>
      syncGroupMemberships(tx, {
        connectionId,
        userId,
        username: 'sam',
        groups,
        audit,
        log,
      }),
    );
  const roleIn = async (organization: string) =>
    (
      await ctx.db
        .select()
        .from(memberships)
        .where(and(eq(memberships.organizationId, organization), eq(memberships.userId, userId)))
    )[0];
  const orgRole = () => roleIn(org);
  const freshOrg = async (key: string) => {
    const [row] = await ctx.db
      .insert(organizations)
      .values({ key: `${key}-${Math.random().toString(36).slice(2, 8)}`, name: key })
      .returning();
    return row!.id;
  };
  const deps = () => ({ db: ctx.db, audit });

  beforeAll(async () => {
    ctx = await ssoContext({});
    conn = await oidcConnection(ctx, { groupSource: 'claims' });
    other = await oidcConnection(ctx, { name: 'Other', groupSource: 'claims' });
    org = await organizationId(ctx, 'default');
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    project = (await createProject(ctx, admin, { organizationId: org, key: 'grp/p' })).id;
    await replaceMappings(deps(), SYSTEM_ACTOR, conn, [
      { group: 'admins', organizationId: org, projectId: null, role: 'admin' },
      { group: 'devs', organizationId: org, projectId: null, role: 'member' },
      { group: 'readers', organizationId: org, projectId: project, role: 'viewer' },
      { group: '*', organizationId: org, projectId: null, role: 'viewer' },
    ]);
  });
  beforeEach(async () => {
    userId = (await createUser(ctx, { username: `sam-${Math.random().toString(36).slice(2, 8)}` }))
      .id;
    warnings.length = 0;
  });
  afterAll(async () => ctx.close());

  it('gives the strongest mapped role, managed by the connection', async () => {
    const r = await sync(['devs', 'admins']);
    expect(r).toMatchObject({ added: 1 });
    expect(await orgRole()).toMatchObject({ role: 'admin', managedByConnectionId: conn });
  });

  it('gives the * mapping to everyone, and changes a managed role when groups change', async () => {
    await sync([]);
    expect(await orgRole()).toMatchObject({ role: 'viewer' });
    await sync(['devs']);
    expect(await orgRole()).toMatchObject({ role: 'member' });
  });

  it('never touches a membership made by hand', async () => {
    await addMember(ctx, org, userId, 'member');
    await sync(['admins']);
    expect(await orgRole()).toMatchObject({ role: 'member', managedByConnectionId: null });
  });

  it('never touches a membership another connection manages', async () => {
    await ctx.db
      .insert(memberships)
      .values({ organizationId: org, userId, role: 'member', managedByConnectionId: other });
    await sync(['admins']);
    expect(await orgRole()).toMatchObject({ role: 'member', managedByConnectionId: other });
  });

  it('removes a managed membership when no mapping matches any more (the * mapping aside)', async () => {
    await replaceMappings(deps(), SYSTEM_ACTOR, other, [
      { group: 'x', organizationId: org, projectId: null, role: 'member' },
    ]);
    await sync(['x'], other);
    expect(await orgRole()).toMatchObject({ managedByConnectionId: other });
    await sync([], other);
    expect(await orgRole()).toBeUndefined();
  });

  it('sync applies mappings in every organisation, however many there are', async () => {
    // enterprise.md §8: no organisation is read-only after a lapse, so none is skipped.
    const many = await oidcConnection(ctx, { name: 'Many', groupSource: 'claims' });
    const orgs: string[] = [];
    for (let i = 0; i < 5; i++) orgs.push(await freshOrg(`many-${i}`));
    await replaceMappings(
      deps(),
      SYSTEM_ACTOR,
      many,
      orgs.map((o) => ({ group: 'many', organizationId: o, projectId: null, role: 'member' })),
    );
    const r = await sync(['many'], many);
    expect(r.added).toBe(5);
    expect(r.skipped).toBe(0);
    for (const o of orgs) {
      expect(await roleIn(o)).toMatchObject({ role: 'member', managedByConnectionId: many });
    }
  });

  it('keeps the last admin of an organisation', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: await adminHeaders(ctx),
      payload: { key: `lastadm-${Date.now()}`, name: 'L' },
    });
    const lastOrg = res.json().id as string;
    await ctx.db.delete(memberships).where(eq(memberships.organizationId, lastOrg));
    await ctx.db
      .insert(memberships)
      .values({ organizationId: lastOrg, userId, role: 'admin', managedByConnectionId: conn });
    const r = await sync([]);
    expect(r.keptLastAdmin).toBe(1);
    const [row] = await ctx.db
      .select()
      .from(memberships)
      .where(and(eq(memberships.organizationId, lastOrg), eq(memberships.userId, userId)));
    expect(row).toMatchObject({ role: 'admin' });
    expect(warnings).toMatchObject([
      { msg: 'sync kept the last admin', obj: { organizationId: lastOrg, connectionId: conn } },
    ]);
  });

  it('refuses more than 1 000 group values (a cut would drop access at random)', async () => {
    await expect(sync(Array.from({ length: 1_001 }, (_, i) => `g${i}`))).rejects.toThrow(
      /groups\.too_many/,
    );
  });

  describe('beyond the brief', () => {
    let third: string;
    let lastOrg: string;

    beforeAll(async () => {
      third = await oidcConnection(ctx, { name: 'Third', groupSource: 'claims' });
      lastOrg = await freshOrg('demote');
      await replaceMappings(deps(), SYSTEM_ACTOR, third, [
        { group: 'm', organizationId: lastOrg, projectId: null, role: 'member' },
        { group: 'Admins', organizationId: org, projectId: null, role: 'admin' },
      ]);
    });

    it('keeps the last admin on a demotion too, logs it, and demotes once another admin exists', async () => {
      await ctx.db
        .insert(memberships)
        .values({ organizationId: lastOrg, userId, role: 'admin', managedByConnectionId: third });
      const kept = await sync(['m'], third);
      expect(kept).toMatchObject({ keptLastAdmin: 1, changed: 0 });
      expect(await roleIn(lastOrg)).toMatchObject({ role: 'admin' });
      expect(warnings).toMatchObject([
        {
          msg: 'sync kept the last admin',
          obj: { component: 'sso', connectionId: third, organizationId: lastOrg },
        },
      ]);

      const helper = await createUser(ctx, { username: `helper-${Date.now()}` });
      await addMember(ctx, lastOrg, helper.id, 'admin');
      const demoted = await sync(['m'], third);
      expect(demoted).toMatchObject({ keptLastAdmin: 0, changed: 1 });
      expect(await roleIn(lastOrg)).toMatchObject({ role: 'member', managedByConnectionId: third });
      const events = (await auditRows(ctx)).filter(
        (e) => e.action === 'member.role_changed' && e.targetId === userId,
      );
      expect(events.at(-1)).toMatchObject({
        actorType: 'system',
        organizationId: lastOrg,
        details: { from: 'admin', to: 'member', managedBy: third },
      });
    });

    it('records additions and removals as the system with managedBy', async () => {
      await sync(['devs']);
      await ctx.db.delete(memberships).where(eq(memberships.userId, userId));
      await ctx.db
        .insert(memberships)
        .values({ organizationId: lastOrg, userId, role: 'member', managedByConnectionId: conn });
      await sync(['devs']);
      const mine = (await auditRows(ctx)).filter((e) => e.targetId === userId);
      expect(mine.map((e) => [e.action, e.actorType, e.details])).toEqual([
        ['member.added', 'system', { role: 'member', managedBy: conn }],
        ['member.added', 'system', { role: 'member', managedBy: conn }],
        ['member.removed', 'system', { role: 'member', managedBy: conn }],
      ]);
    });

    it('matches exactly: case, look-alike letters, duplicates, and values that can never match are ignored', async () => {
      const nul = String.fromCharCode(0);
      const lone = String.fromCharCode(0xd800);
      const cyrillicA = String.fromCharCode(0x0410);
      const hostile = [
        'admins', // conn's mapping, not third's
        'ADMINS',
        'admins',
        `${cyrillicA}dmins`,
        `Admins${nul}`,
        `Admins${lone}`,
        'x'.repeat(256),
        '',
        ...Array.from({ length: 900 }, () => 'm'),
      ];
      const r = await sync(hostile, third);
      // Only `m` matched (lastOrg, member); `Admins` never did: case and look-alikes differ.
      expect(r).toMatchObject({ added: 1, changed: 0, removed: 0 });
      expect(await roleIn(lastOrg)).toMatchObject({ role: 'member', managedByConnectionId: third });
      expect(await orgRole()).toBeUndefined();
      await sync(['Admins'], third);
      expect(await orgRole()).toMatchObject({ role: 'admin', managedByConnectionId: third });
    });

    it('removes a managed project grant when its mapping no longer matches', async () => {
      await sync(['readers']);
      await sync([]);
      expect(
        await ctx.db.select().from(projectMemberships).where(eq(projectMemberships.userId, userId)),
      ).toEqual([]);
    });

    it('lets a hand change take a managed project grant over (§9.3)', async () => {
      await sync(['readers']);
      await setProjectGrant(ctx.db, project, userId, 'project_admin');
      await sync(['readers']);
      expect(
        await ctx.db.select().from(projectMemberships).where(eq(projectMemberships.userId, userId)),
      ).toMatchObject([{ role: 'project_admin', managedByConnectionId: null }]);
      await sync([]);
      expect(
        await ctx.db.select().from(projectMemberships).where(eq(projectMemberships.userId, userId)),
      ).toMatchObject([{ role: 'project_admin', managedByConnectionId: null }]);
    });
  });
});

describe('group mappings under a licence listing only sso (sso-scim.md §9, rbac-audit.md §1.3)', () => {
  let ctx: TestContext;
  let conn: string;
  let org: string;
  let mapped: string;
  let byHand: string;
  let userId: string;
  const audit = createAuditRecorder({ isActive: () => true, log: { error() {} } });
  const log = { warn() {} };
  const sync = (groups: readonly string[]) =>
    ctx.db.transaction((tx) =>
      syncGroupMemberships(tx, { connectionId: conn, userId, username: 'sam', groups, audit, log }),
    );
  const grants = () =>
    ctx.db
      .select({
        projectId: projectMemberships.projectId,
        role: projectMemberships.role,
        managedByConnectionId: projectMemberships.managedByConnectionId,
      })
      .from(projectMemberships)
      .where(eq(projectMemberships.userId, userId));

  beforeAll(async () => {
    ctx = await ssoContext({ features: ['sso'] });
    conn = await oidcConnection(ctx, { groupSource: 'claims' });
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = (
      await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: admin.headers,
        payload: { key: 'sso-only', name: 'SSO only' },
      })
    ).json().id as string;
    const second = (
      await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: admin.headers,
        payload: { key: 'sso-only-2', name: 'SSO only 2' },
      })
    ).json().id as string;
    mapped = (await createProject(ctx, admin, { organizationId: org, key: 'sso/mapped' })).id;
    byHand = (await createProject(ctx, admin, { organizationId: org, key: 'sso/hand' })).id;
    // Through the service, as the plugin's PUT calls it: the licence lists sso and nothing else.
    expect(ctx.edition?.isFeatureActive('sso')).toBe(true);
    const service = createSsoService({
      db: ctx.db,
      config: ctx.config,
      edition: () => ctx.edition!,
      audit,
      log: ctx.app.log,
    });
    const views = await service.replaceMappings(SYSTEM_ACTOR, conn, [
      { group: 'readers', organizationId: org, projectId: null, role: 'viewer' },
      { group: 'leads', organizationId: second, projectId: null, role: 'project_admin' },
      { group: 'contractors', organizationId: org, projectId: mapped, role: 'viewer' },
    ]);
    expect(views).toHaveLength(3);
  });
  beforeEach(async () => {
    userId = (await createUser(ctx, { username: `sam-${Math.random().toString(36).slice(2, 8)}` }))
      .id;
  });
  afterAll(async () => ctx.close());

  it('mappings to every role and to projects apply with sso alone', async () => {
    const r = await sync(['readers', 'leads', 'contractors']);
    expect(r).toMatchObject({ added: 3, changed: 0, removed: 0, skipped: 0 });
    const orgs = await ctx.db
      .select({ organizationId: memberships.organizationId, role: memberships.role })
      .from(memberships)
      .where(and(eq(memberships.userId, userId), eq(memberships.managedByConnectionId, conn)));
    expect(orgs.map((m) => m.role).sort()).toEqual(['project_admin', 'viewer']);
    expect(await grants()).toEqual([
      { projectId: mapped, role: 'viewer', managedByConnectionId: conn },
    ]);
  });

  it('removes managed project grants no longer mapped', async () => {
    await sync(['contractors']);
    await setProjectGrant(ctx.db, byHand, userId, 'member');
    const r = await sync([]);
    expect(r).toMatchObject({ removed: 1, skipped: 0 });
    expect(await grants()).toEqual([
      { projectId: byHand, role: 'member', managedByConnectionId: null },
    ]);
  });
});

describe('replaceMappings and listMappings (sso-scim.md §9.2)', () => {
  let ctx: TestContext;
  let conn: string;
  let org: string;
  let otherOrg: string;
  let project: string;
  let foreignProject: string;
  const audit = createAuditRecorder({ isActive: () => true, log: { error() {} } });
  const replace = (input: SsoGroupMappingInput[], id = conn) =>
    replaceMappings({ db: ctx.db, audit }, SYSTEM_ACTOR, id, input);

  beforeAll(async () => {
    ctx = await ssoContext({});
    conn = await oidcConnection(ctx, { groupSource: 'claims' });
    org = await organizationId(ctx, 'default');
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: admin.headers,
      payload: { key: 'zz-other', name: 'Other' },
    });
    otherOrg = created.json().id as string;
    project = (await createProject(ctx, admin, { organizationId: org, key: 'map/p' })).id;
    foreignProject = (await createProject(ctx, admin, { organizationId: otherOrg, key: 'map/q' }))
      .id;
  });
  afterAll(async () => ctx.close());

  it('replaces the list, lists it by group then organisation key, and records the counts', async () => {
    await replace([{ group: 'a', organizationId: org, projectId: null, role: 'member' }]);
    const views = await replace([
      { group: 'b', organizationId: otherOrg, projectId: null, role: 'admin' },
      { group: 'b', organizationId: org, projectId: null, role: 'viewer' },
      { group: 'a', organizationId: org, projectId: project, role: 'project_admin' },
    ]);
    expect(views.map((v) => [v.group, v.organizationKey, v.projectKey, v.role])).toEqual([
      ['a', 'default', 'map/p', 'project_admin'],
      ['b', 'default', null, 'viewer'],
      ['b', 'zz-other', null, 'admin'],
    ]);
    expect(await listMappings(ctx.db, conn)).toEqual(views);
    const events = (await auditRows(ctx)).filter((e) => e.action === 'sso.group_mappings_replaced');
    expect(events.at(-1)).toMatchObject({
      actorType: 'system',
      targetType: 'sso_connection',
      targetId: conn,
      details: { count: 3, added: 3, removed: 1 },
    });
  });

  it('refuses a project of another organisation and a project-level admin (422)', async () => {
    await expect(
      replace([{ group: 'a', organizationId: org, projectId: foreignProject, role: 'member' }]),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.0.projectId' }] });
    await expect(
      replace([
        { group: 'a', organizationId: org, projectId: null, role: 'member' },
        { group: 'a', organizationId: org, projectId: project, role: 'admin' },
      ]),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.1.role' }] });
  });

  it('refuses bad groups, duplicates, unknown organisations and more than 500 mappings', async () => {
    const ctl = String.fromCharCode(7);
    const lone = String.fromCharCode(0xdc00);
    for (const group of ['', 'x'.repeat(256), `a${ctl}b`, `a${lone}`]) {
      await expect(
        replace([{ group, organizationId: org, projectId: null, role: 'member' }]),
      ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.0.group' }] });
    }
    await expect(
      replace([
        { group: 'd', organizationId: org, projectId: null, role: 'member' },
        { group: 'd', organizationId: org, projectId: null, role: 'admin' },
      ]),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.1.group' }] });
    await expect(
      replace([
        {
          group: 'd',
          organizationId: '00000000-0000-7000-8000-000000000000',
          projectId: null,
          role: 'member',
        },
      ]),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.0.organizationId' }] });
    await expect(
      replace([{ group: 'd', organizationId: 'not-a-uuid', projectId: null, role: 'member' }]),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.0.organizationId' }] });
    await expect(
      replace(
        Array.from({ length: MAX_MAPPINGS + 1 }, (_, i) => ({
          group: `g${i}`,
          organizationId: org,
          projectId: null,
          role: 'member' as const,
        })),
      ),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body' }] });
  });

  it('allows 500 mappings, and the same group in another case as a separate one', async () => {
    const input = Array.from({ length: MAX_MAPPINGS }, (_, i) => ({
      group: i === 1 ? 'G0' : `g${i}`,
      organizationId: org,
      projectId: null,
      role: 'member' as const,
    }));
    expect(await replace(input)).toHaveLength(MAX_MAPPINGS);
  });

  it('answers 404 for an unknown connection', async () => {
    await expect(replace([], '00000000-0000-7000-8000-000000000000')).rejects.toMatchObject({
      status: 404,
    });
  });
});

describe('a sync demotion racing a hand demotion of the other admin (rbac-audit.md §16)', () => {
  let ctx: TestContext;
  let conn: string;
  let raceOrg: string;
  let userId: string;
  let other: string;
  let headers: Record<string, string>;
  const audit = createAuditRecorder({ isActive: () => true, log: { error() {} } });
  const log = { warn() {} };
  const admins = async () =>
    (
      await ctx.db
        .select()
        .from(memberships)
        .where(and(eq(memberships.organizationId, raceOrg), eq(memberships.role, 'admin')))
    ).length;
  const waiting = async () => {
    const [row] = (
      await ctx.db.execute<{ n: number }>(
        sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`,
      )
    ).rows;
    return row!.n;
  };
  /** Until `n` backends of this database wait on a lock (or `done` says the waiter finished). */
  const until = async (n: number, done: () => boolean = () => false) => {
    for (let i = 0; i < 1_000 && !done() && (await waiting()) < n; i += 1) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(done()).toBe(false);
    expect(await waiting()).toBeGreaterThanOrEqual(n);
  };
  const demoteOther = () =>
    ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/organizations/${raceOrg}/members/${other}`,
      headers,
      payload: { role: 'member' },
    });
  const syncOn = (db: Database['db']) =>
    db.transaction((tx) =>
      syncGroupMemberships(tx, {
        connectionId: conn,
        userId,
        username: 'sam',
        groups: ['m'],
        audit,
        log,
      }),
    );

  beforeAll(async () => {
    ctx = await ssoContext({});
    conn = await oidcConnection(ctx, { groupSource: 'claims' });
    headers = await adminHeaders(ctx);
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers,
      payload: { key: 'race', name: 'Race' },
    });
    raceOrg = created.json().id as string;
    await replaceMappings({ db: ctx.db, audit }, SYSTEM_ACTOR, conn, [
      { group: 'm', organizationId: raceOrg, projectId: null, role: 'member' },
    ]);
  });
  beforeEach(async () => {
    const suffix = Math.random().toString(36).slice(2, 8);
    userId = (await createUser(ctx, { username: `synced-${suffix}` })).id;
    other = (await createUser(ctx, { username: `by-hand-${suffix}` })).id;
    await ctx.db.delete(memberships).where(eq(memberships.organizationId, raceOrg));
    await ctx.db.insert(memberships).values([
      { organizationId: raceOrg, userId, role: 'admin', managedByConnectionId: conn },
      { organizationId: raceOrg, userId: other, role: 'admin' },
    ]);
  });
  afterAll(async () => ctx.close());

  it('the sync first: the hand demotion then answers LAST_ADMIN', async () => {
    const pool = createDatabase(ctx.database.url, { max: 1 });
    try {
      let put: Awaited<ReturnType<typeof demoteOther>> | undefined;
      let putting: Promise<unknown> | undefined;
      const r = await pool.db.transaction(async (tx) => {
        const res = await syncGroupMemberships(tx, {
          connectionId: conn,
          userId,
          username: 'sam',
          groups: ['m'],
          audit,
          log,
        });
        putting = demoteOther().then((p) => (put = p));
        // The hand demotion waits for the organisation lock the sync holds until commit.
        await until(1, () => put !== undefined);
        return res;
      });
      await putting;
      expect(r).toMatchObject({ changed: 1, keptLastAdmin: 0 });
      expect(put?.statusCode).toBe(409);
      expect(put?.json()).toMatchObject({ code: 'LAST_ADMIN' });
      expect(await admins()).toBe(1);
    } finally {
      await pool.close();
    }
  });

  it('both waiting on the organisation: exactly one admin remains, whichever wins', async () => {
    const holder = createDatabase(ctx.database.url, { max: 1 });
    const pool = createDatabase(ctx.database.url, { max: 1 });
    try {
      let put: Promise<Awaited<ReturnType<typeof demoteOther>>> | undefined;
      let synced: Promise<Awaited<ReturnType<typeof syncOn>>> | undefined;
      let putDone = false;
      let syncDone = false;
      await holder.db.transaction(async (tx) => {
        await tx
          .select({ id: organizations.id })
          .from(organizations)
          .where(eq(organizations.id, raceOrg))
          .for('no key update');
        put = demoteOther().finally(() => (putDone = true));
        await until(1, () => putDone);
        synced = syncOn(pool.db).finally(() => (syncDone = true));
        await until(2, () => syncDone);
      });
      const [p, r] = await Promise.all([put!, synced!]);
      expect(await admins()).toBe(1);
      if (p.statusCode === 200) expect(r).toMatchObject({ keptLastAdmin: 1, changed: 0 });
      else {
        expect(p.json()).toMatchObject({ code: 'LAST_ADMIN' });
        expect(r).toMatchObject({ keptLastAdmin: 0, changed: 1 });
      }
    } finally {
      await holder.close();
      await pool.close();
    }
  });
});

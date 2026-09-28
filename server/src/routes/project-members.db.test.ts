import { randomUUID } from 'node:crypto';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { fillProjectGrants, grantProject } from '../../test/rbac';
import { gzipJson, REPORT_CONTENT_TYPE, sampleReport } from '../../test/reports';
import { projectMemberships } from '../db/schema';
import { PROJECT_GRANT_LIMIT } from '../rbac/grants';
import { communityLimits } from '../limits';

type Method = 'GET' | 'PUT' | 'DELETE';
type Grant = {
  userId: string;
  username: string;
  displayName: string | null;
  role: string;
  createdAt: string;
};

/**
 * rbac-audit.md §16: the project grant routes are core routes, in every edition. This suite runs
 * on a community server (no licence, no plugin), so it also shows that nothing about them needs a
 * licence, and that they record nothing without `audit-log` (§8.1).
 */
describe('project grants in core (rbac-audit.md §16)', () => {
  let ctx: TestContext;
  let root: Session;
  let org: string;
  let p1: { id: string; key: string };
  let p2: { id: string; key: string };
  let full: { id: string; key: string };
  const s: Record<string, Session> = {};
  const ids: Record<string, string> = {};
  const tokens: Record<string, Record<string, string>> = {};

  async function personalToken(session: Session, scopes: string[]) {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: session.headers,
      payload: { name: scopes.join('-'), scopes },
    });
    if (res.statusCode !== 201) throw new Error(`token: ${res.statusCode} ${res.body}`);
    return bearer((res.json() as { token: string }).token);
  }

  const call = (
    headers: Record<string, string>,
    method: Method,
    url: string,
    payload?: Record<string, unknown>,
  ) =>
    ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const grantUrl = (projectId: string, userId: string) =>
    `/projects/${projectId}/members/${userId}`;
  const put = (who: string, projectId: string, userId: string, role: string) =>
    call(s[who]!.headers, 'PUT', grantUrl(projectId, userId), { role });

  beforeAll(async () => {
    ctx = await createTestContext({ limits: communityLimits() });
    root = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    p1 = await createProject(ctx, root, { organizationId: org, key: 'pm-one' });
    p2 = await createProject(ctx, root, { organizationId: org, key: 'pm-two' });
    full = await createProject(ctx, root, { organizationId: org, key: 'pm-full' });
    const roles = {
      orgadmin: 'admin',
      padmin: 'project_admin',
      maintainer: 'member',
      viewer: 'viewer',
      contractor: null,
      granted: null,
      outsider: null,
      gina: null,
      hal: null,
      synced: null,
    } as const;
    for (const [name, role] of Object.entries(roles)) {
      const u = await createUser(ctx, { username: name });
      ids[name] = u.id;
      if (role) await addMember(ctx, org, u.id, role);
      s[name] = await login(ctx, u.username, u.password);
    }
    ids.gone = (await createUser(ctx, { username: 'gone', active: false })).id;
    // A project admin by grant: it administers the project, but manages no grants.
    await grantProject(ctx, p1.id, ids.granted!, 'project_admin');
    tokens.orgadminWrite = await personalToken(s.orgadmin!, ['write']);
    tokens.orgadminAdmin = await personalToken(s.orgadmin!, ['admin']);
    tokens.project = bearer(await createProjectToken(ctx, root, p1.id));
  });
  afterAll(async () => ctx.close());

  it('a community grant makes the project, and only it, visible', async () => {
    const res = await put('orgadmin', p1.id, ids.contractor!, 'member');
    expect(res.statusCode, res.body).toBe(200);
    const grant = res.json() as Grant;
    expect(grant).toEqual({
      userId: ids.contractor,
      username: 'contractor',
      displayName: null,
      role: 'member',
      createdAt: expect.any(String),
    });

    const contractor = s.contractor!.headers;
    const projects = await call(contractor, 'GET', '/projects');
    expect(projects.statusCode).toBe(200);
    expect((projects.json() as { items: { key: string }[] }).items.map((p) => p.key)).toEqual([
      'pm-one',
    ]);
    const orgs = await call(contractor, 'GET', '/organizations');
    expect((orgs.json() as { items: { id: string }[] }).items.map((o) => o.id)).toEqual([org]);
    expect((await call(contractor, 'GET', `/quality-gates?organizationId=${org}`)).statusCode).toBe(
      200,
    );
    const upload = await ctx.app.inject({
      method: 'POST',
      url: `/api/v0/analyses?projectKey=${p1.key}`,
      headers: {
        ...(await personalToken(s.contractor!, ['analysis:write'])),
        'content-type': REPORT_CONTENT_TYPE,
        'content-encoding': 'gzip',
      },
      payload: gzipJson(sampleReport({ projectKey: p1.key })),
    });
    expect(upload.statusCode, upload.body).toBe(202);
    const other = await call(contractor, 'GET', `/projects/${p2.id}`);
    expect([other.statusCode, other.json().code]).toEqual([404, 'NOT_FOUND']);
  });

  it('lets an organisation admin with an admin-scoped token manage grants', async () => {
    const res = await call(tokens.orgadminAdmin!, 'PUT', grantUrl(p2.id, ids.hal!), {
      role: 'viewer',
    });
    expect([res.statusCode, res.json().role]).toEqual([200, 'viewer']);
    expect(
      (await call(tokens.orgadminAdmin!, 'DELETE', grantUrl(p2.id, ids.hal!))).statusCode,
    ).toBe(204);
  });

  it('lists, changes and removes grants', async () => {
    expect((await put('orgadmin', p1.id, ids.gina!, 'member')).statusCode).toBe(200);
    expect((await put('orgadmin', p1.id, ids.hal!, 'project_admin')).statusCode).toBe(200);

    const seen: Grant[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const query: string = cursor === null ? '' : `&cursor=${encodeURIComponent(cursor)}`;
      const page = await call(
        s.orgadmin!.headers,
        'GET',
        `/projects/${p1.id}/members?limit=1${query}`,
      );
      expect(page.statusCode, page.body).toBe(200);
      const body = page.json() as { items: Grant[]; nextCursor: string | null };
      expect(body.items).toHaveLength(1);
      seen.push(...body.items);
      cursor = body.nextCursor;
      pages += 1;
    } while (cursor !== null && pages < 10);
    // The grant-only project admin, the contractor, gina and hal, ordered by user id.
    const expected = ['granted', 'contractor', 'gina', 'hal'].map((n) => ids[n]!).sort();
    expect(seen.map((g) => g.userId)).toEqual(expected);
    expect(seen.find((g) => g.userId === ids.gina)).toMatchObject({
      username: 'gina',
      role: 'member',
    });

    const changed = await put('orgadmin', p1.id, ids.gina!, 'viewer');
    expect([changed.statusCode, changed.json().role]).toEqual([200, 'viewer']);
    const [row] = await ctx.db
      .select({ role: projectMemberships.role })
      .from(projectMemberships)
      .where(
        and(eq(projectMemberships.projectId, p1.id), eq(projectMemberships.userId, ids.gina!)),
      );
    expect(row).toEqual({ role: 'viewer' });

    const removed = await call(s.orgadmin!.headers, 'DELETE', grantUrl(p1.id, ids.gina!));
    expect(removed.statusCode).toBe(204);
    const again = await call(s.orgadmin!.headers, 'DELETE', grantUrl(p1.id, ids.gina!));
    expect([again.statusCode, again.json().code]).toEqual([404, 'NOT_FOUND']);
    // A grant elsewhere is not this project's: removing it through p1 is 404 too.
    await grantProject(ctx, p2.id, ids.gina!, 'viewer');
    const elsewhere = await call(s.orgadmin!.headers, 'DELETE', grantUrl(p1.id, ids.gina!));
    expect(elsewhere.statusCode).toBe(404);
  });

  it("answers in §3.3's order", async () => {
    const cases: [string, Record<string, string>, number, string][] = [
      ['an outsider', s.outsider!.headers, 404, 'NOT_FOUND'],
      ['a maintainer', s.maintainer!.headers, 403, 'FORBIDDEN'],
      ['a viewer', s.viewer!.headers, 403, 'FORBIDDEN'],
      ['an organisation project admin', s.padmin!.headers, 403, 'FORBIDDEN'],
      ['a project admin by grant', s.granted!.headers, 403, 'FORBIDDEN'],
      ['an org admin with a write token', tokens.orgadminWrite!, 403, 'INSUFFICIENT_SCOPE'],
      ['a project token', tokens.project!, 403, 'TOKEN_NOT_ALLOWED'],
    ];
    const before = await ctx.db.select().from(projectMemberships);
    for (const [who, headers, status, code] of cases) {
      for (const [method, url, payload] of [
        ['PUT', grantUrl(p1.id, ids.hal!), { role: 'viewer' }],
        ['DELETE', grantUrl(p1.id, ids.hal!), undefined],
      ] as const) {
        const res = await call(headers, method, url, payload);
        expect([res.statusCode, res.json().code], `${who} ${method}`).toEqual([status, code]);
      }
    }
    // The read: org.members.read, which only organisation admins hold.
    for (const [who, headers, status, code] of cases) {
      const res = await call(headers, 'GET', `/projects/${p1.id}/members`);
      expect([res.statusCode, res.json().code], `${who} GET`).toEqual([status, code]);
    }
    expect(await ctx.db.select().from(projectMemberships)).toEqual(before);
    // An unknown project is 404 to an organisation admin too.
    const unknown = await put('orgadmin', randomUUID(), ids.hal!, 'viewer');
    expect([unknown.statusCode, unknown.json().code]).toEqual([404, 'NOT_FOUND']);
  });

  it('refuses admin and unknown roles', async () => {
    for (const role of ['admin', 'owner', '']) {
      const res = await put('orgadmin', p1.id, ids.hal!, role);
      expect(res.statusCode, role).toBe(422);
      expect((res.json() as { errors: { path: string }[] }).errors.map((e) => e.path)).toEqual([
        'body.role',
      ]);
    }
    const [row] = await ctx.db
      .select({ role: projectMemberships.role })
      .from(projectMemberships)
      .where(and(eq(projectMemberships.projectId, p1.id), eq(projectMemberships.userId, ids.hal!)));
    expect(row).toEqual({ role: 'project_admin' });
  });

  it('404 for an unknown or inactive user', async () => {
    for (const userId of [ids.gone!, randomUUID()]) {
      const res = await put('orgadmin', p2.id, userId, 'viewer');
      expect([res.statusCode, res.json().code]).toEqual([404, 'NOT_FOUND']);
    }
    const rows = await ctx.db
      .select()
      .from(projectMemberships)
      .where(eq(projectMemberships.userId, ids.gone!));
    expect(rows).toEqual([]);
  });

  it(`409 PROJECT_GRANT_LIMIT_REACHED beyond ${PROJECT_GRANT_LIMIT}`, async () => {
    await fillProjectGrants(ctx, full.id, PROJECT_GRANT_LIMIT);
    const res = await put('orgadmin', full.id, ids.hal!, 'viewer');
    expect([res.statusCode, res.json().code]).toEqual([409, 'PROJECT_GRANT_LIMIT_REACHED']);
    // An existing grant still changes at the bound.
    const bulk = await ctx.db.execute<{ id: string }>(
      sql`SELECT id FROM users WHERE username = 'bulk-1'`,
    );
    const changed = await put('orgadmin', full.id, bulk.rows[0]!.id, 'member');
    expect([changed.statusCode, changed.json().role]).toEqual([200, 'member']);
  });

  it('takes a grant made by group sync over', async () => {
    const connection = randomUUID();
    await ctx.db.execute(
      sql`INSERT INTO sso_connections (id, name, protocol, config) VALUES (${connection}, 'Sync', 'saml', '{}')`,
    );
    await ctx.db.insert(projectMemberships).values({
      projectId: p2.id,
      userId: ids.synced!,
      role: 'viewer',
      managedByConnectionId: connection,
    });
    const res = await put('orgadmin', p2.id, ids.synced!, 'viewer');
    expect([res.statusCode, res.json().role]).toEqual([200, 'viewer']);
    const [row] = await ctx.db
      .select({ role: projectMemberships.role, managed: projectMemberships.managedByConnectionId })
      .from(projectMemberships)
      .where(
        and(eq(projectMemberships.projectId, p2.id), eq(projectMemberships.userId, ids.synced!)),
      );
    expect(row).toEqual({ role: 'viewer', managed: null });
  });

  it('the removed /ee/rbac paths answer 404', async () => {
    const base = `/ee/rbac/projects/${p1.id}/members`;
    for (const [method, url, payload] of [
      ['GET', base, undefined],
      ['PUT', `${base}/${ids.hal!}`, { role: 'viewer' }],
      ['DELETE', `${base}/${ids.hal!}`, undefined],
    ] as const) {
      const res = await call(s.orgadmin!.headers, method, url, payload);
      expect(res.statusCode, `${method} ${url}`).toBe(404);
    }
  });

  it('writes no audit event without audit-log', async () => {
    const counts = await ctx.db.execute<{ n: number }>(
      sql`SELECT count(*)::int AS n FROM audit_events`,
    );
    expect(counts.rows[0]).toEqual({ n: 0 });
  });
});

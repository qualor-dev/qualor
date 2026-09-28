import { and, eq, sql } from 'drizzle-orm';
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createUser, type TestContext } from '../../test/app';
import { ENTERPRISE_FEATURES } from '../../test/license';
import {
  activeSessions,
  auditRows,
  givePersonalToken,
  giveSession,
  linkScimIdentityToAdmin,
  licensedEdition,
  liveTokens,
  ONE_CONNECTION_FEATURES,
  oidcConnection,
  scimApp,
  scimDeps,
  ssoContext,
  userActive,
  userIdOfIdentity,
} from '../../test/sso';
import { SYSTEM_ACTOR } from '../audit/recorder';
import { identities, users } from '../db/schema';
import { inEffectConnectionIds } from '../sso/connections';
import { updateSignInSettings } from '../sso/sign-in-policy';
import { handleScim } from './handle';
import { createScimToken } from './tokens';

/** Inside the test licence's validity (issued 2026-10-01). */
const LICENSED = () => new Date('2027-01-01T00:00:00Z');
const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

type Scim = (
  method: string,
  path: string,
  body?: unknown,
  auth?: string | null,
) => Promise<LightMyRequestResponse>;

function client(app: FastifyInstance, token: string): Scim {
  return (method, path, body, auth = `Bearer ${token}`) =>
    app.inject({
      method: method as never,
      url: `/scim/v2${path}`,
      headers: {
        ...(auth === null ? {} : { authorization: auth }),
        'content-type': 'application/scim+json',
      },
      ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
    });
}

async function tokenFor(ctx: TestContext, connectionId: string): Promise<string> {
  return (
    await createScimToken(scimDeps(ctx), SYSTEM_ACTOR, {
      connectionId,
      name: `t-${Math.random().toString(36).slice(2, 8)}`,
      expiresAt: null,
    })
  ).token;
}

const deactivate = {
  schemas: [PATCH],
  Operations: [{ op: 'replace', path: 'active', value: false }],
};

describe('SCIM Users (sso-scim.md §12.4–§12.6)', () => {
  let ctx: TestContext;
  let conn: string;
  let linking: string;
  let app: FastifyInstance;
  let scim: Scim;
  let scimLinking: Scim;
  const newUser = async (userName: string, extra: Record<string, unknown> = {}, as = scim) => {
    const res = await as('POST', '/Users', { schemas: [USER], userName, ...extra });
    expect(res.statusCode, res.body).toBe(201);
    return res.json().id as string;
  };

  beforeAll(async () => {
    ctx = await ssoContext({ now: LICENSED });
    conn = await oidcConnection(ctx, { groupSource: 'scim' });
    linking = await oidcConnection(ctx, { name: 'Linking', linkByEmail: true });
    app = scimApp(ctx);
    await app.ready();
    scim = client(app, await tokenFor(ctx, conn));
    scimLinking = client(app, await tokenFor(ctx, linking));
  });
  afterAll(async () => {
    await app.close();
    await ctx.close();
  });

  it('creates a user without a password, the username from userName’s local part, and records scim.user_created', async () => {
    const id = await newUser('Kim.Lee@acme.example', {
      name: { givenName: 'Kim', familyName: 'Lee' },
      emails: [{ value: 'kim@acme.example', type: 'work' }],
    });
    const [row] = await ctx.db
      .select({ user: users, identity: identities })
      .from(identities)
      .innerJoin(users, eq(users.id, identities.userId))
      .where(eq(identities.id, id));
    expect(row?.user).toMatchObject({
      username: 'Kim.Lee',
      passwordHash: null,
      isInstanceAdmin: false,
      email: 'kim@acme.example',
      displayName: 'Kim Lee',
      active: true,
    });
    expect(row?.identity).toMatchObject({ subject: null, linkedBy: 'scim', connectionId: conn });
    const events = (await auditRows(ctx)).filter((e) => e.action === 'scim.user_created');
    expect(events.at(-1)).toMatchObject({
      actorType: 'system',
      targetId: row?.user.id,
      details: { connectionId: conn, linkedExisting: false },
    });
  });

  it('refuses a taken externalId on create and on PATCH (409 uniqueness)', async () => {
    await newUser('ext1@acme.example', { externalId: 'oid-1' });
    const other = await newUser('ext2@acme.example', { externalId: 'oid-2' });
    expect(
      (
        await scim('POST', '/Users', {
          schemas: [USER],
          userName: 'ext3@acme.example',
          externalId: 'oid-1',
        })
      ).json(),
    ).toMatchObject({ status: '409', scimType: 'uniqueness' });
    const res = await scim('PATCH', `/Users/${other}`, {
      schemas: [PATCH],
      Operations: [{ op: 'replace', path: 'externalId', value: 'oid-1' }],
    });
    expect(res.statusCode).toBe(409);
    expect(res.headers['content-type']).toBe('application/scim+json; charset=utf-8');
    expect(res.json()).toMatchObject({ scimType: 'uniqueness' });
  });

  it('refuses an email another account has, on create and on PATCH', async () => {
    await createUser(ctx, { username: 'owner1', email: 'owner1@acme.example' });
    const res = await scim('POST', '/Users', {
      schemas: [USER],
      userName: 'x1@acme.example',
      emails: [{ value: 'OWNER1@acme.example', primary: true }],
    });
    expect(res.json()).toMatchObject({
      status: '409',
      scimType: 'uniqueness',
      detail: expect.stringContaining('enable linking by verified email'),
    });
    const id = await newUser('x2@acme.example');
    expect(
      (
        await scim('PATCH', `/Users/${id}`, {
          schemas: [PATCH],
          Operations: [
            { op: 'add', path: 'emails[type eq "work"].value', value: 'owner1@acme.example' },
          ],
        })
      ).json(),
    ).toMatchObject({ status: '409', scimType: 'uniqueness' });
  });

  it('links an existing user by email with linkByEmail, never an instance admin', async () => {
    const existing = await createUser(ctx, { username: 'lena', email: 'lena@acme.example' });
    const res = await scimLinking('POST', '/Users', {
      schemas: [USER],
      userName: 'lena@idp.example',
      displayName: 'Lena L',
      emails: [{ value: 'lena@acme.example', primary: true }],
    });
    expect(res.statusCode).toBe(201);
    expect(await userIdOfIdentity(ctx, res.json().id)).toBe(existing.id);
    expect(res.json()).toMatchObject({ displayName: 'Lena L', active: true });
    const created = (await auditRows(ctx)).filter((e) => e.action === 'scim.user_created');
    expect(created.at(-1)).toMatchObject({
      targetId: existing.id,
      details: { linkedExisting: true },
    });
    // A second SCIM user with the same email: that user already has an identity here.
    expect(
      (
        await scimLinking('POST', '/Users', {
          schemas: [USER],
          userName: 'lena2@idp.example',
          emails: [{ value: 'lena@acme.example', primary: true }],
        })
      ).json(),
    ).toMatchObject({ status: '409', scimType: 'uniqueness' });
    // An instance admin is never linked (spec §8.3), nor an inactive user.
    await createUser(ctx, { username: 'boss', email: 'boss@acme.example', isInstanceAdmin: true });
    await createUser(ctx, { username: 'gone', email: 'gone@acme.example', active: false });
    for (const email of ['boss@acme.example', 'gone@acme.example']) {
      expect(
        (
          await scimLinking('POST', '/Users', {
            schemas: [USER],
            userName: `x-${email}`,
            emails: [{ value: email, primary: true }],
          })
        ).json(),
      ).toMatchObject({ status: '409', scimType: 'uniqueness' });
    }
  });

  it('PUT clears the optional attributes it leaves out, and active absent means true', async () => {
    const id = await newUser('put@acme.example', {
      externalId: 'put-ext',
      displayName: 'Put P',
      name: { givenName: 'Put', familyName: 'P' },
      emails: [{ value: 'put@acme.example' }],
      active: false,
    });
    const res = await scim('PUT', `/Users/${id}`, {
      schemas: [USER],
      userName: 'put@acme.example',
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({
      userName: 'put@acme.example',
      name: {},
      emails: [],
      active: true,
    });
    expect(body.externalId).toBeUndefined();
    expect(body.displayName).toBeUndefined();
    const updated = (await auditRows(ctx)).filter((e) => e.action === 'scim.user_updated').at(-1);
    expect(
      (updated?.details as { changes: { field: string }[] }).changes.map((c) => c.field).sort(),
    ).toEqual(['displayName', 'email', 'externalId']);
    expect((await auditRows(ctx)).at(-1)?.action).toBe('scim.user_reactivated');
  });

  it('deactivation records the sessions ended and tokens revoked; memberships stay', async () => {
    const id = await newUser('deact@acme.example');
    const userId = await userIdOfIdentity(ctx, id);
    await giveSession(ctx, userId);
    await giveSession(ctx, userId);
    await givePersonalToken(ctx, userId);
    const res = await scim('PATCH', `/Users/${id}`, deactivate);
    expect(res.json().active).toBe(false);
    const event = (await auditRows(ctx)).at(-1);
    expect(event).toMatchObject({
      action: 'scim.user_deactivated',
      targetId: userId,
      details: { connectionId: conn, sessionsEnded: 2, tokensRevoked: 1 },
    });
    expect(await activeSessions(ctx, userId)).toBe(0);
    expect(await liveTokens(ctx, userId)).toBe(0);
    // Reactivation does not bring the revoked token back.
    const on = await scim('PATCH', `/Users/${id}`, {
      schemas: [PATCH],
      Operations: [{ op: 'replace', path: 'active', value: 'True' }],
    });
    expect(on.json().active).toBe(true);
    expect(await liveTokens(ctx, userId)).toBe(0);
  });

  it('refuses to deactivate or delete the last usable break-glass admin while the policy is break_glass_only', async () => {
    const bg = await createUser(ctx, { username: 'glass', isInstanceAdmin: true });
    const identity = await linkScimIdentityToAdmin(ctx, conn, bg.id);
    const enabled = await oidcConnection(ctx, { name: 'Enabled', enabled: true });
    expect(enabled).toBeTruthy();
    await updateSignInSettings({ db: ctx.db, audit: scimDeps(ctx).audit }, SYSTEM_ACTOR, {
      passwordSignIn: 'break_glass_only',
      breakGlassUserIds: [bg.id],
    });
    try {
      for (const res of [
        await scim('PATCH', `/Users/${identity}`, deactivate),
        await scim('DELETE', `/Users/${identity}`),
      ]) {
        expect(res.statusCode).toBe(400);
        expect(res.json()).toMatchObject({ status: '400', scimType: 'mutability' });
      }
      expect(await userActive(ctx, bg.id)).toBe(true);
    } finally {
      await updateSignInSettings({ db: ctx.db, audit: scimDeps(ctx).audit }, SYSTEM_ACTOR, {
        passwordSignIn: 'everyone',
        breakGlassUserIds: [],
      });
    }
  });

  it('never changes is_instance_admin', async () => {
    const id = await newUser('noadmin@acme.example');
    await scim('PATCH', `/Users/${id}`, {
      schemas: [PATCH],
      Operations: [
        { op: 'replace', path: 'isInstanceAdmin', value: true },
        { op: 'replace', value: { isInstanceAdmin: true, roles: [{ value: 'admin' }] } },
      ],
    });
    const [row] = await ctx.db
      .select({ admin: users.isInstanceAdmin })
      .from(users)
      .where(eq(users.id, await userIdOfIdentity(ctx, id)));
    expect(row?.admin).toBe(false);
  });

  it('attributes= keeps id, schemas, meta and the listed ones', async () => {
    const id = await newUser('attrs@acme.example', { emails: [{ value: 'attrs@acme.example' }] });
    const res = await scim(
      'GET',
      `/Users?filter=${encodeURIComponent(`id eq "${id}"`)}&attributes=userName,name.givenName`,
    );
    const [r] = res.json().Resources;
    expect(Object.keys(r).sort()).toEqual(['id', 'meta', 'name', 'schemas', 'userName']);
  });

  it('pages with startIndex and count: clamps, count=0 and the order of creation', async () => {
    const pager = await oidcConnection(ctx, { name: 'Pager' });
    const p = client(app, await tokenFor(ctx, pager));
    const ids = [];
    for (const n of [1, 2, 3]) ids.push(await newUser(`page${n}@acme.example`, {}, p));
    expect((await p('GET', '/Users?count=0')).json()).toMatchObject({
      totalResults: 3,
      itemsPerPage: 0,
      Resources: [],
    });
    expect((await p('GET', '/Users?count=-4')).json()).toMatchObject({
      totalResults: 3,
      Resources: [],
    });
    const all = (await p('GET', '/Users?count=5000&startIndex=0')).json();
    expect(all).toMatchObject({ totalResults: 3, startIndex: 1, itemsPerPage: 3 });
    expect(all.Resources.map((r: { id: string }) => r.id)).toEqual(ids);
    const second = (await p('GET', '/Users?startIndex=2&count=1')).json();
    expect(second).toMatchObject({ totalResults: 3, startIndex: 2, itemsPerPage: 1 });
    expect(second.Resources[0].id).toBe(ids[1]);
    expect((await p('GET', '/Users?startIndex=abc&count=x')).json().itemsPerPage).toBe(3);
    expect((await p('GET', '/Users?startIndex=9')).json()).toMatchObject({
      totalResults: 3,
      Resources: [],
    });
  });

  it('filters by emails.value and externalId; a malformed id is 404 or no result', async () => {
    const id = await newUser('filt@acme.example', {
      externalId: 'filt-ext',
      emails: [{ value: 'Filt@Acme.example' }],
    });
    for (const f of [
      'emails.value eq "filt@acme.example"',
      'emails[type eq "work"].value eq "FILT@acme.example"',
      'externalId eq "filt-ext"',
    ]) {
      expect((await scim('GET', `/Users?filter=${encodeURIComponent(f)}`)).json()).toMatchObject({
        totalResults: 1,
        Resources: [{ id }],
      });
    }
    expect(
      (await scim('GET', `/Users?filter=${encodeURIComponent('externalId eq "FILT-EXT"')}`)).json()
        .totalResults,
    ).toBe(0);
    expect(
      (await scim('GET', `/Users?filter=${encodeURIComponent('id eq "nope"')}`)).json()
        .totalResults,
    ).toBe(0);
    expect((await scim('GET', '/Users/nope')).statusCode).toBe(404);
    expect((await scim('GET', '/Users/0192a000-0000-7000-8000-000000000000')).statusCode).toBe(404);
  });

  it('a token of another connection sees none of this connection’s users (404 on every verb)', async () => {
    const id = await newUser('mine@acme.example');
    const other = client(app, await tokenFor(ctx, linking));
    expect((await other('GET', `/Users/${id}`)).statusCode).toBe(404);
    expect(
      (await other('PUT', `/Users/${id}`, { schemas: [USER], userName: 'mine@acme.example' }))
        .statusCode,
    ).toBe(404);
    expect((await other('PATCH', `/Users/${id}`, deactivate)).statusCode).toBe(404);
    expect((await other('DELETE', `/Users/${id}`)).statusCode).toBe(404);
    expect(
      (
        await other('GET', `/Users?filter=${encodeURIComponent('userName eq "mine@acme.example"')}`)
      ).json().totalResults,
    ).toBe(0);
    expect(await userActive(ctx, await userIdOfIdentity(ctx, id))).toBe(true);
  });

  it('answers malformed bodies, unknown paths and a revoked token with SCIM errors', async () => {
    expect((await scim('POST', '/Users', { schemas: [USER] })).json()).toMatchObject({
      status: '400',
      scimType: 'invalidValue',
    });
    expect((await scim('POST', '/Users', [1, 2])).json()).toMatchObject({
      status: '400',
      scimType: 'invalidSyntax',
    });
    expect(
      (await scim('POST', '/Users', { schemas: [USER], userName: 'a\u0007b' })).json(),
    ).toMatchObject({ status: '400' });
    expect(
      (
        await scim('PATCH', '/Users/0192a000-0000-7000-8000-000000000000', { Operations: [] })
      ).json(),
    ).toMatchObject({ status: '404' });
    for (const path of ['/Nope', '/Users/a/b', '/Bulk']) {
      const res = await scim('GET', path);
      expect(res.statusCode).toBe(404);
      expect(res.headers['content-type']).toBe('application/scim+json; charset=utf-8');
    }
    expect((await scim('POST', '/Users/abc', { userName: 'x' })).statusCode).toBe(404);
  });

  it('after a DELETE, a POST with the same email is refused (409 uniqueness): the user row stays', async () => {
    const id = await newUser('again@acme.example', { emails: [{ value: 'again@acme.example' }] });
    expect((await scim('DELETE', `/Users/${id}`)).statusCode).toBe(204);
    const res = await scim('POST', '/Users', {
      schemas: [USER],
      userName: 'again@acme.example',
      emails: [{ value: 'again@acme.example' }],
    });
    expect(res.json()).toMatchObject({
      status: '409',
      scimType: 'uniqueness',
      detail: expect.stringContaining('enable linking by verified email'),
    });
  });

  it('GET /Users/{id} honours attributes=', async () => {
    const id = await newUser('one@acme.example', { emails: [{ value: 'one@acme.example' }] });
    const res = await scim('GET', `/Users/${id}?attributes=emails`);
    expect(Object.keys(res.json()).sort()).toEqual(['emails', 'id', 'meta', 'schemas']);
    expect(
      Object.keys((await scim('GET', `/Users/${id}?excludedAttributes=members`)).json()),
    ).toContain('userName');
  });

  it('every 401 names the Bearer scheme', async () => {
    for (const auth of [null, 'Basic dXNlcjpwYXNz', 'Bearer qlr_scim_' + 'z'.repeat(32)]) {
      const res = await scim('GET', '/Users', undefined, auth);
      expect(res.statusCode).toBe(401);
      expect(res.headers['www-authenticate']).toBe('Bearer');
    }
  });

  it('answers 500 "Set QUALOR_PUBLIC_URL" without a public URL', async () => {
    const bare = Fastify({ logger: false });
    const deps = scimDeps(ctx);
    bare.all('/scim/v2/*', (req, reply) =>
      handleScim({ ...deps, config: { ...deps.config, publicUrl: null } }, req, reply),
    );
    const res = await client(bare, await tokenFor(ctx, conn))('GET', '/ServiceProviderConfig');
    expect(res.statusCode).toBe(500);
    expect(res.json()).toMatchObject({ status: '500', detail: 'Set QUALOR_PUBLIC_URL' });
    await bare.close();
  });

  it('rate-limits each token to 1 200 requests a minute (429 with Retry-After)', async () => {
    const limited = client(app, await tokenFor(ctx, conn));
    const statuses = await Promise.all(
      Array.from({ length: 1_200 }, () =>
        limited('GET', '/ServiceProviderConfig').then((r) => r.statusCode),
      ),
    );
    expect(statuses.every((s) => s === 200)).toBe(true);
    const res = await limited('GET', '/ServiceProviderConfig');
    expect(res.statusCode).toBe(429);
    expect(res.headers['retry-after']).toBe('60');
    expect(res.json()).toMatchObject({ status: '429' });
    // Another token is not limited.
    expect((await scim('GET', '/ServiceProviderConfig')).statusCode).toBe(200);
  }, 60_000);

  it('never logs the token', async () => {
    const token = await tokenFor(ctx, conn);
    await client(app, token)('GET', '/Users');
    expect(ctx.logs.join('\n')).not.toContain(token.slice(9));
  });
});

describe('SCIM deactivation while the audit anchor is malformed (rbac-audit.md §10.2.1)', () => {
  let ctx: TestContext;
  let app: FastifyInstance;
  let scim: Scim;
  let a: string;
  let b: string;

  beforeAll(async () => {
    ctx = await ssoContext({ now: LICENSED });
    const conn = await oidcConnection(ctx, {});
    app = scimApp(ctx);
    await app.ready();
    scim = client(app, await tokenFor(ctx, conn));
    a = (await scim('POST', '/Users', { schemas: [USER], userName: 'a@acme.example' })).json().id;
    b = (await scim('POST', '/Users', { schemas: [USER], userName: 'b@acme.example' })).json().id;
    await ctx.db.transaction(async (tx) => {
      await tx.execute(sql`ALTER TABLE audit_events DISABLE TRIGGER audit_events_guard`);
      await tx.execute(sql`DELETE FROM audit_events`);
      await tx.execute(sql`ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard`);
    });
    await ctx.db.execute(sql`
      INSERT INTO instance_settings (key, value) VALUES ('audit-chain', '{"throughSeq":1}'::jsonb)`);
  });
  afterAll(async () => {
    await app.close();
    await ctx.close();
  });

  it('deactivates and deletes (the events skipped), but refuses a change that is not access-removing', async () => {
    const userA = await userIdOfIdentity(ctx, a);
    await giveSession(ctx, userA);
    expect((await scim('PATCH', `/Users/${a}`, deactivate)).statusCode).toBe(200);
    expect(await activeSessions(ctx, userA)).toBe(0);
    expect(await userActive(ctx, userA)).toBe(false);
    const rename = await scim('PATCH', `/Users/${b}`, {
      schemas: [PATCH],
      Operations: [{ op: 'replace', path: 'displayName', value: 'B' }],
    });
    expect(rename.statusCode).toBe(409);
    expect(rename.json()).toMatchObject({
      status: '409',
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
    });
    const userB = await userIdOfIdentity(ctx, b);
    expect((await scim('DELETE', `/Users/${b}`)).statusCode).toBe(204);
    expect(await userActive(ctx, userB)).toBe(false);
    const [left] = await ctx.db
      .select({ id: identities.id })
      .from(identities)
      .where(and(eq(identities.id, b)));
    expect(left).toBeUndefined();
    expect(await auditRows(ctx)).toEqual([]);
  });
});

describe('SCIM on a connection not in effect (sso-scim.md §4.4)', () => {
  it('a SCIM token of a connection not in effect still deactivates a user', async () => {
    // Review Focus 7: a key listing sso, scim and audit-log, without sso.multi.
    const ctx = await ssoContext({ now: LICENSED, features: ONE_CONNECTION_FEATURES });
    const app = scimApp(ctx);
    try {
      await app.ready();
      expect(ctx.edition?.isFeatureActive('sso.multi')).toBe(false);
      // Both enabled under an Enterprise key; the older one stays in effect.
      const enterprise = licensedEdition(ENTERPRISE_FEATURES);
      const inEffect = await oidcConnection(ctx, { enabled: true, edition: enterprise });
      const kept = await oidcConnection(ctx, { enabled: true, edition: enterprise });
      expect([...(await inEffectConnectionIds(ctx.db, ctx.edition!))]).toEqual([inEffect]);
      const scim = client(app, await tokenFor(ctx, kept));
      const created = await scim('POST', '/Users', {
        schemas: [USER],
        userName: 'leaver@acme.example',
      });
      expect(created.statusCode, created.body).toBe(201);
      const identityId = created.json().id as string;
      const userId = await userIdOfIdentity(ctx, identityId);
      await giveSession(ctx, userId);
      await givePersonalToken(ctx, userId);
      const res = await scim('PATCH', `/Users/${identityId}`, deactivate);
      expect(res.statusCode, res.body).toBe(200);
      expect(await userActive(ctx, userId)).toBe(false);
      expect(await activeSessions(ctx, userId)).toBe(0);
      expect(await liveTokens(ctx, userId)).toBe(0);
    } finally {
      await app.close();
      await ctx.close();
    }
  });
});

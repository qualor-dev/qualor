import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { organizationId, type TestContext } from '../../test/app';
import {
  activeSessions,
  givePersonalToken,
  giveSession,
  linkScimIdentityToAdmin,
  liveTokens,
  oidcConnection,
  orgRoleOf,
  scimApp,
  scimDeps,
  ssoContext,
  userActive,
  userIdOfIdentity,
} from '../../test/sso';
import { SYSTEM_ACTOR } from '../audit/recorder';
import { replaceMappings } from '../sso/groups';
import { handleScim, SCIM_INVALID_JSON } from './handle';
import { createScimToken } from './tokens';

/** Inside the test licence's validity (issued 2026-10-01). */
const LICENSED = () => new Date('2027-01-01T00:00:00Z');

describe('SCIM as Entra ID and Okta drive it (sso-scim.md §12)', () => {
  let ctx: TestContext;
  let conn: string;
  let token: string;
  let app: FastifyInstance;

  beforeAll(async () => {
    ctx = await ssoContext({ now: LICENSED });
    conn = await oidcConnection(ctx, { groupSource: 'scim' });
    const org = await organizationId(ctx, 'default');
    await replaceMappings({ db: ctx.db, audit: scimDeps(ctx).audit }, SYSTEM_ACTOR, conn, [
      { group: 'Qualor Devs', organizationId: org, projectId: null, role: 'member' },
    ]);
    token = (
      await createScimToken(scimDeps(ctx), SYSTEM_ACTOR, {
        connectionId: conn,
        name: 'entra',
        expiresAt: null,
      })
    ).token;
    app = scimApp(ctx);
    await app.ready();
  });
  afterAll(async () => {
    await app.close();
    await ctx.close();
  });

  // `null` sends no Authorization header (an explicit `undefined` would take the default).
  const scim = (
    method: string,
    path: string,
    body?: unknown,
    auth: string | null = `Bearer ${token}`,
  ) =>
    app.inject({
      method: method as never,
      url: `/scim/v2${path}`,
      headers: {
        ...(auth === null ? {} : { authorization: auth }),
        'content-type': 'application/scim+json',
      },
      ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
    });

  it('Entra: create, find by userName, deactivate with Replace/"False", which ends sessions and revokes tokens', async () => {
    const created = await scim('POST', '/Users', {
      schemas: [
        'urn:ietf:params:scim:schemas:core:2.0:User',
        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
      ],
      externalId: 'entra-oid-1',
      userName: 'Ana@Acme.example',
      active: true,
      displayName: 'Ana A',
      emails: [{ primary: true, type: 'work', value: 'ana@acme.example' }],
      name: { givenName: 'Ana', familyName: 'A', formatted: 'Ana A' },
      'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': { department: 'Eng' },
    });
    expect(created.statusCode).toBe(201);
    expect(created.headers['content-type']).toBe('application/scim+json; charset=utf-8');
    const id = created.json().id as string;
    expect(created.headers.location).toBe(`https://q.example/api/v0/ee/scim/v2/Users/${id}`);
    const found = await scim(
      'GET',
      `/Users?filter=${encodeURIComponent('userName eq "ana@acme.example"')}`,
    );
    expect(found.json()).toMatchObject({
      totalResults: 1,
      Resources: [{ id, userName: 'Ana@Acme.example', active: true }],
    });
    // the person signs in once and makes a token, to see both die
    const userId = await userIdOfIdentity(ctx, id);
    await givePersonalToken(ctx, userId);
    await giveSession(ctx, userId);
    const off = await scim('PATCH', `/Users/${id}`, {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Replace', path: 'active', value: 'False' }],
    });
    expect(off.statusCode).toBe(200);
    expect(off.json().active).toBe(false);
    expect(await activeSessions(ctx, userId)).toBe(0);
    expect(await liveTokens(ctx, userId)).toBe(0);
  });

  it('Okta: create, PUT the whole user, deactivate with a pathless replace', async () => {
    const created = await scim('POST', '/Users', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'ole@acme.example',
      name: { givenName: 'Ole', familyName: 'O' },
      emails: [{ primary: true, value: 'ole@acme.example', type: 'work' }],
      active: true,
    });
    const id = created.json().id as string;
    const put = await scim('PUT', `/Users/${id}`, {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      id,
      userName: 'ole@acme.example',
      name: { givenName: 'Olé', familyName: 'O' },
      emails: [{ primary: true, value: 'ole@acme.example', type: 'work' }],
      active: true,
    });
    expect(put.json().name).toMatchObject({ givenName: 'Olé' });
    const off = await scim('PATCH', `/Users/${id}`, {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'replace', value: { active: false } }],
    });
    expect(off.json().active).toBe(false);
  });

  it('groups: create with a member, add and remove by Entra path, and group sync follows', async () => {
    const u = (
      await scim('POST', '/Users', {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'gus@acme.example',
        active: true,
      })
    ).json().id as string;
    const g = await scim('POST', '/Groups', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      displayName: 'Qualor Devs',
      members: [{ value: u }],
    });
    expect(g.statusCode).toBe(201);
    expect(await orgRoleOf(ctx, await userIdOfIdentity(ctx, u))).toBe('member');
    await scim('PATCH', `/Groups/${g.json().id}`, {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Remove', path: `members[value eq "${u}"]` }],
    });
    expect(await orgRoleOf(ctx, await userIdOfIdentity(ctx, u))).toBeNull();
    const list = await scim(
      'GET',
      `/Groups?filter=${encodeURIComponent('displayName eq "Qualor Devs"')}&excludedAttributes=members`,
    );
    expect(list.json().Resources[0].members).toBeUndefined();
  });

  it('delete: 204, then 404, the user row stays and is inactive', async () => {
    const id = (
      await scim('POST', '/Users', {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'del@acme.example',
      })
    ).json().id as string;
    const userId = await userIdOfIdentity(ctx, id);
    expect((await scim('DELETE', `/Users/${id}`)).statusCode).toBe(204);
    expect((await scim('GET', `/Users/${id}`)).statusCode).toBe(404);
    expect(await userActive(ctx, userId)).toBe(false);
  });

  it.each([
    ['no token', null, 401],
    ['a personal token', 'Bearer qlr_pat_' + 'a'.repeat(32), 401],
    ['Basic auth', 'Basic dXNlcjpwYXNz', 401],
  ])('refuses %s with a SCIM 401', async (_n, auth, status) => {
    const res = await scim('GET', '/Users', undefined, auth);
    expect(res.statusCode).toBe(status);
    expect(res.json()).toMatchObject({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: String(status),
    });
  });

  it('never shows another connection’s users', async () => {
    const other = await oidcConnection(ctx, { name: 'Other' });
    const otherToken = (
      await createScimToken(scimDeps(ctx), SYSTEM_ACTOR, {
        connectionId: other,
        name: 'o',
        expiresAt: null,
      })
    ).token;
    const res = await scim('GET', '/Users', undefined, `Bearer ${otherToken}`);
    expect(res.json().totalResults).toBe(0);
  });

  it('refuses a duplicate userName (409 uniqueness), an unsupported filter, and the last instance admin’s deactivation', async () => {
    await scim('POST', '/Users', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'dup@acme.example',
    });
    expect(
      (
        await scim('POST', '/Users', {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'DUP@acme.example',
        })
      ).json(),
    ).toMatchObject({ status: '409', scimType: 'uniqueness' });
    expect(
      (await scim('GET', `/Users?filter=${encodeURIComponent('userName co "a"')}`)).json(),
    ).toMatchObject({ status: '400', scimType: 'invalidFilter' });
    const adminIdentity = await linkScimIdentityToAdmin(ctx, conn); // an identity of the bootstrap admin on this connection
    expect(
      (
        await scim('PATCH', `/Users/${adminIdentity}`, {
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [{ op: 'replace', path: 'active', value: false }],
        })
      ).json(),
    ).toMatchObject({ status: '400', scimType: 'mutability' });
  });

  it('answers ServiceProviderConfig, ResourceTypes and Schemas', async () => {
    const spc = (await scim('GET', '/ServiceProviderConfig')).json();
    expect(spc).toMatchObject({
      patch: { supported: true },
      bulk: { supported: false },
      filter: { supported: true, maxResults: 100 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
    });
    expect(
      (await scim('GET', '/ResourceTypes'))
        .json()
        .Resources.map((r: { name: string }) => r.name)
        .sort(),
    ).toEqual(['Group', 'User']);
    const schemas = (await scim('GET', '/Schemas')).json();
    expect(schemas.Resources.map((r: { id: string }) => r.id).sort()).toEqual([
      'urn:ietf:params:scim:schemas:core:2.0:Group',
      'urn:ietf:params:scim:schemas:core:2.0:User',
    ]);
  });

  it('answers a body the plugin could not read as JSON with 400 invalidSyntax, after the token', async () => {
    // The enterprise plugin's parser hands core this marker (enterprise/src/scim-routes.ts).
    const bare = Fastify({ logger: false });
    bare.removeAllContentTypeParsers();
    bare.addContentTypeParser('application/scim+json', { parseAs: 'string' }, (_req, _body, done) =>
      done(null, SCIM_INVALID_JSON),
    );
    const deps = scimDeps(ctx);
    bare.all('/scim/v2/*', (req, reply) => handleScim(deps, req, reply));
    try {
      const post = (headers: Record<string, string>) =>
        bare.inject({
          method: 'POST',
          url: '/scim/v2/Users',
          headers: { 'content-type': 'application/scim+json', ...headers },
          payload: '{"schemas":',
        });
      const res = await post({ authorization: `Bearer ${token}` });
      expect(res.statusCode).toBe(400);
      expect(res.headers['content-type']).toBe('application/scim+json; charset=utf-8');
      expect(res.json()).toMatchObject({ status: '400', scimType: 'invalidSyntax' });
      expect((await post({})).statusCode).toBe(401);
    } finally {
      await bare.close();
    }
  });
});

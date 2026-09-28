import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, createUser, organizationId, type TestContext } from '../../test/app';
import {
  auditRows,
  oidcConnection,
  orgRoleOf,
  scimApp,
  scimDeps,
  ssoContext,
  userIdOfIdentity,
} from '../../test/sso';
import { SYSTEM_ACTOR } from '../audit/recorder';
import { memberships, scimGroupMembers } from '../db/schema';
import { replaceMappings } from '../sso/groups';
import { createScimToken } from './tokens';

/** Inside the test licence's validity (issued 2026-10-01). */
const LICENSED = () => new Date('2027-01-01T00:00:00Z');
const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

describe('SCIM Groups (sso-scim.md §12.7) and group sync (§9.1)', () => {
  let ctx: TestContext;
  let conn: string;
  let other: string;
  let org: string;
  let app: FastifyInstance;
  let token: string;
  let otherToken: string;

  const scim = (method: string, path: string, body?: unknown, as = token) =>
    app.inject({
      method: method as never,
      url: `/scim/v2${path}`,
      headers: { authorization: `Bearer ${as}`, 'content-type': 'application/scim+json' },
      ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
    });
  let n = 0;
  const newUser = async (as = token) => {
    n += 1;
    const res = await scim(
      'POST',
      '/Users',
      { schemas: [USER], userName: `g${n}@acme.example` },
      as,
    );
    expect(res.statusCode, res.body).toBe(201);
    return res.json().id as string;
  };
  const newGroup = async (displayName: string, members: string[] = [], extra = {}) => {
    const res = await scim('POST', '/Groups', {
      schemas: [GROUP],
      displayName,
      members: members.map((value) => ({ value })),
      ...extra,
    });
    expect(res.statusCode, res.body).toBe(201);
    return res.json().id as string;
  };
  const role = async (identity: string) => orgRoleOf(ctx, await userIdOfIdentity(ctx, identity));
  const patch = (id: string, Operations: unknown[]) =>
    scim('PATCH', `/Groups/${id}`, { schemas: [PATCH], Operations });

  beforeAll(async () => {
    ctx = await ssoContext({ now: LICENSED });
    conn = await oidcConnection(ctx, { groupSource: 'scim' });
    other = await oidcConnection(ctx, { name: 'Other', groupSource: 'scim' });
    org = await organizationId(ctx, 'default');
    await replaceMappings({ db: ctx.db, audit: scimDeps(ctx).audit }, SYSTEM_ACTOR, conn, [
      { group: 'Devs', organizationId: org, projectId: null, role: 'member' },
      { group: 'ext-admins', organizationId: org, projectId: null, role: 'admin' },
      { group: 'Leads', organizationId: org, projectId: null, role: 'project_admin' },
      ...['devs-batch', 'devs-put', 'devs-doomed', 'devs-del'].map((group) => ({
        group,
        organizationId: org,
        projectId: null,
        role: 'member' as const,
      })),
    ]);
    const mint = async (connectionId: string) =>
      (
        await createScimToken(scimDeps(ctx), SYSTEM_ACTOR, {
          connectionId,
          name: 'g',
          expiresAt: null,
        })
      ).token;
    token = await mint(conn);
    otherToken = await mint(other);
    app = scimApp(ctx);
    await app.ready();
  });
  afterAll(async () => {
    await app.close();
    await ctx.close();
  });

  it('counts a member of another connection as unknown, and never adds it', async () => {
    const mine = await newUser();
    const theirs = await newUser(otherToken);
    const res = await scim('POST', '/Groups', {
      schemas: [GROUP],
      displayName: 'Mixed',
      members: [{ value: mine }, { value: theirs }, { value: 'not-a-uuid' }],
    });
    expect(res.statusCode).toBe(201);
    expect(res.headers.location).toBe(
      `https://q.example/api/v0/ee/scim/v2/Groups/${res.json().id}`,
    );
    expect(res.json().members.map((m: { value: string }) => m.value)).toEqual([mine]);
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'scim.group_created',
      targetType: 'scim_group',
      details: { connectionId: conn, displayName: 'Mixed', members: 1, unknownMembers: 2 },
    });
    // PATCH add with another connection's id: ignored and counted.
    const g = res.json().id as string;
    const added = await patch(g, [{ op: 'add', path: 'members', value: [{ value: theirs }] }]);
    expect(added.json().members).toHaveLength(1);
  });

  it('refuses a displayName taken ignoring case, and a taken externalId (409 uniqueness)', async () => {
    await newGroup('Unique One', [], { externalId: 'u-1' });
    expect(
      (await scim('POST', '/Groups', { schemas: [GROUP], displayName: 'UNIQUE one' })).json(),
    ).toMatchObject({
      status: '409',
      scimType: 'uniqueness',
    });
    expect(
      (
        await scim('POST', '/Groups', {
          schemas: [GROUP],
          displayName: 'Unique Two',
          externalId: 'u-1',
        })
      ).json(),
    ).toMatchObject({ status: '409', scimType: 'uniqueness' });
    const two = await newGroup('Unique Two');
    expect(
      (await patch(two, [{ op: 'replace', path: 'displayName', value: 'unique ONE' }])).json(),
    ).toMatchObject({
      status: '409',
      scimType: 'uniqueness',
    });
    // Another connection may use the same name.
    expect(
      (await scim('POST', '/Groups', { schemas: [GROUP], displayName: 'Unique One' }, otherToken))
        .statusCode,
    ).toBe(201);
  });

  it('maps a group by its externalId when it has one, else by its displayName (spec §9.2)', async () => {
    // Another admin, by hand: sync never removes an organisation's last admin (rbac-audit.md §16).
    await addMember(ctx, org, (await createUser(ctx, { username: 'hand-admin' })).id, 'admin');
    const u = await newUser();
    const g = await newGroup('Admins by name', [u], { externalId: 'ext-admins' });
    expect(await role(u)).toBe('admin');
    // A displayName that a mapping names does not count while the group has an externalId.
    const v = await newUser();
    await newGroup('Devs', [v], { externalId: 'not-mapped' });
    expect(await role(v)).toBeNull();
    // Clearing the externalId makes the displayName count: every member syncs after a rename.
    const cleared = await patch(g, [{ op: 'remove', path: 'externalId' }]);
    expect(cleared.statusCode).toBe(200);
    expect(await role(u)).toBeNull();
    await patch(g, [{ op: 'replace', path: 'displayName', value: 'Devs2' }]);
    await patch(g, [{ op: 'replace', value: { displayName: 'Leads' } }]);
    expect(await role(u)).toBe('project_admin');
  });

  it('PATCH adds a value list, replaces the whole list, and bounds member changes at 1 000', async () => {
    const [a, b, c] = [await newUser(), await newUser(), await newUser()];
    const g = await newGroup('Batch', [], { externalId: 'devs-batch' });
    await patch(g, [{ op: 'Add', path: 'members', value: [{ value: a }, { value: b }] }]);
    expect([await role(a), await role(b), await role(c)]).toEqual(['member', 'member', null]);
    const replaced = await patch(g, [{ op: 'replace', path: 'members', value: [{ value: c }] }]);
    expect(replaced.json().members.map((m: { value: string }) => m.value)).toEqual([c]);
    expect([await role(a), await role(b), await role(c)]).toEqual([null, null, 'member']);
    const update = (await auditRows(ctx)).at(-1);
    expect(update).toMatchObject({
      action: 'scim.group_updated',
      details: { membersAdded: 1, membersRemoved: 2, unknownMembers: 0, renamed: false },
    });
    const many = Array.from({ length: 1_001 }, (_v, i) => ({
      value: `0192a000-0000-7000-8000-${String(i).padStart(12, '0')}`,
    }));
    expect((await patch(g, [{ op: 'add', path: 'members', value: many }])).json()).toMatchObject({
      status: '400',
      scimType: 'tooMany',
    });
  });

  it('PUT replaces the name, clears externalId and replaces the members', async () => {
    const [a, b] = [await newUser(), await newUser()];
    const g = await newGroup('Put group', [a], { externalId: 'devs-put' });
    expect(await role(a)).toBe('member');
    const res = await scim('PUT', `/Groups/${g}`, {
      schemas: [GROUP],
      displayName: 'devs-put',
      members: [{ value: b }],
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().externalId).toBeUndefined();
    expect(res.json().members.map((m: { value: string }) => m.value)).toEqual([b]);
    // Still mapped through the displayName now, for b only.
    expect([await role(a), await role(b)]).toEqual([null, 'member']);
    const cleared = await scim('PUT', `/Groups/${g}`, {
      schemas: [GROUP],
      displayName: 'devs-put',
    });
    expect(cleared.json().members).toEqual([]);
    expect(await role(b)).toBeNull();
  });

  it('DELETE removes the managed memberships and leaves one made by hand', async () => {
    const [managed, byHand] = [await newUser(), await newUser()];
    await addMember(ctx, org, await userIdOfIdentity(ctx, byHand), 'viewer');
    const g = await newGroup('Doomed', [managed, byHand], { externalId: 'devs-doomed' });
    expect([await role(managed), await role(byHand)]).toEqual(['member', 'viewer']);
    expect((await scim('DELETE', `/Groups/${g}`)).statusCode).toBe(204);
    expect((await scim('GET', `/Groups/${g}`)).statusCode).toBe(404);
    expect([await role(managed), await role(byHand)]).toEqual([null, 'viewer']);
    expect(
      await ctx.db.select().from(scimGroupMembers).where(eq(scimGroupMembers.groupId, g)),
    ).toEqual([]);
    expect(
      (await auditRows(ctx)).filter((e) => e.action === 'scim.group_deleted').at(-1),
    ).toMatchObject({
      details: { displayName: 'Doomed', members: 2 },
    });
  });

  it('DELETE of a user removes it from the groups and its managed memberships', async () => {
    const u = await newUser();
    await newGroup('Del', [u], { externalId: 'devs-del' });
    const userId = await userIdOfIdentity(ctx, u);
    expect(await orgRoleOf(ctx, userId)).toBe('member');
    expect((await scim('DELETE', `/Users/${u}`)).statusCode).toBe(204);
    expect(await orgRoleOf(ctx, userId)).toBeNull();
    const [kept] = await ctx.db
      .select()
      .from(memberships)
      .where(and(eq(memberships.userId, userId), eq(memberships.organizationId, org)));
    expect(kept).toBeUndefined();
  });

  it('GET honours excludedAttributes=members and attributes=; another connection’s group is 404', async () => {
    const u = await newUser();
    const g = await newGroup('Shown', [u]);
    expect((await scim('GET', `/Groups/${g}`)).json().members).toHaveLength(1);
    expect(
      (await scim('GET', `/Groups/${g}?excludedAttributes=members`)).json().members,
    ).toBeUndefined();
    expect(
      Object.keys((await scim('GET', `/Groups/${g}?attributes=displayName`)).json()).sort(),
    ).toEqual(['displayName', 'id', 'meta', 'schemas']);
    for (const [method, body] of [
      ['GET', undefined],
      [
        'PATCH',
        { schemas: [PATCH], Operations: [{ op: 'replace', path: 'displayName', value: 'x' }] },
      ],
      ['PUT', { schemas: [GROUP], displayName: 'x' }],
      ['DELETE', undefined],
    ] as const) {
      expect((await scim(method, `/Groups/${g}`, body, otherToken)).statusCode).toBe(404);
    }
    expect(
      (await scim('GET', `/Groups?filter=${encodeURIComponent('displayName eq "shown"')}`)).json()
        .totalResults,
    ).toBe(1);
    expect(
      (
        await scim(
          'GET',
          `/Groups?filter=${encodeURIComponent('displayName eq "shown"')}`,
          undefined,
          otherToken,
        )
      ).json().totalResults,
    ).toBe(0);
  });
});

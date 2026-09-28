import Fastify, { type FastifyInstance } from 'fastify';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { organizationId, type TestContext } from '../../test/app';
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
import { createDatabase, type Database } from '../db/client';
import { replaceMappings } from '../sso/groups';
import { handleScim } from './handle';
import { createScimToken } from './tokens';

/** Inside the test licence's validity (issued 2026-10-01). */
const LICENSED = () => new Date('2027-01-01T00:00:00Z');
const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

/**
 * Two requests on two pools, held at a point both reach, then released together: the order in
 * which their syncs read the person's groups decides the result unless LOCKS.scimSync serialises
 * them (sso-scim.md §9.1).
 */
describe('SCIM group sync under concurrent group changes', () => {
  let ctx: TestContext;
  let second: Database;
  let blocker: Database;
  let org: string;
  let appA: FastifyInstance;
  let appB: FastifyInstance;
  let token: string;

  const request = (app: FastifyInstance) => (method: string, path: string, body?: unknown) =>
    app.inject({
      method: method as never,
      url: `/scim/v2${path}`,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/scim+json' },
      ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
    });
  let n = 0;
  const newUser = async () => {
    n += 1;
    const res = await request(appA)('POST', '/Users', {
      schemas: [USER],
      userName: `race${n}@acme.example`,
    });
    expect(res.statusCode, res.body).toBe(201);
    return res.json().id as string;
  };
  const newGroup = async (externalId: string, members: string[]) => {
    const res = await request(appA)('POST', '/Groups', {
      schemas: [GROUP],
      displayName: `${externalId}-${n}`,
      externalId: `${externalId}`,
      members: members.map((value) => ({ value })),
    });
    expect(res.statusCode, res.body).toBe(201);
    return res.json().id as string;
  };
  const patch = (app: FastifyInstance, group: string, operation: unknown) =>
    request(app)('PATCH', `/Groups/${group}`, { schemas: [PATCH], Operations: [operation] });

  /** Waits until `count` other backends wait on a lock (a row lock or an advisory lock). */
  async function waiters(count: number): Promise<void> {
    for (let i = 0; i < 200; i += 1) {
      const { rows } = await blocker.pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM pg_stat_activity
          WHERE datname = current_database() AND wait_event_type = 'Lock'`,
      );
      if ((rows[0]?.n ?? 0) >= count) return;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    throw new Error(`fewer than ${count} requests reached the lock`);
  }

  /** Holds `lockSql` in an open transaction, runs `race`, releases once `count` requests wait. */
  async function held<T>(
    lockSql: string,
    params: unknown[],
    count: number,
    race: () => Promise<T>,
  ) {
    const client: PoolClient = await blocker.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(lockSql, params);
      const running = race();
      await waiters(count);
      await client.query('COMMIT');
      return await running;
    } finally {
      client.release();
    }
  }

  beforeAll(async () => {
    ctx = await ssoContext({ now: LICENSED });
    second = createDatabase(ctx.database.url);
    blocker = createDatabase(ctx.database.url);
    const conn = await oidcConnection(ctx, { groupSource: 'scim' });
    org = await organizationId(ctx, 'default');
    await replaceMappings(
      { db: ctx.db, audit: scimDeps(ctx).audit },
      SYSTEM_ACTOR,
      conn,
      ['race-1', 'race-2', 'race-3', 'race-4'].map((group) => ({
        group,
        organizationId: org,
        projectId: null,
        role: 'member' as const,
      })),
    );
    token = (
      await createScimToken(scimDeps(ctx), SYSTEM_ACTOR, {
        connectionId: conn,
        name: 'race',
        expiresAt: null,
      })
    ).token;
    appA = scimApp(ctx);
    const depsB = { ...scimDeps(ctx), db: second.db };
    appB = Fastify({ logger: false });
    appB.addContentTypeParser(
      'application/scim+json',
      { parseAs: 'string' },
      appB.getDefaultJsonParser('error', 'error'),
    );
    appB.all('/scim/v2/*', (req, reply) => handleScim(depsB, req, reply));
    await Promise.all([appA.ready(), appB.ready()]);
  });
  afterAll(async () => {
    await Promise.all([appA.close(), appB.close()]);
    await second.close();
    await blocker.close();
    await ctx.close();
  });

  const orgRowLock = `SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE`;

  it('removals from two groups at once leave no membership', async () => {
    const x = await newUser();
    const g1 = await newGroup('race-1', [x]);
    const g2 = await newGroup('race-2', [x]);
    const userId = await userIdOfIdentity(ctx, x);
    expect(await orgRoleOf(ctx, userId)).toBe('member');
    const [a, b] = await held(orgRowLock, [org], 2, () =>
      Promise.all([
        patch(appA, g1, { op: 'remove', path: `members[value eq "${x}"]` }),
        patch(appB, g2, { op: 'remove', path: `members[value eq "${x}"]` }),
      ]),
    );
    expect([a.statusCode, b.statusCode], `${a.body} ${b.body}`).toEqual([200, 200]);
    expect(await orgRoleOf(ctx, userId)).toBeNull();
  });

  it('adding to one group while removing from another keeps the membership', async () => {
    const x = await newUser();
    const g3 = await newGroup('race-3', [x]);
    const g4 = await newGroup('race-4', []);
    const userId = await userIdOfIdentity(ctx, x);
    expect(await orgRoleOf(ctx, userId)).toBe('member');
    const [a, b] = await held(orgRowLock, [org], 2, () =>
      Promise.all([
        patch(appA, g4, { op: 'add', path: 'members', value: [{ value: x }] }),
        patch(appB, g3, { op: 'remove', path: `members[value eq "${x}"]` }),
      ]),
    );
    expect([a.statusCode, b.statusCode], `${a.body} ${b.body}`).toEqual([200, 200]);
    expect(await orgRoleOf(ctx, userId)).toBe('member');
  });

  it('a member deleted while the group change runs is skipped, never a 500 (23503)', async () => {
    const x = await newUser();
    const g = await newGroup('race-5', []);
    const res = await held(`DELETE FROM identities WHERE id = $1`, [x], 1, () =>
      patch(appA, g, { op: 'add', path: 'members', value: [{ value: x }] }),
    );
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json().members).toEqual([]);
    const events = await auditRows(ctx);
    const updated = events.filter((e) => e.action === 'scim.group_updated');
    // Nothing changed, so no event; the refusal was not a 500 either.
    expect(updated.filter((e) => e.targetId === g)).toEqual([]);
    const { rows } = await second.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM scim_group_members WHERE group_id = $1',
      [g],
    );
    expect(rows[0]?.n).toBe(0);
  });
});

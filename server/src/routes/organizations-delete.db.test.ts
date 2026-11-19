import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  createProject,
  createUser,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import { rbacContext } from '../../test/rbac';
import { createDatabase } from '../db/client';
import { LOCKS } from '../db/locks';
import { auditEvents, jobs } from '../db/schema';
import {
  ORGANIZATION_DELETE_QUEUE,
  organizationDeleteHandlers,
  organizationDeleteKey,
} from '../orgs/delete';
import { runUntilIdle } from '../queue/worker';

const NOW = new Date('2027-01-01T00:00:00Z');

interface Organization {
  id: string;
  key: string;
  name: string;
  deleting: boolean;
  createdAt: string;
  updatedAt: string;
}

/** A worker logger that drops every line. */
const QUIET = { info() {}, warn() {}, error() {} };

/**
 * A licensed server with `audit-log`, so the route records its event, and the bootstrap admin
 * signed in. Its only organisation is `default`.
 */
async function server(): Promise<{ ctx: TestContext; admin: Session }> {
  const ctx = await rbacContext({ now: () => NOW });
  return { ctx, admin: await login(ctx, 'admin', ADMIN_PASSWORD) };
}

/** The calls of one server. */
function routes(ctx: TestContext) {
  const remove = (headers: Record<string, string>, id: string, confirm?: string) =>
    ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/organizations/${id}${confirm === undefined ? '' : `?confirm=${encodeURIComponent(confirm)}`}`,
      headers,
    });
  return {
    remove,
    create: async (admin: Session, key: string): Promise<Organization> => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: admin.headers,
        payload: { key, name: `Org ${key}` },
      });
      expect(res.statusCode, res.body).toBe(201);
      return res.json();
    },
    list: async (admin: Session): Promise<Organization[]> => {
      const res = await ctx.app.inject({
        method: 'GET',
        url: '/api/v0/organizations?limit=500',
        headers: admin.headers,
      });
      expect(res.statusCode, res.body).toBe(200);
      return res.json().items;
    },
    /** The `organization.deleted` events whose target is the organisation. */
    events: (id: string) =>
      ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, 'organization.deleted'), eq(auditEvents.targetId, id)))
        .orderBy(auditEvents.seq),
    /** The delete jobs of the organisation, oldest first. */
    jobs: (id: string) =>
      ctx.db
        .select({ queue: jobs.queue, status: jobs.status, payload: jobs.payload })
        .from(jobs)
        .where(eq(jobs.concurrencyKey, organizationDeleteKey(id)))
        .orderBy(jobs.createdAt, jobs.id),
    /** The main worker's organisation deletes, until none is left to run. */
    runWorker: () =>
      runUntilIdle(ctx.db, organizationDeleteHandlers({ db: ctx.db, logger: QUIET }), QUIET),
  };
}

const problem = (res: { statusCode: number; json(): { code?: string } }) => [
  res.statusCode,
  res.json().code,
];

/**
 * Runs the requests at once (Promise.all), held in flight together: another connection holds the
 * audit chain's lock, which each delete takes to record its event after its checks, until as many
 * backends of this database wait on an advisory lock as there are requests. Each request has then
 * either passed its checks or waits for another's lock before them; without the lock of the
 * deletes both would have passed them. Then the hold ends and they finish.
 */
async function inFlightTogether<T>(ctx: TestContext, start: () => Promise<T>[]): Promise<T[]> {
  const holder = createDatabase(ctx.database.url, { max: 1 });
  let all: Promise<T[]> | undefined;
  try {
    await holder.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.auditChain})`);
      const requests = start();
      all = Promise.all(requests);
      const deadline = Date.now() + 10_000;
      for (;;) {
        const { rows } = await ctx.db.execute<{ n: number }>(sql`
          SELECT count(*)::int AS n FROM pg_locks
           WHERE locktype = 'advisory' AND NOT granted
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`);
        if (rows[0]!.n >= requests.length) break;
        if (Date.now() > deadline) throw new Error('the requests never waited together');
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    });
  } finally {
    await holder.close();
  }
  return all!;
}

describe('DELETE /organizations/:id (0.16 issue #37)', () => {
  let ctx: TestContext;
  let admin: Session;
  let r: ReturnType<typeof routes>;

  beforeAll(async () => {
    ({ ctx, admin } = await server());
    r = routes(ctx);
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('an instance admin deletes: 202 deleting, one event, one job; the worker removes it', async () => {
    const org = await r.create(admin, 'doomed');
    expect(org.deleting).toBe(false);
    await createProject(ctx, admin, { organizationId: org.id, key: 'doomed-web' });
    await createProject(ctx, admin, { organizationId: org.id, key: 'doomed-api' });

    const res = await r.remove(admin.headers, org.id, org.key);

    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toEqual({ ...org, deleting: true });
    const events = await r.events(org.id);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      outcome: 'success',
      actorType: 'user',
      actorUsername: 'admin',
      organizationId: org.id,
      organizationKey: 'doomed',
      projectId: null,
      targetType: 'organization',
      targetId: org.id,
      targetLabel: 'Org doomed',
      details: { key: 'doomed', name: 'Org doomed', projects: 2 },
    });
    expect(await r.jobs(org.id)).toEqual([
      { queue: ORGANIZATION_DELETE_QUEUE, status: 'queued', payload: { organizationId: org.id } },
    ]);

    expect(await r.runWorker()).toBe(1);
    expect((await r.list(admin)).map((o) => o.id)).not.toContain(org.id);
    expect((await r.jobs(org.id)).map((j) => j.status)).toEqual(['succeeded']);
    // The event outlives the organisation.
    expect(await r.events(org.id)).toEqual(events);
  });

  it('wrong confirm: 422 on query.confirm, no event, no job', async () => {
    const org = await r.create(admin, 'confirmed');
    for (const confirm of ['other', 'CONFIRMED', '', undefined]) {
      const res = await r.remove(admin.headers, org.id, confirm);
      expect(res.statusCode, `confirm=${confirm}`).toBe(422);
      expect(res.json().errors.map((e: { path: string }) => e.path)).toEqual(['query.confirm']);
    }
    expect(await r.events(org.id)).toEqual([]);
    expect(await r.jobs(org.id)).toEqual([]);
    expect((await r.list(admin)).find((o) => o.id === org.id)?.deleting).toBe(false);
  });

  it('not an instance admin: 403 for an organisation admin, 401 without a session; no event', async () => {
    const org = await r.create(admin, 'guarded');
    const user = await createUser(ctx, { username: 'guarded-admin' });
    await addMember(ctx, org.id, user.id, 'admin');
    const orgAdmin = await login(ctx, user.username, user.password);

    expect(problem(await r.remove(orgAdmin.headers, org.id, org.key))).toEqual([403, 'FORBIDDEN']);
    expect((await r.remove({}, org.id, org.key)).statusCode).toBe(401);
    expect(await r.events(org.id)).toEqual([]);
    expect(await r.jobs(org.id)).toEqual([]);
  });

  it('a missing organisation: 404', async () => {
    const res = await r.remove(admin.headers, '01900000-0000-7000-8000-000000000000', 'gone');
    expect(problem(res)).toEqual([404, 'NOT_FOUND']);
    expect(res.json()).toMatchObject({ title: 'Organization not found' });
  });

  it('already deleting: a second DELETE while the job is queued answers 409 ORGANIZATION_DELETING', async () => {
    const org = await r.create(admin, 'twice');
    expect((await r.remove(admin.headers, org.id, org.key)).statusCode).toBe(202);

    expect(problem(await r.remove(admin.headers, org.id, org.key))).toEqual([
      409,
      'ORGANIZATION_DELETING',
    ]);
    expect(await r.events(org.id)).toHaveLength(1);
    expect((await r.jobs(org.id)).map((j) => j.status)).toEqual(['queued']);
  });

  it('a dead job is not deleting: the list shows false and DELETE answers 202 again', async () => {
    const org = await r.create(admin, 'revived');
    expect((await r.remove(admin.headers, org.id, org.key)).statusCode).toBe(202);
    await ctx.db
      .update(jobs)
      .set({ status: 'dead' })
      .where(eq(jobs.concurrencyKey, organizationDeleteKey(org.id)));

    expect((await r.list(admin)).find((o) => o.id === org.id)?.deleting).toBe(false);
    const again = await r.remove(admin.headers, org.id, org.key);
    expect(again.statusCode, again.body).toBe(202);
    expect(again.json()).toMatchObject({ id: org.id, deleting: true });
    expect((await r.jobs(org.id)).map((j) => j.status)).toEqual(['dead', 'queued']);
    expect(await r.events(org.id)).toHaveLength(2);
  });

  it('the list: deleting is true for a queued delete and false for the others', async () => {
    const queued = await r.create(admin, 'listed-queued');
    const idle = await r.create(admin, 'listed-idle');
    expect((await r.remove(admin.headers, queued.id, queued.key)).statusCode).toBe(202);

    const listed = new Map((await r.list(admin)).map((o) => [o.key, o.deleting]));
    expect(listed.get('listed-queued')).toBe(true);
    expect(listed.get('listed-idle')).toBe(false);
    expect(listed.get('default')).toBe(false);
    expect(idle.deleting).toBe(false);
  });

  it("an upper-case id in the path: the job and the event carry the organisation row's id (ruling C1)", async () => {
    const org = await r.create(admin, 'upper');
    const res = await r.remove(admin.headers, org.id.toUpperCase(), org.key);

    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toMatchObject({ id: org.id, deleting: true });
    expect(await r.jobs(org.id)).toEqual([
      { queue: ORGANIZATION_DELETE_QUEUE, status: 'queued', payload: { organizationId: org.id } },
    ]);
    expect(await r.events(org.id)).toEqual([
      expect.objectContaining({ organizationId: org.id, targetId: org.id }),
    ]);
  });
});

describe('the last organisation is kept (0.16 issue #37, Review Focus 2)', () => {
  it('last organisation: the only organisation answers 409 LAST_ORGANIZATION', async () => {
    const { ctx, admin } = await server();
    try {
      const r = routes(ctx);
      const [only] = await r.list(admin);
      expect(only?.key).toBe('default');

      expect(problem(await r.remove(admin.headers, only!.id, 'default'))).toEqual([
        409,
        'LAST_ORGANIZATION',
      ]);
      expect(await r.events(only!.id)).toEqual([]);
      expect(await r.jobs(only!.id)).toEqual([]);
    } finally {
      await ctx.close();
    }
  });

  it('concurrent deletes keep one', async () => {
    // Two organisations: A, then B before the worker runs. A is being deleted, so B is the last.
    const two = await server();
    try {
      const r = routes(two.ctx);
      const [b] = await r.list(two.admin);
      const a = await r.create(two.admin, 'org-a');
      expect((await r.remove(two.admin.headers, a.id, a.key)).statusCode).toBe(202);
      expect(problem(await r.remove(two.admin.headers, b!.id, b!.key))).toEqual([
        409,
        'LAST_ORGANIZATION',
      ]);
      expect(await r.jobs(b!.id)).toEqual([]);

      // A is gone; with C, two organisations again, both asked for at once: one is kept.
      expect(await r.runWorker()).toBe(1);
      const c = await r.create(two.admin, 'org-c');
      const raced = await inFlightTogether(two.ctx, () => [
        r.remove(two.admin.headers, b!.id, b!.key),
        r.remove(two.admin.headers, c.id, c.key),
      ]);
      expect(raced.map(problem).sort()).toEqual([
        [202, undefined],
        [409, 'LAST_ORGANIZATION'],
      ]);
      expect([...(await r.jobs(b!.id)), ...(await r.jobs(c.id))]).toHaveLength(1);
    } finally {
      await two.ctx.close();
    }

    // A fresh state with three organisations: A and B at once both pass, because C remains.
    const three = await server();
    try {
      const r = routes(three.ctx);
      const [c] = await r.list(three.admin);
      const a = await r.create(three.admin, 'org-a');
      const b = await r.create(three.admin, 'org-b');
      const raced = await inFlightTogether(three.ctx, () => [
        r.remove(three.admin.headers, a.id, a.key),
        r.remove(three.admin.headers, b.id, b.key),
      ]);
      expect(raced.map((res) => res.statusCode)).toEqual([202, 202]);
      expect(new Map((await r.list(three.admin)).map((o) => [o.key, o.deleting]))).toEqual(
        new Map([
          [c!.key, false],
          ['org-a', true],
          ['org-b', true],
        ]),
      );
      expect(problem(await r.remove(three.admin.headers, c!.id, c!.key))).toEqual([
        409,
        'LAST_ORGANIZATION',
      ]);
    } finally {
      await three.ctx.close();
    }
  });
});

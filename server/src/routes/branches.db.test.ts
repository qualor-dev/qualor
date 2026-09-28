import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import type { Db } from '../db/client';
import { analyses, branches, projects } from '../db/schema';

/**
 * Polls `pg_stat_activity` until some backend in this test's own database is genuinely blocked
 * waiting on a lock, instead of assuming a fixed delay was enough. Each test file runs against
 * its own freshly cloned database (see test/db.ts), so `datname = current_database()` scopes
 * this to exactly the backend(s) this test spawned — nothing from other, parallel test files.
 */
async function waitUntilABackendIsLockWaiting(
  db: Db,
  { timeoutMs = 5_000, intervalMs = 10 } = {},
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await db.execute(sql`
      SELECT count(*)::int AS n FROM pg_stat_activity
       WHERE wait_event_type = 'Lock' AND datname = current_database()
    `);
    if (Number(result.rows[0]?.n) > 0) return;
    if (Date.now() > deadline) {
      throw new Error('Timed out waiting for a backend to block on a lock');
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/** A promise plus its resolver, used to hand-synchronise two concurrent async flows exactly
 *  (never by a fixed sleep) in the interleaving test below. */
function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe('branches', () => {
  let ctx: TestContext;
  let orgAdmin: Session;
  let member: Session;
  let outsider: Session;
  let projectId: string;
  let mainId: string;
  let featureId: string;

  const call = (method: 'GET' | 'DELETE', url: string, headers: Record<string, string>) =>
    ctx.app.inject({ method, url: `/api/v0${url}`, headers });
  const mintToken = async (
    session: Session,
    scopes: string[],
  ): Promise<{ id: string; token: string }> =>
    (
      await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: session.headers,
        payload: {
          name: `t-${scopes.join('-')}-${Math.random().toString(36).slice(2, 8)}`,
          scopes,
        },
      })
    ).json();

  beforeAll(async () => {
    ctx = await createTestContext();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const defaultOrg = await organizationId(ctx, 'default');
    const otherOrg = (
      await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: admin.headers,
        payload: { key: 'other', name: 'Other' },
      })
    ).json().id;
    const a = await createUser(ctx, { username: 'b-admin' });
    const m = await createUser(ctx, { username: 'b-member' });
    const o = await createUser(ctx, { username: 'b-outsider' });
    await addMember(ctx, defaultOrg, a.id, 'admin');
    await addMember(ctx, defaultOrg, m.id, 'member');
    await addMember(ctx, otherOrg, o.id, 'member');
    orgAdmin = await login(ctx, a.username, a.password);
    member = await login(ctx, m.username, m.password);
    outsider = await login(ctx, o.username, o.password);
    projectId = (
      await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: 'acme/branches' })
    ).id;
    const inserted = await ctx.db
      .insert(branches)
      .values([
        { projectId, kind: 'branch', name: 'feature/x' },
        {
          projectId,
          kind: 'merge_request',
          name: '42',
          mrSourceBranch: 'feature/x',
          mrTargetBranch: 'main',
          mrTitle: 'Add x',
        },
      ])
      .returning();
    featureId = inserted[0]!.id;
    mainId = (await call('GET', `/projects/${projectId}`, member.headers)).json().mainBranch.id;
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('lists branches and merge requests, filtered by kind, with pagination', async () => {
    const all = await call('GET', `/projects/${projectId}/branches`, member.headers);
    expect(all.statusCode).toBe(200);
    expect(
      all
        .json()
        .items.map((b: { name: string }) => b.name)
        .sort(),
    ).toEqual(['42', 'feature/x', 'main']);
    expect(all.json().items.find((b: { name: string }) => b.name === 'main')).toMatchObject({
      isMain: true,
      kind: 'branch',
      gateStatus: null,
      measures: {},
    });
    const mrs = await call(
      'GET',
      `/projects/${projectId}/branches?kind=merge_request`,
      member.headers,
    );
    expect(mrs.json().items).toEqual([
      expect.objectContaining({ name: '42', mrTargetBranch: 'main', mrTitle: 'Add x' }),
    ]);
    const page1 = await call('GET', `/projects/${projectId}/branches?limit=2`, member.headers);
    const page2 = await call(
      'GET',
      `/projects/${projectId}/branches?limit=2&cursor=${page1.json().nextCursor}`,
      member.headers,
    );
    expect(page1.json().items).toHaveLength(2);
    expect(page2.json()).toMatchObject({ nextCursor: null });
    expect(page2.json().items).toHaveLength(1);
  });

  it('validates and authorises the list (422/401/404)', async () => {
    const bad = await call('GET', `/projects/${projectId}/branches?kind=tag`, member.headers);
    expect(bad.json().errors[0].path).toBe('query.kind');
    expect((await call('GET', `/projects/${projectId}/branches`, {})).statusCode).toBe(401);
    expect(
      (await call('GET', `/projects/${projectId}/branches`, outsider.headers)).statusCode,
    ).toBe(404);
  });

  it('deletes a non-main branch; the main branch is protected', async () => {
    const main = await call('DELETE', `/branches/${mainId}`, orgAdmin.headers);
    expect([main.statusCode, main.json().code]).toEqual([409, 'MAIN_BRANCH']);
    expect((await call('DELETE', `/branches/${featureId}`, member.headers)).statusCode).toBe(403);
    expect((await call('DELETE', `/branches/${featureId}`, outsider.headers)).statusCode).toBe(404);
    expect((await call('DELETE', `/branches/${featureId}`, {})).statusCode).toBe(401);
    expect((await call('DELETE', '/branches/nope', orgAdmin.headers)).json().errors[0].path).toBe(
      'params.id',
    );
    expect((await call('DELETE', `/branches/${featureId}`, orgAdmin.headers)).statusCode).toBe(204);
    expect((await call('DELETE', `/branches/${featureId}`, orgAdmin.headers)).statusCode).toBe(404);
  });

  it('deleting a branch cascades to its analyses and leaves other branches alone', async () => {
    const [doomed, kept] = await ctx.db
      .insert(branches)
      .values([
        { projectId, kind: 'branch', name: 'cascade/doomed' },
        { projectId, kind: 'branch', name: 'cascade/kept' },
      ])
      .returning();
    await ctx.db.insert(analyses).values([
      { projectId, branchId: doomed!.id, status: 'failed' },
      { projectId, branchId: doomed!.id, status: 'queued' },
      { projectId, branchId: kept!.id, status: 'failed' },
    ]);
    const countFor = async (branchId: string) =>
      (await ctx.db.select().from(analyses).where(eq(analyses.branchId, branchId))).length;
    expect(await countFor(doomed!.id)).toBe(2);
    expect((await call('DELETE', `/branches/${doomed!.id}`, orgAdmin.headers)).statusCode).toBe(
      204,
    );
    expect(await countFor(doomed!.id)).toBe(0);
    expect(await countFor(kept!.id)).toBe(1);
  });

  it('deletion respects token scopes: read and write tokens get INSUFFICIENT_SCOPE, admin is enough (controller ruling S10)', async () => {
    const other = await createProject(ctx, orgAdmin, {
      organizationId: await organizationId(ctx, 'default'),
      key: 'acme/branches-scopes',
    });
    const [extra] = await ctx.db
      .insert(branches)
      .values({ projectId: other.id, kind: 'branch', name: 'scoped' })
      .returning();
    const readOnly = await mintToken(orgAdmin, ['read']);
    const insufficient = await call('DELETE', `/branches/${extra!.id}`, bearer(readOnly.token));
    expect([insufficient.statusCode, insufficient.json().code]).toEqual([
      403,
      'INSUFFICIENT_SCOPE',
    ]);
    // DELETE /branches/{id} is 🛡 (api.md §3): an org admin's 'write' token is not enough either.
    const writeOnly = await mintToken(orgAdmin, ['write']);
    const writeRes = await call('DELETE', `/branches/${extra!.id}`, bearer(writeOnly.token));
    expect([writeRes.statusCode, writeRes.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    const admin = await mintToken(orgAdmin, ['admin']);
    expect((await call('DELETE', `/branches/${extra!.id}`, bearer(admin.token))).statusCode).toBe(
      204,
    );
  });

  it('a delete racing an in-flight main-branch promotion of the same branch never leaves zero main branches (fix round 1, finding 2)', async () => {
    const defaultOrg = await organizationId(ctx, 'default');
    const p = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'acme/branches-race',
    });
    const [candidate] = await ctx.db
      .insert(branches)
      .values({ projectId: p.id, kind: 'branch', name: 'candidate' })
      .returning();
    // A plain pair of concurrent HTTP requests (PATCH mainBranchName=candidate + DELETE
    // candidate) essentially never lands the dangerous interleaving in this environment: the
    // real DELETE handler's outer read + role check are enough round trips that every DELETE
    // finishes well before a queued-behind-the-project-lock PATCH gets anywhere near the same
    // row. So this drives the exact interleaving by hand — the same lock order and statements
    // PATCH /projects/{id} uses — synchronised with the real DELETE call through a real barrier
    // (pg_stat_activity showing a genuinely blocked backend), never a fixed sleep, so this can't
    // go spuriously green or red just because a CI runner is slower or faster than expected.
    const lockAcquired = deferred();
    const readyToPromote = deferred();
    const promote = ctx.db.transaction(async (tx) => {
      await tx.select().from(projects).where(eq(projects.id, p.id)).for('update');
      lockAcquired.resolve();
      // Hold the project-row lock open until the real DELETE below is confirmed to be blocked
      // trying to take the very same lock.
      await readyToPromote.promise;
      await tx
        .update(branches)
        .set({ isMain: false })
        .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
      await tx.update(branches).set({ isMain: true }).where(eq(branches.id, candidate!.id));
      await tx.update(projects).set({ mainBranchName: 'candidate' }).where(eq(projects.id, p.id));
    });
    // Only fire DELETE once `promote` genuinely holds the project-row lock, so DELETE's unlocked
    // outer read is guaranteed to see is_main = false (the pre-fix code's stale read) and its own
    // transaction is guaranteed to have something to block on.
    await lockAcquired.promise;
    const del = call('DELETE', `/branches/${candidate!.id}`, orgAdmin.headers);
    // Only let the promotion proceed and commit once DELETE's own transaction is genuinely
    // blocked waiting on that same project-row lock.
    await waitUntilABackendIsLockWaiting(ctx.db);
    readyToPromote.resolve();
    const [, delResult] = await Promise.all([promote, del]);
    expect(delResult.statusCode).not.toBe(500);
    // The branch was not yet main when DELETE's outer read ran, but was already the committed
    // main branch by the time DELETE could act on it: it must be refused, never silently removed.
    expect([delResult.statusCode, delResult.json().code]).toEqual([409, 'MAIN_BRANCH']);
    const mains = await ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    expect(mains).toHaveLength(1);
    const [row] = await ctx.db.select().from(projects).where(eq(projects.id, p.id));
    expect(mains[0]!.name).toBe(row!.mainBranchName);
  });
});

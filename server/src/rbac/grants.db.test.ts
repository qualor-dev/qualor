import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  organizationId,
  type TestContext,
} from '../../test/app';
import { fillProjectGrants, grantProject } from '../../test/rbac';
import { requireOrganizationAccess, type AccessContext } from '../auth/access';
import { createDatabase } from '../db/client';
import { LOCKS } from '../db/locks';
import type { UserPrincipal } from '../auth/principal';
import { projectMemberships, users, type OrganizationRole, type ProjectRole } from '../db/schema';
import { ProblemError } from '../http/problem';
import { projectForUser } from '../projects/access';
import {
  listProjectGrants,
  PROJECT_GRANT_LIMIT,
  removeProjectGrant,
  setProjectGrant,
} from './grants';

async function problemOf(promise: Promise<unknown>): Promise<[number, string]> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof ProblemError) return [err.status, err.code];
    throw err;
  }
  throw new Error('expected a problem');
}

describe('project grants (rbac-audit.md §7.2, §16)', () => {
  let ctx: TestContext;
  let org: string;
  let project: { id: string; key: string };
  const ids: Record<string, string> = {};

  beforeAll(async () => {
    ctx = await createTestContext();
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    project = await createProject(ctx, root, { organizationId: org, key: 'grants' });
    for (const name of ['ann', 'ben', 'cat'])
      ids[name] = (await createUser(ctx, { username: name })).id;
    ids.gone = (await createUser(ctx, { username: 'gone', active: false })).id;
  });
  afterAll(async () => ctx.close());
  beforeEach(async () => {
    await ctx.db.delete(projectMemberships);
  });

  it('adds, changes and removes a grant, reporting the previous role', async () => {
    const added = await setProjectGrant(ctx.db, project.id, ids.ann!, 'viewer');
    expect(added.previous).toBeNull();
    expect(added.grant).toMatchObject({ userId: ids.ann, username: 'ann', role: 'viewer' });
    const changed = await setProjectGrant(ctx.db, project.id, ids.ann!, 'project_admin');
    expect(changed.previous).toBe('viewer');
    expect(changed.grant.role).toBe('project_admin');
    expect(changed.grant.createdAt).toBe(added.grant.createdAt);
    expect(await removeProjectGrant(ctx.db, project.id, ids.ann!)).toBe('project_admin');
    expect(await removeProjectGrant(ctx.db, project.id, ids.ann!)).toBeNull();
  });

  it('removes a grant under the per-project lock that setProjectGrant takes', async () => {
    await grantProject(ctx, project.id, ids.ann!, 'member');
    // Another connection holds the project's grant lock: the removal must wait for it, so it can
    // never interleave with a concurrent set (which would mislabel the recorded event).
    const holder = createDatabase(ctx.database.url, { max: 1 });
    let removing: Promise<unknown> | undefined;
    let settled = false;
    try {
      await holder.db.transaction(async (tx) => {
        await tx.execute(
          sql`SELECT pg_advisory_xact_lock(${LOCKS.projectGrants}, hashtext(${project.id}))`,
        );
        removing = removeProjectGrant(ctx.db, project.id, ids.ann!).finally(() => {
          settled = true;
        });
        // Deterministic: wait until the removal's backend is queued on that advisory lock (or,
        // without the lock, until it has finished, which the check below then refuses).
        for (;;) {
          if (settled) break;
          const [row] = (
            await ctx.db.execute<{ n: number }>(
              sql`SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`,
            )
          ).rows;
          if (row!.n > 0) break;
        }
        expect(settled).toBe(false);
        const [still] = (
          await ctx.db.execute<{ n: number }>(
            sql`SELECT count(*)::int AS n FROM project_memberships WHERE project_id = ${project.id}`,
          )
        ).rows;
        expect(still!.n).toBe(1);
      });
    } finally {
      await holder.close();
    }
    await expect(removing).resolves.toBe('member');
  });

  it('lists the grants a page at a time', async () => {
    for (const name of ['ann', 'ben', 'cat']) {
      await setProjectGrant(ctx.db, project.id, ids[name]!, 'member');
    }
    const first = await listProjectGrants(ctx.db, project.id, { limit: 2 });
    expect(first.items).toHaveLength(2);
    expect(first.nextCursor).not.toBeNull();
    const second = await listProjectGrants(ctx.db, project.id, {
      limit: 2,
      cursor: first.nextCursor!,
    });
    expect(second.items).toHaveLength(1);
    expect(second.nextCursor).toBeNull();
    const all = [...first.items, ...second.items].map((g) => g.userId);
    expect(all).toEqual([ids.ann, ids.ben, ids.cat].sort());
  });

  it('refuses an unknown or inactive user with 404 and writes nothing', async () => {
    expect(await problemOf(setProjectGrant(ctx.db, project.id, ids.gone!, 'viewer'))).toEqual([
      404,
      'NOT_FOUND',
    ]);
    expect(
      await problemOf(
        setProjectGrant(ctx.db, project.id, '00000000-0000-4000-8000-000000000000', 'viewer'),
      ),
    ).toEqual([404, 'NOT_FOUND']);
    expect(await ctx.db.select().from(projectMemberships)).toEqual([]);
  });

  describe('the bound of 1 000 grants a project', () => {
    const fill = (n: number) => fillProjectGrants(ctx, project.id, n);

    it('refuses a new grant at the bound, and still changes an existing one', async () => {
      await fill(PROJECT_GRANT_LIMIT);
      expect(await problemOf(setProjectGrant(ctx.db, project.id, ids.ann!, 'viewer'))).toEqual([
        409,
        'PROJECT_GRANT_LIMIT_REACHED',
      ]);
      const [bulk] = await ctx.db.select().from(users).where(eq(users.username, 'bulk-1'));
      const changed = await setProjectGrant(ctx.db, project.id, bulk!.id, 'member');
      expect(changed.previous).toBe('viewer');
      const [row] = await ctx.db
        .execute<{ n: number }>(
          sql`SELECT count(*)::int AS n FROM project_memberships WHERE project_id = ${project.id}`,
        )
        .then((r) => r.rows);
      expect(row!.n).toBe(PROJECT_GRANT_LIMIT);
    });

    it('lets exactly one of two concurrent grants take the last place', async () => {
      await fill(PROJECT_GRANT_LIMIT - 1);
      // Another connection holds the project row, so each insert (its foreign key takes KEY SHARE
      // on the row) waits after its count: without the per-project lock both would count 999.
      const blocker = createDatabase(ctx.database.url, { max: 1 });
      let racing: Promise<PromiseSettledResult<unknown>[]> | undefined;
      try {
        await blocker.db.transaction(async (tx) => {
          await tx.execute(sql`SELECT 1 FROM projects WHERE id = ${project.id} FOR UPDATE`);
          racing = Promise.allSettled([
            setProjectGrant(ctx.db, project.id, ids.ann!, 'viewer'),
            setProjectGrant(ctx.db, project.id, ids.ben!, 'viewer'),
          ]);
          await tx.execute(sql`SELECT pg_sleep(0.3)`);
        });
      } finally {
        await blocker.close();
      }
      const results = await racing!;
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      const refused = results.find((r) => r.status === 'rejected');
      expect((refused as PromiseRejectedResult).reason).toMatchObject({
        code: 'PROJECT_GRANT_LIMIT_REACHED',
      });
    });
  });
});

/**
 * Who may manage a project's grants: the core routes (rbac-audit.md §16, routes/project-members.ts)
 * resolve the project with `project.read`, then ask for `org.members.manage` on its organisation. Grants only add to
 * the organisation role, and never make anyone a grant manager.
 */
describe('managing grants is for organisation admins (rbac-audit.md §3.2, §16)', () => {
  let ctx: TestContext;
  let org: string;
  let project: { id: string; key: string };
  const principals: Record<string, UserPrincipal> = {};
  const access = (): AccessContext => ({ db: ctx.db });

  const manage = async (who: string, role: ProjectRole) => {
    const caller = principals[who]!;
    const found = await projectForUser(access(), caller, project.id, 'project.read');
    await requireOrganizationAccess(access(), caller, found.organizationId, 'org.members.manage');
    return setProjectGrant(ctx.db, found.id, principals.target!.user.id, role);
  };

  beforeAll(async () => {
    ctx = await createTestContext();
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    project = await createProject(ctx, root, { organizationId: org, key: 'managed' });
    const roles: Record<string, OrganizationRole | null> = {
      orgadmin: 'admin',
      padmin: 'project_admin',
      maintainer: 'member',
      viewer: 'viewer',
      granted: null,
      outsider: null,
      target: null,
    };
    for (const [name, role] of Object.entries(roles)) {
      const created = await createUser(ctx, { username: name });
      if (role) await addMember(ctx, org, created.id, role);
      const [user] = await ctx.db.select().from(users).where(eq(users.id, created.id));
      principals[name] = { kind: 'session', user: user!, sessionSecret: 'unused' };
    }
    await grantProject(ctx, project.id, principals.granted!.user.id, 'project_admin');
  });
  afterAll(async () => ctx.close());

  it('lets an organisation admin add and change a grant', async () => {
    expect((await manage('orgadmin', 'viewer')).previous).toBeNull();
    expect((await manage('orgadmin', 'member')).previous).toBe('viewer');
  });

  it.each(['padmin', 'maintainer', 'viewer', 'granted'])(
    'refuses %s with 403 FORBIDDEN',
    async (who) => {
      expect(await problemOf(manage(who, 'project_admin'))).toEqual([403, 'FORBIDDEN']);
    },
  );

  it('hides the project from an outsider (404)', async () => {
    expect(await problemOf(manage('outsider', 'project_admin'))).toEqual([404, 'NOT_FOUND']);
  });
});

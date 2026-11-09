import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  organizationId,
  type TestContext,
} from '../../test/app';
import {
  memberships,
  notificationPreferences,
  projectMemberships,
  projectWatches,
} from '../db/schema';
import { vulnerabilityWatchers, watchersFor, type NotifyEvent } from './recipients';

describe('who gets a project notification (mail E3 N4)', () => {
  let ctx: TestContext;
  let org: string;
  let projectId: string;
  const ids: Record<string, string> = {};

  const add = async (
    username: string,
    options: {
      email?: string | null;
      active?: boolean;
      isInstanceAdmin?: boolean;
      member?: boolean;
      grant?: boolean;
      watch?: Partial<typeof projectWatches.$inferInsert>;
    } = {},
  ) => {
    const user = await createUser(ctx, {
      username,
      email: options.email === undefined ? `${username}@example.com` : options.email,
      active: options.active ?? true,
      isInstanceAdmin: options.isInstanceAdmin ?? false,
    });
    ids[username] = user.id;
    if (options.member !== false) await addMember(ctx, org, user.id, 'viewer');
    if (options.grant) {
      await ctx.db
        .insert(projectMemberships)
        .values({ projectId, userId: user.id, role: 'viewer' });
    }
    await ctx.db.insert(projectWatches).values({ userId: user.id, projectId, ...options.watch });
  };
  const who = async (event: NotifyEvent, branchIsMain: boolean | null) =>
    (await watchersFor(ctx.db, { projectId, event, branchIsMain, demoUser: 'guest' }))
      .map((w) => w.username)
      .sort();

  beforeAll(async () => {
    ctx = await createTestContext();
    org = await organizationId(ctx, 'default');
    const owner = await createUser(ctx, { username: 'rcp-owner' });
    await addMember(ctx, org, owner.id, 'admin');
    const session = await login(ctx, owner.username, owner.password);
    projectId = (await createProject(ctx, session, { organizationId: org, key: 'rcp/project' })).id;
    await add('main-watcher');
    await add('all-watcher', { watch: { branches: 'all' } });
    await add('no-gate-failed', { watch: { gateFailed: false } });
    await add('inactive', { active: false });
    await add('no-email', { email: null });
    await add('email-off');
    await ctx.db
      .insert(notificationPreferences)
      .values({ userId: ids['email-off']!, email: false });
    await add('guest');
    await add('grant-only', { member: false, grant: true });
    await add('instance-admin', { member: false, isInstanceAdmin: true });
    await add('outsider', { member: false });
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('picks the active, reachable watchers of the event who can see the project', async () => {
    expect(await who('gate.failed', true)).toEqual([
      'all-watcher',
      'grant-only',
      'instance-admin',
      'main-watcher',
    ]);
    expect(await who('gate.recovered', true)).toEqual([
      'all-watcher',
      'grant-only',
      'instance-admin',
      'main-watcher',
      'no-gate-failed',
    ]);
  });

  it('mails other branches only to "all" watchers, and an unknown branch to both scopes', async () => {
    expect(await who('gate.failed', false)).toEqual(['all-watcher']);
    expect(await who('analysis.failed', null)).toEqual([
      'all-watcher',
      'grant-only',
      'instance-admin',
      'main-watcher',
      'no-gate-failed',
    ]);
  });

  it('excludes the demo user by its configured name only', async () => {
    const all = await watchersFor(ctx.db, {
      projectId,
      event: 'gate.failed',
      branchIsMain: true,
      demoUser: null,
    });
    expect(all.find((w) => w.username === 'guest')).toEqual({
      userId: ids['guest'],
      email: 'guest@example.com',
      username: 'guest',
      displayName: null,
    });
  });

  it('stops on lost access without deleting the watch, and starts again when access returns', async () => {
    const id = ids['main-watcher']!;
    await ctx.db
      .delete(memberships)
      .where(and(eq(memberships.userId, id), eq(memberships.organizationId, org)));
    expect(await who('gate.failed', true)).not.toContain('main-watcher');
    expect(
      await ctx.db.select().from(projectWatches).where(eq(projectWatches.userId, id)),
    ).toHaveLength(1);
    await addMember(ctx, org, id, 'viewer');
    expect(await who('gate.failed', true)).toContain('main-watcher');
  });

  it('vulnerabilityWatchers: the new_vulnerabilities watchers, whatever the branch scope', async () => {
    const names = async (projectIds: string[], demoUser: string | null = 'guest') =>
      (await vulnerabilityWatchers(ctx.db, { projectIds, demoUser })).map((w) => w.username).sort();
    // main-watcher lost access in the test above and got it back: it watches 'main' only.
    expect(await names([projectId])).toEqual([
      'all-watcher',
      'grant-only',
      'instance-admin',
      'main-watcher',
      'no-gate-failed',
    ]);
    await ctx.db
      .update(projectWatches)
      .set({ newVulnerabilities: false })
      .where(eq(projectWatches.userId, ids['all-watcher']!));
    expect(await names([projectId])).not.toContain('all-watcher');
    const [row] = await vulnerabilityWatchers(ctx.db, { projectIds: [projectId], demoUser: null });
    expect(row).toMatchObject({ projectId });
    expect(await names([projectId], null)).toContain('guest');
    expect(await names([])).toEqual([]);
    const id = ids['main-watcher']!;
    await ctx.db
      .delete(memberships)
      .where(and(eq(memberships.userId, id), eq(memberships.organizationId, org)));
    expect(await names([projectId])).not.toContain('main-watcher');
    await addMember(ctx, org, id, 'viewer');
    expect(await names([projectId])).toContain('main-watcher');
  });
});

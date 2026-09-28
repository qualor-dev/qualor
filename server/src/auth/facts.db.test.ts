import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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
import { memberships, projectMemberships, projects, users } from '../db/schema';
import { grantInOrganization, grantOf, memberOf, organizationFacts, projectFacts } from './facts';

describe('access facts in one query (rbac-audit.md §5, ruling RB2)', () => {
  let ctx: TestContext;
  let org: string;
  let p1: string;
  let p2: string;
  let userId: string;

  beforeAll(async () => {
    ctx = await createTestContext();
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    p1 = (await createProject(ctx, root, { organizationId: org, key: 'f1' })).id;
    p2 = (await createProject(ctx, root, { organizationId: org, key: 'f2' })).id;
    userId = (await createUser(ctx, { username: 'dora' })).id;
    await addMember(ctx, org, userId, 'viewer');
    await ctx.db.insert(projectMemberships).values({ projectId: p1, userId, role: 'member' });
  });
  afterAll(async () => ctx.close());

  const user = async () => (await ctx.db.select().from(users).where(eq(users.id, userId)))[0]!;

  it('reads the organisation role and the project grant together', async () => {
    const u = await user();
    const rows = await ctx.db
      .select({
        id: projects.id,
        organizationRole: memberships.role,
        projectRole: projectMemberships.role,
      })
      .from(projects)
      .leftJoin(memberships, memberOf(u, projects.organizationId))
      .leftJoin(projectMemberships, grantOf(u, projects.id))
      .where(eq(projects.organizationId, org));
    const byId = new Map(rows.map((r) => [r.id, r]));
    expect(byId.get(p1)).toMatchObject({ organizationRole: 'viewer', projectRole: 'member' });
    expect(byId.get(p2)).toMatchObject({ organizationRole: 'viewer', projectRole: null });
    expect(projectFacts(u, byId.get(p1)!)).toMatchObject({
      organizationRole: 'viewer',
      projectRole: 'member',
    });
  });

  it('knows whether the user has a grant somewhere in the organisation', async () => {
    const u = await user();
    const [row] = await ctx.db
      .select({ hasProjectGrant: grantInOrganization(u, projects.organizationId) })
      .from(projects)
      .where(eq(projects.id, p2));
    expect(row!.hasProjectGrant).toBe(true);
    expect(organizationFacts(u, { organizationRole: null, hasProjectGrant: true })).toMatchObject({
      hasProjectGrantInOrganization: true,
    });
  });
});

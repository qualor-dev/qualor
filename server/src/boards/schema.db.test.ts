import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, expectPgError, type TestDatabase } from '../../test/db';
import { PG_NOT_NULL_VIOLATION } from '../../test/refusals';
import { PG_CHECK_VIOLATION, PG_UNIQUE_VIOLATION } from '../db/errors';
import { uuidv7 } from '../db/ids';
import {
  boardsLinks,
  branches,
  issues,
  organizations,
  projectBoardsSettings,
  projects,
  rules,
  scmConnections,
  users,
  type BoardsLinkState,
  type BoardsStateCategory,
} from '../db/schema';

const ENVELOPE = { v: 1 as const, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' };
const AZURE_PROJECT = '713818b4-749e-43d9-88c1-fa6e0000b72a';

describe('the Boards tables (Azure DevOps design §7.8, migration 0037_azure_boards)', () => {
  let t: TestDatabase;
  let organizationId: string;
  let projectId: string;
  let branchId: string;
  let ruleId: string;
  let seq = 0;

  const makeOrganization = async (): Promise<string> => {
    seq += 1;
    const [org] = await t.db
      .insert(organizations)
      .values({ key: `boards-org-${seq}`, name: `Org ${seq}` })
      .returning();
    return org!.id;
  };
  const makeConnection = async (orgId = organizationId) => {
    const [row] = await t.db
      .insert(scmConnections)
      .values({
        organizationId: orgId,
        provider: 'azure',
        baseUrl: 'https://dev.azure.com/acme',
        tokenEnc: ENVELOPE,
        azureAuth: 'pat',
      })
      .returning();
    return row!;
  };
  const makeProject = async (orgId: string) => {
    seq += 1;
    const [project] = await t.db
      .insert(projects)
      .values({ organizationId: orgId, key: `boards-p-${seq}`, name: `P ${seq}` })
      .returning();
    return project!;
  };
  const makeIssue = async () => {
    seq += 1;
    const [issue] = await t.db
      .insert(issues)
      .values({
        projectId,
        branchId,
        ruleId,
        fingerprint: String(seq).padStart(32, '0'),
        lineHash: 'a'.repeat(32),
        contextHash: 'b'.repeat(32),
        message: 'm',
        severity: 'high',
        quality: 'maintainability',
        kind: 'issue',
        firstSeenAt: new Date(),
      })
      .returning();
    return issue!;
  };
  const settings = (
    connectionId: string,
    over: Partial<typeof projectBoardsSettings.$inferInsert> = {},
  ) => ({
    projectId,
    connectionId,
    azureProjectId: AZURE_PROJECT,
    azureProjectName: 'Payments Team',
    workItemTypeRef: 'Microsoft.VSTS.WorkItemTypes.Bug',
    workItemTypeName: 'Bug',
    ...over,
  });
  const issueLink = (connectionId: string, issueId: string | null, over = {}) => ({
    projectId,
    connectionId,
    azureProjectId: AZURE_PROJECT,
    kind: 'issue' as const,
    issueId,
    state: 'pending' as const,
    origin: 'manual' as const,
    ...over,
  });
  const vulnLink = (connectionId: string, over = {}) => ({
    projectId,
    connectionId,
    azureProjectId: AZURE_PROJECT,
    kind: 'vulnerability' as const,
    packageName: 'lodash',
    vulnerabilityId: 'CVE-2021-23337',
    state: 'pending' as const,
    origin: 'manual' as const,
    ...over,
  });
  const clearMapping = () =>
    t.db.delete(projectBoardsSettings).where(eq(projectBoardsSettings.projectId, projectId));

  beforeAll(async () => {
    t = await createTestDatabase();
    organizationId = await makeOrganization();
    projectId = (await makeProject(organizationId)).id;
    const [branch] = await t.db
      .insert(branches)
      .values({ projectId, kind: 'branch', name: 'main' })
      .returning();
    branchId = branch!.id;
    const [rule] = await t.db
      .insert(rules)
      .values({
        key: 'eslint:no-console',
        engineId: 'eslint',
        engineRuleId: 'no-console',
        name: 'no-console',
        defaultSeverity: 'medium',
        quality: 'maintainability',
        kind: 'issue',
        origin: 'reported',
      })
      .returning();
    ruleId = rule!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  describe('accepts', () => {
    it('a mapping with 10 tags, the project roots (NULL paths) and the defaults', async () => {
      const conn = await makeConnection();
      await clearMapping();
      const [row] = await t.db
        .insert(projectBoardsSettings)
        .values(settings(conn.id, { tags: Array.from({ length: 10 }, (_, i) => `t${i}`) }))
        .returning();
      expect(row).toMatchObject({
        areaPath: null,
        iterationPath: null,
        autoMinSeverity: null,
        autoExploited: false,
        autoSince: null,
      });
      expect(row?.tags).toHaveLength(10);
      await clearMapping();
      const [bare] = await t.db.insert(projectBoardsSettings).values(settings(conn.id)).returning();
      expect(bare?.tags).toEqual([]);
    });

    it('a mapping with paths, and the rule on with auto_since', async () => {
      const conn = await makeConnection();
      await clearMapping();
      const [row] = await t.db
        .insert(projectBoardsSettings)
        .values(
          settings(conn.id, {
            areaPath: 'Payments Team\\Backend',
            iterationPath: 'Payments Team\\Iteration 1',
            autoMinSeverity: 'high',
            autoExploited: true,
            autoSince: new Date(),
          }),
        )
        .returning();
      expect(row?.areaPath).toBe('Payments Team\\Backend');
    });

    it('an issue link and a vulnerability link of one project, with their defaults', async () => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      const [a] = await t.db.insert(boardsLinks).values(issueLink(conn.id, issue.id)).returning();
      const [b] = await t.db
        .insert(boardsLinks)
        .values(vulnLink(conn.id, { packageName: 'defaults-pkg' }))
        .returning();
      expect(a).toMatchObject({
        azureProjectId: AZURE_PROJECT,
        generation: 1,
        missedPasses: 0,
        failure: null,
        workItemId: null,
        stateName: null,
        stateCategory: null,
        stateCheckedAt: null,
        createdBy: null,
      });
      expect(b?.kind).toBe('vulnerability');
    });

    it.each(['pending', 'created', 'failed', 'missing', 'dismissed'] as BoardsLinkState[])(
      'the state %s with a work item id',
      async (state) => {
        const conn = await makeConnection();
        const issue = await makeIssue();
        const [row] = await t.db
          .insert(boardsLinks)
          .values(issueLink(conn.id, issue.id, { state, workItemId: 42 }))
          .returning();
        expect(row?.state).toBe(state);
      },
    );

    it.each(['pending', 'failed', 'dismissed'] as BoardsLinkState[])(
      'the state %s without a work item id',
      async (state) => {
        const conn = await makeConnection();
        const issue = await makeIssue();
        await t.db.insert(boardsLinks).values(issueLink(conn.id, issue.id, { state }));
      },
    );

    it.each([
      'proposed',
      'inprogress',
      'resolved',
      'completed',
      'removed',
    ] as BoardsStateCategory[])('the state category %s', async (stateCategory) => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      const [row] = await t.db
        .insert(boardsLinks)
        .values(
          issueLink(conn.id, issue.id, {
            state: 'created',
            workItemId: 7,
            stateName: 'Active',
            stateCategory,
            stateCheckedAt: new Date(),
          }),
        )
        .returning();
      expect(row?.stateCategory).toBe(stateCategory);
    });

    it.each(['manual', 'auto'] as const)('the origin %s', async (origin) => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      await t.db.insert(boardsLinks).values(issueLink(conn.id, issue.id, { origin }));
    });
  });

  describe('refuses', () => {
    it.each([
      ['11 tags', { tags: Array.from({ length: 11 }, (_, i) => `t${i}`) }],
      [
        'an auto_min_severity "unknown"',
        { autoMinSeverity: 'unknown' as never, autoSince: new Date() },
      ],
      ['the rule on (a severity) without auto_since', { autoMinSeverity: 'high' as const }],
      ['the rule on (exploited) without auto_since', { autoExploited: true }],
      ['an upper-case project id', { azureProjectId: AZURE_PROJECT.toUpperCase() }],
      ['a project name as the project id', { azureProjectId: 'Payments Team' }],
    ])('a mapping with %s', async (_what, over) => {
      const conn = await makeConnection();
      await clearMapping();
      await expectPgError(
        t.db.insert(projectBoardsSettings).values(settings(conn.id, over)),
        PG_CHECK_VIOLATION,
      );
    });

    it('an issue link without issue_id, and a vulnerability link with one', async () => {
      const conn = await makeConnection();
      await expectPgError(
        t.db.insert(boardsLinks).values(issueLink(conn.id, null)),
        PG_CHECK_VIOLATION,
      );
      const issue = await makeIssue();
      await expectPgError(
        t.db.insert(boardsLinks).values(vulnLink(conn.id, { issueId: issue.id })),
        PG_CHECK_VIOLATION,
      );
    });

    it.each([
      ['created without a work_item_id', { state: 'created' as const }],
      ['missing without a work_item_id', { state: 'missing' as const }],
      ['the state "open"', { state: 'open' as never }],
      ['the origin "robot"', { origin: 'robot' as never }],
      ['the state_category "x"', { stateCategory: 'x' as never }],
      [
        'the state_category "InProgress" (Azure DevOps\' own case)',
        { stateCategory: 'InProgress' as never },
      ],
      ['the kind "epic"', { kind: 'epic' as never }],
      ['an upper-case Azure DevOps project id', { azureProjectId: AZURE_PROJECT.toUpperCase() }],
      ['a project name as the Azure DevOps project id', { azureProjectId: 'Payments Team' }],
    ])('a link with %s', async (_what, over) => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      await expectPgError(
        t.db.insert(boardsLinks).values(issueLink(conn.id, issue.id, over)),
        PG_CHECK_VIOLATION,
      );
    });

    it('a link without its Azure DevOps project', async () => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      await expectPgError(
        t.pool.query(
          `INSERT INTO boards_links (id, project_id, connection_id, kind, issue_id, state, origin)
           VALUES ($1, $2, $3, 'issue', $4, 'pending', 'manual')`,
          [uuidv7(), projectId, conn.id, issue.id],
        ),
        PG_NOT_NULL_VIOLATION,
      );
    });

    it('a second link of one issue, and a second link of one pair', async () => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      await t.db.insert(boardsLinks).values(issueLink(conn.id, issue.id));
      await expectPgError(
        t.db.insert(boardsLinks).values(issueLink(conn.id, issue.id)),
        PG_UNIQUE_VIOLATION,
      );
      await t.db.insert(boardsLinks).values(vulnLink(conn.id, { packageName: 'pair-pkg' }));
      await expectPgError(
        t.db.insert(boardsLinks).values(vulnLink(conn.id, { packageName: 'pair-pkg' })),
        PG_UNIQUE_VIOLATION,
      );
    });
  });

  describe('cascades', () => {
    it('deleting the Azure DevOps connection deletes its mappings and links', async () => {
      const orgId = await makeOrganization();
      const project = await makeProject(orgId);
      const conn = await makeConnection(orgId);
      await t.db
        .insert(projectBoardsSettings)
        .values({ ...settings(conn.id), projectId: project.id });
      await t.db.insert(boardsLinks).values({ ...vulnLink(conn.id), projectId: project.id });
      await t.db.delete(scmConnections).where(eq(scmConnections.id, conn.id));
      expect(
        await t.db
          .select()
          .from(projectBoardsSettings)
          .where(eq(projectBoardsSettings.projectId, project.id)),
      ).toEqual([]);
      expect(
        await t.db.select().from(boardsLinks).where(eq(boardsLinks.projectId, project.id)),
      ).toEqual([]);
    });

    it('deleting the project deletes its mapping and links', async () => {
      const orgId = await makeOrganization();
      const project = await makeProject(orgId);
      const conn = await makeConnection(orgId);
      await t.db
        .insert(projectBoardsSettings)
        .values({ ...settings(conn.id), projectId: project.id });
      await t.db.insert(boardsLinks).values({ ...vulnLink(conn.id), projectId: project.id });
      await t.db.delete(projects).where(eq(projects.id, project.id));
      expect(
        await t.db
          .select()
          .from(projectBoardsSettings)
          .where(eq(projectBoardsSettings.connectionId, conn.id)),
      ).toEqual([]);
      expect(
        await t.db.select().from(boardsLinks).where(eq(boardsLinks.connectionId, conn.id)),
      ).toEqual([]);
    });

    it('deleting an issue deletes its link', async () => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      const [link] = await t.db
        .insert(boardsLinks)
        .values(issueLink(conn.id, issue.id))
        .returning();
      await t.db.delete(issues).where(eq(issues.id, issue.id));
      expect(await t.db.select().from(boardsLinks).where(eq(boardsLinks.id, link!.id))).toEqual([]);
    });

    it('deleting the user sets created_by to NULL', async () => {
      const conn = await makeConnection();
      const [user] = await t.db
        .insert(users)
        .values({ username: `boards-user-${uuidv7()}` })
        .returning();
      const [link] = await t.db
        .insert(boardsLinks)
        .values(vulnLink(conn.id, { packageName: 'creator-pkg', createdBy: user!.id }))
        .returning();
      await t.db.delete(users).where(eq(users.id, user!.id));
      const [kept] = await t.db.select().from(boardsLinks).where(eq(boardsLinks.id, link!.id));
      expect(kept?.createdBy).toBeNull();
    });
  });

  it('indexes the pass in the state order: never read first', async () => {
    const { rows } = await t.pool.query<{ indexname: string; indexdef: string }>(
      `SELECT indexname, indexdef FROM pg_indexes
        WHERE schemaname = 'public' AND tablename IN ('boards_links', 'project_boards_settings')
        ORDER BY indexname`,
    );
    expect(
      Object.fromEntries(rows.map((r) => [r.indexname, r.indexdef.replace(/^.* USING /, '')])),
    ).toEqual({
      boards_links_created_by_idx: 'btree (created_by) WHERE (created_by IS NOT NULL)',
      boards_links_issue_uq: 'btree (issue_id)',
      boards_links_pass_idx: 'btree (connection_id, state, state_checked_at NULLS FIRST)',
      boards_links_pkey: 'btree (id)',
      boards_links_project_idx: 'btree (project_id)',
      boards_links_vulnerability_uq:
        "btree (project_id, package_name, vulnerability_id) WHERE (kind = 'vulnerability'::text)",
      project_boards_settings_connection_idx: 'btree (connection_id)',
      project_boards_settings_pkey: 'btree (project_id)',
    });
  });
});

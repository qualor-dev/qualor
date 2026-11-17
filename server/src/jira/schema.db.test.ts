import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, expectPgError, type TestDatabase } from '../../test/db';
import { PG_CHECK_VIOLATION, PG_UNIQUE_VIOLATION } from '../db/errors';
import { uuidv7 } from '../db/ids';
import {
  branches,
  issues,
  jiraConnections,
  jiraLinks,
  organizations,
  projectJiraSettings,
  projects,
  rules,
  users,
} from '../db/schema';

const ENVELOPE = { v: 1 as const, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' };

describe('the Jira tables (0.16 spec §7, migration 0032_jira)', () => {
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
      .values({ key: `jira-org-${seq}`, name: `Org ${seq}` })
      .returning();
    return org!.id;
  };
  const connection = (over: Partial<typeof jiraConnections.$inferInsert> = {}) => ({
    organizationId,
    deployment: 'data_center' as const,
    siteUrl: 'https://jira.example.com',
    tokenEnc: ENVELOPE,
    ...over,
  });
  const makeConnection = async (over: Partial<typeof jiraConnections.$inferInsert> = {}) => {
    const orgId = over.organizationId ?? (await makeOrganization());
    const [row] = await t.db
      .insert(jiraConnections)
      .values(connection({ organizationId: orgId, ...over }))
      .returning();
    return row!;
  };
  const makeProject = async (orgId: string) => {
    seq += 1;
    const [project] = await t.db
      .insert(projects)
      .values({ organizationId: orgId, key: `jira-p-${seq}`, name: `P ${seq}` })
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
    over: Partial<typeof projectJiraSettings.$inferInsert> = {},
  ) => ({
    projectId,
    connectionId,
    jiraProjectId: '10001',
    jiraProjectKey: 'QL',
    jiraProjectName: 'Qualor',
    issueTypeId: '10002',
    issueTypeName: 'Bug',
    labelsAvailable: true,
    priorityAvailable: true,
    ...over,
  });
  const issueLink = (connectionId: string, issueId: string | null, over = {}) => ({
    projectId,
    connectionId,
    kind: 'issue' as const,
    issueId,
    state: 'pending' as const,
    origin: 'manual' as const,
    ...over,
  });
  const vulnLink = (connectionId: string, over = {}) => ({
    projectId,
    connectionId,
    kind: 'vulnerability' as const,
    packageName: 'lodash',
    vulnerabilityId: 'CVE-2021-23337',
    state: 'pending' as const,
    origin: 'manual' as const,
    ...over,
  });

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
    it('a Cloud connection with an email and an api_url, and a Data Center one without either', async () => {
      const cloud = await makeConnection({
        deployment: 'cloud',
        siteUrl: 'https://acme.atlassian.net',
        apiUrl: 'https://api.atlassian.com/ex/jira/0b5f4f3e-8a43-4c6d-9d0e-0a3d2f2b7c11',
        email: 'ada@example.com',
      });
      expect(cloud).toMatchObject({ deployment: 'cloud', problem: null });
      const dc = await makeConnection();
      expect(dc).toMatchObject({ deployment: 'data_center', email: null, apiUrl: null });
    });

    it('a mapping with 10 labels and the rule on with auto_since', async () => {
      const conn = await makeConnection();
      await t.db.delete(projectJiraSettings).where(eq(projectJiraSettings.projectId, projectId));
      const [row] = await t.db
        .insert(projectJiraSettings)
        .values(
          settings(conn.id, {
            labels: Array.from({ length: 10 }, (_, i) => `l${i}`),
            autoMinSeverity: 'high',
            autoExploited: true,
            autoSince: new Date(),
          }),
        )
        .returning();
      expect(row?.labels).toHaveLength(10);
      expect(row?.priorities).toBeNull();
    });

    it('an issue link and a vulnerability link of one project, with their defaults', async () => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      const [a] = await t.db.insert(jiraLinks).values(issueLink(conn.id, issue.id)).returning();
      const [b] = await t.db.insert(jiraLinks).values(vulnLink(conn.id)).returning();
      expect(a).toMatchObject({ generation: 1, missedPasses: 0, failure: null, createdBy: null });
      expect(b?.kind).toBe('vulnerability');
    });
  });

  describe('refuses', () => {
    it.each([
      ['a Data Center connection with an email', { email: 'ada@example.com' }],
      [
        'a Data Center connection with an api_url',
        { apiUrl: 'https://api.atlassian.com/ex/jira/x' },
      ],
      ['a Cloud connection without an email', { deployment: 'cloud' as const }],
      ['the deployment "server"', { deployment: 'server' as never }],
    ])('%s', async (_what, over) => {
      const orgId = await makeOrganization();
      await expectPgError(
        t.db.insert(jiraConnections).values(connection({ organizationId: orgId, ...over })),
        PG_CHECK_VIOLATION,
      );
    });

    it('a second connection of one organisation', async () => {
      const first = await makeConnection();
      await expectPgError(
        t.db.insert(jiraConnections).values(connection({ organizationId: first.organizationId })),
        PG_UNIQUE_VIOLATION,
      );
    });

    it.each([
      ['11 labels', { labels: Array.from({ length: 11 }, (_, i) => `l${i}`) }],
      [
        'an auto_min_severity "unknown"',
        { autoMinSeverity: 'unknown' as never, autoSince: new Date() },
      ],
      ['the rule on (a severity) without auto_since', { autoMinSeverity: 'high' as const }],
      ['the rule on (exploited) without auto_since', { autoExploited: true }],
    ])('a mapping with %s', async (_what, over) => {
      const conn = await makeConnection();
      await t.db.delete(projectJiraSettings).where(eq(projectJiraSettings.projectId, projectId));
      await expectPgError(
        t.db.insert(projectJiraSettings).values(settings(conn.id, over)),
        PG_CHECK_VIOLATION,
      );
    });

    it('an issue link without issue_id, and a vulnerability link with one', async () => {
      const conn = await makeConnection();
      await expectPgError(
        t.db.insert(jiraLinks).values(issueLink(conn.id, null)),
        PG_CHECK_VIOLATION,
      );
      const issue = await makeIssue();
      await expectPgError(
        t.db.insert(jiraLinks).values(vulnLink(conn.id, { issueId: issue.id })),
        PG_CHECK_VIOLATION,
      );
    });

    it.each([
      ['created without a jira_key', { state: 'created' as const, jiraIssueId: '1' }],
      ['missing without a jira_issue_id', { state: 'missing' as const, jiraKey: 'QL-1' }],
      ['the state "open"', { state: 'open' as never }],
      ['the origin "robot"', { origin: 'robot' as never }],
      ['the status_category "todo"', { statusCategory: 'todo' as never }],
    ])('a link with %s', async (_what, over) => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      await expectPgError(
        t.db.insert(jiraLinks).values(issueLink(conn.id, issue.id, over)),
        PG_CHECK_VIOLATION,
      );
    });

    it('a second link of one issue, and a second link of one pair', async () => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      await t.db.insert(jiraLinks).values(issueLink(conn.id, issue.id));
      await expectPgError(
        t.db.insert(jiraLinks).values(issueLink(conn.id, issue.id)),
        PG_UNIQUE_VIOLATION,
      );
      await t.db.insert(jiraLinks).values(vulnLink(conn.id, { packageName: 'pair-pkg' }));
      await expectPgError(
        t.db.insert(jiraLinks).values(vulnLink(conn.id, { packageName: 'pair-pkg' })),
        PG_UNIQUE_VIOLATION,
      );
    });
  });

  describe('cascades', () => {
    it('deleting the connection deletes its mappings and links', async () => {
      const orgId = await makeOrganization();
      const project = await makeProject(orgId);
      const conn = await makeConnection({ organizationId: orgId });
      await t.db
        .insert(projectJiraSettings)
        .values({ ...settings(conn.id), projectId: project.id });
      await t.db.insert(jiraLinks).values({ ...vulnLink(conn.id), projectId: project.id });
      await t.db.delete(jiraConnections).where(eq(jiraConnections.id, conn.id));
      expect(
        await t.db
          .select()
          .from(projectJiraSettings)
          .where(eq(projectJiraSettings.projectId, project.id)),
      ).toEqual([]);
      expect(
        await t.db.select().from(jiraLinks).where(eq(jiraLinks.projectId, project.id)),
      ).toEqual([]);
    });

    it('deleting an issue deletes its link', async () => {
      const conn = await makeConnection();
      const issue = await makeIssue();
      const [link] = await t.db.insert(jiraLinks).values(issueLink(conn.id, issue.id)).returning();
      await t.db.delete(issues).where(eq(issues.id, issue.id));
      expect(await t.db.select().from(jiraLinks).where(eq(jiraLinks.id, link!.id))).toEqual([]);
    });

    it('deleting the user sets created_by to NULL', async () => {
      const conn = await makeConnection();
      const [user] = await t.db
        .insert(users)
        .values({ username: `jira-user-${uuidv7()}` })
        .returning();
      const [link] = await t.db
        .insert(jiraLinks)
        .values(vulnLink(conn.id, { packageName: 'creator-pkg', createdBy: user!.id }))
        .returning();
      await t.db.delete(users).where(eq(users.id, user!.id));
      const [kept] = await t.db.select().from(jiraLinks).where(eq(jiraLinks.id, link!.id));
      expect(kept?.createdBy).toBeNull();
    });
  });
});

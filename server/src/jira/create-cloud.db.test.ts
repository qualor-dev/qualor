import { eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { jiraJobDeps } from '../../test/jira';
import { trustTestCa } from '../../test/tls';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { jiraConnections, jiraLinks, projectJiraSettings } from '../db/schema';
import { JiraClient } from './client';
import { JIRA_TOKEN_AAD, type JiraConnectionRow } from './connection';
import { createPending } from './create';
import type { JiraRunContext } from './run';

const QUAL = { id: '10000', key: 'QUAL', name: 'Qualor findings' };

/**
 * R15: Cloud mode at the job level. The run's client is a Cloud client of an https fake on
 * 127.0.0.1 (the test CA trusted); the stored connection is a Cloud row no production seam could
 * reach this way, so `jiraClientFor` is not used.
 */
describe('the Jira create job on Cloud (R15)', () => {
  let h: IngestHarness;
  let fake: FakeJira;
  let untrust: () => void;
  let projectId: string;
  let main: string;
  let codeRule: string;
  let connection: JiraConnectionRow;

  const db = () => h.ctx.db;
  const context = (): JiraRunContext => ({
    deps: jiraJobDeps(h),
    connection,
    client: new JiraClient(
      {
        deployment: 'cloud',
        apiBase: fake.url,
        auth: { kind: 'basic', email: fake.email, token: fake.token },
        allowInternalHosts: true,
      },
      { timeoutMs: 1_000 },
    ),
  });
  const request = async (issueIds: string[]): Promise<string[]> => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${projectId}/jira/links`,
      headers: h.orgAdmin.headers,
      payload: { issueIds },
    });
    expect(res.statusCode, res.body).toBe(202);
    return (res.json() as { items: { link: { id: string } }[] }).items.map((i) => i.link.id);
  };
  const issue = (message: string) =>
    seedIssue(db(), { projectId, branchId: main, ruleId: codeRule, message });

  beforeAll(async () => {
    untrust = trustTestCa();
    fake = await createFakeJira({ deployment: 'cloud', https: true });
    fake.addProject(QUAL);
    h = await createIngestHarness();
    projectId = (await h.project('JCC')).id;
    main = await mainBranchId(db(), projectId);
    codeRule = await seedRule(db(), { key: 'eslint:no-eval' });
    const [row] = await db()
      .insert(jiraConnections)
      .values({
        organizationId: h.organizationId,
        deployment: 'cloud',
        siteUrl: 'https://acme.atlassian.net',
        email: fake.email,
        tokenEnc: encryptSecret(encryptionKey(h.ctx.config.secretKey), fake.token, JIRA_TOKEN_AAD),
      })
      .returning();
    connection = row!;
    await db().insert(projectJiraSettings).values({
      projectId,
      connectionId: connection.id,
      jiraProjectId: QUAL.id,
      jiraProjectKey: QUAL.key,
      jiraProjectName: QUAL.name,
      issueTypeId: '10001',
      issueTypeName: 'Bug',
      labels: [],
      labelsAvailable: true,
      priorityAvailable: true,
    });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
    untrust();
  });

  it('partial (spec §11.3): the bulk path with Basic auth, then the status read through search/jql', async () => {
    const messages = Array.from({ length: 7 }, (_, i) => `cloud finding ${i}`);
    const issueIds: string[] = [];
    for (const m of messages) issueIds.push(await issue(m));
    const linkIds = await request(issueIds);
    fake.rejectElements([2, 5]);
    fake.clearRequests();

    expect(await createPending(context())).toEqual({
      created: 5,
      failed: 2,
      unanswered: 0,
      stop: null,
    });
    expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      'POST /rest/api/2/issue/bulk',
      'POST /rest/api/2/search/jql',
    ]);
    const basic = `Basic ${Buffer.from(`${fake.email}:${fake.token}`).toString('base64')}`;
    expect(fake.requests.every((r) => r.headers.authorization === basic)).toBe(true);
    const search = JSON.parse(fake.requests[1]!.body) as { jql: string; nextPageToken?: string };
    expect(search.jql).toMatch(/^id in \(\d+(,\d+){4}\)$/);

    const stored = await db().select().from(jiraLinks).where(inArray(jiraLinks.id, linkIds));
    const created = stored.filter((r) => r.state === 'created');
    expect(created).toHaveLength(5);
    for (const r of created) {
      expect(fake.issue(r.jiraKey!)?.fields['summary']).toBe(
        messages[issueIds.indexOf(r.issueId!)],
      );
      expect(r).toMatchObject({ statusName: 'To Do', statusCategory: 'new' });
      expect(r.statusCheckedAt).not.toBeNull();
    }
    const failed = stored.filter((r) => r.state === 'failed');
    expect(failed.map((r) => r.failure)).toEqual([
      { code: 'field_refused', message: 'Components is required.' },
      { code: 'field_refused', message: 'Components is required.' },
    ]);
  });

  it('never the token or the email (spec §11.5): a 400 that echoes the Basic credential', async () => {
    const basic = Buffer.from(`${fake.email}:${fake.token}`).toString('base64');
    const [linkId] = await request([await issue('echoed')]);
    fake.inject('POST', /\/rest\/api\/2\/issue$/, {
      status: 400,
      body: {
        errorMessages: [`Authorization: Basic ${basic}`],
        errors: { reporter: `No account ${fake.email} (${fake.token})` },
      },
    });
    expect(await createPending(context())).toMatchObject({ failed: 1, stop: null });
    const [stored] = await db().select().from(jiraLinks).where(eq(jiraLinks.id, linkId!));
    expect(stored?.failure?.code).toBe('field_refused');
    for (const secret of [fake.token, fake.email, basic]) {
      expect(stored?.failure?.message).not.toContain(secret);
    }
  });
});

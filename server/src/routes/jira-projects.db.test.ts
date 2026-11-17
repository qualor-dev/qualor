import { and, eq, gt, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session } from '../../test/app';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { connectJira, jiraTestConfig, mapJira, seedJiraLink } from '../../test/jira';
import { rbacPlugins } from '../../test/rbac';
import { trustTestCa } from '../../test/tls';
import { auditEvents, jiraConnections, jiraLinks, jobs, projectJiraSettings } from '../db/schema';
import { JIRA_QUEUE } from '../jira/jobs';
import { JIRA_PROBLEM_TEXT } from '../jira/problems';

const NOW = new Date('2027-01-01T00:00:00Z');

describe('the project Jira mapping (0.16 Jira §6.2, §6.8)', () => {
  let h: IngestHarness;
  let fake: FakeJira;
  let viewer: Session;
  let member: Session;
  let outsider: Session;
  let connectionId: string;
  let projectId: string;
  let untrust: () => void;
  /** Whether the test edition licenses `vuln.priority`. */
  let priorityLicensed = false;
  let since = 0;
  const url = (suffix = '') => `/api/v0/projects/${projectId}/jira${suffix}`;
  const call = (
    method: 'GET' | 'PUT' | 'DELETE',
    path: string,
    payload?: object,
    headers: Record<string, string> = h.orgAdmin.headers,
  ) =>
    h.ctx.app.inject({
      method,
      url: path,
      headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const body = (over: object = {}) => ({
    jiraProject: { id: '10000', key: 'QUAL', name: 'Qualor findings' },
    issueType: { id: '10001', name: 'Bug' },
    labels: [],
    priorities: null,
    autoCreate: { minSeverity: null, exploited: false },
    ...over,
  });
  const put = (over: object = {}, headers?: Record<string, string>) =>
    call('PUT', url(), body(over), headers);
  const paths = (res: { json(): unknown }) =>
    (res.json() as { errors: { path: string }[] }).errors.map((e) => e.path);
  const events = async () =>
    (
      await h.ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, 'project.jira_updated'), gt(auditEvents.seq, since)))
        .orderBy(auditEvents.seq)
    ).map((e) => e.details);
  const stored = async () =>
    (
      await h.ctx.db
        .select()
        .from(projectJiraSettings)
        .where(eq(projectJiraSettings.projectId, projectId))
    )[0];
  const connect = async () => {
    connectionId = await connectJira(h, fake);
  };
  const lastSeq = async () =>
    Number(
      (
        await h.ctx.db
          .select({ seq: sql<number>`coalesce(max(${auditEvents.seq}), 0)` })
          .from(auditEvents)
      )[0]?.seq ?? 0,
    );

  beforeAll(async () => {
    untrust = trustTestCa();
    fake = await createFakeJira({ deployment: 'data_center' });
    fake.addProject({ id: '10000', key: 'QUAL', name: 'Qualor findings' });
    h = await createIngestHarness({
      config: jiraTestConfig(fake),
      pluginsFor: rbacPlugins({
        now: () => NOW,
        edition: (edition) => ({
          ...edition,
          limits: () => ({
            ...edition.limits(),
            vulnerabilities: { ...edition.limits().vulnerabilities, priority: priorityLicensed },
          }),
        }),
      }),
    });
    const make = async (username: string, role?: 'viewer' | 'member') => {
      const user = await createUser(h.ctx, { username });
      if (role) await addMember(h.ctx, h.organizationId, user.id, role);
      return login(h.ctx, user.username, user.password);
    };
    viewer = await make('jp-viewer', 'viewer');
    member = await make('jp-member', 'member');
    outsider = await make('jp-outsider');
    projectId = (await h.project('JP')).id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
    untrust();
  });
  beforeEach(async () => {
    priorityLicensed = false;
    since = await lastSeq();
  });
  afterEach(async () => {
    fake.clearRequests();
    await h.ctx.db.delete(jiraConnections);
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, JIRA_QUEUE));
  });

  const monitoring = (enabled: boolean) =>
    call('PUT', `/api/v0/projects/${projectId}/vulnerability-monitoring`, {
      enabled,
      branchPatterns: [],
      versionRule: { kind: 'none' },
      labelVersions: false,
    });

  it('GET: a viewer sees no mapping, the connection and the monitoring state', async () => {
    await connect();
    expect((await monitoring(false)).statusCode).toBe(200);
    const res = await call('GET', url(), undefined, viewer.headers);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      mapping: null,
      connection: { deployment: 'data_center', siteUrl: fake.url, problem: null },
      monitoringOn: false,
      exploitedAvailable: false,
    });
  });

  it('GET: without a connection the connection is null; monitoring is on by default', async () => {
    expect((await monitoring(true)).statusCode).toBe(200);
    const res = await call('GET', url(), undefined, viewer.headers);
    expect(res.json()).toEqual({
      mapping: null,
      connection: null,
      monitoringOn: true,
      exploitedAvailable: false,
    });
  });

  it('GET: exploitedAvailable follows vuln.priority', async () => {
    priorityLicensed = true;
    const res = await call('GET', url(), undefined, viewer.headers);
    expect(res.json()).toMatchObject({ exploitedAvailable: true });
  });

  describe('the picker', () => {
    it('lists the matching projects, at most 50', async () => {
      for (let n = 1; n <= 60; n++) {
        fake.addProject({
          id: String(20_000 + n),
          key: `PAY${n}`,
          name: n % 2 === 0 ? `Payments ${n}` : `Billing ${n}`,
        });
      }
      await connect();
      const res = await call('GET', url('/projects?query=pay'));
      expect(res.statusCode, res.body).toBe(200);
      const { items } = res.json() as { items: { id: string; key: string; name: string }[] };
      expect(items).toHaveLength(50);
      expect(items.every((p) => /pay/i.test(`${p.key} ${p.name}`))).toBe(true);
      expect(Object.keys(items[0]!).sort()).toEqual(['id', 'key', 'name']);
      const one = await call('GET', url('/projects?query=QUAL'));
      expect((one.json() as { items: { key: string }[] }).items.map((p) => p.key)).toEqual([
        'QUAL',
      ]);
    });

    it('answers 409 JIRA_NOT_CONNECTED without a connection', async () => {
      const res = await call('GET', url('/projects'));
      expect(res.statusCode).toBe(409);
      expect(res.json()).toMatchObject({ code: 'JIRA_NOT_CONNECTED' });
    });

    it("answers 502 JIRA_UNAVAILABLE with the fixed text, never Jira's words, and records the problem", async () => {
      await connect();
      fake.inject('GET', /\/rest\/api\/2\/project$/, {
        status: 401,
        body: { errorMessages: ['Jira says: go away'] },
      });
      const res = await call('GET', url('/projects?query=q'));
      expect(res.statusCode).toBe(502);
      expect(res.json()).toMatchObject({
        code: 'JIRA_UNAVAILABLE',
        detail: JIRA_PROBLEM_TEXT.token_refused,
      });
      expect(res.body).not.toContain('go away');
      const [row] = await h.ctx.db.select().from(jiraConnections);
      expect(row?.problem).toMatchObject({ code: 'token_refused' });
    });

    it('does not record a failure that is not about the credential', async () => {
      await connect();
      fake.inject('GET', /\/rest\/api\/2\/project$/, { status: 404, body: {} });
      const res = await call('GET', url('/projects'));
      expect(res.statusCode).toBe(502);
      expect(res.json()).toMatchObject({ detail: JIRA_PROBLEM_TEXT.not_found });
      const [row] = await h.ctx.db.select().from(jiraConnections);
      expect(row?.problem).toBeNull();
    });

    it('rejects a query over 100 characters', async () => {
      await connect();
      const res = await call('GET', url(`/projects?query=${'a'.repeat(101)}`));
      expect(res.statusCode).toBe(422);
    });
  });

  describe('the issue types', () => {
    it('lists Bug and Story, never Sub-task, with what Qualor cannot fill', async () => {
      await connect();
      const res = await call('GET', url('/issue-types?jiraProject=QUAL'));
      expect(res.statusCode, res.body).toBe(200);
      const { items } = res.json() as {
        items: {
          id: string;
          name: string;
          supported: boolean;
          missingFields: string[];
          labels: boolean;
          priority: { allowed: { id: string; name: string }[]; required: boolean } | null;
        }[];
      };
      expect(items.map((t) => t.name)).toEqual(['Bug', 'Story']);
      const [bug, story] = items;
      expect(bug).toMatchObject({ id: '10001', supported: true, missingFields: [], labels: true });
      expect(bug?.priority?.required).toBe(false);
      expect(bug?.priority?.allowed.map((p) => p.id)).toEqual(['1', '2', '3', '4', '5']);
      expect(story).toMatchObject({ supported: false, missingFields: ['Components'] });
    });

    it('answers 409 without a connection and 502 when Jira refuses', async () => {
      const none = await call('GET', url('/issue-types?jiraProject=QUAL'));
      expect(none.statusCode).toBe(409);
      expect(none.json()).toMatchObject({ code: 'JIRA_NOT_CONNECTED' });
      await connect();
      fake.inject('GET', /\/createmeta\//, { status: 403, body: {} });
      const refused = await call('GET', url('/issue-types?jiraProject=QUAL'));
      expect(refused.statusCode).toBe(502);
      expect(refused.json()).toMatchObject({ detail: JIRA_PROBLEM_TEXT.permission_missing });
    });

    it('rejects a project key that is not one', async () => {
      await connect();
      const res = await call('GET', url('/issue-types?jiraProject=a%20b'));
      expect(res.statusCode).toBe(422);
    });
  });

  describe('saving', () => {
    it('stores the mapping with what the screen has and audits it as created', async () => {
      await connect();
      const res = await put({ labels: ['sec'], priorities: { blocker: '1' } });
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toMatchObject({
        mapping: {
          jiraProject: { id: '10000', key: 'QUAL', name: 'Qualor findings' },
          issueType: { id: '10001', name: 'Bug' },
          labels: ['sec'],
          priorities: { blocker: '1' },
          labelsAvailable: true,
          priorityAvailable: true,
          autoCreate: { minSeverity: null, exploited: false, since: null },
        },
        connection: { deployment: 'data_center' },
      });
      expect(await stored()).toMatchObject({
        connectionId,
        labels: ['sec'],
        priorities: { blocker: '1' },
        autoSince: null,
      });
      expect(await events()).toEqual([{ changed: ['mapping'] }]);
      const again = await call('GET', url(), undefined, viewer.headers);
      expect((again.json() as { mapping: unknown }).mapping).not.toBeNull();
    });

    it('lists what changed on an update, nothing when nothing did', async () => {
      await connect();
      const rule = { minSeverity: 'high', exploited: false };
      await put({ labels: ['sec'] });
      await put({ labels: ['sec'] });
      await put({ labels: ['sec', 'qa'], autoCreate: rule });
      await put({ labels: ['sec', 'qa'], priorities: { high: '2' }, autoCreate: rule });
      expect(await events()).toEqual([
        { changed: ['mapping'] },
        { changed: ['labels', 'autoCreate'] },
        { changed: ['priorities'] },
      ]);
    });

    it('records a changed Jira project', async () => {
      fake.addProject({ id: '10050', key: 'OTHER', name: 'Other' });
      await connect();
      await put();
      const res = await put({ jiraProject: { id: '10050', key: 'OTHER', name: 'Other' } });
      expect(res.statusCode, res.body).toBe(200);
      expect((await events()).at(-1)).toEqual({ changed: ['jiraProject'] });
    });

    it("stores the issue type's name as Jira has it, not as sent", async () => {
      await connect();
      const res = await put({ issueType: { id: '10001', name: 'Not a bug' } });
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toMatchObject({ mapping: { issueType: { id: '10001', name: 'Bug' } } });
    });
  });

  describe('refusing', () => {
    it('refuses a type Qualor cannot fill, listing the fields', async () => {
      await connect();
      const res = await put({ issueType: { id: '10002', name: 'Story' } });
      expect(res.statusCode).toBe(422);
      expect(res.json()).toMatchObject({
        code: 'JIRA_ISSUE_TYPE_UNSUPPORTED',
        missingFields: ['Components'],
      });
      expect(await stored()).toBeUndefined();
      expect(await events()).toEqual([]);
    });

    it('refuses a priority Jira does not offer, and a sub-task', async () => {
      await connect();
      const priority = await put({ priorities: { blocker: '9' } });
      expect(priority.statusCode).toBe(422);
      expect(paths(priority)).toEqual(['body.priorities.blocker']);
      const subtask = await put({ issueType: { id: '10003', name: 'Sub-task' } });
      expect(subtask.statusCode).toBe(422);
      expect(paths(subtask)).toEqual(['body.issueType.id']);
    });

    it('validates the shape of the body', async () => {
      await connect();
      const bad = [
        { labels: Array.from({ length: 11 }, (_, i) => `l${i}`) },
        { labels: ['has space'] },
        { labels: ['x'.repeat(101)] },
        { labels: ['dup', 'dup'] },
        { jiraProject: { id: 'abc', key: 'QUAL', name: 'x' } },
        { jiraProject: { id: '10000', key: '1BAD', name: 'x' } },
        { issueType: { id: '1x', name: 'Bug' } },
        { priorities: { blocker: 'high' } },
        { autoCreate: { minSeverity: 'unknown', exploited: false } },
      ];
      for (const over of bad) {
        const res = await put(over);
        expect(res.statusCode, JSON.stringify(over)).toBe(422);
      }
      expect(await stored()).toBeUndefined();
    });

    it('answers 409 JIRA_NOT_CONNECTED without a connection', async () => {
      const res = await put();
      expect(res.statusCode).toBe(409);
      expect(res.json()).toMatchObject({ code: 'JIRA_NOT_CONNECTED' });
    });

    it('answers 502 with the fixed text when Jira fails, and stores nothing', async () => {
      await connect();
      fake.inject('GET', /\/createmeta\//, {
        status: 401,
        body: { errorMessages: ['secret words'] },
      });
      const res = await put();
      expect(res.statusCode).toBe(502);
      expect(res.json()).toMatchObject({
        code: 'JIRA_UNAVAILABLE',
        detail: JIRA_PROBLEM_TEXT.token_refused,
      });
      expect(res.body).not.toContain('secret words');
      expect(await stored()).toBeUndefined();
      const [row] = await h.ctx.db.select().from(jiraConnections);
      expect(row?.problem).toMatchObject({ code: 'token_refused' });
    });
  });

  describe('the automatic rule', () => {
    it('refuses turning exploited on without vuln.priority, keeps a stored true (R10)', async () => {
      await connect();
      const on = { minSeverity: null, exploited: true };
      const refused = await put({ autoCreate: on });
      expect(refused.statusCode).toBe(403);
      expect(refused.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
      expect(await stored()).toBeUndefined();

      priorityLicensed = true;
      const allowed = await put({ autoCreate: on });
      expect(allowed.statusCode, allowed.body).toBe(200);
      expect(await stored()).toMatchObject({ autoExploited: true });

      priorityLicensed = false;
      const kept = await put({ autoCreate: on });
      expect(kept.statusCode, kept.body).toBe(200);
      expect(kept.json()).toMatchObject({ mapping: { autoCreate: { exploited: true } } });
      expect(await stored()).toMatchObject({ autoExploited: true });
    });

    it('sets since whenever the rule changes, and clears it when the rule goes off', async () => {
      await connect();
      const high = { minSeverity: 'high', exploited: false };
      expect((await put()).statusCode).toBe(200);
      expect((await stored())?.autoSince).toBeNull();

      await put({ autoCreate: high });
      expect((await stored())?.autoSince).toBeInstanceOf(Date);

      const old = new Date('2026-01-01T00:00:00Z');
      await h.ctx.db
        .update(projectJiraSettings)
        .set({ autoSince: old })
        .where(eq(projectJiraSettings.projectId, projectId));
      await put({ labels: ['sec'], autoCreate: high });
      expect((await stored())?.autoSince?.getTime()).toBe(old.getTime());
      expect((await events()).at(-1)).toEqual({ changed: ['labels'] });

      await put({ labels: ['sec'], autoCreate: { minSeverity: 'medium', exploited: false } });
      expect((await stored())?.autoSince?.getTime()).toBeGreaterThan(old.getTime());

      await put({ labels: ['sec'], autoCreate: { minSeverity: null, exploited: false } });
      expect(await stored()).toMatchObject({ autoMinSeverity: null, autoSince: null });
    });
  });

  describe('removing', () => {
    it('answers 204, keeps the links and audits mapping', async () => {
      await connect();
      await mapJira(h, projectId);
      const link = await seedJiraLink(h.ctx.db, { projectId, connectionId });
      since = await lastSeq();
      const res = await call('DELETE', url());
      expect(res.statusCode).toBe(204);
      expect(await stored()).toBeUndefined();
      expect(await h.ctx.db.select().from(jiraLinks).where(eq(jiraLinks.id, link))).toHaveLength(1);
      expect(await events()).toEqual([{ changed: ['mapping'] }]);
    });

    it('answers 404 without a mapping and records nothing (P15)', async () => {
      await connect();
      const res = await call('DELETE', url());
      expect(res.statusCode).toBe(404);
      expect(await events()).toEqual([]);
    });
  });

  describe('access', () => {
    it('refuses a member the settings routes and a non-member everything', async () => {
      await connect();
      for (const [method, path, payload] of [
        ['PUT', url(), body()],
        ['DELETE', url(), undefined],
        ['GET', url('/projects'), undefined],
        ['GET', url('/issue-types?jiraProject=QUAL'), undefined],
      ] as const) {
        const asMember = await call(method, path, payload, member.headers);
        expect(asMember.statusCode, `${method} ${path}`).toBe(403);
        const asOutsider = await call(method, path, payload, outsider.headers);
        expect(asOutsider.statusCode, `${method} ${path}`).toBe(404);
      }
      expect((await call('GET', url(), undefined, outsider.headers)).statusCode).toBe(404);
      expect((await call('GET', url(), undefined, member.headers)).statusCode).toBe(200);
    });
  });
});

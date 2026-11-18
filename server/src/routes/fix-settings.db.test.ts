import { and, eq, gt, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { enableFixes } from '../../test/fixes';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { rbacPlugins } from '../../test/rbac';
import { mappedProject, scmTestConfig } from '../../test/scm';
import {
  auditEvents,
  jobs,
  projectFixSettings,
  projectMemberships,
  projects,
  scmConnections,
} from '../db/schema';
import { FIX_QUEUE } from '../fixes/jobs';
import { requireFixesUsable } from '../fixes/settings';

const NOW = new Date('2027-01-01T00:00:00Z');

describe('the project fix MR settings (0.16 fix MRs §6.1)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let viewer: Session;
  let member: Session;
  let outsider: Session;
  let projectId: string;
  let projectToken: string;
  let priorityLicensed = false;
  let since = 0;
  const url = (id = projectId) => `/api/v0/projects/${id}/fixes/settings`;
  const call = (
    method: 'GET' | 'PUT',
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
    enabled: true,
    autoCreate: { minSeverity: null, exploited: false },
    maxOpen: 5,
    ...over,
  });
  const put = (over: object = {}, headers?: Record<string, string>, id = projectId) =>
    call('PUT', url(id), body(over), headers);
  const stored = async (id = projectId) =>
    (
      await h.ctx.db.select().from(projectFixSettings).where(eq(projectFixSettings.projectId, id))
    )[0];
  const events = async () =>
    (
      await h.ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, 'project.fixes_updated'), gt(auditEvents.seq, since)))
        .orderBy(auditEvents.seq)
    ).map((e) => e.details);
  const syncJobs = () =>
    h.ctx.db
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, FIX_QUEUE), eq(jobs.status, 'queued')));
  const lastSeq = async () =>
    Number(
      (
        await h.ctx.db
          .select({ seq: sql<number>`coalesce(max(${auditEvents.seq}), 0)` })
          .from(auditEvents)
      )[0]?.seq ?? 0,
    );
  const monitoring = (id: string, enabled: boolean) =>
    call('PUT', `/api/v0/projects/${id}/vulnerability-monitoring`, {
      enabled,
      branchPatterns: [],
      versionRule: { kind: 'none' },
      labelVersions: false,
    });
  const projectRow = async (id: string) =>
    (await h.ctx.db.select().from(projects).where(eq(projects.id, id)))[0]!;

  beforeAll(async () => {
    fake = await createFakeGitLab();
    fake.addProject({ id: 11, path: 'acme/fixes/one' });
    h = await createIngestHarness({
      config: scmTestConfig(fake),
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
    viewer = await make('fs-viewer', 'viewer');
    member = await make('fs-member', 'member');
    outsider = await make('fs-outsider');
    const project = await h.project('FS');
    projectId = project.id;
    projectToken = project.token;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    priorityLicensed = false;
    since = await lastSeq();
  });
  afterEach(async () => {
    await h.ctx.db.delete(projectFixSettings);
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, FIX_QUEUE));
  });

  it('defaults: off, five open at most, nothing bound or claimed, no fixes', async () => {
    const res = await call('GET', url(), undefined, viewer.headers);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      settings: {
        enabled: false,
        autoCreate: { minSeverity: null, exploited: false, since: null },
        maxOpen: 5,
        updatedAt: null,
      },
      preconditions: {
        scmBound: false,
        provider: null,
        fixMrsAllowed: false,
        monitoringOn: true,
        lastClaimAt: null,
      },
      counts: { requested: 0, preparing: 0, committing: 0, open: 0 },
      exploitedAvailable: false,
    });
  });

  it('saves the settings, sets since, records the change and queues one pass', async () => {
    const res = await put({ autoCreate: { minSeverity: 'high', exploited: false }, maxOpen: 3 });
    expect(res.statusCode, res.body).toBe(200);
    const row = await stored();
    expect(row).toMatchObject({
      enabled: true,
      autoMinSeverity: 'high',
      autoExploited: false,
      maxOpen: 3,
    });
    expect(row?.autoSince).toBeInstanceOf(Date);
    expect(res.json().settings).toMatchObject({
      enabled: true,
      autoCreate: { minSeverity: 'high', exploited: false, since: row?.autoSince?.toISOString() },
      maxOpen: 3,
    });
    expect(await events()).toEqual([{ changed: ['enabled', 'autoCreate', 'maxOpen'] }]);
    const queued = await syncJobs();
    expect(queued).toHaveLength(1);
    expect(queued[0]?.payload).toEqual({ kind: 'sync', organizationId: h.organizationId });
  });

  it('keeps since while only maxOpen changes and clears it when the rule goes off', async () => {
    await put({ autoCreate: { minSeverity: 'high', exploited: false } });
    const first = (await stored())?.autoSince;
    since = await lastSeq();
    await put({ autoCreate: { minSeverity: 'high', exploited: false }, maxOpen: 7 });
    expect((await stored())?.autoSince?.getTime()).toBe(first?.getTime());
    expect(await events()).toEqual([{ changed: ['maxOpen'] }]);
    since = await lastSeq();
    await put({ maxOpen: 7 });
    expect((await stored())?.autoSince).toBeNull();
    expect(await events()).toEqual([{ changed: ['autoCreate'] }]);
    since = await lastSeq();
    await put({ maxOpen: 7 });
    expect(await events()).toEqual([]);
  });

  it('turns exploited on only with vuln.priority; a stored true is sent back freely', async () => {
    const refused = await put({ autoCreate: { minSeverity: null, exploited: true } });
    expect(refused.statusCode).toBe(403);
    expect(refused.json().code).toBe('FEATURE_NOT_LICENSED');
    expect(await stored()).toBeUndefined();
    priorityLicensed = true;
    expect((await call('GET', url())).json().exploitedAvailable).toBe(true);
    const on = await put({ autoCreate: { minSeverity: null, exploited: true } });
    expect(on.statusCode, on.body).toBe(200);
    expect((await stored())?.autoSince).toBeInstanceOf(Date);
    priorityLicensed = false;
    const again = await put({ autoCreate: { minSeverity: null, exploited: true }, maxOpen: 4 });
    expect(again.statusCode, again.body).toBe(200);
    expect((await stored())?.autoExploited).toBe(true);
  });

  it('bounds maxOpen to 1-20', async () => {
    expect((await put({ maxOpen: 0 })).statusCode).toBe(422);
    expect((await put({ maxOpen: 21 })).statusCode).toBe(422);
    expect((await put({ maxOpen: 1 })).statusCode).toBe(200);
    expect((await put({ maxOpen: 20 })).statusCode).toBe(200);
  });

  it('reports the preconditions of a project bound to an allowing GitLab connection', async () => {
    const bound = await mappedProject(h, fake, 'FS-BOUND', 11, { ownConnection: true });
    await h.ctx.db
      .update(scmConnections)
      .set({ fixMrsAllowed: true })
      .where(eq(scmConnections.id, bound.connectionId));
    const res = await call('GET', url(bound.id), undefined, viewer.headers);
    expect(res.json().preconditions).toEqual({
      scmBound: true,
      provider: 'gitlab',
      fixMrsAllowed: true,
      monitoringOn: true,
      lastClaimAt: null,
    });
    await enableFixes(h, bound.id);
    await h.ctx.db
      .update(projectFixSettings)
      .set({ lastClaimAt: NOW })
      .where(eq(projectFixSettings.projectId, bound.id));
    expect((await call('GET', url(bound.id))).json().preconditions.lastClaimAt).toBe(
      NOW.toISOString(),
    );
    expect((await monitoring(bound.id, false)).statusCode).toBe(200);
    expect((await call('GET', url(bound.id))).json().preconditions.monitoringOn).toBe(false);
  });

  it('refuses a member and a project token the PUT, a non-member everything', async () => {
    const asMember = await put({}, member.headers);
    expect(asMember.statusCode).toBe(403);
    const asOutsider = await put({}, outsider.headers);
    expect(asOutsider.statusCode).toBe(404);
    expect((await call('GET', url(), undefined, outsider.headers)).statusCode).toBe(404);
    expect((await call('GET', url(), undefined, member.headers)).statusCode).toBe(200);
    for (const method of ['GET', 'PUT'] as const) {
      const res = await call(
        method,
        url(),
        method === 'PUT' ? body() : undefined,
        bearer(projectToken),
      );
      expect(res.statusCode, method).toBe(403);
      expect(res.json().code).toBe('TOKEN_NOT_ALLOWED');
    }
    expect(await stored()).toBeUndefined();
  });

  it('lets a project admin who is only an organisation member save', async () => {
    const user = await createUser(h.ctx, { username: 'fs-padmin' });
    await addMember(h.ctx, h.organizationId, user.id, 'member');
    await h.ctx.db
      .insert(projectMemberships)
      .values({ projectId, userId: user.id, role: 'project_admin' });
    const session = await login(h.ctx, user.username, user.password);
    expect((await put({}, session.headers)).statusCode).toBe(200);
  });

  describe('requireFixesUsable', () => {
    it('answers the first failing precondition with its 409', async () => {
      const unbound = await projectRow(projectId);
      const code = async (project: typeof unbound) =>
        requireFixesUsable(h.ctx.db, project).then(
          () => 'usable',
          (err: { code?: string; status?: number }) => `${err.status}:${err.code}`,
        );
      expect(await code(unbound)).toBe('409:FIXES_DISABLED');
      await put({ enabled: false });
      expect(await code(unbound)).toBe('409:FIXES_DISABLED');
      await put({ enabled: true });
      expect(await code(unbound)).toBe('409:SCM_NOT_BOUND');
      const bound = await mappedProject(h, fake, 'FS-USABLE', 11, { ownConnection: true });
      await put({}, undefined, bound.id);
      expect(await code(await projectRow(bound.id))).toBe('409:FIX_MRS_NOT_ALLOWED');
      await h.ctx.db
        .update(scmConnections)
        .set({ fixMrsAllowed: true })
        .where(eq(scmConnections.id, bound.connectionId));
      expect((await monitoring(bound.id, false)).statusCode).toBe(200);
      expect(await code(await projectRow(bound.id))).toBe('409:MONITORING_OFF');
      expect((await monitoring(bound.id, true)).statusCode).toBe(200);
      expect(await code(await projectRow(bound.id))).toBe('usable');
    });
  });
});

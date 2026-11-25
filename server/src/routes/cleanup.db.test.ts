import { and, eq, gt, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  createProject,
  createUser,
  login,
  type Session,
} from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { rbacPlugins } from '../../test/rbac';
import { auditEvents, instanceSettings, projects } from '../db/schema';
import { CLEANUP_SETTINGS_KEY } from '../cleanup/settings';

const NOW = new Date('2027-01-01T00:00:00Z');

describe('the cleanup settings of the server and of a project (issue #38)', () => {
  let h: IngestHarness;
  let instanceAdmin: Session;
  let viewer: Session;
  let outsider: Session;
  let since = 0;
  let n = 0;

  const call = (method: 'GET' | 'PUT', url: string, session: Session, payload?: object) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const putSystem = (payload: object, session: Session = instanceAdmin) =>
    call('PUT', '/system/cleanup', session, payload);
  const project = async () => (await h.project(`acme/cleanup-${++n}`)).id;
  const putProject = (id: string, payload: object, session: Session = h.orgAdmin) =>
    call('PUT', `/projects/${id}/cleanup`, session, payload);
  const RULE = { branchesDays: null, mergeRequestsDays: null, keepBranches: [] };
  const lastSeq = async () =>
    Number(
      (
        await h.ctx.db
          .select({ seq: sql<number>`coalesce(max(${auditEvents.seq}), 0)` })
          .from(auditEvents)
      )[0]?.seq ?? 0,
    );
  const events = (action: string) =>
    h.ctx.db
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.action, action), gt(auditEvents.seq, since)))
      .orderBy(auditEvents.seq);

  beforeAll(async () => {
    h = await createIngestHarness({ pluginsFor: rbacPlugins({ now: () => NOW }) });
    instanceAdmin = await login(h.ctx, 'admin', ADMIN_PASSWORD);
    const make = async (username: string, role?: 'viewer') => {
      const user = await createUser(h.ctx, { username });
      if (role) await addMember(h.ctx, h.organizationId, user.id, role);
      return login(h.ctx, user.username, user.password);
    };
    viewer = await make('cl-viewer', 'viewer');
    outsider = await make('cl-outsider');
  });
  afterAll(async () => {
    await h.close();
  });
  beforeEach(async () => {
    since = await lastSeq();
  });
  afterEach(async () => {
    await h.ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, CLEANUP_SETTINGS_KEY));
  });

  describe('GET/PUT /system/cleanup', () => {
    it('answers both rules off before anything is saved', async () => {
      const res = await call('GET', '/system/cleanup', instanceAdmin);
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toEqual({ branchesDays: null, mergeRequestsDays: null });
    });

    it('is for instance administrators only', async () => {
      expect((await call('GET', '/system/cleanup', h.orgAdmin)).statusCode).toBe(403);
      const put = await putSystem({ branchesDays: 30, mergeRequestsDays: null }, h.orgAdmin);
      expect(put.statusCode).toBe(403);
      expect((await call('GET', '/system/cleanup', instanceAdmin)).json()).toEqual({
        branchesDays: null,
        mergeRequestsDays: null,
      });
    });

    it('saves the defaults and records the names of the changed rules, none when nothing changed', async () => {
      const put = await putSystem({ branchesDays: 30, mergeRequestsDays: 60 });
      expect(put.statusCode, put.body).toBe(200);
      expect(put.json()).toEqual({ branchesDays: 30, mergeRequestsDays: 60 });
      expect((await call('GET', '/system/cleanup', instanceAdmin)).json()).toEqual({
        branchesDays: 30,
        mergeRequestsDays: 60,
      });
      expect((await putSystem({ branchesDays: 30, mergeRequestsDays: 60 })).statusCode).toBe(200);
      expect((await putSystem({ branchesDays: 30, mergeRequestsDays: null })).statusCode).toBe(200);
      const recorded = await events('cleanup.settings_updated');
      expect(recorded.map((e) => e.details)).toEqual([
        { changed: ['branchesDays', 'mergeRequestsDays'] },
        { changed: ['mergeRequestsDays'] },
      ]);
      expect(recorded[0]).toMatchObject({ targetType: 'cleanup_settings', targetId: 'cleanup' });
    });

    it('takes 1 to 3650 days or null, and refuses anything else', async () => {
      for (const days of [1, 3650, null]) {
        const res = await putSystem({ branchesDays: days, mergeRequestsDays: days });
        expect(res.statusCode, `${days}: ${res.body}`).toBe(200);
      }
      for (const body of [
        { branchesDays: 0, mergeRequestsDays: null },
        { branchesDays: null, mergeRequestsDays: 3651 },
        { branchesDays: 1.5, mergeRequestsDays: null },
        { branchesDays: '30', mergeRequestsDays: null },
        { branchesDays: 30 },
        { branchesDays: 30, mergeRequestsDays: null, keepBranches: [] },
      ]) {
        const res = await putSystem(body);
        expect(res.statusCode, JSON.stringify(body)).toBe(422);
        expect(res.json().code, JSON.stringify(body)).toBe('VALIDATION_FAILED');
      }
    });
  });

  describe('GET/PUT /projects/:id/cleanup', () => {
    it('answers no rule of its own, the server default and what is always kept', async () => {
      const id = await project();
      const res = await call('GET', `/projects/${id}/cleanup`, viewer);
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toEqual({
        branchesDays: null,
        mergeRequestsDays: null,
        keepBranches: [],
        serverDefaults: { branchesDays: null, mergeRequestsDays: null },
        effective: { branchesDays: null, mergeRequestsDays: null },
        alwaysKept: { mainBranch: 'main', trackedPatterns: [] },
      });
    });

    it('lets a viewer read, refuses a viewer who writes, and hides the project from an outsider', async () => {
      const id = await project();
      expect((await call('GET', `/projects/${id}/cleanup`, viewer)).statusCode).toBe(200);
      expect((await putProject(id, RULE, viewer)).statusCode).toBe(403);
      expect((await call('GET', `/projects/${id}/cleanup`, outsider)).statusCode).toBe(404);
      expect((await putProject(id, RULE, outsider)).statusCode).toBe(404);
    });

    it('names the main branch and the tracked branch patterns as always kept', async () => {
      const { id } = await createProject(h.ctx, h.orgAdmin, {
        organizationId: h.organizationId,
        key: `acme/cleanup-trunk-${++n}`,
        mainBranchName: 'trunk',
      });
      const monitoring = await call('PUT', `/projects/${id}/vulnerability-monitoring`, h.orgAdmin, {
        enabled: false,
        branchPatterns: ['release/*', 'lts/**'],
        versionRule: { kind: 'none' },
        labelVersions: false,
      });
      expect(monitoring.statusCode, monitoring.body).toBe(200);
      expect((await call('GET', `/projects/${id}/cleanup`, viewer)).json()).toMatchObject({
        alwaysKept: { mainBranch: 'trunk', trackedPatterns: ['release/*', 'lts/**'] },
      });
    });

    it('inherits the server default (null), switches a rule off (0) or overrides it (days)', async () => {
      expect((await putSystem({ branchesDays: 30, mergeRequestsDays: 60 })).statusCode).toBe(200);
      const id = await project();
      const effective = async () =>
        (await call('GET', `/projects/${id}/cleanup`, viewer)).json() as Record<string, unknown>;
      expect(await effective()).toMatchObject({
        branchesDays: null,
        mergeRequestsDays: null,
        serverDefaults: { branchesDays: 30, mergeRequestsDays: 60 },
        effective: { branchesDays: 30, mergeRequestsDays: 60 },
      });
      const off = await putProject(id, { ...RULE, branchesDays: 0 });
      expect(off.statusCode, off.body).toBe(200);
      expect(off.json()).toMatchObject({
        branchesDays: 0,
        mergeRequestsDays: null,
        effective: { branchesDays: null, mergeRequestsDays: 60 },
      });
      const override = await putProject(id, { ...RULE, branchesDays: 90, mergeRequestsDays: 0 });
      expect(override.json()).toMatchObject({
        branchesDays: 90,
        mergeRequestsDays: 0,
        effective: { branchesDays: 90, mergeRequestsDays: null },
      });
      // The server default off: a project that inherits has no rule; its own days still apply.
      expect((await putSystem({ branchesDays: null, mergeRequestsDays: null })).statusCode).toBe(
        200,
      );
      expect(await effective()).toMatchObject({
        serverDefaults: { branchesDays: null, mergeRequestsDays: null },
        effective: { branchesDays: 90, mergeRequestsDays: null },
      });
      await putProject(id, { ...RULE, mergeRequestsDays: 14 });
      expect(await effective()).toMatchObject({
        effective: { branchesDays: null, mergeRequestsDays: 14 },
      });
    });

    it('stores the rule and the keep patterns, trimmed and without duplicates', async () => {
      const id = await project();
      const put = await putProject(id, {
        branchesDays: 180,
        mergeRequestsDays: 30,
        keepBranches: [' keep/* ', 'keep/*', 'demo-**'],
      });
      expect(put.statusCode, put.body).toBe(200);
      expect(put.json()).toEqual({
        branchesDays: 180,
        mergeRequestsDays: 30,
        keepBranches: ['keep/*', 'demo-**'],
        serverDefaults: { branchesDays: null, mergeRequestsDays: null },
        effective: { branchesDays: 180, mergeRequestsDays: 30 },
        alwaysKept: { mainBranch: 'main', trackedPatterns: [] },
      });
      expect((await call('GET', `/projects/${id}/cleanup`, viewer)).json()).toEqual(put.json());
      const [row] = await h.ctx.db.select().from(projects).where(eq(projects.id, id));
      expect(row).toMatchObject({
        cleanupBranchesDays: 180,
        cleanupMergeRequestsDays: 30,
        cleanupKeepBranches: ['keep/*', 'demo-**'],
      });
    });

    it('takes 0 to 3650 days or null and 20 patterns, and refuses anything else', async () => {
      const id = await project();
      const twenty = Array.from({ length: 20 }, (_, i) => `keep/${i}`);
      for (const body of [
        { branchesDays: 0, mergeRequestsDays: 3650, keepBranches: twenty },
        { branchesDays: 1, mergeRequestsDays: null, keepBranches: ['x'.repeat(255)] },
        { branchesDays: null, mergeRequestsDays: 0, keepBranches: ['release/*', 'f/{a,b}'] },
      ]) {
        const res = await putProject(id, body);
        expect(res.statusCode, `${JSON.stringify(body)}: ${res.body}`).toBe(200);
      }
      for (const body of [
        { ...RULE, branchesDays: -1 },
        { ...RULE, mergeRequestsDays: 3651 },
        { ...RULE, branchesDays: 1.5 },
        { ...RULE, branchesDays: '30' },
        { ...RULE, keepBranches: [...twenty, 'keep/20'] },
        { ...RULE, keepBranches: ['   '] },
        { ...RULE, keepBranches: ['x'.repeat(256)] },
        { ...RULE, keepBranches: 'keep/*' },
        { branchesDays: null, mergeRequestsDays: null },
        { ...RULE, extra: 1 },
      ]) {
        const res = await putProject(id, body);
        expect(res.statusCode, JSON.stringify(body)).toBe(422);
        expect(res.json().code, JSON.stringify(body)).toBe('VALIDATION_FAILED');
      }
    });

    it('refuses a pattern that is not a branch glob as the monitoring patterns do', async () => {
      const id = await project();
      for (const bad of ['release/[z-a]*', 'a{', '[z-a]', 'a\u0001b']) {
        const res = await putProject(id, { ...RULE, keepBranches: ['keep/*', bad] });
        expect(res.statusCode, bad).toBe(422);
        expect(res.json().errors, bad).toEqual([
          expect.objectContaining({ path: 'body.keepBranches' }),
        ]);
      }
      expect((await call('GET', `/projects/${id}/cleanup`, viewer)).json()).toMatchObject({
        keepBranches: [],
      });
    });

    it('records the names of the changed fields, none when nothing changed', async () => {
      const id = await project();
      const rule = { branchesDays: 90, mergeRequestsDays: 30, keepBranches: ['keep/*'] };
      expect((await putProject(id, rule)).statusCode).toBe(200);
      expect((await putProject(id, rule)).statusCode).toBe(200);
      expect((await putProject(id, { ...rule, keepBranches: [' keep/* '] })).statusCode).toBe(200);
      expect((await putProject(id, { ...rule, keepBranches: ['keep/*', 'v*'] })).statusCode).toBe(
        200,
      );
      expect(
        (await putProject(id, { ...rule, keepBranches: ['keep/*', 'v*'], branchesDays: 0 }))
          .statusCode,
      ).toBe(200);
      expect(
        (
          await putProject(id, {
            branchesDays: null,
            mergeRequestsDays: 30,
            keepBranches: ['keep/*', 'v*'],
          })
        ).statusCode,
      ).toBe(200);
      const recorded = (await events('project.cleanup_updated')).filter((e) => e.projectId === id);
      expect(recorded.map((e) => e.details)).toEqual([
        { changed: ['branchesDays', 'mergeRequestsDays', 'keepBranches'] },
        { changed: ['keepBranches'] },
        { changed: ['branchesDays'] },
        { changed: ['branchesDays'] },
      ]);
      expect(recorded[0]).toMatchObject({ targetType: 'project', targetId: id });
    });
  });
});

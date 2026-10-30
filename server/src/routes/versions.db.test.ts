import { desc, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { rbacPlugins } from '../../test/rbac';
import { auditEvents, branches, projectVersions } from '../db/schema';

const BASE = Date.UTC(2026, 9, 1);

describe('versions and vulnerability monitoring API (0.15)', () => {
  let h: IngestHarness;
  let viewer: Session;
  let n = 0;

  const call = (
    method: 'GET' | 'PATCH' | 'PUT',
    url: string,
    session: Session = h.orgAdmin,
    payload?: unknown,
  ) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const project = async () => h.project(`acme/vapi-${++n}`);
  const addVersions = async (projectId: string, labels: string[], offset = 0) => {
    await h.ctx.db.insert(projectVersions).values(
      labels.map((label, i) => ({
        projectId,
        label,
        source: 'tag' as const,
        tag: label,
        analyzedAt: new Date(BASE + (offset + i) * 60_000),
      })),
    );
  };

  beforeAll(async () => {
    h = await createIngestHarness();
    const user = await createUser(h.ctx, { username: 'vapi-viewer' });
    await addMember(h.ctx, h.organizationId, user.id, 'viewer');
    viewer = await login(h.ctx, user.username, user.password);
  });
  afterAll(async () => {
    await h.close();
  });

  const SETTINGS = {
    enabled: true,
    branchPatterns: ['release/*'],
    versionRule: { kind: 'lines', lines: 2 },
    labelVersions: true,
  };

  it('lets a viewer read and refuses a viewer who writes', async () => {
    const p = await project();
    await addVersions(p.id, ['1.0.0']);
    const [v] = await h.ctx.db
      .select()
      .from(projectVersions)
      .where(eq(projectVersions.projectId, p.id));
    expect((await call('GET', `/projects/${p.id}/versions`, viewer)).statusCode).toBe(200);
    expect(
      (await call('GET', `/projects/${p.id}/vulnerability-monitoring`, viewer)).statusCode,
    ).toBe(200);
    const patch = await call('PATCH', `/projects/${p.id}/versions/${v!.id}`, viewer, {
      tracking: 'pinned',
    });
    expect(patch.statusCode).toBe(403);
    const put = await call('PUT', `/projects/${p.id}/vulnerability-monitoring`, viewer, SETTINGS);
    expect(put.statusCode).toBe(403);
  });

  it('answers the defaults before anything is saved', async () => {
    const p = await project();
    const res = await call('GET', `/projects/${p.id}/vulnerability-monitoring`);
    expect(res.json()).toEqual({
      enabled: true,
      branchPatterns: [],
      versionRule: { kind: 'lines', lines: 5 },
      labelVersions: false,
      mainBranchName: 'main',
      matchingBranches: [],
      trackedVersions: [],
      versionCount: 0,
    });
  });

  it('rejects 11 patterns, lines 0, an empty pattern and a pattern that cannot compile', async () => {
    const p = await project();
    const url = `/projects/${p.id}/vulnerability-monitoring`;
    const put = (change: object) => call('PUT', url, h.orgAdmin, { ...SETTINGS, ...change });
    expect(
      (await put({ branchPatterns: Array.from({ length: 11 }, (_, i) => `r${i}`) })).statusCode,
    ).toBe(422);
    expect((await put({ versionRule: { kind: 'lines', lines: 0 } })).statusCode).toBe(422);
    expect((await put({ versionRule: { kind: 'lines', lines: 21 } })).statusCode).toBe(422);
    expect((await put({ branchPatterns: ['   '] })).statusCode).toBe(422);
    const control = await put({ branchPatterns: ['a\u0001b'] });
    expect(control.statusCode).toBe(422);
    expect(control.json().errors).toEqual([
      expect.objectContaining({ path: 'body.branchPatterns' }),
    ]);
    for (const bad of ['release/[z-a]*', 'a{', '[z-a]']) {
      const res = await put({ branchPatterns: ['release/*', bad] });
      expect(res.statusCode, bad).toBe(422);
      expect(res.json().errors, bad).toEqual([
        expect.objectContaining({ path: 'body.branchPatterns' }),
      ]);
    }
    const valid = await put({ branchPatterns: ['release/*', 'hotfix/**', 'v1.[0-9]*', 'f/{a,b}'] });
    expect(valid.statusCode, valid.body).toBe(200);
    expect((await put({ extra: 1 })).statusCode).toBe(422);
  });

  it('saves the settings and answers the matching branches and tracked versions', async () => {
    const p = await project();
    const url = `/projects/${p.id}/vulnerability-monitoring`;
    await h.ctx.db.insert(branches).values([
      { projectId: p.id, kind: 'branch', name: 'release/2.0' },
      { projectId: p.id, kind: 'branch', name: 'release/1.0' },
      { projectId: p.id, kind: 'branch', name: 'feature/x' },
      { projectId: p.id, kind: 'merge_request', name: 'release/9' },
    ]);
    await addVersions(p.id, ['1.0.0', '1.1.0', '2.0.0', '2.0.1-rc.1']);
    const put = await call('PUT', url, h.orgAdmin, {
      ...SETTINGS,
      branchPatterns: [' release/* ', 'release/*'],
    });
    expect(put.statusCode, put.body).toBe(200);
    const expected = {
      enabled: true,
      branchPatterns: ['release/*'],
      versionRule: { kind: 'lines', lines: 2 },
      labelVersions: true,
      mainBranchName: 'main',
      matchingBranches: ['release/1.0', 'release/2.0'],
      trackedVersions: ['2.0.0', '1.1.0'],
      versionCount: 4,
    };
    expect(put.json()).toEqual(expected);
    expect((await call('GET', url)).json()).toEqual(expected);
    const again = await call('PUT', url, h.orgAdmin, {
      enabled: false,
      branchPatterns: [],
      versionRule: { kind: 'all' },
      labelVersions: false,
    });
    expect(again.json()).toMatchObject({
      enabled: false,
      branchPatterns: [],
      versionRule: { kind: 'all' },
      matchingBranches: [],
      trackedVersions: ['2.0.0', '1.1.0', '1.0.0'],
    });
  });

  it('pins a version and answers its tracking', async () => {
    const p = await project();
    await call('PUT', `/projects/${p.id}/vulnerability-monitoring`, h.orgAdmin, {
      ...SETTINGS,
      versionRule: { kind: 'lines', lines: 1 },
    });
    await addVersions(p.id, ['1.0.0', '2.0.0']);
    const list = async () =>
      (await call('GET', `/projects/${p.id}/versions`)).json().items as {
        id: string;
        label: string;
        tracked: boolean;
        trackingReason: string;
        tracking: string;
        prerelease: boolean;
        packages: number;
      }[];
    const old = (await list()).find((v) => v.label === '1.0.0')!;
    expect(old).toMatchObject({ tracked: false, trackingReason: 'older_line', tracking: 'auto' });
    const res = await call('PATCH', `/projects/${p.id}/versions/${old.id}`, h.orgAdmin, {
      tracking: 'pinned',
    });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({
      label: '1.0.0',
      source: 'tag',
      tag: '1.0.0',
      tracking: 'pinned',
      tracked: true,
      trackingReason: 'pinned',
      prerelease: false,
      packages: 0,
    });
    expect((await list()).map((v) => [v.label, v.tracked])).toEqual([
      ['2.0.0', true],
      ['1.0.0', true],
    ]);
    const bad = await call('PATCH', `/projects/${p.id}/versions/${old.id}`, h.orgAdmin, {
      tracking: 'nope',
    });
    expect(bad.statusCode).toBe(422);
  });

  it("treats another project's version as not found", async () => {
    const a = await project();
    const b = await project();
    await addVersions(a.id, ['1.0.0']);
    const [v] = await h.ctx.db
      .select()
      .from(projectVersions)
      .where(eq(projectVersions.projectId, a.id));
    const res = await call('PATCH', `/projects/${b.id}/versions/${v!.id}`, h.orgAdmin, {
      tracking: 'unsupported',
    });
    expect(res.statusCode).toBe(404);
  });

  it('pages 60 versions in two with a cursor, newest first', async () => {
    const p = await project();
    await addVersions(
      p.id,
      Array.from({ length: 60 }, (_, i) => `1.${i}.0`),
    );
    const first = (await call('GET', `/projects/${p.id}/versions`)).json();
    expect(first.items).toHaveLength(50);
    expect(first.items[0].label).toBe('1.59.0');
    expect(first.nextCursor).toEqual(expect.any(String));
    const second = (
      await call('GET', `/projects/${p.id}/versions?cursor=${first.nextCursor as string}`)
    ).json();
    expect(second.items).toHaveLength(10);
    expect(second.items[0].label).toBe('1.9.0');
    expect(second.items.at(-1).label).toBe('1.0.0');
    expect(second.nextCursor).toBeNull();
    const small = (await call('GET', `/projects/${p.id}/versions?limit=5`)).json();
    expect(small.items.map((v: { label: string }) => v.label)).toEqual([
      '1.59.0',
      '1.58.0',
      '1.57.0',
      '1.56.0',
      '1.55.0',
    ]);
    expect((await call('GET', `/projects/${p.id}/versions?limit=101`)).statusCode).toBe(422);
    expect((await call('GET', `/projects/${p.id}/versions?cursor=garbage`)).statusCode).toBe(422);
  });

  it('counts the packages of a version', async () => {
    const p = await project();
    await p.ingestOk(
      (await import('../../test/reports')).reportWith({
        projectKey: p.key,
        branch: null,
        tag: 'v3.0.0',
        findings: [],
        files: [],
        dependencies: [
          {
            path: 'package-lock.json',
            ecosystem: 'npm',
            name: 'a',
            version: '1.0.0',
            licenses: [],
          },
          {
            path: 'package-lock.json',
            ecosystem: 'npm',
            name: 'b',
            version: '1.0.0',
            licenses: [],
          },
        ],
      }),
    );
    const items = (await call('GET', `/projects/${p.id}/versions`)).json().items;
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ source: 'tag', packages: 2 });
  });

  it('records both events while the audit log is active', async () => {
    const audited = await createIngestHarness({
      pluginsFor: rbacPlugins({ now: () => new Date('2026-10-30T00:00:00Z') }),
    });
    try {
      const p = await audited.project('acme/audited');
      await audited.ctx.db.insert(projectVersions).values({
        projectId: p.id,
        label: '1.0.0',
        source: 'tag',
        tag: '1.0.0',
        analyzedAt: new Date(BASE),
      });
      const [v] = await audited.ctx.db
        .select()
        .from(projectVersions)
        .where(eq(projectVersions.projectId, p.id));
      const headers = audited.orgAdmin.headers;
      const patch = await audited.ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/projects/${p.id}/versions/${v!.id}`,
        headers,
        payload: { tracking: 'unsupported' },
      });
      expect(patch.statusCode, patch.body).toBe(200);
      const put = await audited.ctx.app.inject({
        method: 'PUT',
        url: `/api/v0/projects/${p.id}/vulnerability-monitoring`,
        headers,
        payload: { ...SETTINGS, enabled: false },
      });
      expect(put.statusCode, put.body).toBe(200);
      const events = await audited.ctx.db
        .select()
        .from(auditEvents)
        .where(eq(auditEvents.projectId, p.id))
        .orderBy(desc(auditEvents.seq));
      const byAction = Object.fromEntries(events.map((e) => [e.action, e]));
      expect(byAction['project_version.updated']).toMatchObject({
        targetType: 'project',
        details: { label: '1.0.0', tracking: 'unsupported' },
      });
      expect(byAction['project.vulnerability_monitoring_updated']).toMatchObject({
        targetType: 'project',
        details: {
          changed: ['enabled', 'branchPatterns', 'versionRule', 'labelVersions'],
        },
      });
    } finally {
      await audited.close();
    }
  });
});

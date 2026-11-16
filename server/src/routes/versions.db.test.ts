import { desc, eq } from 'drizzle-orm';
import type { PgColumn, PgTable } from 'drizzle-orm/pg-core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { rbacPlugins } from '../../test/rbac';
import { reportWith } from '../../test/reports';
import { seedCheck, seedTargetRow } from '../../test/vulnerabilities';
import {
  analyses,
  auditEvents,
  branches,
  complianceReports,
  jobs,
  projectVersions,
  targetVulnerabilities,
  versionDependencies,
  vulnerabilityAlertItems,
  vulnerabilityAlertTargets,
  vulnerabilityDecisions,
  vulnerabilityTargetChecks,
} from '../db/schema';
import { first } from '../db/rows';
import { upsertVersion } from '../versions/store';
import { writeVulndbSettings } from '../vulndb/settings';
import { RECHECK_QUEUE } from '../vulnerabilities/recheck';

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
      instanceEnabled: true,
      branchPatterns: [],
      versionRule: { kind: 'lines', lines: 5 },
      labelVersions: false,
      mainBranchName: 'main',
      matchingBranches: [],
      trackedVersions: [],
      versionCount: 0,
    });
  });

  it('tells whether the instance switch is on, on GET and PUT', async () => {
    const p = await project();
    const url = `/projects/${p.id}/vulnerability-monitoring`;
    try {
      await writeVulndbSettings(h.ctx.db, { enabled: false }, 'k');
      expect((await call('GET', url)).json()).toMatchObject({
        enabled: true,
        instanceEnabled: false,
      });
      const put = await call('PUT', url, h.orgAdmin, SETTINGS);
      expect(put.json()).toMatchObject({ instanceEnabled: false });
    } finally {
      await writeVulndbSettings(h.ctx.db, { enabled: true }, 'k');
    }
    expect((await call('GET', url)).json()).toMatchObject({ instanceEnabled: true });
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
      instanceEnabled: true,
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

  it('answers 404 to a user outside the organisation', async () => {
    const p = await project();
    await addVersions(p.id, ['1.0.0']);
    const [v] = await h.ctx.db
      .select()
      .from(projectVersions)
      .where(eq(projectVersions.projectId, p.id));
    const user = await createUser(h.ctx, { username: 'vapi-outsider' });
    const outsider = await login(h.ctx, user.username, user.password);
    const monitoring = `/projects/${p.id}/vulnerability-monitoring`;
    const results = {
      list: await call('GET', `/projects/${p.id}/versions`, outsider),
      patch: await call('PATCH', `/projects/${p.id}/versions/${v!.id}`, outsider, {
        tracking: 'pinned',
      }),
      read: await call('GET', monitoring, outsider),
      save: await call('PUT', monitoring, outsider, SETTINGS),
    };
    for (const [name, res] of Object.entries(results)) expect(res.statusCode, name).toBe(404);
    // Nothing changed.
    expect((await call('GET', `/projects/${p.id}/versions`)).json().items[0].tracking).toBe('auto');
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

  it('pages 120 versions with tied analysis times, each once', async () => {
    const p = await project();
    await addVersions(
      p.id,
      Array.from({ length: 100 }, (_, i) => `1.${i}.0`),
    );
    // 20 versions with one analysis time, between the 51st and the 50th minute: the tie spans
    // the boundary of the first page of 50.
    const tied = new Date(BASE + 50 * 60_000 + 30_000);
    await h.ctx.db.insert(projectVersions).values(
      Array.from({ length: 20 }, (_, i) => ({
        projectId: p.id,
        label: `2.0.${i}`,
        source: 'tag' as const,
        tag: `2.0.${i}`,
        analyzedAt: tied,
      })),
    );
    type Item = { id: string; tracked: boolean; trackingReason: string };
    const pages = async (limit: number) => {
      const items: Item[] = [];
      let cursor: string | null = null;
      do {
        const query: string = cursor === null ? '' : `&cursor=${cursor}`;
        const res = await call('GET', `/projects/${p.id}/versions?limit=${limit}${query}`);
        expect(res.statusCode, res.body).toBe(200);
        const page = res.json() as { items: Item[]; nextCursor: string | null };
        items.push(...page.items);
        cursor = page.nextCursor;
      } while (cursor !== null);
      return items;
    };
    const by50 = await pages(50);
    expect(by50).toHaveLength(120);
    expect(new Set(by50.map((v) => v.id)).size).toBe(120);
    const rows = await h.ctx.db
      .select({ id: projectVersions.id, analyzedAt: projectVersions.analyzedAt })
      .from(projectVersions)
      .where(eq(projectVersions.projectId, p.id));
    const newestFirst = rows
      .sort((a, b) => {
        const byTime = b.analyzedAt.getTime() - a.analyzedAt.getTime();
        if (byTime !== 0) return byTime;
        return b.id < a.id ? -1 : 1;
      })
      .map((r) => r.id);
    expect(by50.map((v) => v.id)).toEqual(newestFirst);
    const by100 = new Map((await pages(100)).map((v) => [v.id, v]));
    for (const v of by50) {
      expect([v.tracked, v.trackingReason], v.id).toEqual([
        by100.get(v.id)?.tracked,
        by100.get(v.id)?.trackingReason,
      ]);
    }
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

  it('records one event for two PATCHes to the same tracking', async () => {
    const audited = await createIngestHarness({
      pluginsFor: rbacPlugins({ now: () => new Date('2026-10-30T00:00:00Z') }),
    });
    try {
      const p = await audited.project('acme/audited-twice');
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
      for (let i = 0; i < 2; i++) {
        const patch = await audited.ctx.app.inject({
          method: 'PATCH',
          url: `/api/v0/projects/${p.id}/versions/${v!.id}`,
          headers: audited.orgAdmin.headers,
          payload: { tracking: 'unsupported' },
        });
        expect(patch.statusCode, patch.body).toBe(200);
        expect(patch.json()).toMatchObject({ tracking: 'unsupported', tracked: false });
      }
      const events = await audited.ctx.db
        .select()
        .from(auditEvents)
        .where(eq(auditEvents.projectId, p.id))
        .orderBy(desc(auditEvents.seq));
      expect(events.filter((e) => e.action === 'project_version.updated')).toHaveLength(1);
    } finally {
      await audited.close();
    }
  });

  it('queues no re-check for a PATCH that changes nothing', async () => {
    const p = await project();
    await addVersions(p.id, ['1.0.0']);
    const [v] = await h.ctx.db
      .select()
      .from(projectVersions)
      .where(eq(projectVersions.projectId, p.id));
    const rechecks = () => h.ctx.db.select().from(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
    const url = `/projects/${p.id}/versions/${v!.id}`;

    const same = await call('PATCH', url, h.orgAdmin, { tracking: 'auto' });
    expect(same.statusCode, same.body).toBe(200);
    expect(same.json()).toMatchObject({ id: v!.id, tracking: 'auto', tracked: true });
    expect(await rechecks()).toHaveLength(0);
    const [unchanged] = await h.ctx.db
      .select({ updatedAt: projectVersions.updatedAt })
      .from(projectVersions)
      .where(eq(projectVersions.id, v!.id));
    expect(unchanged?.updatedAt).toEqual(v!.updatedAt);

    const pinned = await call('PATCH', url, h.orgAdmin, { tracking: 'pinned' });
    expect(pinned.statusCode, pinned.body).toBe(200);
    expect(await rechecks()).toHaveLength(1);
  });
});

describe('SBOM versions: DTO and DELETE (0.16)', () => {
  let h: IngestHarness;
  let member: Session;
  let n = 0;

  const call = (method: 'GET' | 'DELETE', url: string, session: Session = h.orgAdmin) =>
    h.ctx.app.inject({ method, url: `/api/v0${url}`, headers: session.headers });
  const project = async () => h.project(`acme/sbomv-${++n}`);
  const seedSbom = async (projectId: string, label: string) => {
    const result = await h.ctx.db.transaction((tx) =>
      upsertVersion(tx, {
        projectId,
        label,
        source: 'sbom',
        tag: null,
        analysisId: null,
        analyzedAt: new Date(BASE),
        inventory: {
          dependencies: [
            {
              path: 'sbom',
              ecosystem: 'npm',
              name: 'left-pad',
              version: '1.3.0',
              licenses: [],
            },
          ],
          ignores: null,
        },
        sbom: {
          format: 'CycloneDX 1.7',
          subject: 'debian:12',
          distribution: { family: 'debian', version: '12.15' },
        },
      }),
    );
    if (typeof result === 'string') throw new Error(`upsertVersion: ${result}`);
    return result.version.id;
  };
  const rechecks = () => h.ctx.db.select().from(jobs).where(eq(jobs.queue, RECHECK_QUEUE));

  beforeAll(async () => {
    h = await createIngestHarness({
      pluginsFor: rbacPlugins({ now: () => new Date('2026-10-30T00:00:00Z') }),
    });
    const user = await createUser(h.ctx, { username: 'sbomv-member' });
    await addMember(h.ctx, h.organizationId, user.id, 'viewer');
    member = await login(h.ctx, user.username, user.password);
  });
  afterAll(async () => {
    await h.close();
  });

  it('lists the SBOM facts of a version, and nulls for a tag version', async () => {
    const p = await project();
    await seedSbom(p.id, '1.4.0');
    await h.ctx.db.insert(projectVersions).values({
      projectId: p.id,
      label: '1.0.0',
      source: 'tag',
      tag: 'v1.0.0',
      analyzedAt: new Date(BASE - 60_000),
    });
    const items = (await call('GET', `/projects/${p.id}/versions`)).json().items as {
      label: string;
    }[];
    expect(items.find((i) => i.label === '1.4.0')).toMatchObject({
      source: 'sbom',
      tag: null,
      sbomFormat: 'CycloneDX 1.7',
      sbomSubject: 'debian:12',
      distribution: { family: 'debian', version: '12.15' },
      packages: 1,
    });
    expect(items.find((i) => i.label === '1.0.0')).toMatchObject({
      source: 'tag',
      sbomFormat: null,
      sbomSubject: null,
      distribution: null,
    });
  });

  it('carries source, subject and distribution on the targets', async () => {
    const p = await project();
    const pinned = await seedSbom(p.id, '1.4.0');
    const dropped = await seedSbom(p.id, '1.3.0');
    await h.ctx.db
      .update(projectVersions)
      .set({ tracking: 'pinned' })
      .where(eq(projectVersions.id, pinned));
    await h.ctx.db
      .update(projectVersions)
      .set({ tracking: 'unsupported' })
      .where(eq(projectVersions.id, dropped));
    const res = await call('GET', `/projects/${p.id}/vulnerabilities/targets`);
    expect(res.statusCode, res.body).toBe(200);
    const body = res.json() as {
      targets: { kind: string; id: string; source: unknown }[];
      untracked: { id: string }[];
    };
    expect(body.targets.find((t) => t.id === pinned)).toMatchObject({
      kind: 'version',
      source: 'sbom',
      sbomSubject: 'debian:12',
      distribution: { family: 'debian', version: '12.15' },
    });
    expect(body.targets.find((t) => t.kind === 'branch')).toMatchObject({
      source: null,
      sbomSubject: null,
      distribution: null,
    });
    expect(body.untracked.find((t) => t.id === dropped)).toMatchObject({
      source: 'sbom',
      sbomSubject: 'debian:12',
      distribution: { family: 'debian', version: '12.15' },
    });
  });

  it('deletes a version with everything that hangs on it, and keeps analyses and reports', async () => {
    const p = await project();
    const versionId = await seedSbom(p.id, '1.4.0');
    const db = h.ctx.db;
    await seedCheck(db, { projectId: p.id, versionId, baselineAt: new Date(BASE) });
    await seedTargetRow(db, {
      projectId: p.id,
      versionId,
      packageName: 'left-pad',
      vulnerabilityId: 'CVE-2026-0001',
    });
    const alertTarget = first(
      await db
        .insert(vulnerabilityAlertTargets)
        .values({ projectId: p.id, versionId, dayOne: false })
        .returning({ id: vulnerabilityAlertTargets.id }),
    ).id;
    await db
      .insert(vulnerabilityAlertItems)
      .values({ targetId: alertTarget, vulnerabilityId: 'CVE-2026-0001', baseline: true });
    await db.insert(vulnerabilityDecisions).values({
      projectId: p.id,
      versionId,
      packageName: 'left-pad',
      vulnerabilityId: 'CVE-2026-0001',
      status: 'wont_fix',
    });
    const analysisId = first(
      await db
        .insert(analyses)
        .values({ projectId: p.id, versionId, status: 'queued' })
        .returning({ id: analyses.id }),
    ).id;
    const reportId = first(
      await db
        .insert(complianceReports)
        .values({
          organizationId: h.organizationId,
          projectId: p.id,
          versionId,
          scope: 'project',
          createdByName: 'admin',
          standards: [],
        })
        .returning({ id: complianceReports.id }),
    ).id;
    await db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));

    const count = async (table: PgTable, column: PgColumn, value: string) =>
      (await db.select().from(table).where(eq(column, value))).length;
    /** The rows that hang on the version, by table. */
    const hanging = async () => ({
      versions: await count(projectVersions, projectVersions.id, versionId),
      packages: await count(versionDependencies, versionDependencies.versionId, versionId),
      results: await count(targetVulnerabilities, targetVulnerabilities.versionId, versionId),
      checks: await count(
        vulnerabilityTargetChecks,
        vulnerabilityTargetChecks.versionId,
        versionId,
      ),
      alertTargets: await count(
        vulnerabilityAlertTargets,
        vulnerabilityAlertTargets.versionId,
        versionId,
      ),
      alertItems: await count(
        vulnerabilityAlertItems,
        vulnerabilityAlertItems.targetId,
        alertTarget,
      ),
      decisions: await count(vulnerabilityDecisions, vulnerabilityDecisions.versionId, versionId),
    });
    const none = {
      versions: 0,
      packages: 0,
      results: 0,
      checks: 0,
      alertTargets: 0,
      alertItems: 0,
      decisions: 0,
    };
    // Every table holds a row of the version before the delete: the zeros below mean something.
    const before = await hanging();
    for (const [table, n] of Object.entries(before)) expect(n, table).toBeGreaterThan(0);

    const res = await call('DELETE', `/projects/${p.id}/versions/${versionId}`);
    expect(res.statusCode, res.body).toBe(204);

    expect(await hanging()).toEqual(none);
    const [analysis] = await db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(analysis).toMatchObject({ id: analysisId, versionId: null });
    const [report] = await db
      .select()
      .from(complianceReports)
      .where(eq(complianceReports.id, reportId));
    expect(report).toMatchObject({ id: reportId, versionId: null });

    const [event] = await db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.projectId, p.id))
      .orderBy(desc(auditEvents.seq))
      .limit(1);
    expect(event).toMatchObject({
      action: 'project_version.deleted',
      targetType: 'project',
      details: { label: '1.4.0', source: 'sbom' },
    });
    expect(await rechecks()).toHaveLength(1);
  });

  it('queues no re-check while the instance switch is off', async () => {
    const p = await project();
    const versionId = await seedSbom(p.id, '2.0.0');
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
    try {
      await writeVulndbSettings(h.ctx.db, { enabled: false }, 'k');
      expect((await call('DELETE', `/projects/${p.id}/versions/${versionId}`)).statusCode).toBe(
        204,
      );
    } finally {
      await writeVulndbSettings(h.ctx.db, { enabled: true }, 'k');
    }
    expect(await rechecks()).toHaveLength(0);
  });

  it('refuses a member without project.settings, and answers 404 for another project', async () => {
    const a = await project();
    const b = await project();
    const versionId = await seedSbom(a.id, '1.4.0');
    const denied = await call('DELETE', `/projects/${a.id}/versions/${versionId}`, member);
    expect(denied.statusCode).toBe(403);
    const other = await call('DELETE', `/projects/${b.id}/versions/${versionId}`);
    expect(other.statusCode).toBe(404);
    expect(JSON.stringify(other.json())).toContain('Version not found');
    expect(
      await h.ctx.db.select().from(projectVersions).where(eq(projectVersions.id, versionId)),
    ).toHaveLength(1);
  });

  it('needs the admin scope on a personal token', async () => {
    const p = await project();
    const versionId = await seedSbom(p.id, '1.4.0');
    const tokenWith = async (scopes: string[]) => {
      const res = await h.ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: h.orgAdmin.headers,
        payload: { name: scopes.join('-'), scopes },
      });
      expect(res.statusCode, res.body).toBe(201);
      return bearer((res.json() as { token: string }).token);
    };
    const del = async (headers: Record<string, string>) =>
      h.ctx.app.inject({
        method: 'DELETE',
        url: `/api/v0/projects/${p.id}/versions/${versionId}`,
        headers,
      });
    const refused = await del(await tokenWith(['read']));
    expect(refused.statusCode).toBe(403);
    expect(JSON.stringify(refused.json())).toContain('INSUFFICIENT_SCOPE');
    expect(
      await h.ctx.db.select().from(projectVersions).where(eq(projectVersions.id, versionId)),
    ).toHaveLength(1);
    expect((await del(await tokenWith(['admin']))).statusCode).toBe(204);
    expect(
      await h.ctx.db.select().from(projectVersions).where(eq(projectVersions.id, versionId)),
    ).toHaveLength(0);
  });

  it('refuses a project token', async () => {
    const p = await project();
    const versionId = await seedSbom(p.id, '1.4.0');
    const res = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${p.id}/versions/${versionId}`,
      headers: bearer(p.token),
    });
    expect(res.statusCode).toBe(403);
    expect(JSON.stringify(res.json())).toContain('TOKEN_NOT_ALLOWED');
  });

  it('lets a later tag scan create the version again, with a new id', async () => {
    const p = await project();
    const versionId = await seedSbom(p.id, '1.4.0');
    expect((await call('DELETE', `/projects/${p.id}/versions/${versionId}`)).statusCode).toBe(204);
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: null,
        tag: 'v1.4.0',
        version: '1.4.0',
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
        ],
      }),
    );
    const rows = await h.ctx.db
      .select()
      .from(projectVersions)
      .where(eq(projectVersions.projectId, p.id));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ label: '1.4.0', source: 'tag' });
    expect(rows[0]!.id).not.toBe(versionId);
  });
});

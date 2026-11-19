import { and, eq, gt, sql } from 'drizzle-orm';
import pg from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { enableFixes, seedFix, seedMainVulnerability } from '../../test/fixes';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { rbacPlugins } from '../../test/rbac';
import { mappedProject, scmTestConfig } from '../../test/scm';
import { seedTargetRow } from '../../test/vulnerabilities';
import {
  auditEvents,
  branches,
  dependencyFixes,
  jobs,
  projectFixSettings,
  projectMemberships,
  projectVersions,
  scmConnections,
  users,
  type FixState,
} from '../db/schema';
import type { Executor } from '../db/client';
import { FIX_QUEUE } from '../fixes/jobs';

const NOW = new Date('2027-01-01T00:00:00Z');
const CVE = 'CVE-2026-5001';
const HEAD = 'd'.repeat(40);
const BASE = 'e'.repeat(40);

interface Fix {
  id: string;
  state: FixState;
  refresh: boolean;
  targetVersion: string | null;
  mrNumber: number | null;
  mrUrl: string | null;
  failure: { code: string; message: string } | null;
  updatedAt: string;
}
interface FixItem extends Fix {
  family: string;
  packageName: string;
  origin: 'manual' | 'auto';
  installedVersion: string | null;
  branch: string;
  createdAt: string;
}

describe('fix requests: request, retry, cancel, list and the embedded fix (0.16 fix MRs §6.2-§6.4, §6.8)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let viewer: Session;
  let outsider: Session;
  let granted: Session;
  let project: IngestProject & { connectionId: string };
  let other: IngestProject;
  let projectId: string;
  let main: string;
  let adminId: string;
  let since = 0;
  let pkgs = 0;

  const db = () => h.ctx.db;
  const fresh = () => `qf-${++pkgs}`;
  const vulnerable = (
    packageName: string,
    over: Partial<Parameters<typeof seedMainVulnerability>[2]> = {},
  ) =>
    seedMainVulnerability(
      db(),
      { id: projectId, mainBranchId: main },
      {
        ecosystem: 'npm',
        packageName,
        version: '1.2.5',
        vulnerabilityId: CVE,
        severity: 'high',
        fixedVersion: '1.2.6',
        ...over,
      },
    );
  const post = (
    body: object,
    headers: Record<string, string> = h.orgAdmin.headers,
    id = projectId,
  ) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${id}/fixes`,
      headers,
      payload: body,
    });
  const request = async (packageName: string, ecosystem = 'npm'): Promise<FixItem> => {
    const res = await post({ ecosystem, packageName });
    expect(res.statusCode, res.body).toBe(202);
    return res.json() as FixItem;
  };
  const retry = (id: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    h.ctx.app.inject({ method: 'POST', url: `/api/v0/fixes/${id}/retry`, headers });
  const cancel = (id: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    h.ctx.app.inject({ method: 'DELETE', url: `/api/v0/fixes/${id}`, headers });
  const get = async <T>(url: string, headers = h.orgAdmin.headers): Promise<T> => {
    const res = await h.ctx.app.inject({ method: 'GET', url: `/api/v0${url}`, headers });
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as T;
  };
  const answer = (res: { statusCode: number; json: () => { code?: string } }) => [
    res.statusCode,
    res.json().code,
  ];
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  const fixRows = () =>
    db().select().from(dependencyFixes).where(eq(dependencyFixes.projectId, projectId));
  const lastSeq = async () =>
    Number(
      (
        await db()
          .select({ seq: sql<number>`coalesce(max(${auditEvents.seq}), 0)` })
          .from(auditEvents)
      )[0]?.seq ?? 0,
    );
  const events = async (action: string) =>
    (
      await db()
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, action), gt(auditEvents.seq, since)))
        .orderBy(auditEvents.seq)
    ).map((e) => ({ details: e.details, targetType: e.targetType, targetId: e.targetId }));
  /** The queued jobs of single fixes (commit, close), not the organisation's sync passes. */
  const queuedFixJobs = () =>
    db()
      .select()
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, FIX_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.concurrencyKey} LIKE 'fix:%'`,
        ),
      );
  const monitoring = (enabled: boolean) =>
    h.ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/projects/${projectId}/vulnerability-monitoring`,
      headers: h.orgAdmin.headers,
      payload: { enabled, branchPatterns: [], versionRule: { kind: 'none' }, labelVersions: false },
    });

  beforeAll(async () => {
    fake = await createFakeGitLab();
    fake.addProject({ id: 31, path: 'acme/fixes/requests' });
    h = await createIngestHarness({
      config: scmTestConfig(fake),
      pluginsFor: rbacPlugins({ now: () => NOW }),
    });
    const make = async (username: string, role?: 'viewer' | 'member') => {
      const user = await createUser(h.ctx, { username });
      if (role) await addMember(h.ctx, h.organizationId, user.id, role);
      return login(h.ctx, user.username, user.password);
    };
    viewer = await make('fx-viewer', 'viewer');
    outsider = await make('fx-outsider');
    project = await mappedProject(h, fake, 'FX', 31, { ownConnection: true });
    projectId = project.id;
    other = await h.project('FX-OTHER');
    // A project admin of the other project only, no member of the organisation.
    const grantee = await createUser(h.ctx, { username: 'fx-granted' });
    await db()
      .insert(projectMemberships)
      .values({ projectId: other.id, userId: grantee.id, role: 'project_admin' });
    granted = await login(h.ctx, grantee.username, grantee.password);
    main = await mainBranchId(db(), projectId);
    adminId = (await db().select().from(users).where(eq(users.username, 'ingest-admin')))[0]!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    await enableFixes(h, projectId, { maxOpen: 20 });
    since = await lastSeq();
  });
  afterEach(async () => {
    await db().delete(dependencyFixes);
    await db().delete(jobs).where(eq(jobs.queue, FIX_QUEUE));
  });

  it('creates a requested fix of the package on its first branch and records it', async () => {
    await vulnerable('qf-a');
    const made = await request('qf-a');
    expect(made).toEqual<FixItem>({
      id: expect.any(String),
      state: 'requested',
      refresh: false,
      targetVersion: null,
      mrNumber: null,
      mrUrl: null,
      failure: null,
      updatedAt: expect.any(String),
      family: 'js',
      packageName: 'qf-a',
      origin: 'manual',
      installedVersion: null,
      branch: 'qualor/fix/js/qf-a',
      createdAt: expect.any(String),
    });
    expect(await row(made.id)).toMatchObject({
      projectId,
      state: 'requested',
      origin: 'manual',
      requestedBy: adminId,
      generation: 1,
      branch: 'qualor/fix/js/qf-a',
    });
    expect(await events('dependency_fix.requested')).toEqual([
      {
        details: { family: 'js', packageName: 'qf-a' },
        targetType: 'project',
        targetId: projectId,
      },
    ]);

    // No duplicate: the same package through another ecosystem of its family answers the row.
    const again = await request('qf-a', 'yarn');
    expect(again.id).toBe(made.id);
    expect(await fixRows()).toHaveLength(1);
    expect(await events('dependency_fix.requested')).toHaveLength(1);
  });

  it('answers each precondition of requireFixesUsable with its 409 and writes nothing (B2, B5)', async () => {
    const pkg = fresh();
    await vulnerable(pkg);
    const body = { ecosystem: 'npm', packageName: pkg };

    await enableFixes(h, projectId, { enabled: false });
    expect(answer(await post(body))).toEqual([409, 'FIXES_DISABLED']);
    await enableFixes(h, projectId, { maxOpen: 20 });

    const unbound = await h.project('FX-UNBOUND');
    await enableFixes(h, unbound.id);
    expect(answer(await post(body, h.orgAdmin.headers, unbound.id))).toEqual([
      409,
      'SCM_NOT_BOUND',
    ]);

    await db()
      .update(scmConnections)
      .set({ fixMrsAllowed: false })
      .where(eq(scmConnections.id, project.connectionId));
    expect(answer(await post(body))).toEqual([409, 'FIX_MRS_NOT_ALLOWED']);
    await db()
      .update(scmConnections)
      .set({ fixMrsAllowed: true })
      .where(eq(scmConnections.id, project.connectionId));

    expect((await monitoring(false)).statusCode).toBe(200);
    expect(answer(await post(body))).toEqual([409, 'MONITORING_OFF']);
    expect((await monitoring(true)).statusCode).toBe(200);

    expect(await db().select().from(dependencyFixes)).toEqual([]);
    expect(await events('dependency_fix.requested')).toEqual([]);
    expect((await post(body)).statusCode).toBe(202);
  });

  it('refuses a package main cannot fix: no fixed version, Go stdlib, another ecosystem (422)', async () => {
    const none = fresh();
    await vulnerable(none, { fixedVersion: null });
    expect(answer(await post({ ecosystem: 'npm', packageName: none }))).toEqual([
      422,
      'NOT_FIXABLE',
    ]);
    // Not on main at all.
    expect(answer(await post({ ecosystem: 'npm', packageName: fresh() }))).toEqual([
      422,
      'NOT_FIXABLE',
    ]);
    await vulnerable('stdlib', { ecosystem: 'gomod', version: 'v1.22.1', fixedVersion: '1.22.2' });
    expect(answer(await post({ ecosystem: 'gomod', packageName: 'stdlib' }))).toEqual([
      422,
      'NOT_FIXABLE',
    ]);
    const gradle = fresh();
    await vulnerable(gradle, { ecosystem: 'gradle' });
    const unsupported = await post({ ecosystem: 'gradle', packageName: gradle });
    expect(answer(unsupported)).toEqual([422, 'FIX_ECOSYSTEM_UNSUPPORTED']);
    expect(unsupported.json().title).toBe('No automatic fix for gradle yet');
    for (const body of [
      { ecosystem: 'NPM', packageName: 'x' },
      { ecosystem: 'npm', packageName: '' },
      { ecosystem: 'npm', packageName: 'x'.repeat(513) },
      { ecosystem: 'a'.repeat(33), packageName: 'x' },
      { ecosystem: 'npm', packageName: 'x', extra: true },
    ]) {
      expect(answer(await post(body)), JSON.stringify(body).slice(0, 60)).toEqual([
        422,
        'VALIDATION_FAILED',
      ]);
    }
    expect(await fixRows()).toEqual([]);
  });

  it('caps the fixes in flight: open and committing count (§11.5, R9)', async () => {
    await enableFixes(h, projectId, { maxOpen: 2 });
    const open = fresh();
    const openId = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: open,
      state: 'open',
    });
    await seedFix(db(), { projectId, family: 'js', packageName: fresh(), state: 'committing' });
    const pkg = fresh();
    await vulnerable(pkg);
    const refused = await post({ ecosystem: 'npm', packageName: pkg });
    expect(answer(refused)).toEqual([409, 'FIX_LIMIT_REACHED']);
    expect(refused.json().title).toBe('2 of 2 fix merge requests are open or in progress');
    // An active row is answered before the cap.
    expect((await request(open)).id).toBe(openId);
    expect(await fixRows()).toHaveLength(2);
    expect(await events('dependency_fix.requested')).toEqual([]);
  });

  it('re-arms an ended fix: generation + 1, the attempt cleared, the head kept (B4)', async () => {
    const ended = ['failed', 'no_fix', 'cancelled', 'declined', 'merged', 'fixed'] as const;
    for (const state of ended) {
      const pkg = fresh();
      await vulnerable(pkg);
      const id = await seedFix(db(), {
        projectId,
        family: 'js',
        packageName: pkg,
        state,
        origin: 'auto',
        refresh: true,
        failure: { code: 'package_manager', message: 'npm ERR!' },
        leaseTokenHash: 'a'.repeat(64),
        leaseUntil: NOW,
        mrNumber: 7,
        mrUrl: 'https://scm.example/mr/7',
        headSha: HEAD,
        baseSha: BASE,
        prepared: { baseSha: BASE, files: [], lockfiles: [], unfixable: [], additions: [] },
        targetVersion: '1.2.6',
        declinedTarget: state === 'declined' ? '1.2.6' : null,
      });
      const made = await request(pkg);
      expect(made.id, state).toBe(id);
      expect(await row(id), state).toMatchObject({
        state: 'requested',
        generation: 2,
        origin: 'manual',
        requestedBy: adminId,
        refresh: false,
        failure: null,
        leaseTokenHash: null,
        leaseUntil: null,
        mrNumber: null,
        mrUrl: null,
        prepared: null,
        headSha: HEAD,
        baseSha: BASE,
        branch: `qualor/fix/js/${pkg}`,
        declinedTarget: state === 'declined' ? '1.2.6' : null,
      });
    }
    expect(await events('dependency_fix.requested')).toHaveLength(ended.length);

    // A fix a person took over gets the next branch, and the next after a second take-over.
    const pkg = fresh();
    await vulnerable(pkg);
    const id = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: pkg,
      state: 'taken_over',
      headSha: HEAD,
    });
    expect((await request(pkg)).branch).toBe(`qualor/fix/js/${pkg}-2`);
    await db()
      .update(dependencyFixes)
      .set({ state: 'taken_over' })
      .where(eq(dependencyFixes.id, id));
    expect((await request(pkg)).branch).toBe(`qualor/fix/js/${pkg}-3`);
    expect(await row(id)).toMatchObject({ generation: 3, headSha: HEAD });
  });

  it('retries an ended fix and refuses an active one (R11)', async () => {
    const pkg = fresh();
    await vulnerable(pkg);
    const failed = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: pkg,
      state: 'failed',
      failure: { code: 'upload_refused', message: 'x' },
    });
    const res = await retry(failed);
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toMatchObject({ id: failed, state: 'requested', failure: null });
    expect(await row(failed)).toMatchObject({ state: 'requested', generation: 2 });
    expect(await events('dependency_fix.retried')).toEqual([
      { details: { family: 'js', packageName: pkg }, targetType: 'project', targetId: projectId },
    ]);

    const openPkg = fresh();
    await vulnerable(openPkg);
    const open = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: openPkg,
      state: 'open',
    });
    const before = await row(open);
    expect(answer(await retry(open))).toEqual([409, 'FIX_NOT_RETRYABLE']);
    expect(answer(await retry(failed))).toEqual([409, 'FIX_NOT_RETRYABLE']);
    expect(await row(open)).toEqual(before);

    // A taken-over fix retries on its next branch.
    const takenPkg = fresh();
    await vulnerable(takenPkg);
    const taken = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: takenPkg,
      state: 'taken_over',
    });
    expect((await retry(taken)).json()).toMatchObject({ branch: `qualor/fix/js/${takenPkg}-2` });

    // As a request: nothing to fix on main, or the cap.
    const gone = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: fresh(),
      state: 'fixed',
    });
    expect(answer(await retry(gone))).toEqual([422, 'NOT_FIXABLE']);
    // Three active now (the two retried and the open one): the cap comes before eligibility.
    await enableFixes(h, projectId, { maxOpen: 3 });
    const capped = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: fresh(),
      state: 'failed',
    });
    expect(answer(await retry(capped))).toEqual([409, 'FIX_LIMIT_REACHED']);
    await enableFixes(h, projectId, { enabled: false });
    expect(answer(await retry(capped))).toEqual([409, 'FIXES_DISABLED']);
    expect(await events('dependency_fix.retried')).toHaveLength(2);
  });

  it('retries an open fix whose refresh failed in place, and refuses one without a failure (T18a)', async () => {
    const stuck = fresh();
    await vulnerable(stuck);
    const failing = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: stuck,
      state: 'open',
      mrNumber: 12,
      failure: { code: 'scm_permission', message: 'x' },
    });
    const before = await row(failing);
    const res = await retry(failing);
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toMatchObject({
      id: failing,
      state: 'open',
      refresh: true,
      failure: null,
      mrNumber: 12,
    });
    expect(await row(failing)).toMatchObject({
      state: 'open',
      refresh: true,
      failure: null,
      mrNumber: 12,
      generation: before.generation + 1,
    });
    expect(
      (await events('dependency_fix.retried')).filter((e) => e.details.packageName === stuck),
    ).toEqual([
      { details: { family: 'js', packageName: stuck }, targetType: 'project', targetId: projectId },
    ]);

    const quiet = fresh();
    await vulnerable(quiet);
    const open = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: quiet,
      state: 'open',
      mrNumber: 13,
    });
    const untouched = await row(open);
    expect(answer(await retry(open))).toEqual([409, 'FIX_NOT_RETRYABLE']);
    expect(await row(open)).toEqual(untouched);
  });

  it('cancels: requested and preparing end, committing is busy, open closes its MR (R10, F1)', async () => {
    const requestedPkg = fresh();
    const requested = await seedFix(db(), { projectId, family: 'js', packageName: requestedPkg });
    expect((await cancel(requested)).statusCode).toBe(204);
    expect(await row(requested)).toMatchObject({ state: 'cancelled', generation: 2 });

    const preparingPkg = fresh();
    const preparing = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: preparingPkg,
      state: 'preparing',
    });
    expect((await cancel(preparing)).statusCode).toBe(204);
    expect(await row(preparing)).toMatchObject({
      state: 'cancelled',
      generation: 2,
      leaseTokenHash: null,
      leaseUntil: null,
    });
    expect(await queuedFixJobs()).toEqual([]);

    const committing = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: fresh(),
      state: 'committing',
    });
    const before = await row(committing);
    expect(answer(await cancel(committing))).toEqual([409, 'FIX_BUSY']);
    expect(await row(committing)).toEqual(before);

    const openPkg = fresh();
    const open = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: openPkg,
      state: 'open',
    });
    expect((await cancel(open)).statusCode).toBe(204);
    expect(await row(open)).toMatchObject({ state: 'cancelled', generation: 2, mrNumber: 12 });
    const queued = await queuedFixJobs();
    expect(queued.map((j) => [j.concurrencyKey, j.payload])).toEqual([
      [`fix:${open}`, { kind: 'close', fixId: open, generation: 2, attempt: 0 }],
    ]);
    expect(await events('dependency_fix.cancelled')).toEqual(
      [requestedPkg, preparingPkg, openPkg].map((packageName) => ({
        details: { family: 'js', packageName },
        targetType: 'project',
        targetId: projectId,
      })),
    );

    // Cancelling an ended fix changes and records nothing.
    expect((await cancel(open)).statusCode).toBe(204);
    expect(await row(open)).toMatchObject({ state: 'cancelled', generation: 2 });
    expect(await events('dependency_fix.cancelled')).toHaveLength(3);
    expect(await queuedFixJobs()).toHaveLength(1);
  });

  it('closes the MR of any cancelled fix that has one: a refresh in preparation, a requested one (R8, R10)', async () => {
    // A claimed refresh of an open MR is `preparing` with its MR (R8); so is a released one later.
    const mr = { mrNumber: 31, mrUrl: 'https://scm.example/mr/31', headSha: HEAD };
    const preparing = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: fresh(),
      state: 'preparing',
      ...mr,
    });
    const requested = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: fresh(),
      state: 'requested',
      ...mr,
    });
    for (const id of [preparing, requested]) {
      expect((await cancel(id)).statusCode).toBe(204);
      expect(await row(id)).toMatchObject({ state: 'cancelled', generation: 2, ...mr });
    }
    const queued = await queuedFixJobs();
    expect(
      queued
        .map((j) => j.payload)
        .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    ).toEqual(
      [preparing, requested]
        .map((fixId) => ({ kind: 'close', fixId, generation: 2, attempt: 0 }))
        .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    );
  });

  it('embeds the fix and fixable in vulnerability items and Trivy issues of main (R12)', async () => {
    const pkg = fresh();
    await vulnerable(pkg);
    const made = await request(pkg);
    const expected: Fix = {
      id: made.id,
      state: 'requested',
      refresh: false,
      targetVersion: null,
      mrNumber: null,
      mrUrl: null,
      failure: null,
      updatedAt: made.updatedAt,
    };
    type Item = { packageName: string; fix: Fix | null; fixable: boolean };
    const listed = async (query: string) =>
      (
        await get<{ items: Item[] }>(`/projects/${projectId}/vulnerabilities?pageSize=100${query}`)
      ).items.find((i) => i.packageName === pkg);
    for (const query of ['', `&target=branch:${main}`]) {
      const item = await listed(query);
      expect(item?.fix, query).toEqual(expected);
      expect(item?.fix, query).not.toHaveProperty('branch');
      expect(item?.fixable, query).toBe(true);
    }

    // A pair only a version has is not fixable.
    const [version] = await db()
      .insert(projectVersions)
      .values({
        projectId,
        label: `2.${pkgs}.0`,
        source: 'tag',
        tag: `v2.${pkgs}.0`,
        analyzedAt: NOW,
        tracking: 'pinned',
      })
      .returning();
    const versionPkg = fresh();
    await seedTargetRow(db(), {
      projectId,
      versionId: version!.id,
      packageName: versionPkg,
      vulnerabilityId: CVE,
      fixedVersion: '2.0.0',
    });
    const onVersion = (
      await get<{ items: Item[] }>(
        `/projects/${projectId}/vulnerabilities?target=version:${version!.id}&pageSize=100`,
      )
    ).items.find((i) => i.packageName === versionPkg);
    expect(onVersion).toMatchObject({ fix: null, fixable: false });

    // A Trivy issue of main shows the same fix; a merge request's and a code issue show none.
    const trivyRule = await seedRule(db(), { key: `trivy:${CVE}`, quality: 'security' });
    const codeRule = await seedRule(db(), { key: 'eslint:no-eval' });
    const trivy = (branchId: string) =>
      seedIssue(db(), {
        projectId,
        branchId,
        ruleId: trivyRule,
        path: 'package-lock.json',
        packageName: pkg,
        quality: 'security',
      });
    const onMain = await trivy(main);
    const code = await seedIssue(db(), { projectId, branchId: main, ruleId: codeRule });
    const [mr] = await db()
      .insert(branches)
      .values({ projectId, kind: 'merge_request', name: '77', isMain: false })
      .returning();
    const onMr = await trivy(mr!.id);
    type Issue = { id: string; fix: Fix | null; fixable: boolean; fixEcosystem: string | null };
    const mainIssues = (await get<{ items: Issue[] }>(`/issues?branchId=${main}&limit=500`)).items;
    expect(mainIssues.find((i) => i.id === onMain)).toMatchObject({
      fix: expected,
      fixable: true,
      fixEcosystem: 'npm',
    });
    expect(mainIssues.find((i) => i.id === code)).toMatchObject({
      fix: null,
      fixable: false,
      fixEcosystem: null,
    });
    expect(await get<Issue>(`/issues/${onMain}`)).toMatchObject({
      fix: expected,
      fixable: true,
      fixEcosystem: 'npm',
    });
    const mrIssues = (await get<{ items: Issue[] }>(`/issues?branchId=${mr!.id}`)).items;
    expect(mrIssues.find((i) => i.id === onMr)).toMatchObject({
      fix: null,
      fixable: false,
      fixEcosystem: null,
    });
    expect(await get<Issue>(`/issues/${onMr}`)).toMatchObject({
      fix: null,
      fixable: false,
      fixEcosystem: null,
    });
  });

  it('lists the fixes newest first in keyset pages, by state (spec §6.8)', async () => {
    const ids: string[] = [];
    for (const state of ['requested', 'open', 'failed'] as const) {
      ids.push(await seedFix(db(), { projectId, family: 'js', packageName: fresh(), state }));
    }
    await seedFix(db(), { projectId: other.id, family: 'js', packageName: fresh() });
    type Page = { items: FixItem[]; nextCursor: string | null };
    const first = await get<Page>(`/projects/${projectId}/fixes?limit=2`, viewer.headers);
    expect(first.items.map((i) => i.id)).toEqual([ids[2], ids[1]]);
    expect(first.nextCursor).not.toBeNull();
    const second = await get<Page>(
      `/projects/${projectId}/fixes?limit=2&cursor=${encodeURIComponent(first.nextCursor!)}`,
    );
    expect(second.items.map((i) => i.id)).toEqual([ids[0]]);
    expect(second.nextCursor).toBeNull();
    expect(second.items[0]).toMatchObject({
      state: 'requested',
      family: 'js',
      origin: 'manual',
      branch: expect.stringMatching(/^qualor\/fix\/js\/qf-\d+$/),
    });
    const open = await get<Page>(`/projects/${projectId}/fixes?state=open`);
    expect(open.items.map((i) => [i.id, i.state])).toEqual([[ids[1], 'open']]);
    const bad = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/projects/${projectId}/fixes?state=closed`,
      headers: h.orgAdmin.headers,
    });
    expect(answer(bad)).toEqual([422, 'VALIDATION_FAILED']);
  });

  it('lets triagers act: a viewer, a project token and an outsider are refused', async () => {
    const pkg = fresh();
    await vulnerable(pkg);
    const body = { ecosystem: 'npm', packageName: pkg };
    expect(answer(await post(body, viewer.headers))).toEqual([403, 'FORBIDDEN']);
    expect(answer(await post(body, outsider.headers))).toEqual([404, 'NOT_FOUND']);
    const token = bearer(project.token);
    expect(answer(await post(body, token))).toEqual([403, 'TOKEN_NOT_ALLOWED']);
    const failed = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: pkg,
      state: 'failed',
    });
    for (const call of [retry, cancel]) {
      expect(answer(await call(failed, viewer.headers))).toEqual([403, 'FORBIDDEN']);
      expect(answer(await call(failed, token))).toEqual([403, 'TOKEN_NOT_ALLOWED']);
      // A fix of a project the caller cannot see is not found, as an unknown one.
      expect(answer(await call(failed, outsider.headers))).toEqual([404, 'NOT_FOUND']);
      expect(answer(await call(failed, granted.headers))).toEqual([404, 'NOT_FOUND']);
      expect(answer(await call('00000000-0000-7000-8000-000000000000'))).toEqual([
        404,
        'NOT_FOUND',
      ]);
    }
    expect((await cancel(failed, outsider.headers)).json().title).toBe('Fix not found');
    // The other project's admin reaches its own fix (and its fixes are switched off).
    const own = await seedFix(db(), {
      projectId: other.id,
      family: 'js',
      packageName: fresh(),
      state: 'failed',
    });
    expect(answer(await retry(own, granted.headers))).toEqual([409, 'FIXES_DISABLED']);
    const list = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/projects/${projectId}/fixes`,
      headers: token,
    });
    expect(answer(list)).toEqual([403, 'TOKEN_NOT_ALLOWED']);
    expect(await row(failed)).toMatchObject({ state: 'failed', generation: 1 });
    expect(await events('dependency_fix.requested')).toEqual([]);
  });

  /**
   * Starts the requests while a transaction holds the project row (which a fix request locks
   * first), waits until all of them queue behind it, runs `whileHeld` in that transaction, then
   * lets them go at once.
   */
  const inLockstep = async <T>(
    start: () => Promise<T>[],
    whileHeld?: (tx: Executor) => Promise<unknown>,
  ): Promise<T[]> => {
    let started: Promise<T>[] = [];
    await db().transaction(async (tx) => {
      await tx.execute(sql`SELECT 1 FROM projects WHERE id = ${projectId} FOR UPDATE`);
      started = start();
      for (let i = 0; i < 200; i += 1) {
        const waiting = await db().execute<{ n: number }>(sql`
          SELECT count(*)::int AS n FROM pg_stat_activity
           WHERE datname = current_database() AND wait_event_type = 'Lock'`);
        if ((waiting.rows[0]?.n ?? 0) >= started.length) {
          await whileHeld?.(tx);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error('the requests never queued behind the project row');
    });
    return Promise.all(started);
  };

  it('gives two packages that slug alike two branches, also at once (R32, T2a)', async () => {
    await vulnerable('@a/b');
    await vulnerable('a-b');
    const answers = await inLockstep(() => [
      post({ ecosystem: 'npm', packageName: '@a/b' }),
      post({ ecosystem: 'npm', packageName: 'a-b' }),
    ]);
    expect(answers.map((r) => r.statusCode)).toEqual([202, 202]);
    expect(answers.map((r) => (r.json() as FixItem).branch).sort()).toEqual([
      'qualor/fix/js/a-b',
      'qualor/fix/js/a-b-2',
    ]);
    expect((await fixRows()).map((r) => r.branch).sort()).toEqual([
      'qualor/fix/js/a-b',
      'qualor/fix/js/a-b-2',
    ]);
  });

  it('reads the switch and the cap under the project lock, as the settings save writes them', async () => {
    const pkg = fresh();
    await vulnerable(pkg);
    const body = { ecosystem: 'npm', packageName: pkg };
    const setSettings =
      (values: Partial<typeof projectFixSettings.$inferInsert>) => (tx: Executor) =>
        tx
          .update(projectFixSettings)
          .set(values)
          .where(eq(projectFixSettings.projectId, projectId));

    // Switched off while the request waits for the project row.
    const [off] = await inLockstep(() => [post(body)], setSettings({ enabled: false }));
    expect(answer(off!)).toEqual([409, 'FIXES_DISABLED']);
    await enableFixes(h, projectId, { maxOpen: 20 });

    // The cap lowered to the one fix in flight while the request waits.
    await seedFix(db(), { projectId, family: 'js', packageName: fresh(), state: 'open' });
    const [capped] = await inLockstep(() => [post(body)], setSettings({ maxOpen: 1 }));
    expect(answer(capped!)).toEqual([409, 'FIX_LIMIT_REACHED']);

    // A retry reads them under the lock too.
    await enableFixes(h, projectId, { maxOpen: 20 });
    const failed = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: pkg,
      state: 'failed',
    });
    const [retried] = await inLockstep(() => [retry(failed)], setSettings({ enabled: false }));
    expect(answer(retried!)).toEqual([409, 'FIXES_DISABLED']);
    expect(await row(failed)).toMatchObject({ state: 'failed', generation: 1 });
    expect(await events('dependency_fix.requested')).toEqual([]);
    expect(await events('dependency_fix.retried')).toEqual([]);
  });

  it('runs one query at a time on its transaction (no pg queued-query deprecation)', async () => {
    const pkg = fresh();
    await vulnerable(pkg);
    const failedPkg = fresh();
    await vulnerable(failedPkg);
    const failed = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: failedPkg,
      state: 'failed',
    });
    // pg warns when a query is queued behind another one already waiting on the same client.
    const proto = pg.Client.prototype as unknown as {
      query: (...args: unknown[]) => unknown;
    };
    const original = proto.query;
    let queuedBehind = 0;
    const spy = vi.spyOn(proto, 'query').mockImplementation(function (
      this: { _queryQueue?: unknown[] },
      ...args: unknown[]
    ) {
      if ((this._queryQueue?.length ?? 0) > 0) queuedBehind += 1;
      return original.apply(this, args);
    });
    try {
      expect((await post({ ecosystem: 'npm', packageName: pkg })).statusCode).toBe(202);
      expect((await retry(failed)).statusCode).toBe(202);
      expect((await cancel(failed)).statusCode).toBe(204);
    } finally {
      spy.mockRestore();
    }
    expect(queuedBehind).toBe(0);
  });

  it('names a Python fix by its PEP 503 name, whichever spelling asks (ruling T8b)', async () => {
    await vulnerable('Django_Rest', {
      ecosystem: 'uv',
      version: '3.14.0',
      vulnerabilityId: 'CVE-2026-5101',
      fixedVersion: '3.15.2',
    });
    await vulnerable('django-rest', {
      ecosystem: 'poetry',
      version: '3.14.0',
      vulnerabilityId: 'CVE-2026-5102',
      fixedVersion: '3.15.2',
    });
    const made = await request('Django_Rest', 'uv');
    expect(made).toMatchObject({
      family: 'python',
      packageName: 'django-rest',
      branch: 'qualor/fix/python/django-rest',
    });
    expect((await request('django-rest', 'poetry')).id).toBe(made.id);
    expect((await request('DJANGO.rest', 'uv')).id).toBe(made.id);
    expect(await fixRows()).toHaveLength(1);
    expect((await events('dependency_fix.requested')).map((e) => e.details)).toEqual([
      { family: 'python', packageName: 'django-rest' },
    ]);
    type Item = { packageName: string; fix: Fix | null; fixable: boolean };
    const items = (
      await get<{ items: Item[] }>(
        `/projects/${projectId}/vulnerabilities?pageSize=100&target=branch:${main}`,
      )
    ).items.filter((i) => ['Django_Rest', 'django-rest'].includes(i.packageName));
    expect(items.map((i) => [i.packageName, i.fix?.id, i.fixable]).sort()).toEqual([
      ['Django_Rest', made.id, true],
      ['django-rest', made.id, true],
    ]);
    // A retry of the ended fix reads both spellings' rows as its vulnerabilities.
    await db()
      .update(dependencyFixes)
      .set({ state: 'failed' })
      .where(eq(dependencyFixes.id, made.id));
    expect((await retry(made.id)).statusCode).toBe(202);
  });
});

import { mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { and, asc, eq, sql } from 'drizzle-orm';
import type { DependencyEntry, DependencyIgnore } from '@qualor/shared';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { reportWith, type ReportParts } from '../../test/reports';
import { trivyArchive } from '../../test/trivy-archive';
import { uuidv7 } from '../db/ids';
import {
  analyses,
  branches,
  instanceSettings,
  jobs,
  matchedPackages,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  targetVulnerabilities,
  vulndbChunks,
  vulnerabilityMatches,
  vulnerabilityTargetChecks,
} from '../db/schema';
import { claimJob } from '../queue/queue';
import { runUntilIdle } from '../queue/worker';
import { writeVulndbSettings } from '../vulndb/settings';
import { readVulndbState, updateVulndbState } from '../vulndb/state';
import { makeDatasetCurrent, storeDataset, type DatasetRow } from '../vulndb/store';
import { purlOf } from './purl';
import {
  enqueueRecheck,
  ignoreActive,
  RECHECK_QUEUE,
  recheckHandlers,
  recheckProjects,
  type RecheckDeps,
  type RecheckScope,
} from './recheck';
import type { TrivyRun, TrivyRunner, VulnerabilityMatch } from './trivy';

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };

const dep = (name: string, version: string, ecosystem = 'npm'): DependencyEntry => ({
  path: 'package-lock.json',
  ecosystem,
  name,
  version,
  licenses: [],
});
const A = dep('lodash', '4.17.20');
const B = dep('minimist', '1.2.0');
const C = dep('zod', '4.0.0');
const D = dep('@babel/traverse', '7.0.0');
const purl = (d: DependencyEntry): string => purlOf(d.ecosystem, d.name, d.version)!;
const [PA, PB, PC, PD] = [A, B, C, D].map(purl) as [string, string, string, string];

/** What the fake Trivy finds, per purl. */
const FINDS: Record<string, string[]> = {
  [PA]: ['CVE-2026-0001'],
  [PB]: ['CVE-2026-0002', 'CVE-2026-0003'],
  [PD]: ['CVE-2026-0004'],
};

const matchOf = (id: string): VulnerabilityMatch => ({
  vulnerabilityId: id,
  severity: 'high',
  title: `Title of ${id}`,
  fixedVersion: '9.9.9',
  primaryUrl: `https://avd.aquasec.com/nvd/${id.toLowerCase()}`,
  publishedAt: '2026-01-02T03:04:05Z',
});

interface FakeTrivy extends TrivyRunner {
  calls: { purls: string[]; names: string[]; cacheDir: string }[];
  failure: TrivyRun | null;
  onRun: (() => Promise<void>) | null;
}

/** A Trivy that answers {@link FINDS} for the purls of the SBOM and records each run. */
function fakeTrivy(): FakeTrivy {
  const fake: FakeTrivy = {
    calls: [],
    failure: null,
    onRun: null,
    async run(sbomJson, cacheDir) {
      const components = (JSON.parse(sbomJson) as { components: { purl: string; name: string }[] })
        .components;
      fake.calls.push({
        purls: components.map((c) => c.purl),
        names: components.map((c) => c.name),
        cacheDir,
      });
      const hook = fake.onRun;
      fake.onRun = null;
      await hook?.();
      if (fake.failure !== null) return fake.failure;
      const matches = new Map<string, VulnerabilityMatch[]>();
      for (const { purl: p } of components) {
        const ids = FINDS[p];
        // Trivy may report one id twice for a package (two advisories): stored once.
        if (ids !== undefined) matches.set(p, [...ids, ...ids.slice(0, 1)].map(matchOf));
      }
      return { ok: true, matches };
    },
  };
  return fake;
}

describe('vulnerability re-checks', () => {
  let h: IngestHarness;
  let dir: string;
  let primary: DatasetRow;
  let trivy: FakeTrivy;
  let now: Date;
  let n = 0;

  const db = () => h.ctx.db;
  const deps = (overrides: Partial<RecheckDeps> = {}): RecheckDeps => ({
    db: db(),
    config: { vulndb: { dir, trivyPath: '/nonexistent/trivy' } },
    runner: trivy,
    now: () => now,
    logger: silent,
    ...overrides,
  });
  const recheck = (scope: RecheckScope, overrides: Partial<RecheckDeps> = {}) =>
    recheckProjects(deps(overrides), scope);
  const storeDs = async (text: string): Promise<DatasetRow> => {
    const got = await storeDataset(db(), {
      kind: 'trivy',
      source: 'upload',
      chunks: (async function* () {
        await Promise.resolve();
        yield trivyArchive({ db: Buffer.from(text) });
      })(),
      maxBytes: 1024 ** 3,
    });
    if (!('dataset' in got)) throw new Error(JSON.stringify(got));
    return got.dataset;
  };
  const prefix = (d: DatasetRow): string => d.digest.replace('sha256:', '').slice(0, 16);

  const project = async (
    settings: Partial<typeof projectVulnerabilitySettings.$inferInsert> = {},
  ): Promise<IngestProject> => {
    const p = await h.project(`acme/rck-${++n}`);
    await db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId: p.id, ...settings });
    return p;
  };
  let day = 0;
  /** A branch analysis, each one dated a day after the one before. */
  const onBranch = (p: IngestProject, branch: string, parts: ReportParts = {}) =>
    p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch,
        analysisDate: new Date(Date.UTC(2026, 9, 1) + ++day * 86_400_000).toISOString(),
        revision: (day % 16).toString(16).repeat(40),
        ...parts,
      }),
    );
  /** A tag scan: the version `label`. */
  const tagScan = (p: IngestProject, label: string, parts: ReportParts = {}) =>
    onBranch(p, 'unused', { branch: null, tag: `v${label}`, version: label, ...parts });

  const branchId = async (p: IngestProject, name: string): Promise<string> => {
    const [row] = await db()
      .select({ id: branches.id })
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.name, name)));
    return row!.id;
  };
  const versionId = async (p: IngestProject, label: string): Promise<string> => {
    const [row] = await db()
      .select({ id: projectVersions.id })
      .from(projectVersions)
      .where(and(eq(projectVersions.projectId, p.id), eq(projectVersions.label, label)));
    return row!.id;
  };
  const rows = (p: IngestProject) =>
    db()
      .select()
      .from(targetVulnerabilities)
      .where(eq(targetVulnerabilities.projectId, p.id))
      .orderBy(asc(targetVulnerabilities.id));
  /** `<branch name or version label> <purl> <id>[ ignored]`, sorted. */
  const described = async (p: IngestProject): Promise<string[]> => {
    const names = new Map<string, string>();
    for (const b of await db()
      .select({ id: branches.id, name: branches.name })
      .from(branches)
      .where(eq(branches.projectId, p.id))) {
      names.set(b.id, b.name);
    }
    for (const v of await db()
      .select({ id: projectVersions.id, label: projectVersions.label })
      .from(projectVersions)
      .where(eq(projectVersions.projectId, p.id))) {
      names.set(v.id, v.label);
    }
    return (await rows(p))
      .map(
        (r) =>
          `${names.get(r.branchId ?? r.versionId ?? '') ?? '?'} ${r.purl} ${r.vulnerabilityId}${r.ignored ? ' ignored' : ''}`,
      )
      .sort();
  };
  const digests = async (purls: string[]): Promise<Record<string, string>> => {
    const got = await db().select().from(matchedPackages);
    return Object.fromEntries(
      got.filter((r) => purls.includes(r.purl)).map((r) => [r.purl, r.datasetDigest]),
    );
  };
  const recheckJobs = () =>
    db()
      .select({ status: jobs.status, payload: jobs.payload, key: jobs.concurrencyKey })
      .from(jobs)
      .where(eq(jobs.queue, RECHECK_QUEUE))
      .orderBy(asc(jobs.id));
  const instanceSwitch = (enabled: boolean) =>
    db().transaction((tx) => writeVulndbSettings(tx, { enabled }, h.ctx.config.secretKey));
  const api = (method: 'PATCH' | 'PUT', url: string, payload: object) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: h.orgAdmin.headers,
      payload,
    });

  beforeAll(async () => {
    h = await createIngestHarness();
    dir = await mkdtemp(join(tmpdir(), 'qualor-recheck-'));
    primary = await storeDs('primary database');
  });
  beforeEach(async () => {
    await db().delete(targetVulnerabilities);
    await db().delete(vulnerabilityMatches);
    await db().delete(matchedPackages);
    await db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
    await db().delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
    await db().delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb_state'));
    expect(await makeDatasetCurrent(db(), primary.id)).toBe(true);
    trivy = fakeTrivy();
    now = new Date('2026-10-31T12:00:00Z');
  });
  afterAll(async () => {
    await h.close();
    await rm(dir, { recursive: true, force: true });
  });

  describe('one re-check across target kinds', () => {
    it('writes rows per target from one Trivy run, then none until the dataset changes', async () => {
      const p = await project({ branchPatterns: ['release/*'] });
      await onBranch(p, 'main', { dependencies: [A, B] });
      await onBranch(p, 'release/1.0', { dependencies: [B, C] });
      await tagScan(p, '1.0.0', { dependencies: [A, D] });

      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'done', summary: { projects: 1, packages: 4 } });
      expect(trivy.calls).toHaveLength(1);
      expect(trivy.calls[0]!.purls.sort()).toEqual([PA, PB, PC, PD].sort());
      // R13: the SBOM names a package by its stored name.
      expect(trivy.calls[0]!.names).toContain('@babel/traverse');
      expect(trivy.calls[0]!.cacheDir).toBe(join(dir, prefix(primary)));
      expect(await described(p)).toEqual(
        [
          `main ${PA} CVE-2026-0001`,
          `main ${PB} CVE-2026-0002`,
          `main ${PB} CVE-2026-0003`,
          `release/1.0 ${PB} CVE-2026-0002`,
          `release/1.0 ${PB} CVE-2026-0003`,
          `1.0.0 ${PA} CVE-2026-0001`,
          `1.0.0 ${PD} CVE-2026-0004`,
        ].sort(),
      );
      const babel = (await rows(p)).find((r) => r.purl === PD);
      expect(babel).toMatchObject({
        ecosystem: 'npm',
        packageName: '@babel/traverse',
        packageVersion: '7.0.0',
        versionId: await versionId(p, '1.0.0'),
        branchId: null,
        ignored: false,
      });
      const [stored] = await db()
        .select()
        .from(vulnerabilityMatches)
        .where(eq(vulnerabilityMatches.purl, PA));
      expect(stored).toMatchObject({
        vulnerabilityId: 'CVE-2026-0001',
        severity: 'high',
        title: 'Title of CVE-2026-0001',
        fixedVersion: '9.9.9',
        primaryUrl: 'https://avd.aquasec.com/nvd/cve-2026-0001',
      });
      expect(stored!.publishedAt?.toISOString()).toBe('2026-01-02T03:04:05.000Z');
      expect(await digests([PA, PB, PC, PD])).toEqual({
        [PA]: primary.digest,
        [PB]: primary.digest,
        [PC]: primary.digest,
        [PD]: primary.digest,
      });

      // The same dataset again: nothing to match, the rows stay as they are.
      const before = await rows(p);
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({ kind: 'done' });
      expect(trivy.calls).toHaveLength(1);
      expect(await rows(p)).toEqual(before);

      // A new dataset: every package is matched again, the rows keep their first_seen_at.
      const next = await storeDs('next database');
      expect(await makeDatasetCurrent(db(), next.id)).toBe(true);
      await recheck({ projectIds: [p.id] });
      expect(trivy.calls).toHaveLength(2);
      expect(trivy.calls[1]!.purls.sort()).toEqual([PA, PB, PC, PD].sort());
      expect(trivy.calls[1]!.cacheDir).toBe(join(dir, prefix(next)));
      expect(Object.values(await digests([PA, PB, PC, PD]))).toEqual(Array(4).fill(next.digest));
      expect(await rows(p)).toEqual(before);
    });

    it('re-checks every project for a full re-check and records the run', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      const result = await recheck({ all: true });
      expect(result).toMatchObject({ kind: 'done' });
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001`]);
      const state = await readVulndbState(db());
      expect(state.lastRecheck).toMatchObject({ at: now.toISOString() });
      expect(state.lastRecheck!.projects).toBeGreaterThanOrEqual(1);
    });

    it('a scoped re-check leaves the summary of the last full one (R15)', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await recheck({ all: true });
      const full = (await readVulndbState(db())).lastRecheck;
      expect(full).not.toBeNull();
      now = new Date('2026-11-02T08:00:00Z');
      await onBranch(p, 'main', { dependencies: [A, B] });
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({
        kind: 'done',
        summary: { projects: 1, packages: 2 },
      });
      expect((await readVulndbState(db())).lastRecheck).toEqual(full);
    });
  });

  describe('per-target checks', () => {
    const checks = async (p: IngestProject) => {
      const names = new Map<string, string>();
      for (const b of await db()
        .select({ id: branches.id, name: branches.name })
        .from(branches)
        .where(eq(branches.projectId, p.id))) {
        names.set(b.id, b.name);
      }
      for (const v of await db()
        .select({ id: projectVersions.id, label: projectVersions.label })
        .from(projectVersions)
        .where(eq(projectVersions.projectId, p.id))) {
        names.set(v.id, v.label);
      }
      const got = await db()
        .select()
        .from(vulnerabilityTargetChecks)
        .where(eq(vulnerabilityTargetChecks.projectId, p.id));
      return new Map(got.map((r) => [names.get(r.branchId ?? r.versionId ?? '') ?? '?', r]));
    };
    const lastAnalysis = async (p: IngestProject, name: string): Promise<string> => {
      const [row] = await db()
        .select({ id: branches.lastAnalysisId })
        .from(branches)
        .where(eq(branches.id, await branchId(p, name)));
      return row!.id ?? '';
    };

    it('writes a check for every tracked target, with the first_seen_at of its rows as baseline', async () => {
      const p = await project({ branchPatterns: ['release/*'] });
      await onBranch(p, 'main', { dependencies: [A] });
      await onBranch(p, 'release/1.0', { dependencies: [C] });
      await tagScan(p, '1.0.0', { dependencies: [A] });
      expect((await checks(p)).size).toBe(0);

      await recheck({ projectIds: [p.id] });
      const got = await checks(p);
      expect([...got.keys()].sort()).toEqual(['1.0.0', 'main', 'release/1.0']);
      const [seen] = await rows(p);
      for (const check of got.values()) {
        expect(check.baselineAt).toEqual(check.checkedAt);
      }
      // The rows were first seen in the same run, at the same moment.
      expect(got.get('main')!.baselineAt).toEqual(seen!.firstSeenAt);
      expect(got.get('main')!.basis).toBe(await lastAnalysis(p, 'main'));
      // A target without a vulnerability is checked too.
      expect(got.get('release/1.0')!.basis).toBe(await lastAnalysis(p, 'release/1.0'));
      const [version] = await db()
        .select({ analyzedAt: projectVersions.analyzedAt })
        .from(projectVersions)
        .where(eq(projectVersions.id, await versionId(p, '1.0.0')));
      expect(got.get('1.0.0')!.basis).toBe(version!.analyzedAt.toISOString());
    });

    it('moves only checked_at when nothing was analysed since, and baseline_at after a new analysis', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await tagScan(p, '1.0.0', { dependencies: [A] });
      await recheck({ projectIds: [p.id] });
      const first = await checks(p);

      await recheck({ projectIds: [p.id] });
      const second = await checks(p);
      for (const label of ['main', '1.0.0']) {
        expect(second.get(label)).toMatchObject({
          basis: first.get(label)!.basis,
          baselineAt: first.get(label)!.baselineAt,
        });
        expect(second.get(label)!.checkedAt.getTime()).toBeGreaterThan(
          first.get(label)!.checkedAt.getTime(),
        );
      }

      await onBranch(p, 'main', { dependencies: [A, B] });
      await recheck({ projectIds: [p.id] });
      const third = await checks(p);
      expect(third.get('main')!.basis).toBe(await lastAnalysis(p, 'main'));
      expect(third.get('main')!.basis).not.toBe(first.get('main')!.basis);
      expect(third.get('main')!.baselineAt.getTime()).toBeGreaterThan(
        second.get('main')!.baselineAt.getTime(),
      );
      // The new rows were first seen at the new baseline; the old rows stay older.
      const fresh = (await rows(p)).filter((r) => r.purl === PB);
      expect(fresh.length).toBeGreaterThan(0);
      for (const r of fresh) expect(r.firstSeenAt).toEqual(third.get('main')!.baselineAt);
      // The version was not scanned again.
      expect(third.get('1.0.0')).toMatchObject({
        basis: first.get('1.0.0')!.basis,
        baselineAt: first.get('1.0.0')!.baselineAt,
      });
    });

    it('records the analysis the inventory was read at, not one that landed during the run', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      const seenByDiff: string[] = [];
      // Pass one matches A. A new analysis then adds D, which pass two reads and matches late;
      // a third analysis lands during that late match, after the inventory was read.
      trivy.onRun = async () => {
        await onBranch(p, 'main', { dependencies: [A, D] });
        trivy.onRun = async () => {
          seenByDiff.push(await lastAnalysis(p, 'main'));
          await onBranch(p, 'main', { dependencies: [A, D] });
        };
      };
      await recheck({ projectIds: [p.id] });
      expect(trivy.calls).toHaveLength(2);
      const landed = await lastAnalysis(p, 'main');
      expect(landed).not.toBe(seenByDiff[0]);
      const first = (await checks(p)).get('main')!;
      expect(first.basis).toBe(seenByDiff[0]);

      // The next re-check sees the newer analysis as a changed basis and moves the baseline.
      await recheck({ projectIds: [p.id] });
      const second = (await checks(p)).get('main')!;
      expect(second.basis).toBe(landed);
      expect(second.baselineAt.getTime()).toBeGreaterThan(first.baselineAt.getTime());
    });

    it('leaves the check of an untracked target as it is (R17)', async () => {
      const p = await project({ versionRule: 'lines', versionLines: 1 });
      await tagScan(p, '1.0.0', { dependencies: [A] });
      await tagScan(p, '2.0.0', { dependencies: [D] });
      const old = await versionId(p, '1.0.0');
      const track = async (tracking: string) =>
        expect(
          (await api('PATCH', `/projects/${p.id}/versions/${old}`, { tracking })).statusCode,
        ).toBe(200);
      await track('pinned');
      await recheck({ projectIds: [p.id] });
      const before = (await checks(p)).get('1.0.0')!;

      await track('auto');
      await recheck({ projectIds: [p.id] });
      const after = await checks(p);
      expect(after.get('1.0.0')).toEqual(before);
      expect(after.get('2.0.0')).toBeDefined();
    });
  });

  describe('a target changes', () => {
    it('drops the rows of a package a new analysis no longer has and keeps the others', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B] });
      await recheck({ projectIds: [p.id] });
      const kept = (await rows(p)).find((r) => r.purl === PA)!;
      await onBranch(p, 'main', { dependencies: [A, D] });
      await recheck({ projectIds: [p.id] });
      expect(await described(p)).toEqual(
        [`main ${PA} CVE-2026-0001`, `main ${PD} CVE-2026-0004`].sort(),
      );
      const again = (await rows(p)).find((r) => r.purl === PA)!;
      expect(again.id).toBe(kept.id);
      expect(again.firstSeenAt).toEqual(kept.firstSeenAt);
      // Only the new package went to Trivy.
      expect(trivy.calls.map((c) => [...c.purls].sort())).toEqual([[PA, PB].sort(), [PD]]);
    });

    it('keeps the rows of an analysis without an inventory', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await recheck({ projectIds: [p.id] });
      await onBranch(p, 'main', {});
      await recheck({ projectIds: [p.id] });
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001`]);
    });

    // R17 (spec §6.2, §8.1): an untracked target keeps its rows; it is not re-checked or deleted.
    it('keeps the rows of a version unpinned out of tracking, untouched; re-pinning keeps first_seen_at', async () => {
      const p = await project({ versionRule: 'lines', versionLines: 1 });
      await tagScan(p, '1.0.0', { dependencies: [A] });
      await tagScan(p, '2.0.0', { dependencies: [D] });
      const old = await versionId(p, '1.0.0');
      const track = async (tracking: string) =>
        expect(
          (await api('PATCH', `/projects/${p.id}/versions/${old}`, { tracking })).statusCode,
        ).toBe(200);
      await track('pinned');
      await recheck({ projectIds: [p.id] });
      const both = [`1.0.0 ${PA} CVE-2026-0001`, `2.0.0 ${PD} CVE-2026-0004`];
      expect(await described(p)).toEqual(both);
      const pinned = (await rows(p)).find((r) => r.purl === PA)!;

      await track('auto');
      // Not re-checked: a row changed by hand stays changed, and a new dataset skips its package.
      await db()
        .update(targetVulnerabilities)
        .set({ ignored: true })
        .where(eq(targetVulnerabilities.id, pinned.id));
      expect(await makeDatasetCurrent(db(), (await storeDs('after unpinning')).id)).toBe(true);
      await recheck({ projectIds: [p.id] });
      expect(trivy.calls.map((c) => [...c.purls].sort())).toEqual([[PA, PD].sort(), [PD]]);
      expect(await described(p)).toEqual([
        `1.0.0 ${PA} CVE-2026-0001 ignored`,
        `2.0.0 ${PD} CVE-2026-0004`,
      ]);
      expect((await rows(p)).find((r) => r.id === pinned.id)?.firstSeenAt).toEqual(
        pinned.firstSeenAt,
      );

      // Pinned again: diffed against the kept rows, the same row with its first_seen_at.
      await track('pinned');
      await recheck({ projectIds: [p.id] });
      expect(await described(p)).toEqual(both);
      expect((await rows(p)).find((r) => r.purl === PA)).toMatchObject({
        id: pinned.id,
        firstSeenAt: pinned.firstSeenAt,
      });
    });

    it('keeps the rows of a branch that no longer matches the patterns, and skips it', async () => {
      const p = await project({ branchPatterns: ['release/*'] });
      await onBranch(p, 'main', { dependencies: [A] });
      await onBranch(p, 'release/1.0', { dependencies: [B] });
      await recheck({ projectIds: [p.id] });
      const before = await rows(p);
      expect(before).toHaveLength(3);
      await db()
        .update(projectVulnerabilitySettings)
        .set({ branchPatterns: [] })
        .where(eq(projectVulnerabilitySettings.projectId, p.id));
      expect(await makeDatasetCurrent(db(), (await storeDs('after the pattern change')).id)).toBe(
        true,
      );
      await recheck({ projectIds: [p.id] });
      expect(trivy.calls.map((c) => [...c.purls].sort())).toEqual([[PA, PB].sort(), [PA]]);
      expect(await rows(p)).toEqual(before);
    });

    it('keeps the rows of a project switched off and skips it, in a scoped and a full re-check', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B] });
      await recheck({ projectIds: [p.id] });
      const before = await rows(p);
      expect(before).toHaveLength(3);
      await db()
        .update(projectVulnerabilitySettings)
        .set({ enabled: false })
        .where(eq(projectVulnerabilitySettings.projectId, p.id));
      // Neither a new inventory nor a new dataset reaches the rows of a project switched off.
      await onBranch(p, 'main', { dependencies: [A] });
      expect(await makeDatasetCurrent(db(), (await storeDs('after switching off')).id)).toBe(true);
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({
        kind: 'done',
        summary: { projects: 0, packages: 0 },
      });
      expect(trivy.calls).toHaveLength(1);
      await recheck({ all: true });
      expect(await rows(p)).toEqual(before);
    });

    it('deleting a branch or a version deletes its rows', async () => {
      const p = await project({ branchPatterns: ['release/*'] });
      await onBranch(p, 'main', { dependencies: [A] });
      await onBranch(p, 'release/1.0', { dependencies: [B] });
      await tagScan(p, '1.0.0', { dependencies: [D] });
      await recheck({ projectIds: [p.id] });
      expect(await described(p)).toHaveLength(4);
      const deleted = await h.ctx.app.inject({
        method: 'DELETE',
        url: `/api/v0/branches/${await branchId(p, 'release/1.0')}`,
        headers: h.orgAdmin.headers,
      });
      expect(deleted.statusCode, deleted.body).toBe(204);
      // The app never deletes a version; a succeeded tag scan must go first (its check constraint).
      const version = await versionId(p, '1.0.0');
      await db().delete(analyses).where(eq(analyses.versionId, version));
      await db().delete(projectVersions).where(eq(projectVersions.id, version));
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001`]);
    });

    it('a scoped re-check touches only its own projects', async () => {
      const mine = await project();
      const other = await project();
      await onBranch(mine, 'main', { dependencies: [A] });
      await onBranch(other, 'main', { dependencies: [A] });
      await recheck({ projectIds: [mine.id] });
      expect(await rows(mine)).toHaveLength(1);
      expect(await rows(other)).toEqual([]);
    });

    it('does nothing at all while the instance switch is off', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await recheck({ projectIds: [p.id] });
      const before = await rows(p);
      const state = await readVulndbState(db());
      await db()
        .update(projectVulnerabilitySettings)
        .set({ enabled: false })
        .where(eq(projectVulnerabilitySettings.projectId, p.id));
      await instanceSwitch(false);
      expect(await recheck({ all: true })).toEqual({ kind: 'off' });
      expect(trivy.calls).toHaveLength(1);
      expect(await rows(p)).toEqual(before);
      expect(await readVulndbState(db())).toEqual(state);
    });

    it('does nothing without a current dataset', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await updateVulndbState(db(), (s) => ({ ...s, currentDatasetId: null }));
      expect(await recheck({ projectIds: [p.id] })).toEqual({ kind: 'no_data' });
      expect(trivy.calls).toEqual([]);
      expect(await rows(p)).toEqual([]);
      expect((await readVulndbState(db())).lastRecheck).toBeNull();
    });
  });

  describe('.trivyignore', () => {
    // At 2026-10-31T12:00Z. An entry ends at 00:00 UTC of its expiry day, as Trivy's exp: (R16).
    const ignores: DependencyIgnore[] = [
      // No expiry: ignored.
      { id: 'CVE-2026-0001' },
      // Its expiry day: no longer ignored.
      { id: 'CVE-2026-0002', expiresAt: '2026-10-31' },
      // The day before its expiry: ignored.
      { id: 'CVE-2026-0003', expiresAt: '2026-11-01' },
    ];

    it("sets ignored from the target's own ids until their expiry day begins", async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B], dependencyIgnores: ignores });
      await tagScan(p, '1.0.0', {
        dependencies: [A, D],
        dependencyIgnores: [{ id: 'CVE-2026-0004', expiresAt: '2027-01-01' }],
      });
      await recheck({ projectIds: [p.id] });
      expect(await described(p)).toEqual(
        [
          `main ${PA} CVE-2026-0001 ignored`,
          `main ${PB} CVE-2026-0002`,
          `main ${PB} CVE-2026-0003 ignored`,
          `1.0.0 ${PA} CVE-2026-0001`,
          `1.0.0 ${PD} CVE-2026-0004 ignored`,
        ].sort(),
      );
      const kept = (await rows(p)).find((r) => r.vulnerabilityId === 'CVE-2026-0003')!;

      // The last second before its expiry day the entry still applies.
      now = new Date('2026-10-31T23:59:59Z');
      await recheck({ projectIds: [p.id] });
      expect((await rows(p)).find((r) => r.id === kept.id)?.ignored).toBe(true);
      // From 00:00 UTC of that day it does not; the row stays the same row.
      now = new Date('2026-11-01T00:00:00Z');
      await recheck({ projectIds: [p.id] });
      const row = (await rows(p)).find((r) => r.vulnerabilityId === 'CVE-2026-0003')!;
      expect(row).toMatchObject({ id: kept.id, ignored: false, firstSeenAt: kept.firstSeenAt });
    });

    it('ignoreActive: no expiry, the day before, the expiry day, an unreadable date', () => {
      const at = (iso: string) => new Date(iso);
      expect(ignoreActive({}, at('2099-01-01T00:00:00Z'))).toBe(true);
      expect(ignoreActive({ expiresAt: '2026-11-01' }, at('2026-10-31T23:59:59.999Z'))).toBe(true);
      expect(ignoreActive({ expiresAt: '2026-11-01' }, at('2026-11-01T00:00:00Z'))).toBe(false);
      expect(ignoreActive({ expiresAt: '2026-11-01' }, at('2026-11-01T18:00:00Z'))).toBe(false);
      expect(ignoreActive({ expiresAt: 'soon' }, at('2026-10-01T00:00:00Z'))).toBe(false);
    });

    it("takes a branch's ids from the analysis its inventory came from", async () => {
      const p = await project();
      await onBranch(p, 'main', {
        dependencies: [A],
        dependencyIgnores: [{ id: 'CVE-2026-0001' }],
      });
      // A later analysis without an inventory: the packages, and their ids, stay.
      await onBranch(p, 'main', { dependencyIgnores: [] });
      await recheck({ projectIds: [p.id] });
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001 ignored`]);
      // A new inventory without the id: no longer ignored.
      await onBranch(p, 'main', { dependencies: [A] });
      await recheck({ projectIds: [p.id] });
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001`]);
    });
  });

  describe('inventory edge cases', () => {
    it('counts the packages without a purl as unchecked', async () => {
      const p = await project();
      const conda = dep('numpy', '1.26.0', 'conda-pkg');
      const noVersion = dep('left-pad', '');
      await onBranch(p, 'main', { dependencies: [A, conda, noVersion] });
      await tagScan(p, '1.0.0', { dependencies: [A, conda] });
      const result = await recheck({ projectIds: [p.id] });
      const summary = { projects: 1, packages: 1, unchecked: 2 };
      expect(result).toMatchObject({ kind: 'done', summary });
      expect(trivy.calls.map((c) => c.purls)).toEqual([[PA]]);
      // A scoped run writes no summary (R15).
      expect((await readVulndbState(db())).lastRecheck).toBeNull();
    });

    it('runs no Trivy for targets without packages', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [] });
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'done', summary: { projects: 1, packages: 0 } });
      expect(trivy.calls).toEqual([]);
    });

    it('matches 50 000 distinct packages in three Trivy runs', async () => {
      const p = await project();
      const analysisId = await onBranch(p, 'main', { dependencies: [A] });
      const main = await branchId(p, 'main');
      await db().execute(sql`
        INSERT INTO branch_dependencies (branch_id, path, ecosystem, name, version, licenses,
          analysis_id)
        SELECT ${main}, 'package-lock.json', 'npm', 'pkg-' || g, '1.0.0', '{}', ${analysisId}
          FROM generate_series(1, 49999) AS g`);
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'done', summary: { packages: 50_000 } });
      expect(trivy.calls.map((c) => c.purls.length)).toEqual([20_000, 20_000, 10_000]);
      expect(new Set(trivy.calls.flatMap((c) => c.purls)).size).toBe(50_000);
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001`]);
      // Its inventory would weigh on every later full re-check of this file.
      await db().delete(projects).where(eq(projects.id, p.id));
    }, 120_000);
  });

  describe('one dataset from start to end', () => {
    it('finishes with its own dataset when another becomes current mid-run', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B] });
      const next = await storeDs('mid-run database');
      trivy.onRun = async () => {
        expect(await makeDatasetCurrent(db(), next.id)).toBe(true);
      };
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({ kind: 'done' });
      expect(trivy.calls).toHaveLength(1);
      expect(trivy.calls[0]!.cacheDir).toBe(join(dir, prefix(primary)));
      expect(await digests([PA, PB])).toEqual({ [PA]: primary.digest, [PB]: primary.digest });
      expect(await rows(p)).toHaveLength(3);
      expect((await readVulndbState(db())).currentDatasetId).toBe(next.id);

      // The next run takes the new dataset and matches again.
      await recheck({ projectIds: [p.id] });
      expect(trivy.calls).toHaveLength(2);
      expect(trivy.calls[1]!.cacheDir).toBe(join(dir, prefix(next)));
      expect(await digests([PA, PB])).toEqual({ [PA]: next.digest, [PB]: next.digest });
    });
  });

  describe('failures (R12, R19: lastRecheckError)', () => {
    it('a Trivy failure leaves rows and matches alone and is shown until a full re-check succeeds', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B] });
      await recheck({ projectIds: [p.id] });
      const before = await rows(p);
      const matchedBefore = await digests([PA, PB]);
      const lastRecheck = (await readVulndbState(db())).lastRecheck;
      await onBranch(p, 'main', { dependencies: [A] });
      const next = await storeDs('failing database');
      await makeDatasetCurrent(db(), next.id);
      trivy.failure = { ok: false, code: 'TIMEOUT', message: 'Trivy ran longer than 900000 ms' };
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      const state = await readVulndbState(db());
      expect(state.lastRecheckError?.code).toBe('RECHECK_FAILED');
      expect(state.lastRecheckError?.message).toContain('TIMEOUT');
      expect(state.lastError).toBeNull();
      expect(state.lastRecheck).toEqual(lastRecheck);
      expect(await rows(p)).toEqual(before);
      expect(await digests([PA, PB])).toEqual(matchedBefore);

      trivy.failure = null;
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({ kind: 'done' });
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001`]);
      // R22: a scoped run keeps the error; only a full run clears it.
      expect((await readVulndbState(db())).lastRecheckError?.code).toBe('RECHECK_FAILED');
      expect(await recheck({ all: true })).toMatchObject({ kind: 'done' });
      expect((await readVulndbState(db())).lastRecheckError).toBeNull();
    });

    it("never touches the update's lastError, failing or succeeding", async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      const auth = { code: 'AUTH', message: 'registry answered 401' };
      await updateVulndbState(db(), (s) => ({ ...s, lastError: auth }));
      trivy.failure = { ok: false, code: 'FAILED', message: 'Trivy exited with 1' };
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({ kind: 'failed' });
      expect(await readVulndbState(db())).toMatchObject({
        lastError: auth,
        lastRecheckError: { code: 'RECHECK_FAILED' },
      });
      trivy.failure = null;
      expect(await recheck({ all: true })).toMatchObject({ kind: 'done' });
      expect(await readVulndbState(db())).toMatchObject({
        lastError: auth,
        lastRecheckError: null,
      });
    });

    it('a directory that cannot be written is a DISK error, cleared by the next good full run', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      const file = join(dir, 'not-a-directory');
      await writeFile(file, 'x');
      const result = await recheck(
        { projectIds: [p.id] },
        { config: { vulndb: { dir: join(file, 'sub'), trivyPath: '/nonexistent/trivy' } } },
      );
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'DISK' } });
      expect((await readVulndbState(db())).lastRecheckError?.code).toBe('DISK');
      expect(trivy.calls).toEqual([]);
      expect(await rows(p)).toEqual([]);
      await recheck({ all: true });
      expect((await readVulndbState(db())).lastRecheckError).toBeNull();
      expect(await rows(p)).toHaveLength(1);
    });

    it('a stored dataset that lost its chunks is RECHECK_FAILED', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      const broken = await storeDs('broken database');
      await db().delete(vulndbChunks).where(eq(vulndbChunks.datasetId, broken.id));
      await makeDatasetCurrent(db(), broken.id);
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      expect((await readVulndbState(db())).lastRecheckError?.code).toBe('RECHECK_FAILED');
      expect(trivy.calls).toEqual([]);
    });
  });

  describe("Trivy's work directories", () => {
    it('a re-check starts by removing the stale ones a killed run left', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      const stale = join(dir, 'work-0123456789ab');
      await mkdir(join(stale, 'nested'), { recursive: true });
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({ kind: 'done' });
      await expect(stat(stale)).rejects.toMatchObject({ code: 'ENOENT' });
    });
  });

  describe('a stop (the server shuts down)', () => {
    it('kills a slow Trivy run, records nothing and leaves the scope for the next server', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      const stop = new AbortController();
      let signalled: AbortSignal | undefined;
      let stoppedAt = 0;
      // Ends on its own only after 8 s; the signal ends it at once.
      const slow: TrivyRunner = {
        run: (_sbom, _cacheDir, signal) => {
          signalled = signal;
          setTimeout(() => {
            stoppedAt = Date.now();
            stop.abort();
          }, 100);
          return new Promise((resolve) => {
            const timer = setTimeout(
              () => resolve({ ok: false, code: 'TIMEOUT', message: 'slow' }),
              8_000,
            );
            signal?.addEventListener(
              'abort',
              () => {
                clearTimeout(timer);
                resolve({ ok: false, code: 'ABORTED', message: 'stopped' });
              },
              { once: true },
            );
          });
        },
      };
      const result = await recheck({ projectIds: [p.id] }, { runner: slow, shutdown: stop.signal });
      expect(Date.now() - stoppedAt).toBeLessThan(3_000);
      expect(signalled).toBe(stop.signal);
      expect(result).toEqual({ kind: 'stopped' });
      expect(await readVulndbState(db())).toMatchObject({
        lastError: null,
        lastRecheckError: null,
      });
      expect(await rows(p)).toEqual([]);
      expect(await recheckJobs()).toEqual([
        { status: 'queued', payload: { projectIds: [p.id] }, key: RECHECK_QUEUE },
      ]);
    });

    it('does not start once the server is stopping', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      const stop = new AbortController();
      stop.abort();
      expect(await recheck({ all: true }, { shutdown: stop.signal })).toEqual({ kind: 'stopped' });
      expect(trivy.calls).toEqual([]);
      expect(await recheckJobs()).toEqual([
        { status: 'queued', payload: { all: true }, key: RECHECK_QUEUE },
      ]);
    });
  });

  describe('the queue', () => {
    it('merges a request into the queued job; all wins; a running job gets one queued behind it', async () => {
      const [a, b, c] = [uuidv7(), uuidv7(), uuidv7()];
      await enqueueRecheck(db(), { projectIds: [a] });
      await enqueueRecheck(db(), { projectIds: [b, a] });
      expect(await recheckJobs()).toEqual([
        { status: 'queued', payload: { projectIds: [a, b].sort() }, key: RECHECK_QUEUE },
      ]);
      await enqueueRecheck(db(), { all: true });
      await enqueueRecheck(db(), { projectIds: [c] });
      expect(await recheckJobs()).toEqual([
        { status: 'queued', payload: { all: true }, key: RECHECK_QUEUE },
      ]);
      await db().update(jobs).set({ status: 'running' }).where(eq(jobs.queue, RECHECK_QUEUE));
      await enqueueRecheck(db(), { projectIds: [c] });
      await enqueueRecheck(db(), { projectIds: [a] });
      expect(await recheckJobs()).toEqual([
        { status: 'running', payload: { all: true }, key: RECHECK_QUEUE },
        { status: 'queued', payload: { projectIds: [a, c].sort() }, key: RECHECK_QUEUE },
      ]);
    });

    it('a request waits for one not yet committed and merges into its job', async () => {
      const [a, b] = [uuidv7(), uuidv7()];
      let second: Promise<void> = Promise.resolve();
      await db().transaction(async (tx) => {
        await enqueueRecheck(tx, { projectIds: [a] });
        second = enqueueRecheck(db(), { projectIds: [b] });
        // The second request reaches the lock while this transaction is still open.
        await new Promise((resolve) => setTimeout(resolve, 300));
      });
      await second;
      expect(await recheckJobs()).toEqual([
        { status: 'queued', payload: { projectIds: [a, b].sort() }, key: RECHECK_QUEUE },
      ]);
    });

    it('the worker cannot claim the job a request joined before that request commits', async () => {
      const [a, b] = [uuidv7(), uuidv7()];
      await enqueueRecheck(db(), { projectIds: [a] });
      // Already covered: the payload stays, the job still waits for this transaction.
      await db().transaction(async (tx) => {
        await enqueueRecheck(tx, { projectIds: [a] });
        expect(await claimJob(db(), RECHECK_QUEUE, 'test-worker', 60_000)).toBeNull();
      });
      // Merged.
      await db().transaction(async (tx) => {
        await enqueueRecheck(tx, { projectIds: [b] });
        expect(await claimJob(db(), RECHECK_QUEUE, 'test-worker', 60_000)).toBeNull();
      });
      const job = await claimJob(db(), RECHECK_QUEUE, 'test-worker', 60_000);
      expect(job?.payload).toEqual({ projectIds: [a, b].sort() });
    });

    it('the handler runs a queued job', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      await enqueueRecheck(db(), { projectIds: [p.id] });
      await runUntilIdle(db(), recheckHandlers(deps()), silent);
      expect(await recheckJobs()).toEqual([
        { status: 'succeeded', payload: { projectIds: [p.id] }, key: RECHECK_QUEUE },
      ]);
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001`]);
    });
  });

  describe('enqueue points', () => {
    const queued = async () => (await recheckJobs()).map((j) => j.payload);
    const clear = () => db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));

    it('a tracked-branch ingest with an inventory, a version ingest and the two routes', async () => {
      const p = await project({ branchPatterns: ['release/*'] });
      await onBranch(p, 'main', { dependencies: [A] });
      expect(await queued()).toEqual([{ projectIds: [p.id] }]);
      await clear();
      await onBranch(p, 'release/1.0', { dependencies: [A] });
      expect(await queued()).toEqual([{ projectIds: [p.id] }]);
      await clear();
      await tagScan(p, '1.0.0', { dependencies: [A] });
      expect(await queued()).toEqual([{ projectIds: [p.id] }]);
      await clear();
      const version = await versionId(p, '1.0.0');
      const patch = await api('PATCH', `/projects/${p.id}/versions/${version}`, {
        tracking: 'pinned',
      });
      expect(patch.statusCode, patch.body).toBe(200);
      expect(await queued()).toEqual([{ projectIds: [p.id] }]);
      await clear();
      const put = await api('PUT', `/projects/${p.id}/vulnerability-monitoring`, {
        enabled: true,
        branchPatterns: ['hotfix/*'],
        versionRule: { kind: 'lines', lines: 3 },
        labelVersions: false,
      });
      expect(put.statusCode, put.body).toBe(200);
      expect(await queued()).toEqual([{ projectIds: [p.id] }]);
    });

    it('none for an untracked branch, a merge request or a report without an inventory', async () => {
      const p = await project({ branchPatterns: ['release/*'] });
      await onBranch(p, 'feature/x', { dependencies: [A] });
      await onBranch(p, 'release/2.0', {
        dependencies: [A],
        mergeRequest: { id: '9', targetBranch: 'main', sourceBranch: 'release/2.0' },
      });
      await onBranch(p, 'main', {});
      expect(await queued()).toEqual([]);
    });

    it('none while the project or the instance switch is off', async () => {
      const off = await project({ enabled: false });
      await onBranch(off, 'main', { dependencies: [A] });
      await tagScan(off, '1.0.0', { dependencies: [A] });
      expect(await queued()).toEqual([]);
      const p = await project();
      await instanceSwitch(false);
      await onBranch(p, 'main', { dependencies: [A] });
      await tagScan(p, '1.0.0', { dependencies: [A] });
      expect(await queued()).toEqual([]);
    });
  });
});

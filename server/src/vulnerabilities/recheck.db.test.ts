import { mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { and, asc, eq, sql } from 'drizzle-orm';
import type { DependencyEntry, DependencyIgnore, OsPackageType } from '@qualor/shared';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { waitForLockWaiters } from '../../test/db';
import { reportWith, type ReportParts } from '../../test/reports';
import { trivyArchive } from '@qualor/shared/test/trivy-archive';
import { uuidv7 } from '../db/ids';
import {
  analyses,
  branches,
  instanceSettings,
  jobs,
  matchedPackages,
  organizations,
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
import { withLocalDatabase } from '../vulndb/local';
import { readVulndbState, updateVulndbState } from '../vulndb/state';
import { makeDatasetCurrent, storeDataset, type DatasetRow } from '../vulndb/store';
import { upsertVersion, type VersionDependencyEntry } from '../versions/store';
import { osMatchKey, purlOf } from './purl';
import { buildSbom } from './sbom';
import {
  enqueueRecheck,
  ignoreActive,
  MAX_FAILED_PER_ORGANISATION,
  queueRematchIfCleared,
  RECHECK_QUEUE,
  recheckHandlers,
  recheckProjects,
  type RecheckDeps,
  type RecheckScope,
} from './recheck';
import type { TrivyRun, TrivyRunner, VulnerabilityMatch } from './trivy';
import { ALERTS_QUEUE } from './alerts/jobs';

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

/** An OS package of an uploaded SBOM, with its source package. */
const osDep = (
  ecosystem: 'deb' | 'rpm' | 'apk',
  name: string,
  version: string,
  sourceName = name,
  sourceVersion = version,
): VersionDependencyEntry => ({
  path: '',
  ecosystem,
  name,
  version,
  licenses: [],
  sourceName,
  sourceVersion,
});
const LIBSSL3 = osDep('deb', 'libssl3', '3.0.22-1~deb12u2', 'openssl');
const LOGIN = osDep('deb', 'login', '1:4.13+dfsg1-1+deb12u2', 'shadow');
const PASSWD = osDep('deb', 'passwd', '1:4.13+dfsg1-1+deb12u2', 'shadow');
const LIBCRYPTO3 = osDep('apk', 'libcrypto3', '3.3.2-r0', 'openssl');
const BUSYBOX = osDep('apk', 'busybox', '1.36.1-r29');
const DEBIAN = { family: 'debian', version: '12.15' };
const ALPINE = { family: 'alpine', version: '3.20.3' };
const keyOf = (d: VersionDependencyEntry, os: { family: string; version: string }): string =>
  osMatchKey(
    d.ecosystem as OsPackageType,
    os.family,
    os.version,
    d.name,
    d.version,
    { name: d.sourceName ?? d.name, version: d.sourceVersion ?? d.version },
    { arch: d.arch ?? null, modularityLabel: d.modularityLabel ?? null },
  );
const PSSL = keyOf(LIBSSL3, DEBIAN);
const PCRYPTO = keyOf(LIBCRYPTO3, ALPINE);
/** Red Hat 8.10, and one rpm built for two arches (Task 9b). */
const REDHAT = { family: 'redhat', version: '8.10' };
const OPENSSL_LIBS = osDep('rpm', 'openssl-libs', '1:1.1.1k-5.el8_5', 'openssl');
const OPENSSL_X86 = { ...OPENSSL_LIBS, arch: 'x86_64' };
const OPENSSL_ARM = { ...OPENSSL_LIBS, arch: 'aarch64' };
const NODEJS = {
  ...osDep('rpm', 'nodejs', '1:18.19.0-1.module+el8.9.0+20473+c4e3d824'),
  arch: 'x86_64',
  modularityLabel: 'nodejs:18:8090020240112121244:a75119d5',
};

/** What the fake Trivy finds, per purl. */
const FINDS: Record<string, string[]> = {
  [PA]: ['CVE-2026-0001'],
  [PB]: ['CVE-2026-0002', 'CVE-2026-0003'],
  [PD]: ['CVE-2026-0004'],
  [PSSL]: ['CVE-2025-27587'],
  [keyOf(LIBSSL3, { family: 'debian', version: '12.16' })]: ['CVE-2026-1216'],
  [PCRYPTO]: ['CVE-2024-12797'],
  // A fixed Red Hat advisory lists its arches: this one names x86_64 only.
  [keyOf(OPENSSL_X86, REDHAT)]: ['CVE-2023-0286'],
};

/** The GHSA id the fake Trivy gives a CVE as its vendor id. */
const ghsaOf = (id: string): string => `GHSA-${id.slice(-4)}-xxxx-yyyy`;

const matchOf = (id: string, vendorIds = [ghsaOf(id)]): VulnerabilityMatch => ({
  vulnerabilityId: id,
  severity: 'high',
  title: `Title of ${id}`,
  fixedVersion: '9.9.9',
  primaryUrl: `https://avd.aquasec.com/nvd/${id.toLowerCase()}`,
  publishedAt: '2026-01-02T03:04:05Z',
  vendorIds,
});

interface FakeTrivy extends TrivyRunner {
  calls: {
    purls: string[];
    names: string[];
    cacheDir: string;
    /** The SBOM's `operating-system` components, as `<name> <version>`. */
    systems: string[];
    sbom: string;
  }[];
  failure: TrivyRun | null;
  onRun: (() => Promise<void>) | null;
}

interface FakeComponent {
  type: string;
  purl?: string;
  name: string;
  version?: string;
}

/** A Trivy that answers {@link FINDS} for the purls of the SBOM and records each run. */
function fakeTrivy(): FakeTrivy {
  const fake: FakeTrivy = {
    calls: [],
    failure: null,
    onRun: null,
    async run(sbomJson, cacheDir) {
      const all = (JSON.parse(sbomJson) as { components: FakeComponent[] }).components;
      const components = all.filter(
        (c): c is FakeComponent & { purl: string } => c.purl !== undefined,
      );
      fake.calls.push({
        purls: components.map((c) => c.purl),
        names: components.map((c) => c.name),
        cacheDir,
        systems: all
          .filter((c) => c.type === 'operating-system')
          .map((c) => `${c.name} ${c.version ?? ''}`),
        sbom: sbomJson,
      });
      const hook = fake.onRun;
      fake.onRun = null;
      await hook?.();
      if (fake.failure !== null) return fake.failure;
      const matches = new Map<string, VulnerabilityMatch[]>();
      for (const { purl: p } of components) {
        const ids = FINDS[p];
        // The first id comes twice, the second time with one more vendor id: stored once, with
        // both reports' vendor ids (Trivy 0.74 reports an id once per package; this is defensive).
        if (ids !== undefined) {
          matches.set(p, [
            ...ids.map((id) => matchOf(id)),
            ...ids.slice(0, 1).map((id) => matchOf(id, [ghsaOf(id), `GO-2026-${id.slice(-4)}`])),
          ]);
        }
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
  /**
   * An uploaded SBOM: the version `label` holding `packages`, of `distribution`, pinned so that it
   * is tracked whatever the rule says.
   */
  const sbomVersion = async (
    p: IngestProject,
    label: string,
    distribution: { family: string; version: string } | null,
    packages: VersionDependencyEntry[],
  ): Promise<string> => {
    const written = await db().transaction((tx) =>
      upsertVersion(tx, {
        projectId: p.id,
        label,
        source: 'sbom',
        tag: null,
        analysisId: null,
        analyzedAt: new Date(Date.UTC(2026, 9, 1) + ++day * 86_400_000),
        inventory: { dependencies: packages, ignores: null },
        sbom: { format: 'CycloneDX 1.6', subject: null, distribution },
      }),
    );
    if (written === 'taken') throw new Error(`${label} is taken`);
    await db()
      .update(projectVersions)
      .set({ tracking: 'pinned' })
      .where(eq(projectVersions.id, written.version.id));
    return written.version.id;
  };
  /** The runs of the fake Trivy as `<OS or "libraries">: <purls, sorted>`. */
  const runsByGroup = () =>
    trivy.calls.map(
      (c) => `${c.systems.join(', ') || 'libraries'}: ${[...c.purls].sort().join(' ')}`,
    );
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
        vendorIds: ['GHSA-0001-xxxx-yyyy', 'GO-2026-0001'],
      });
      expect(stored!.publishedAt?.toISOString()).toBe('2026-01-02T03:04:05.000Z');
      // B's second id came once: its own vendor id.
      const [second] = await db()
        .select({ vendorIds: vulnerabilityMatches.vendorIds })
        .from(vulnerabilityMatches)
        .where(
          and(
            eq(vulnerabilityMatches.purl, PB),
            eq(vulnerabilityMatches.vulnerabilityId, 'CVE-2026-0003'),
          ),
        );
      expect(second).toEqual({ vendorIds: ['GHSA-0003-xxxx-yyyy'] });
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

  describe('pruning what no inventory needs', () => {
    const ORPHAN = 'pkg:npm/orphan@1.0.0';
    const KEPT = 'pkg:npm/only-untracked@2.0.0';
    /** Matches and matched marks for a package no inventory has, and one an untracked target has. */
    const seedStale = async (p: IngestProject): Promise<void> => {
      const old = await versionId(p, '1.0.0');
      await db().insert(targetVulnerabilities).values({
        projectId: p.id,
        versionId: old,
        ecosystem: 'npm',
        packageName: 'only-untracked',
        packageVersion: '2.0.0',
        purl: KEPT,
        vulnerabilityId: 'CVE-2026-0900',
      });
      for (const purl of [ORPHAN, KEPT]) {
        await db()
          .insert(vulnerabilityMatches)
          .values({ purl, vulnerabilityId: 'CVE-2026-0900', severity: 'low' });
        await db().insert(matchedPackages).values({ purl, datasetDigest: primary.digest });
      }
    };
    const matchPurls = async () =>
      (await db().select({ purl: vulnerabilityMatches.purl }).from(vulnerabilityMatches))
        .map((r) => r.purl)
        .sort();
    const markedPurls = async () =>
      (await db().select({ purl: matchedPackages.purl }).from(matchedPackages))
        .map((r) => r.purl)
        .sort();
    const setup = async (): Promise<IngestProject> => {
      const p = await project({ versionRule: 'lines', versionLines: 1 });
      await tagScan(p, '1.0.0', { dependencies: [A] });
      await tagScan(p, '2.0.0', { dependencies: [D] });
      await seedStale(p);
      return p;
    };

    it('a good full re-check deletes the matches and marks of packages no inventory has', async () => {
      // Other tests' projects would be re-matched too: start from none, so the sets are exact.
      await db().delete(projects);
      await setup();
      expect(await recheck({ all: true })).toMatchObject({ kind: 'done' });
      // The package of the tracked version stays matched; the orphan goes; the package an
      // untracked target still lists keeps its matches (they are that target's) but not its mark.
      expect(await matchPurls()).toEqual([KEPT, PD].sort());
      expect(await markedPurls()).toEqual([PD]);
    });

    it('prunes several stale purls and keeps one that an untracked target still lists', async () => {
      await db().delete(projects);
      await setup();
      // Two more packages no inventory has, with two matches each: with the orphan, three go.
      for (const purl of ['pkg:npm/stale-one@1.0.0', 'pkg:maven/org.example/stale-two@3.1']) {
        await db()
          .insert(vulnerabilityMatches)
          .values([
            { purl, vulnerabilityId: 'CVE-2026-0901', severity: 'high' },
            { purl, vulnerabilityId: 'CVE-2026-0902', severity: 'medium' },
          ]);
        await db().insert(matchedPackages).values({ purl, datasetDigest: primary.digest });
      }
      expect(await recheck({ all: true })).toMatchObject({ kind: 'done' });
      expect(await matchPurls()).toEqual([KEPT, PD].sort());
      expect(await markedPurls()).toEqual([PD]);
    });

    it('a full re-check with nothing stale deletes nothing', async () => {
      await db().delete(projects);
      const p = await project({ versionRule: 'lines', versionLines: 1 });
      await tagScan(p, '1.0.0', { dependencies: [A] });
      await tagScan(p, '2.0.0', { dependencies: [D] });
      const matchRows = async () =>
        db()
          .select({ purl: vulnerabilityMatches.purl, id: vulnerabilityMatches.vulnerabilityId })
          .from(vulnerabilityMatches)
          .orderBy(asc(vulnerabilityMatches.purl), asc(vulnerabilityMatches.vulnerabilityId));
      // The first run prunes what other tests left; the second finds every match in its run.
      expect(await recheck({ all: true })).toMatchObject({ kind: 'done' });
      const matches = await matchRows();
      expect(matches.map((m) => m.purl)).toContain(PD);
      expect(await markedPurls()).toEqual([PD]);
      expect(await recheck({ all: true })).toMatchObject({ kind: 'done' });
      expect(await matchRows()).toEqual(matches);
      expect(await markedPurls()).toEqual([PD]);
    });

    it('a re-check of some projects deletes nothing', async () => {
      const p = await setup();
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({ kind: 'done' });
      expect(await matchPurls()).toEqual([ORPHAN, PD, KEPT].sort());
      expect(await markedPurls()).toEqual([ORPHAN, PD, KEPT].sort());
    });

    it('a failed full re-check deletes nothing', async () => {
      await setup();
      trivy.failure = { ok: false, code: 'FAILED', message: 'boom' };
      expect(await recheck({ all: true })).toMatchObject({ kind: 'failed' });
      expect(await matchPurls()).toEqual([ORPHAN, KEPT].sort());
      expect(await markedPurls()).toEqual([ORPHAN, KEPT].sort());
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

    it('drops only the bad entries of an ignore list', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await db()
        .update(analyses)
        .set({ dependencyIgnores: sql`'[{"id":"CVE-2026-0001"},{"id":5},"junk"]'::jsonb` })
        .where(eq(analyses.projectId, p.id));
      await recheck({ projectIds: [p.id] });
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001 ignored`]);
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

    it('matches 50 000 distinct packages in 50 Trivy runs of 1 000', async () => {
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
      expect(trivy.calls.map((c) => c.purls.length)).toEqual(Array<number>(50).fill(1_000));
      expect(new Set(trivy.calls.flatMap((c) => c.purls)).size).toBe(50_000);
      expect(await described(p)).toEqual([`main ${PA} CVE-2026-0001`]);
      // Its inventory would weigh on every later full re-check of this file.
      await db().delete(projects).where(eq(projects.id, p.id));
    }, 120_000);
  });

  describe('OS packages of uploaded SBOMs (0.16)', () => {
    /** The OS packages' rows as `<label> <ecosystem> <name>@<version> <purl> <id>`, sorted. */
    const osRows = async (p: IngestProject): Promise<string[]> => {
      const labels = new Map<string, string>();
      for (const v of await db()
        .select({ id: projectVersions.id, label: projectVersions.label })
        .from(projectVersions)
        .where(eq(projectVersions.projectId, p.id))) {
        labels.set(v.id, v.label);
      }
      return (await rows(p))
        .filter((r) => r.versionId !== null)
        .map(
          (r) =>
            `${labels.get(r.versionId ?? '') ?? '?'} ${r.ecosystem} ${r.packageName}@${r.packageVersion} ${r.purl} ${r.vulnerabilityId}`,
        )
        .sort();
    };

    it('runs one SBOM per distribution, with its operating-system component', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await sbomVersion(p, 'shop-debian', DEBIAN, [LIBSSL3, LOGIN, PASSWD]);
      await sbomVersion(p, 'shop-alpine', ALPINE, [LIBCRYPTO3, BUSYBOX]);

      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: { projects: 1, packages: 6, unchecked: 0 },
      });
      expect(runsByGroup().sort()).toEqual(
        [
          `libraries: ${PA}`,
          `debian 12.15: ${[PSSL, keyOf(LOGIN, DEBIAN), keyOf(PASSWD, DEBIAN)].sort().join(' ')}`,
          `alpine 3.20.3: ${[PCRYPTO, keyOf(BUSYBOX, ALPINE)].sort().join(' ')}`,
        ].sort(),
      );
      // Libraries keep today's SBOM; an OS SBOM names each package's source.
      const library = trivy.calls.find((c) => c.systems.length === 0)!;
      expect(JSON.parse(library.sbom)).toEqual(
        JSON.parse(buildSbom([{ purl: PA, name: 'lodash', version: '4.17.20' }])),
      );
      const debian = trivy.calls.find((c) => c.systems[0] === 'debian 12.15')!;
      const login = (
        JSON.parse(debian.sbom) as {
          components: { purl?: string; properties?: { name: string; value: string }[] }[];
        }
      ).components.find((c) => c.purl === keyOf(LOGIN, DEBIAN));
      expect(login?.properties).toEqual(
        expect.arrayContaining([
          { name: 'aquasecurity:trivy:SrcName', value: 'shadow' },
          { name: 'aquasecurity:trivy:SrcEpoch', value: '1' },
        ]),
      );
      expect(await osRows(p)).toEqual(
        [
          `shop-debian deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
          `shop-alpine apk libcrypto3@3.3.2-r0 ${PCRYPTO} CVE-2024-12797`,
        ].sort(),
      );
      expect(await digests([PSSL, PCRYPTO])).toEqual({
        [PSSL]: primary.digest,
        [PCRYPTO]: primary.digest,
      });
    });

    it('cuts chunks inside a group, and halves an oversized one inside it too', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await sbomVersion(p, 'shop-debian', DEBIAN, [LIBSSL3, LOGIN, PASSWD]);
      await sbomVersion(p, 'shop-alpine', ALPINE, [LIBCRYPTO3, BUSYBOX]);

      expect(await recheck({ projectIds: [p.id] }, { chunk: { components: 2 } })).toMatchObject({
        kind: 'done',
      });
      const groups = trivy.calls.map((c) => c.systems.join(', ') || 'libraries');
      expect(groups.sort()).toEqual(
        ['alpine 3.20.3', 'debian 12.15', 'debian 12.15', 'libraries'].sort(),
      );
      expect(
        trivy.calls
          .filter((c) => c.systems[0] === 'debian 12.15')
          .map((c) => c.purls.length)
          .sort(),
      ).toEqual([1, 2]);

      // The dataset changes, and anything over one component "writes too much output".
      await db().delete(matchedPackages);
      trivy.calls = [];
      const inner = trivy.run.bind(trivy);
      trivy.run = (sbom, cacheDir, signal) =>
        (JSON.parse(sbom) as { components: { purl?: string }[] }).components.filter(
          (c) => c.purl !== undefined,
        ).length > 1
          ? Promise.resolve({ ok: false, code: 'TOO_LARGE', message: 'output over the budget' })
          : inner(sbom, cacheDir, signal);
      expect(await recheck({ projectIds: [p.id] }, { chunk: { components: 4 } })).toMatchObject({
        kind: 'done',
      });
      expect(runsByGroup().sort()).toEqual(
        [
          `libraries: ${PA}`,
          ...[LIBSSL3, LOGIN, PASSWD].map((d) => `debian 12.15: ${keyOf(d, DEBIAN)}`),
          ...[LIBCRYPTO3, BUSYBOX].map((d) => `alpine 3.20.3: ${keyOf(d, ALPINE)}`),
        ].sort(),
      );
      expect(await osRows(p)).toHaveLength(2);
    });

    it('never shares matches between two releases of a distribution', async () => {
      const p = await project();
      const q = await project();
      const debian1216 = { family: 'debian', version: '12.16' };
      await sbomVersion(p, 'shop-1', DEBIAN, [LIBSSL3]);
      await sbomVersion(q, 'shop-2', debian1216, [LIBSSL3]);

      expect(await recheck({ projectIds: [p.id, q.id] })).toMatchObject({
        kind: 'done',
        summary: { packages: 2 },
      });
      expect(runsByGroup().sort()).toEqual(
        [`debian 12.15: ${PSSL}`, `debian 12.16: ${keyOf(LIBSSL3, debian1216)}`].sort(),
      );
      const marks = await db()
        .select({ purl: matchedPackages.purl })
        .from(matchedPackages)
        .where(sql`${matchedPackages.purl} LIKE 'pkg:deb/%'`);
      expect(marks.map((m) => m.purl).sort()).toEqual([PSSL, keyOf(LIBSSL3, debian1216)].sort());
      expect(await osRows(p)).toEqual([
        `shop-1 deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
      ]);
      expect(await osRows(q)).toEqual([
        `shop-2 deb libssl3@3.0.22-1~deb12u2 ${keyOf(LIBSSL3, debian1216)} CVE-2026-1216`,
      ]);
    });

    it('keys two rpm rows apart by arch, and gives Trivy the arch and label; deb rows share a key (Task 9b)', async () => {
      const x86 = await project();
      const arm = await project();
      const debAmd = await project();
      const debArm = await project();
      await sbomVersion(x86, 'ubi-x86', REDHAT, [OPENSSL_X86, NODEJS]);
      await sbomVersion(arm, 'ubi-arm', REDHAT, [OPENSSL_ARM]);
      await sbomVersion(debAmd, 'deb-amd64', DEBIAN, [{ ...LIBSSL3, arch: 'amd64' }]);
      await sbomVersion(debArm, 'deb-arm64', DEBIAN, [{ ...LIBSSL3, arch: 'arm64' }]);

      const result = await recheck({ projectIds: [x86.id, arm.id, debAmd.id, debArm.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: { projects: 4, packages: 4, unchecked: 0 },
      });
      const PX86 = keyOf(OPENSSL_X86, REDHAT);
      const PARM = keyOf(OPENSSL_ARM, REDHAT);
      const PNODE = keyOf(NODEJS, REDHAT);
      expect(PX86).toBe(
        'pkg:rpm/redhat/openssl-libs@1.1.1k-5.el8_5?arch=x86_64&epoch=1&distro=redhat-8.10&upstream=openssl@1%3A1.1.1k-5.el8_5',
      );
      expect(PNODE).toContain(
        '?arch=x86_64&epoch=1&distro=redhat-8.10&modularitylabel=nodejs%3A18%3A',
      );
      // One Red Hat SBOM holding both arches and the label, and one Debian key for two arches.
      expect(runsByGroup().sort()).toEqual(
        [`redhat 8.10: ${[PX86, PARM, PNODE].sort().join(' ')}`, `debian 12.15: ${PSSL}`].sort(),
      );
      const marks = await db().select({ purl: matchedPackages.purl }).from(matchedPackages);
      expect(marks.map((m) => m.purl).sort()).toEqual([PX86, PARM, PNODE, PSSL].sort());
      // Each arch gets its own answer: the x86_64 advisory never reaches the aarch64 image.
      expect(await osRows(x86)).toEqual([
        `ubi-x86 rpm openssl-libs@1:1.1.1k-5.el8_5 ${PX86} CVE-2023-0286`,
      ]);
      expect(await osRows(arm)).toEqual([]);
      expect(await osRows(debAmd)).toEqual([
        `deb-amd64 deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
      ]);
      expect(await osRows(debArm)).toEqual([
        `deb-arm64 deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
      ]);
    });

    it('leaves an rpm with a stored arch Trivy must not get unchecked (Task 9b)', async () => {
      const p = await project();
      await sbomVersion(p, 'ubi', REDHAT, [
        OPENSSL_X86,
        { ...osDep('rpm', 'bad-arch', '1-1'), arch: 'x86 64' },
        { ...osDep('rpm', 'bad-label', '1-1'), modularityLabel: 'm:s\n' },
      ]);
      // A deb's arch is never sent, so it never matters.
      const unused = { ...osDep('deb', 'unused', '1-1'), arch: 'x 86' };
      await sbomVersion(p, 'deb', DEBIAN, [unused]);
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: { packages: 2, unchecked: 2, givenUp: { invalid: 2 } },
      });
      expect(runsByGroup().sort()).toEqual(
        [
          `redhat 8.10: ${keyOf(OPENSSL_X86, REDHAT)}`,
          `debian 12.15: ${keyOf(osDep('deb', 'unused', '1-1'), DEBIAN)}`,
        ].sort(),
      );
    });

    it('counts OS packages without a known distribution as unchecked and matches the rest', async () => {
      const p = await project();
      const q = await project();
      await sbomVersion(p, 'no-distro', null, [LIBSSL3, LOGIN, osDep('rpm', 'bash', '4.4-1'), A]);
      await sbomVersion(q, 'plan9', { family: 'plan9', version: '4' }, [PASSWD]);

      const result = await recheck({ projectIds: [p.id, q.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: { projects: 2, packages: 1, unchecked: 4 },
      });
      expect(runsByGroup()).toEqual([`libraries: ${PA}`]);
      expect(await described(p)).toEqual([`no-distro ${PA} CVE-2026-0001`]);
      expect(await rows(q)).toEqual([]);
    });

    it('validates stored values before Trivy: a malformed epoch, version or source is unchecked (R16)', async () => {
      const p = await project();
      const bad = [
        osDep('deb', 'odd', '1.0-1', 'odd', '99999999999:1.0-1'),
        osDep('deb', 'odd2', '1.0', 'o', 'x:1.0'),
        osDep('deb', 'odd3', 'abc:1.0-1'),
        osDep('deb', 'odd4', '1.0\n-1'),
        osDep('deb', 'odd5', '1.0-1', 'src\u0007'),
        osDep('deb', 'odd6', `1.0-${'1'.repeat(300)}`, 'odd6', '1.0-1'),
      ];
      await sbomVersion(p, 'shop', DEBIAN, [LIBSSL3, ...bad]);
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: {
          packages: 1,
          unchecked: 6,
          givenUp: { invalid: 6, trivyFailed: 0, unsupported: [] },
        },
      });
      // Only the valid package ever reaches Trivy.
      expect(runsByGroup()).toEqual([`debian 12.15: ${PSSL}`]);
      for (const call of trivy.calls) expect(call.names).toEqual(['libssl3']);
    });

    it('never lets one row’s claimed source answer for another’s package (R15)', async () => {
      const genuine = await project();
      const claimed = await project();
      // The same binary package; another organisation's SBOM claims another source for it.
      const fake = { ...LIBSSL3, sourceName: 'not-openssl', sourceVersion: '0.1-1' };
      await sbomVersion(claimed, 'image', DEBIAN, [fake]);
      // Matched first: were the key only the binary, its answer would be cached for both.
      await recheck({ projectIds: [claimed.id] });
      await sbomVersion(genuine, 'image', DEBIAN, [LIBSSL3]);
      await recheck({ projectIds: [genuine.id] });

      const fakeKey = keyOf(fake, DEBIAN);
      expect(fakeKey).not.toBe(PSSL);
      expect(runsByGroup()).toEqual([`debian 12.15: ${fakeKey}`, `debian 12.15: ${PSSL}`]);
      const marks = await db()
        .select({ purl: matchedPackages.purl })
        .from(matchedPackages)
        .where(sql`${matchedPackages.purl} LIKE 'pkg:deb/debian/libssl3@%'`);
      expect(marks.map((m) => m.purl).sort()).toEqual([PSSL, fakeKey].sort());
      expect(await osRows(genuine)).toEqual([
        `image deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
      ]);
      expect(await osRows(claimed)).toEqual([]);
      // Both in one run: two components, one per key.
      await db().delete(matchedPackages);
      trivy.calls = [];
      await recheck({ projectIds: [genuine.id, claimed.id] });
      expect(runsByGroup()).toEqual([`debian 12.15: ${[PSSL, fakeKey].sort().join(' ')}`]);
      expect(await osRows(genuine)).toHaveLength(1);
    });

    /** Trivy's answer when it ran and exited 1, as the runner gives it. */
    const exited = (stderr: string): TrivyRun => ({
      ok: false,
      code: 'FAILED',
      message: `Trivy exited with 1: ${stderr}`,
      exitCode: 1,
      stderr,
    });
    /** A Trivy that fails as `fails` says for an SBOM, and answers FINDS otherwise. */
    const failingWhen = (fails: (components: FakeComponent[]) => TrivyRun | null) => {
      const inner = trivy.run.bind(trivy);
      let failures = 0;
      trivy.run = (sbom, cacheDir, signal) => {
        const failure = fails((JSON.parse(sbom) as { components: FakeComponent[] }).components);
        if (failure === null) return inner(sbom, cacheDir, signal);
        failures += 1;
        return Promise.resolve(failure);
      };
      return { failures: () => failures, restore: () => (trivy.run = inner) };
    };
    const warnings: unknown[] = [];
    const logged = { info: () => undefined, warn: (...args: unknown[]) => warnings.push(args) };

    it('bisects a failed OS chunk: the good packages are matched, the one Trivy fails on is unchecked (R16)', async () => {
      const p = await project();
      const q = await project();
      const BAD = osDep('deb', 'bad', '1.0-1');
      await sbomVersion(p, 'shop', DEBIAN, [LIBSSL3, LOGIN, PASSWD, BAD]);
      // Another organisation's packages of the same distribution are matched all the same.
      await sbomVersion(q, 'other', DEBIAN, [
        osDep('deb', 'libssl3', '3.0.22-1~deb12u2', 'openssl'),
      ]);
      warnings.length = 0;
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.name === 'bad') ? exited('FATAL panic: runtime error') : null,
      );

      const result = await recheck({ projectIds: [p.id, q.id] }, { logger: logged });
      expect(result).toMatchObject({
        kind: 'done',
        summary: {
          packages: 3,
          unchecked: 1,
          givenUp: { invalid: 0, trivyFailed: 1, unsupported: [] },
        },
      });
      // 4 → 2 + 2 → 1 + 1: three failed runs, and the good packages ran in the halves.
      expect(trivyFails.failures()).toBe(3);
      expect(
        trivy.calls
          .flatMap((c) => c.names)
          .filter((name) => name !== 'qualor-release-probe')
          .sort(),
      ).toEqual(['libssl3', 'login', 'passwd']);
      expect(await osRows(p)).toEqual([`shop deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`]);
      expect(await osRows(q)).toEqual([
        `other deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
      ]);
      const badKey = keyOf(BAD, DEBIAN);
      expect(await digests([PSSL, badKey])).toEqual({ [PSSL]: primary.digest });
      expect(JSON.stringify(warnings)).toContain('runtime error');
      expect((await readVulndbState(db())).lastRecheckError).toBeNull();

      // The next re-check tries the bad package again (and only it: the others are matched).
      trivyFails.restore();
      trivy.calls = [];
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({
        kind: 'done',
        summary: { packages: 4, unchecked: 0, givenUp: { trivyFailed: 0 } },
      });
      expect(runsByGroup()).toEqual([`debian 12.15: ${badKey}`]);
    });

    it('gives up a distribution only when its probe fails and a known-good release of its family passes (R20)', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await sbomVersion(p, 'shop-debian', DEBIAN, [LIBSSL3, LOGIN, PASSWD]);
      await sbomVersion(p, 'shop-alpine', ALPINE, [LIBCRYPTO3]);
      warnings.length = 0;
      // Trivy 0.74.0 exits 1 so on a Red Hat release outside its default content sets.
      const cpe =
        'FATAL Fatal error run error: … failed to get Red Hat advisories: unable to find CPE indices. See https://github.com/aquasecurity/trivy-db/issues/435 for details';
      const trivyFails = failingWhen((components) =>
        components.some(
          (c) => c.type === 'operating-system' && c.name === 'debian' && c.version === '12.15',
        )
          ? exited(cpe)
          : null,
      );

      const result = await recheck({ all: true }, { chunk: { components: 2 }, logger: logged });
      // Debian chunks, and no bisecting: the group is given up after its first failure and a probe
      // of the release alone that fails the same way.
      expect(trivyFails.failures()).toBe(2);
      expect(result).toMatchObject({ kind: 'done' });
      if (result.kind !== 'done') return;
      expect(result.summary.givenUp).toEqual({
        invalid: expect.any(Number) as unknown,
        trivyFailed: 0,
        overBudget: 0,
        unsupported: ['debian 12.15'],
      });
      // Shown to the operator: the full run's summary holds it.
      expect((await readVulndbState(db())).lastRecheck?.givenUp.unsupported).toEqual([
        'debian 12.15',
      ]);
      expect(await osRows(p)).toEqual([
        `shop-alpine apk libcrypto3@3.3.2-r0 ${PCRYPTO} CVE-2024-12797`,
      ]);
      expect(await digests([PSSL, PCRYPTO])).toEqual({ [PCRYPTO]: primary.digest });
      expect(JSON.stringify(warnings)).toContain('unable to find CPE indices');
      trivyFails.restore();
    });

    it('never gives up a distribution for a package whose failure only reads like it', async () => {
      const p = await project();
      const q = await project();
      // A package whose failure message carries the phrase (Trivy may echo stored text in it).
      const LIAR = osDep('deb', 'liar', '1.0-1');
      await sbomVersion(p, 'shop', DEBIAN, [LIBSSL3, LIAR]);
      await sbomVersion(q, 'other', DEBIAN, [LOGIN]);
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.name === 'liar')
          ? exited('FATAL liar: unable to find CPE indices')
          : null,
      );
      const result = await recheck({ projectIds: [p.id, q.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: {
          packages: 2,
          unchecked: 1,
          givenUp: { invalid: 0, trivyFailed: 1, unsupported: [] },
        },
      });
      // The probe of the release passed (in each step: never remembered, R20), so the chunk was
      // bisected and the others are matched.
      const names = trivy.calls.flatMap((c) => c.names);
      expect(names.filter((n) => n === 'qualor-release-probe').length).toBeGreaterThan(0);
      expect(names).toEqual(expect.arrayContaining(['libssl3', 'login']));
      expect(await osRows(p)).toEqual([`shop deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`]);
      expect(await digests([keyOf(LOGIN, DEBIAN)])).toEqual({
        [keyOf(LOGIN, DEBIAN)]: primary.digest,
      });
      trivyFails.restore();
    });

    it.each([
      [
        'Trivy’s work directory cannot be made',
        {
          ok: false,
          code: 'FAILED',
          message: "cannot create Trivy's work directory in /x: EACCES",
        } as TrivyRun,
      ],
      [
        'Trivy cannot be started',
        { ok: false, code: 'FAILED', message: 'Trivy is not executable' } as TrivyRun,
      ],
      [
        'Trivy’s output is unreadable',
        { ok: false, code: 'BAD_OUTPUT', message: 'garbage' } as TrivyRun,
      ],
    ])('fails the run, blaming no package, when on an OS chunk %s (R16)', async (_why, failure) => {
      const p = await project();
      await sbomVersion(p, 'shop', DEBIAN, [LIBSSL3, LOGIN]);
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.type === 'operating-system') ? failure : null,
      );
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      // Not bisected: one run, nothing marked.
      expect(trivyFails.failures()).toBe(1);
      expect(await digests([PSSL])).toEqual({});
      trivyFails.restore();
    });

    it('fails the run when Trivy or its database is broken: the probes fail too (R17)', async () => {
      const p = await project();
      const many = Array.from({ length: 24 }, (_, i) => osDep('deb', `pkg-${i}`, '1.0-1'));
      await sbomVersion(p, 'shop', DEBIAN, many);
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.type === 'operating-system')
          ? exited('FATAL failed to open the database')
          : null,
      );
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      if (result.kind === 'failed') {
        expect(result.error.message).toContain('failed to open the database');
      }
      // The chunk, the probe of its release and the server's own baseline probe: no bisecting.
      expect(trivyFails.failures()).toBe(3);
      expect(await digests([keyOf(many[0]!, DEBIAN)])).toEqual({});
      trivyFails.restore();
    });

    /** A project in an organisation of its own: another tenant. */
    const otherTenant = async (): Promise<IngestProject> => {
      n += 1;
      const [org] = await db()
        .insert(organizations)
        .values({ key: `tenant-${n}`, name: `Tenant ${n}` })
        .returning();
      const [row] = await db()
        .insert(projects)
        .values({ organizationId: org!.id, key: `tenant-${n}/app`, name: 'App' })
        .returning();
      await db().insert(projectVulnerabilitySettings).values({ projectId: row!.id });
      return { id: row!.id, key: row!.key } as IngestProject;
    };

    it('never lets one tenant’s failing packages stop another’s: a budget per organisation (R17)', async () => {
      const attacker = await project();
      const victim = await otherTenant();
      const bad = Array.from({ length: 20 }, (_, i) => osDep('deb', `bad-${i}`, '1.0-1'));
      await sbomVersion(attacker, 'image', DEBIAN, bad);
      await sbomVersion(victim, 'image', DEBIAN, [LIBSSL3, LOGIN, PASSWD]);
      warnings.length = 0;
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.name.startsWith('bad-')) ? exited('FATAL panic: bad') : null,
      );

      const result = await recheck({ projectIds: [attacker.id, victim.id] }, { logger: logged });
      // Done: the victim's packages share the attacker's chunks and are matched all the same.
      expect(result).toMatchObject({
        kind: 'done',
        summary: {
          packages: 3,
          unchecked: 20,
          givenUp: {
            invalid: 0,
            trivyFailed: MAX_FAILED_PER_ORGANISATION,
            overBudget: 20 - MAX_FAILED_PER_ORGANISATION,
            unsupported: [],
          },
        },
      });
      expect(await osRows(victim)).toEqual([
        `image deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
      ]);
      expect(
        Object.keys(await digests([PSSL, keyOf(LOGIN, DEBIAN), keyOf(PASSWD, DEBIAN)])),
      ).toHaveLength(3);
      expect((await readVulndbState(db())).lastRecheckError).toBeNull();
      // Bounded by the attacker's own budget: its last packages were dropped, not bisected.
      expect(trivyFails.failures()).toBeLessThan(80);
      expect(JSON.stringify(warnings)).toContain('budget');
      trivyFails.restore();
    });

    it('gives up a distribution whose own name breaks Trivy, never the run (R17)', async () => {
      const p = await project();
      const odd = { family: 'debian', version: 'weird' };
      await sbomVersion(p, 'odd', odd, [osDep('deb', 'a', '1.0-1')]);
      await sbomVersion(p, 'shop', DEBIAN, [LIBSSL3]);
      // Trivy 0.74.0 panics so on Amazon Linux "  " (a release string alone).
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.type === 'operating-system' && c.version === 'weird')
          ? exited('panic: runtime error: index out of range [0] with length 0')
          : null,
      );
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: {
          packages: 1,
          unchecked: 1,
          givenUp: { trivyFailed: 0, overBudget: 0, unsupported: ['debian weird'] },
        },
      });
      // The chunk and the probe of that release failed; the baseline probe passed.
      expect(trivyFails.failures()).toBe(2);
      expect(await osRows(p)).toEqual([`shop deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`]);
      trivyFails.restore();
    });

    it('halves a chunk that is too large down to one package; a single one still too large is given up (Critical 1)', async () => {
      const p = await project();
      const debs = Array.from({ length: 11 }, (_, i) => osDep('deb', `small-${i}`, '1.0-1'));
      await sbomVersion(p, 'shop', DEBIAN, [...debs, osDep('deb', 'huge', '0'), LIBSSL3]);
      await onBranch(p, 'main', { dependencies: [A, B, dep('huge-lib', '0')] });
      warnings.length = 0;
      // One package whose answer alone is over the output cap, as linux@0 can be.
      let tooLarge = 0;
      const inner = trivy.run.bind(trivy);
      trivy.run = (sbom, cacheDir, signal) => {
        const { components } = JSON.parse(sbom) as { components: FakeComponent[] };
        if (!components.some((c) => c.name === 'huge' || c.name === 'huge-lib')) {
          return inner(sbom, cacheDir, signal);
        }
        tooLarge += 1;
        return Promise.resolve({ ok: false, code: 'TOO_LARGE', message: 'output over the budget' });
      };
      // The real chunk size and no floor: down to one package.
      const result = await recheck({ projectIds: [p.id] }, { logger: logged });
      expect(result).toMatchObject({
        kind: 'done',
        summary: {
          packages: 14,
          unchecked: 2,
          givenUp: { invalid: 0, trivyFailed: 2, overBudget: 0, unsupported: [] },
        },
      });
      expect(await osRows(p)).toEqual([`shop deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`]);
      expect(await described(p)).toEqual(
        expect.arrayContaining([`main ${PA} CVE-2026-0001`, `main ${PB} CVE-2026-0002`]),
      );
      // Halving only the chunk that holds it: 13 OS packages down to 1 in at most 5 answers, 3
      // libraries in at most 3.
      expect(tooLarge).toBeGreaterThanOrEqual(5);
      expect(tooLarge).toBeLessThanOrEqual(8);
      expect(JSON.stringify(warnings)).toContain('output over the budget');
    });

    it('leaves a row whose key would pass PostgreSQL’s index limit unchecked (Important 2)', async () => {
      const p = await project();
      // Varied CJK characters, so that PostgreSQL cannot compress the index row below its limit.
      const cjk = (n: number, seed: number) =>
        Array.from({ length: n }, (_, i) =>
          String.fromCharCode(0x4e00 + ((i * 7_919 + seed) % 20_000)),
        ).join('');
      // 512 in the name and in the source: a key of about 9 300 bytes.
      const longDeb = osDep('deb', cjk(512, 1), '1.0-1', cjk(512, 2), '1.0-1');
      await sbomVersion(p, 'shop', DEBIAN, [LIBSSL3, longDeb]);
      // 300 CJK characters in a library's name: a purl of about 2 700 bytes.
      await onBranch(p, 'main', { dependencies: [A, dep(cjk(300, 3), '1.0.0')] });
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: { packages: 2, unchecked: 2, givenUp: { invalid: 2 } },
      });
      expect(trivy.calls.flatMap((c) => c.names).sort()).toEqual(['libssl3', 'lodash']);
      expect(await osRows(p)).toEqual([`shop deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`]);
    });

    it('isolates a library Trivy rejects: another tenant’s libraries are matched (R19)', async () => {
      const attacker = await project();
      const victim = await otherTenant();
      await sbomVersion(attacker, 'image', null, [dep('evil-lib', '1.0.0'), C]);
      await sbomVersion(victim, 'image', null, [A, B]);
      warnings.length = 0;
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.name === 'evil-lib') ? exited('FATAL panic: evil') : null,
      );
      const result = await recheck({ projectIds: [attacker.id, victim.id] }, { logger: logged });
      expect(result).toMatchObject({
        kind: 'done',
        summary: { packages: 3, unchecked: 1, givenUp: { trivyFailed: 1, overBudget: 0 } },
      });
      expect(await described(victim)).toEqual(
        [
          `image ${PA} CVE-2026-0001`,
          `image ${PB} CVE-2026-0002`,
          `image ${PB} CVE-2026-0003`,
        ].sort(),
      );
      expect(await digests([PA, PB, PC])).toEqual({
        [PA]: primary.digest,
        [PB]: primary.digest,
        [PC]: primary.digest,
      });
      expect(JSON.stringify(warnings)).toContain('evil');
      trivyFails.restore();
    });

    it('fails the run when Trivy rejects libraries and the server’s library probe too (R19)', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B] });
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.type === 'operating-system') ? null : exited('FATAL db broken'),
      );
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      if (result.kind === 'failed') expect(result.error.message).toContain('db broken');
      // The chunk and the probe: no bisecting.
      expect(trivyFails.failures()).toBe(2);
      expect(await digests([PA, PB])).toEqual({});
      trivyFails.restore();
    });

    it('fails the run when a known-good release of the family fails too (R20)', async () => {
      const p = await project();
      await sbomVersion(p, 'debian', DEBIAN, [LIBSSL3]);
      await sbomVersion(p, 'alpine', ALPINE, [LIBCRYPTO3]);
      // Trivy's Debian detector is broken, whatever the release; Alpine works.
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.type === 'operating-system' && c.name === 'debian')
          ? exited('FATAL debian detector broken')
          : null,
      );
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      if (result.kind === 'failed') {
        expect(result.error.message).toContain('debian detector broken');
      }
      expect(await digests([PSSL])).toEqual({});
      trivyFails.restore();
    });

    it('decides every give-up in its own step: Trivy breaking mid-run fails the run (R20)', async () => {
      const p = await project();
      await sbomVersion(p, 'debian', DEBIAN, [LIBSSL3]);
      await sbomVersion(p, 'alpine', ALPINE, [LIBCRYPTO3]);
      // Both releases fail as releases; once the first known-good probe has passed, Trivy breaks.
      let broken = false;
      const trivyFails = failingWhen((components) => {
        if (broken) return exited('FATAL broken since the first give-up');
        const os = components.find((c) => c.type === 'operating-system');
        if (os === undefined) return null;
        if (os.version === '12.15' || os.version === '3.20.3') return exited('FATAL release');
        broken = true; // the known-good probe (debian 12 or alpine 3.20) passes, once
        return null;
      });
      const result = await recheck({ projectIds: [p.id] });
      // The second distribution is not filed as unsupported on the first one's verdict.
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      if (result.kind === 'failed') expect(result.error.message).toContain('broken since');
      trivyFails.restore();
    });

    /** Trivy killed by a signal the server did not send (the kernel's OOM killer). */
    const killed: TrivyRun = {
      ok: false,
      code: 'FAILED',
      message: 'Trivy exited with null: ',
      exitCode: null,
      stderr: '',
    };
    const timedOut: TrivyRun = {
      ok: false,
      code: 'TIMEOUT',
      message: 'Trivy ran longer than 900000 ms',
    };

    it.each([
      ['killed by a signal', killed],
      ['timed out', timedOut],
    ])(
      'isolates one package Trivy is %s on: the others are matched (R21)',
      async (_why, failure) => {
        const p = await project();
        const victim = await otherTenant();
        await sbomVersion(p, 'shop', DEBIAN, [osDep('deb', 'poison', '0', 'linux', '0'), LOGIN]);
        await sbomVersion(victim, 'image', DEBIAN, [LIBSSL3, PASSWD]);
        warnings.length = 0;
        const trivyFails = failingWhen((components) =>
          components.some((c) => c.name === 'poison') ? failure : null,
        );
        const result = await recheck({ projectIds: [p.id, victim.id] }, { logger: logged });
        expect(result).toMatchObject({
          kind: 'done',
          summary: { packages: 3, unchecked: 1, givenUp: { trivyFailed: 1, overBudget: 0 } },
        });
        expect(await osRows(victim)).toEqual([
          `image deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
        ]);
        expect(
          Object.keys(await digests([PSSL, keyOf(LOGIN, DEBIAN), keyOf(PASSWD, DEBIAN)])),
        ).toHaveLength(3);
        expect(JSON.stringify(warnings)).toContain('timed out or killed');
        trivyFails.restore();
      },
    );

    it.each([
      ['killed by a signal', killed],
      ['timed out', timedOut],
    ])('fails the run when Trivy is %s on its own probe too (R21)', async (_why, failure) => {
      const p = await project();
      await sbomVersion(p, 'shop', DEBIAN, [LIBSSL3, LOGIN, PASSWD]);
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.type === 'operating-system') ? failure : null,
      );
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      if (result.kind === 'failed') expect(result.error.message).toContain('probe');
      expect(await digests([PSSL])).toEqual({});
      trivyFails.restore();
    });

    it('fails the run when Alpine fails at every release, Debian working: the known-good release is of the same family (R20)', async () => {
      const p = await project();
      await sbomVersion(p, 'debian', DEBIAN, [LIBSSL3]);
      await sbomVersion(p, 'alpine', ALPINE, [LIBCRYPTO3]);
      // A baseline of another family (debian 12) would pass and file Alpine as unsupported.
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.type === 'operating-system' && c.name === 'alpine')
          ? exited('FATAL alpine detector broken')
          : null,
      );
      const result = await recheck({ projectIds: [p.id] });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      if (result.kind === 'failed')
        expect(result.error.message).toContain('alpine detector broken');
      trivyFails.restore();
    });

    it('gives up a library organisation past its budget as overBudget (R17, R19)', async () => {
      const attacker = await project();
      const victim = await otherTenant();
      const evil = Array.from({ length: 20 }, (_, i) => dep(`evil-${i}`, '1.0.0'));
      await sbomVersion(attacker, 'image', null, evil);
      await sbomVersion(victim, 'image', null, [A, B]);
      const trivyFails = failingWhen((components) =>
        components.some((c) => c.name.startsWith('evil-')) ? exited('FATAL panic: evil') : null,
      );
      const result = await recheck({ projectIds: [attacker.id, victim.id] });
      expect(result).toMatchObject({
        kind: 'done',
        summary: {
          packages: 2,
          unchecked: 20,
          givenUp: {
            trivyFailed: MAX_FAILED_PER_ORGANISATION,
            overBudget: 20 - MAX_FAILED_PER_ORGANISATION,
          },
        },
      });
      expect(await described(victim)).toEqual(
        [
          `image ${PA} CVE-2026-0001`,
          `image ${PB} CVE-2026-0002`,
          `image ${PB} CVE-2026-0003`,
        ].sort(),
      );
      trivyFails.restore();
    });

    it('charges too-large packages to their organisation and stops spending runs past its budget (Important A)', async () => {
      const attacker = await project();
      const victim = await otherTenant();
      const heavy = Array.from({ length: 40 }, (_, i) =>
        osDep('deb', `heavy-${i}`, '0', 'linux', '0'),
      );
      await sbomVersion(attacker, 'image', DEBIAN, heavy);
      await sbomVersion(victim, 'image', DEBIAN, [LIBSSL3, LOGIN, PASSWD]);
      let runs = 0;
      const inner = trivy.run.bind(trivy);
      trivy.run = (sbom, cacheDir, signal) => {
        runs += 1;
        const { components } = JSON.parse(sbom) as { components: FakeComponent[] };
        return components.some((c) => c.name.startsWith('heavy-'))
          ? Promise.resolve({ ok: false, code: 'TOO_LARGE', message: 'output over the budget' })
          : inner(sbom, cacheDir, signal);
      };
      const result = await recheck({ projectIds: [attacker.id, victim.id] });
      // Too-large singles count against the budget like rejected ones; then the rest go unbisected.
      expect(result).toMatchObject({
        kind: 'done',
        summary: {
          packages: 3,
          unchecked: 40,
          givenUp: {
            trivyFailed: MAX_FAILED_PER_ORGANISATION,
            overBudget: 40 - MAX_FAILED_PER_ORGANISATION,
          },
        },
      });
      expect(await osRows(victim)).toEqual([
        `image deb libssl3@3.0.22-1~deb12u2 ${PSSL} CVE-2025-27587`,
      ]);
      // Bounded by the budget: about 2 runs and a probe per charged package, a few more to drop the
      // rest (measured: 60; the order of the packages varies). Without the budget first: 125.
      expect(runs).toBeLessThanOrEqual(80);
    });
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

    it('a local copy held past the wait (BUSY) is RECHECK_FAILED, and Trivy never runs', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      let release: () => void = () => undefined;
      const gate = new Promise<void>((r) => (release = r));
      let started: () => void = () => undefined;
      const holding = new Promise<void>((r) => (started = r));
      const holder = withLocalDatabase(db(), dir, primary, async () => {
        started();
        await gate;
      });
      await holding;
      try {
        const result = await recheck({ projectIds: [p.id] }, { lockWaitMs: 50 });
        expect(result).toEqual({
          kind: 'failed',
          error: {
            code: 'RECHECK_FAILED',
            message:
              'Another re-check held the local copy of the vulnerability database for too long. Try the re-check again later.',
          },
        });
        expect((await readVulndbState(db())).lastRecheckError?.code).toBe('RECHECK_FAILED');
        expect(trivy.calls).toEqual([]);
      } finally {
        release();
        await holder;
      }
    });
  });

  describe('Trivy runs in chunks', () => {
    it('more packages than one chunk run several Trivy runs and every match is stored', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B, C, D] });
      const result = await recheck({ projectIds: [p.id] }, { chunk: { components: 2 } });
      expect(result).toMatchObject({ kind: 'done' });
      expect(trivy.calls.map((c) => c.purls.length)).toEqual([2, 2]);
      expect(trivy.calls.flatMap((c) => c.purls).sort()).toEqual([PA, PB, PC, PD].sort());
      expect(await described(p)).toEqual(
        [
          `main ${PA} CVE-2026-0001`,
          `main ${PB} CVE-2026-0002`,
          `main ${PB} CVE-2026-0003`,
          `main ${PD} CVE-2026-0004`,
        ].sort(),
      );
    });

    it('an oversized output splits the chunk in half and every match is still stored', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B, C, D] });
      const inner = trivy.run.bind(trivy);
      // Anything over two components "writes too much output".
      trivy.run = (sbom, cacheDir, signal) =>
        (JSON.parse(sbom) as { components: unknown[] }).components.length > 2
          ? Promise.resolve({ ok: false, code: 'TOO_LARGE', message: 'output over the budget' })
          : inner(sbom, cacheDir, signal);
      const result = await recheck({ projectIds: [p.id] }, { chunk: { components: 4 } });
      expect(result).toMatchObject({ kind: 'done' });
      expect(await described(p)).toHaveLength(4);
      expect((await digests([PA, PB, PC, PD]))[PC]).toBeDefined();
    });

    it('fails the re-check, storing nothing, when even the library probe is too large', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B] });
      // Every run answers TOO_LARGE, the server's own probe too: Trivy is what is broken.
      trivy.failure = { ok: false, code: 'TOO_LARGE', message: 'output over the budget' };
      const result = await recheck({ projectIds: [p.id] }, { chunk: { components: 2 } });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      expect((await readVulndbState(db())).lastRecheckError?.message).toContain('TOO_LARGE');
      expect(await rows(p)).toEqual([]);
      expect(await digests([PA, PB])).toEqual({});
    });

    it('a failure mid-way keeps the earlier chunks and leaves the later ones untouched (R12)', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B, C, D] });
      const inner = trivy.run.bind(trivy);
      let runs = 0;
      trivy.run = (sbom, cacheDir, signal) =>
        ++runs === 2
          ? Promise.resolve({ ok: false, code: 'FAILED', message: 'Trivy exited with 2' })
          : inner(sbom, cacheDir, signal);
      const result = await recheck({ projectIds: [p.id] }, { chunk: { components: 1 } });
      expect(result).toMatchObject({ kind: 'failed', error: { code: 'RECHECK_FAILED' } });
      // Chunk 1 stored, chunk 2 failed, chunks 3 and 4 never ran.
      expect(runs).toBe(2);
      expect(Object.keys(await digests([PA, PB, PC, PD]))).toEqual([trivy.calls[0]!.purls[0]]);
      expect(await rows(p)).toEqual([]);
    });

    it('a stop between chunks ends the run and queues the scope again', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A, B, C] });
      await db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      const stop = new AbortController();
      trivy.onRun = () => {
        stop.abort();
        return Promise.resolve();
      };
      const result = await recheck(
        { projectIds: [p.id] },
        { chunk: { components: 1 }, shutdown: stop.signal },
      );
      expect(result).toEqual({ kind: 'stopped' });
      expect(trivy.calls).toHaveLength(1);
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

  describe('the vulnerability alert job', () => {
    const alertJobs = () =>
      db().select({ status: jobs.status }).from(jobs).where(eq(jobs.queue, ALERTS_QUEUE));

    beforeEach(async () => {
      await db().delete(jobs).where(eq(jobs.queue, ALERTS_QUEUE));
    });

    it('is queued when a re-check finishes', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({ kind: 'done' });
      expect(await alertJobs()).toEqual([{ status: 'queued' }]);
    });

    it('is queued when a re-check fails', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      trivy.failure = { ok: false, code: 'TIMEOUT', message: 'Trivy ran longer than 900000 ms' };
      expect(await recheck({ projectIds: [p.id] })).toMatchObject({ kind: 'failed' });
      expect(await alertJobs()).toEqual([{ status: 'queued' }]);
    });

    it('is not queued when a stop ended the run', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      const stop = new AbortController();
      stop.abort();
      expect(await recheck({ projectIds: [p.id] }, { shutdown: stop.signal })).toEqual({
        kind: 'stopped',
      });
      expect(await alertJobs()).toEqual([]);
    });

    it('is not queued while the instance switch is off', async () => {
      await instanceSwitch(false);
      expect(await recheck({ all: true })).toEqual({ kind: 'off' });
      expect(await alertJobs()).toEqual([]);
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

    it('logs a stop at info, never at warn', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      const stop = new AbortController();
      // Trivy fails the way a killed process does, with the stop already signalled.
      const killed: TrivyRunner = {
        run: () => {
          stop.abort();
          return Promise.resolve({ ok: false, code: 'FAILED', message: 'Trivy exited with 137' });
        },
      };
      const info = vi.fn();
      const warn = vi.fn();
      const result = await recheck(
        { projectIds: [p.id] },
        { runner: killed, shutdown: stop.signal, logger: { info, warn } },
      );
      expect(result).toEqual({ kind: 'stopped' });
      expect(warn).not.toHaveBeenCalled();
      expect(info).toHaveBeenCalledWith(
        expect.anything(),
        expect.stringContaining('re-check stopped'),
      );
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
        await waitForLockWaiters(db(), 1);
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

    describe('a request behind a job on retry backoff', () => {
      const pushBack = () =>
        db().execute(
          sql`UPDATE jobs SET run_at = now() + interval '5 minutes' WHERE queue = ${RECHECK_QUEUE}`,
        );
      /** On the database's own clock, as the queue tests do. */
      const isRunAtInFuture = async (): Promise<boolean> => {
        const result = await db().execute(
          sql`SELECT run_at > now() AS "inFuture" FROM jobs WHERE queue = ${RECHECK_QUEUE} AND status = 'queued'`,
        );
        return Boolean(result.rows[0]?.inFuture);
      };

      it('runs now when the request adds a scope', async () => {
        await enqueueRecheck(db(), { projectIds: [uuidv7()] });
        await pushBack();
        expect(await isRunAtInFuture()).toBe(true);
        await enqueueRecheck(db(), { projectIds: [uuidv7()] });
        expect(await isRunAtInFuture()).toBe(false);
      });

      it('runs now when the request adds nothing', async () => {
        await enqueueRecheck(db(), { all: true });
        await pushBack();
        expect(await isRunAtInFuture()).toBe(true);
        await enqueueRecheck(db(), { all: true });
        expect(await isRunAtInFuture()).toBe(false);
      });
    });

    it('two workers run two requests one after the other, each on its own scope', async () => {
      const p1 = await project();
      const p2 = await project();
      await onBranch(p1, 'main', { dependencies: [A] });
      await onBranch(p2, 'main', { dependencies: [D] });
      await db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      await enqueueRecheck(db(), { projectIds: [p1.id] });
      // The second request arrives while the first is in Trivy: it queues behind the running job.
      trivy.onRun = async () => {
        await enqueueRecheck(db(), { projectIds: [p2.id] });
      };
      let active = 0;
      let overlapped = false;
      const runner: TrivyRunner = {
        async run(sbomJson, cacheDir, shutdown) {
          active += 1;
          overlapped ||= active > 1;
          try {
            return await trivy.run(sbomJson, cacheDir, shutdown);
          } finally {
            active -= 1;
          }
        },
      };
      await Promise.all([
        runUntilIdle(db(), recheckHandlers(deps({ runner })), silent),
        runUntilIdle(db(), recheckHandlers(deps({ runner })), silent),
      ]);
      expect(await recheckJobs()).toEqual([
        { status: 'succeeded', payload: { projectIds: [p1.id] }, key: RECHECK_QUEUE },
        { status: 'succeeded', payload: { projectIds: [p2.id] }, key: RECHECK_QUEUE },
      ]);
      expect(overlapped).toBe(false);
      expect(trivy.calls).toHaveLength(2);
      expect(await described(p1)).toEqual([`main ${PA} CVE-2026-0001`]);
      expect(await described(p2)).toEqual([`main ${PD} CVE-2026-0004`]);
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

  describe('the re-match after 0028 cleared the marks (A14)', () => {
    const vendorIdsOf = async (p: string) =>
      (
        await db()
          .select({
            id: vulnerabilityMatches.vulnerabilityId,
            vendorIds: vulnerabilityMatches.vendorIds,
          })
          .from(vulnerabilityMatches)
          .where(eq(vulnerabilityMatches.purl, p))
      ).map((m) => [m.id, m.vendorIds]);

    it('queues one full re-check at boot, which gives the matches their vendor ids; the next boot queues none', async () => {
      const p = await project();
      await onBranch(p, 'main', { dependencies: [A] });
      await recheck({ projectIds: [p.id] });
      // What 0028 leaves: matches without vendor ids, every package unmarked, also one that no
      // inventory lists any more.
      await db().update(vulnerabilityMatches).set({ vendorIds: [] });
      const gone = 'pkg:npm/no-inventory-lists-it@1.0.0';
      await db().insert(matchedPackages).values({ purl: gone, datasetDigest: primary.digest });
      await db().update(matchedPackages).set({ datasetDigest: '' });
      await db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));

      const info = vi.fn();
      expect(await queueRematchIfCleared(db(), { info })).toBe(true);
      // The log says why a full re-check runs.
      expect(info.mock.calls).toEqual([
        [
          { component: 'vulnerabilities' },
          'a full vulnerability re-check is queued: the upgrade cleared the packages’ match marks, so every match gets Trivy’s vendor ids',
        ],
      ]);
      // A second replica that boots meanwhile merges into the queued job.
      expect(await queueRematchIfCleared(db())).toBe(true);
      expect(await recheckJobs()).toEqual([
        { status: 'queued', payload: { all: true }, key: RECHECK_QUEUE },
      ]);

      await runUntilIdle(db(), recheckHandlers(deps()), silent);
      expect(await vendorIdsOf(PA)).toEqual([
        ['CVE-2026-0001', ['GHSA-0001-xxxx-yyyy', 'GO-2026-0001']],
      ]);
      // Matched again, and the mark no inventory needs is gone: nothing is left cleared.
      expect(await digests([PA, gone])).toEqual({ [PA]: primary.digest });
      await db().delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      expect(await queueRematchIfCleared(db())).toBe(false);
      expect(await recheckJobs()).toEqual([]);
    });

    it('queues none while the instance switch is off, or when no mark is cleared', async () => {
      const info = vi.fn();
      expect(await queueRematchIfCleared(db(), { info })).toBe(false);
      await db().insert(matchedPackages).values({ purl: PA, datasetDigest: primary.digest });
      expect(await queueRematchIfCleared(db(), { info })).toBe(false);
      await db().insert(matchedPackages).values({ purl: PB, datasetDigest: '' });
      await instanceSwitch(false);
      expect(await queueRematchIfCleared(db(), { info })).toBe(false);
      expect(await recheckJobs()).toEqual([]);
      expect(info).not.toHaveBeenCalled();
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

    it('none from the two routes while the instance switch is off', async () => {
      const p = await project();
      await tagScan(p, '1.0.0', { dependencies: [A] });
      const version = await versionId(p, '1.0.0');
      await instanceSwitch(false);
      await clear();
      const patch = await api('PATCH', `/projects/${p.id}/versions/${version}`, {
        tracking: 'pinned',
      });
      expect(patch.statusCode, patch.body).toBe(200);
      const put = await api('PUT', `/projects/${p.id}/vulnerability-monitoring`, {
        enabled: true,
        branchPatterns: ['hotfix/*'],
        versionRule: { kind: 'lines', lines: 3 },
        labelVersions: false,
      });
      expect(put.statusCode, put.body).toBe(200);
      expect(await queued()).toEqual([]);
    });

    it('none from a PUT that changes nothing', async () => {
      const p = await project();
      await clear();
      const put = await api('PUT', `/projects/${p.id}/vulnerability-monitoring`, {
        enabled: true,
        branchPatterns: [],
        versionRule: { kind: 'lines', lines: 5 },
        labelVersions: false,
      });
      expect(put.statusCode, put.body).toBe(200);
      expect(await queued()).toEqual([]);
    });
  });
});

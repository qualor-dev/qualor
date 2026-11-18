import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { seedFix, seedMainVulnerability } from '../../test/fixes';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId as testMainBranchId } from '../../test/issues';
import { seedCheck, seedMatch, seedTargetRow, purlFor } from '../../test/vulnerabilities';
import type { Db } from '../db/client';
import { branches, projectVersions, vulnerabilityDecisions } from '../db/schema';
import { pairKey } from '../jira/presence';
import {
  fixFacets,
  fixProblem,
  mainBranchId,
  mainVulnerabilities,
  type MainVulnerability,
} from './eligibility';

const BASELINE = new Date('2026-12-01T00:00:00Z');

describe('which vulnerabilities a fix handles (spec §6.2, B5, B7, R12)', () => {
  let h: IngestHarness;
  let projectId: string;
  let main: string;
  let pinned: string;
  let pkgs = 0;

  const db = (): Db => h.ctx.db;
  const fresh = (prefix = 'qe') => `${prefix}-${++pkgs}`;
  const onMain = (
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
        vulnerabilityId: 'CVE-2026-0101',
        severity: 'high',
        fixedVersion: '1.2.6, 0.2.4',
        ...over,
      },
    );

  beforeAll(async () => {
    h = await createIngestHarness();
    projectId = (await h.project('ELIGIBLE')).id;
    main = await testMainBranchId(db(), projectId);
    // A pinned version is tracked whatever the rule.
    pinned = (
      await db()
        .insert(projectVersions)
        .values({
          projectId,
          label: '1.0.0',
          source: 'tag',
          tag: 'v1.0.0',
          analyzedAt: new Date(),
          tracking: 'pinned',
        })
        .returning()
    )[0]!.id;
    await seedCheck(db(), { projectId, branchId: main, baselineAt: BASELINE });
  });
  afterAll(async () => {
    await h.close();
  });

  it('finds the main branch', async () => {
    expect(await mainBranchId(db(), projectId)).toBe(main);
    expect(await mainBranchId(db(), '00000000-0000-7000-8000-000000000000')).toBeNull();
  });

  it('reads the main rows of every ecosystem of the family, npm and yarn under js', async () => {
    const pkg = fresh();
    await onMain(pkg, { firstSeenAt: new Date('2026-11-01T00:00:00Z') });
    await onMain(pkg, {
      ecosystem: 'yarn',
      version: '2.0.0',
      vulnerabilityId: 'CVE-2026-0102',
      severity: 'critical',
      fixedVersion: null,
      firstSeenAt: new Date('2026-12-02T00:00:00Z'),
    });
    // The same name in another family is another fix.
    await onMain(pkg, { ecosystem: 'pom', vulnerabilityId: 'CVE-2026-0103' });
    const rows = await mainVulnerabilities(db(), projectId, 'js', pkg);
    expect(rows).toEqual<MainVulnerability[]>([
      {
        vulnerabilityId: 'CVE-2026-0101',
        severity: 'high',
        title: null,
        primaryUrl: null,
        ecosystem: 'npm',
        packageVersion: '1.2.5',
        fixedVersions: ['1.2.6', '0.2.4'],
        firstSeenAt: new Date('2026-11-01T00:00:00Z'),
        isNew: false,
        kev: false,
        kevDateAdded: null,
      },
      {
        vulnerabilityId: 'CVE-2026-0102',
        severity: 'critical',
        title: null,
        primaryUrl: null,
        ecosystem: 'yarn',
        packageVersion: '2.0.0',
        fixedVersions: [],
        firstSeenAt: new Date('2026-12-02T00:00:00Z'),
        isNew: true,
        kev: false,
        kevDateAdded: null,
      },
    ]);
    expect(
      (await mainVulnerabilities(db(), projectId, 'maven', pkg)).map((r) => r.ecosystem),
    ).toEqual(['pom']);
  });

  it('leaves out ignored rows, decided rows and rows only on another target', async () => {
    const ignored = fresh();
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      packageName: ignored,
      vulnerabilityId: 'CVE-2026-0201',
      fixedVersion: '2.0.0',
      ignored: true,
    });
    const falsePositive = fresh();
    await onMain(falsePositive, { vulnerabilityId: 'CVE-2026-0202' });
    await db().insert(vulnerabilityDecisions).values({
      projectId,
      packageName: falsePositive,
      vulnerabilityId: 'CVE-2026-0202',
      status: 'false_positive',
      reason: 'component_not_present',
    });
    const onVersion = fresh();
    await seedTargetRow(db(), {
      projectId,
      versionId: pinned,
      packageName: onVersion,
      vulnerabilityId: 'CVE-2026-0203',
      fixedVersion: '2.0.0',
    });
    const [release] = await db()
      .insert(branches)
      .values({ projectId, kind: 'branch', name: `release/${pkgs}`, isMain: false })
      .returning();
    await seedTargetRow(db(), {
      projectId,
      branchId: release!.id,
      packageName: onVersion,
      vulnerabilityId: 'CVE-2026-0203',
      fixedVersion: '2.0.0',
    });
    for (const pkg of [ignored, falsePositive, onVersion]) {
      expect(await mainVulnerabilities(db(), projectId, 'js', pkg), pkg).toEqual([]);
    }
    // A decision of another branch leaves main's row open.
    await db().insert(vulnerabilityDecisions).values({
      projectId,
      packageName: onVersion,
      vulnerabilityId: 'CVE-2026-0203',
      branchId: release!.id,
      status: 'wont_fix',
      comment: 'release only',
    });
    await onMain(onVersion, { vulnerabilityId: 'CVE-2026-0203' });
    expect(await mainVulnerabilities(db(), projectId, 'js', onVersion)).toHaveLength(1);
  });

  it('tells the request why there is nothing to fix', async () => {
    const pkg = fresh();
    await onMain(pkg);
    const rows = await mainVulnerabilities(db(), projectId, 'js', pkg);
    expect(fixProblem('js', pkg, rows)).toBeNull();
    // R3: the Go standard library is fixed by the Go version.
    expect(fixProblem('go', 'stdlib', rows)).toBe('NOT_FIXABLE');
    expect(fixProblem('go', 'golang.org/x/net', rows)).toBeNull();
    const none = fresh();
    await onMain(none, { fixedVersion: null });
    await onMain(none, { vulnerabilityId: 'CVE-2026-0302', fixedVersion: ' , ' });
    expect(fixProblem('js', none, await mainVulnerabilities(db(), projectId, 'js', none))).toBe(
      'NOT_FIXABLE',
    );
    expect(fixProblem('js', fresh(), [])).toBe('NOT_FIXABLE');
    // gradle is no family (B7).
    expect(fixProblem(null, pkg, rows)).toBe('FIX_ECOSYSTEM_UNSUPPORTED');
  });

  it('answers the fix and fixable of a page of pairs in two queries', async () => {
    const fixable = fresh();
    await onMain(fixable, { vulnerabilityId: 'CVE-2026-0401' });
    const fixId = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: fixable,
      state: 'failed',
      failure: { code: 'package_manager', message: 'npm ERR!' },
      targetVersion: '1.2.6',
    });
    const unfixable = fresh();
    await onMain(unfixable, { vulnerabilityId: 'CVE-2026-0402', fixedVersion: null });
    const gradle = fresh();
    await onMain(gradle, { ecosystem: 'gradle', vulnerabilityId: 'CVE-2026-0403' });
    const versionOnly = fresh();
    await seedTargetRow(db(), {
      projectId,
      versionId: pinned,
      packageName: versionOnly,
      vulnerabilityId: 'CVE-2026-0404',
      fixedVersion: '2.0.0',
    });
    await seedFix(db(), { projectId, family: 'js', packageName: versionOnly });
    await onMain('stdlib', { ecosystem: 'gomod', vulnerabilityId: 'CVE-2026-0405' });
    const pairs = [
      { packageName: fixable, vulnerabilityId: 'CVE-2026-0401' },
      { packageName: unfixable, vulnerabilityId: 'CVE-2026-0402' },
      { packageName: gradle, vulnerabilityId: 'CVE-2026-0403' },
      { packageName: versionOnly, vulnerabilityId: 'CVE-2026-0404' },
      { packageName: 'stdlib', vulnerabilityId: 'CVE-2026-0405' },
      { packageName: fresh(), vulnerabilityId: 'CVE-2026-0406' },
    ];
    const facets = await fixFacets(db(), projectId, pairs);
    const at = (i: number) => facets.get(pairKey(pairs[i]!.packageName, pairs[i]!.vulnerabilityId));
    expect(at(0)).toEqual({
      fix: {
        id: fixId,
        state: 'failed',
        refresh: false,
        targetVersion: '1.2.6',
        mrNumber: null,
        mrUrl: null,
        failure: { code: 'package_manager', message: 'npm ERR!' },
        updatedAt: expect.any(String),
      },
      fixable: true,
    });
    expect(at(1)).toEqual({ fix: null, fixable: false });
    expect(at(2)).toEqual({ fix: null, fixable: false });
    // A fix of the package is not shown on a pair main does not have (it fixes main's rows).
    expect(at(3)).toEqual({ fix: null, fixable: false });
    expect(at(4)).toEqual({ fix: null, fixable: false });
    expect(at(5)).toEqual({ fix: null, fixable: false });
    expect(facets.size).toBe(pairs.length);
    expect(await fixFacets(db(), projectId, [])).toEqual(new Map());

    // A fixed version on another main row of the pair (yarn) makes it fixable.
    await onMain(unfixable, {
      ecosystem: 'yarn',
      version: '3.0.0',
      vulnerabilityId: 'CVE-2026-0402',
      fixedVersion: '3.0.1',
    });
    expect(
      (await fixFacets(db(), projectId, [pairs[1]!])).get(pairKey(unfixable, 'CVE-2026-0402')),
    ).toEqual({ fix: null, fixable: true });
    // The match the rows join must exist; one without a fixed version is not fixable.
    await seedMatch(db(), {
      purl: purlFor(unfixable, '3.0.0', 'yarn'),
      vulnerabilityId: 'CVE-2026-0402',
      fixedVersion: null,
    });
    expect(
      (await fixFacets(db(), projectId, [pairs[1]!])).get(pairKey(unfixable, 'CVE-2026-0402')),
    ).toEqual({ fix: null, fixable: false });
  });

  it('matches Python names by PEP 503 and every other family exactly (ruling T8b)', async () => {
    await onMain('Py_Pkg.One', { ecosystem: 'uv', vulnerabilityId: 'CVE-2026-0501' });
    await onMain('py-pkg-one', { ecosystem: 'poetry', vulnerabilityId: 'CVE-2026-0502' });
    // The same spellings in js are other packages, matched exactly.
    await onMain('PY-pkg_one', { ecosystem: 'npm', vulnerabilityId: 'CVE-2026-0503' });
    const python = await mainVulnerabilities(db(), projectId, 'python', 'PY.pkg_ONE');
    expect(python.map((r) => [r.vulnerabilityId, r.ecosystem])).toEqual([
      ['CVE-2026-0501', 'uv'],
      ['CVE-2026-0502', 'poetry'],
    ]);
    expect(await mainVulnerabilities(db(), projectId, 'js', 'py-pkg-one')).toEqual([]);
    expect(await mainVulnerabilities(db(), projectId, 'js', 'PY-pkg_one')).toHaveLength(1);

    const fixId = await seedFix(db(), { projectId, family: 'python', packageName: 'py-pkg-one' });
    const pairs = [
      { packageName: 'Py_Pkg.One', vulnerabilityId: 'CVE-2026-0501' },
      { packageName: 'py-pkg-one', vulnerabilityId: 'CVE-2026-0502' },
      { packageName: 'PY-pkg_one', vulnerabilityId: 'CVE-2026-0503' },
    ];
    const facets = await fixFacets(db(), projectId, pairs);
    expect(
      pairs.map((p) => {
        const facet = facets.get(pairKey(p.packageName, p.vulnerabilityId));
        return [facet?.fix?.id ?? null, facet?.fixable];
      }),
    ).toEqual([
      [fixId, true],
      [fixId, true],
      [null, true],
    ]);
  });
});

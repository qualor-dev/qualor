import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { mainBranchId } from '../../test/issues';
import { seedCheck, seedMatch, seedTargetRow } from '../../test/vulnerabilities';
import { writeVulndbSettings } from '../vulndb/settings';
import {
  analyses,
  branchDependencies,
  branches,
  organizations,
  projectVersions,
  projectVulnerabilitySettings,
  targetVulnerabilities,
  versionDependencies,
  vulnerabilityDecisions,
} from '../db/schema';
import { first } from '../db/rows';

/** One stored package: npm at `1.0.0` in `package-lock.json` unless given. */
interface Pkg {
  name: string;
  version?: string;
  ecosystem?: string;
  path?: string;
  direct?: boolean | null;
  sourceName?: string;
  sourceVersion?: string;
}

interface Row {
  project: { id: string; key: string; name: string };
  target: {
    kind: 'branch' | 'version';
    id: string;
    name: string;
    main: boolean;
    source: 'tag' | 'label' | 'sbom' | null;
  };
  ecosystem: string;
  purlType: string | null;
  name: string;
  version: string;
  path: string;
  direct: boolean | null;
  distribution: { family: string; version: string } | null;
  vulnerabilities: number | null;
}

interface Answer {
  rows: Row[];
  page: number;
  pageSize: number;
  total: number;
  totalCapped: boolean;
}

const LOG4J_CORE = 'org.apache.logging.log4j:log4j-core';
const LOG4J_API = 'org.apache.logging.log4j:log4j-api';
const LIBSSL = { name: 'libssl3', version: '3.0.11-1~deb12u2' };
/** The match key of the SBOM version's libssl3 (Task 9, ruling R18): distribution and source. */
const LIBSSL_KEY =
  'pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12.15&upstream=openssl@3.0.11-1~deb12u2';

/** The basis the re-check records for a version analysed at 2026-11-01 00:00 UTC. */
const VERSION_BASIS = '2026-11-01T00:00:00.000Z';

/** 0.16 §6.8: where used, `GET /packages/usages`. */
describe('GET /packages/usages (0.16 where used)', () => {
  let ctx: TestContext;
  let admin: Session;
  let member: Session;
  let outsider: Session;
  let a1: string;
  let b1: string;
  let mainA: string;
  let featureA: string;
  let mainB: string;
  let tagVersion: string;
  let imageVersion: string;
  let bareVersion: string;
  let rhelVersion: string;

  const get = (query: string, headers: Record<string, string> = admin.headers) =>
    ctx.app.inject({ method: 'GET', url: `/api/v0/packages/usages?${query}`, headers });
  const search = async (query: string, session: Session = admin): Promise<Answer> => {
    const res = await get(query, session.headers);
    expect(res.statusCode, res.body).toBe(200);
    return res.json();
  };
  const q = (text: string) => `q=${encodeURIComponent(text)}`;
  const names = (answer: Answer) => answer.rows.map((r) => r.name);

  const branchPackages = async (projectId: string, branchId: string, pkgs: Pkg[]) => {
    const analysis = first(
      await ctx.db
        .insert(analyses)
        .values({ projectId, branchId, status: 'queued' })
        .returning({ id: analyses.id }),
    );
    await ctx.db.insert(branchDependencies).values(
      pkgs.map((p) => ({
        branchId,
        path: p.path ?? 'package-lock.json',
        ecosystem: p.ecosystem ?? 'npm',
        name: p.name,
        version: p.version ?? '1.0.0',
        licenses: [],
        direct: p.direct ?? null,
        analysisId: analysis.id,
      })),
    );
    return analysis.id;
  };
  const version = async (
    projectId: string,
    label: string,
    options: { source: 'tag' | 'label' | 'sbom'; os?: { family: string; version: string } },
    pkgs: Pkg[],
  ) => {
    const row = first(
      await ctx.db
        .insert(projectVersions)
        .values({
          projectId,
          label,
          source: options.source,
          tag: options.source === 'tag' ? `v${label}` : null,
          analyzedAt: new Date(Date.UTC(2026, 10, 1)),
          hasInventory: true,
          osFamily: options.os?.family ?? null,
          osVersion: options.os?.version ?? null,
          sbomFormat: options.source === 'sbom' ? 'CycloneDX 1.6' : null,
        })
        .returning({ id: projectVersions.id }),
    );
    await ctx.db.insert(versionDependencies).values(
      pkgs.map((p) => ({
        versionId: row.id,
        path: p.path ?? '',
        ecosystem: p.ecosystem ?? 'npm',
        name: p.name,
        version: p.version ?? '1.0.0',
        licenses: [],
        direct: p.direct ?? null,
        sourceName: p.sourceName ?? null,
        sourceVersion: p.sourceVersion ?? null,
      })),
    );
    return row.id;
  };

  beforeAll(async () => {
    ctx = await createTestContext();
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const orgA = await organizationId(ctx, 'default');
    const orgB = first(
      await ctx.db
        .insert(organizations)
        .values({ key: 'pkg-b', name: 'B' })
        .returning({ id: organizations.id }),
    ).id;
    a1 = (await createProject(ctx, admin, { organizationId: orgA, key: 'a1', name: 'Alpha' })).id;
    b1 = (await createProject(ctx, admin, { organizationId: orgB, key: 'b1', name: 'Beta' })).id;
    mainA = await mainBranchId(ctx.db, a1);
    mainB = await mainBranchId(ctx.db, b1);
    featureA = first(
      await ctx.db
        .insert(branches)
        .values({ projectId: a1, kind: 'branch', name: 'feature/x' })
        .returning({ id: branches.id }),
    ).id;
    const mrA = first(
      await ctx.db
        .insert(branches)
        .values({ projectId: a1, kind: 'merge_request', name: '7', mrSourceBranch: 'feature/x' })
        .returning({ id: branches.id }),
    ).id;

    const mainAnalysis = await branchPackages(a1, mainA, [
      { name: LOG4J_CORE, version: '2.14.1', ecosystem: 'pom', path: 'pom.xml', direct: true },
      { name: LOG4J_CORE, version: '2.14.1', ecosystem: 'pom', path: 'app/pom.xml' },
      { name: LOG4J_CORE, version: '2.17.1', ecosystem: 'pom', path: 'sub/pom.xml' },
      { name: 'qs', version: '6.11.0' },
      { name: 'QS' },
      { name: 'qs-x' },
      { name: 'a%_c' },
      { name: 'abc' },
      { name: '%_' },
      { name: 'requests', version: '2.31.0', ecosystem: 'pip', path: 'requirements.txt' },
      { name: 'requests', version: '2.31.0', ecosystem: 'poetry', path: 'poetry.lock' },
      { name: 'requests', version: '2.30.0', ecosystem: 'pip', path: 'legacy/requirements.txt' },
      { name: 'PyYAML', version: '6.0.1', ecosystem: 'pip', path: 'requirements.txt' },
      { name: 'typing_extensions', version: '4.8.0', ecosystem: 'pip', path: 'requirements.txt' },
      { name: 'lodash', version: '4.17.20' },
      { name: 'minimist', version: '1.2.0' },
      { name: 'ignored-pkg' },
    ]);
    await branchPackages(a1, featureA, [
      { name: LOG4J_CORE, version: '2.14.1', ecosystem: 'pom', path: 'pom.xml' },
    ]);
    await branchPackages(a1, mrA, [
      { name: LOG4J_CORE, version: '2.14.1', ecosystem: 'pom', path: 'pom.xml' },
      { name: 'mr-only' },
    ]);
    tagVersion = await version(a1, '1.0.0', { source: 'tag' }, [
      { name: LOG4J_CORE, version: '2.14.1', ecosystem: 'pom', path: 'pom.xml' },
    ]);
    imageVersion = await version(
      a1,
      'image-1',
      { source: 'sbom', os: { family: 'debian', version: '12.15' } },
      [
        { name: LOG4J_CORE, version: '2.14.1', ecosystem: 'maven' },
        { ...LIBSSL, ecosystem: 'deb', sourceName: 'openssl', sourceVersion: LIBSSL.version },
      ],
    );
    bareVersion = await version(a1, 'no-os', { source: 'sbom' }, [
      { name: 'libfoo', version: '1.0', ecosystem: 'deb' },
    ]);
    rhelVersion = await version(
      a1,
      'rhel-image',
      { source: 'sbom', os: { family: 'redhat', version: '8.4' } },
      [
        { name: 'bash', version: '4.4.20-5.el8', ecosystem: 'rpm' },
        { name: 'x', version: '2:1-1', ecosystem: 'rpm' },
        { name: 'x', version: '1-1', ecosystem: 'rpm', path: 'other' },
      ],
    );
    await branchPackages(b1, mainB, [
      { name: LOG4J_API, version: '2.14.1', ecosystem: 'pom', path: 'pom.xml' },
      { name: LOG4J_CORE, version: '2.14.1', ecosystem: 'pom', path: 'pom.xml' },
      { name: 'qs', version: '6.11.0' },
    ]);

    // Vulnerabilities: main of a1 and the debian SBOM version were re-checked, the others not.
    const baselineAt = new Date(Date.UTC(2026, 10, 1));
    // Each check against the target's current basis (R22): the branch's last analysis, the
    // version's analysis time.
    await ctx.db
      .update(branches)
      .set({ lastAnalysisId: mainAnalysis })
      .where(eq(branches.id, mainA));
    await seedCheck(ctx.db, { projectId: a1, branchId: mainA, baselineAt, basis: mainAnalysis });
    for (const versionId of [imageVersion, bareVersion]) {
      await seedCheck(ctx.db, { projectId: a1, versionId, baselineAt, basis: VERSION_BASIS });
    }
    const onMain = { projectId: a1, branchId: mainA } as const;
    await seedTargetRow(ctx.db, {
      ...onMain,
      packageName: 'lodash',
      packageVersion: '4.17.20',
      vulnerabilityId: 'CVE-2026-0001',
    });
    await seedTargetRow(ctx.db, {
      ...onMain,
      packageName: 'minimist',
      packageVersion: '1.2.0',
      vulnerabilityId: 'CVE-2026-0002',
    });
    await ctx.db.insert(vulnerabilityDecisions).values({
      ...onMain,
      packageName: 'minimist',
      vulnerabilityId: 'CVE-2026-0002',
      status: 'false_positive',
      reason: 'component_not_present',
    });
    await seedTargetRow(ctx.db, {
      ...onMain,
      packageName: 'ignored-pkg',
      vulnerabilityId: 'CVE-2026-0003',
      ignored: true,
    });
    // The libssl3 row under its exact key counts; one under an older key form does not.
    for (const [purl, id] of [
      [LIBSSL_KEY, 'CVE-2026-0010'],
      ['pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12.15', 'CVE-2026-0011'],
    ] as const) {
      await seedMatch(ctx.db, { purl, vulnerabilityId: id });
      await ctx.db.insert(targetVulnerabilities).values({
        projectId: a1,
        versionId: imageVersion,
        ecosystem: 'deb',
        packageName: LIBSSL.name,
        packageVersion: LIBSSL.version,
        purl,
        vulnerabilityId: id,
      });
    }

    const m = await createUser(ctx, { username: 'pkg-member' });
    await addMember(ctx, orgA, m.id, 'viewer');
    member = await login(ctx, m.username, m.password);
    const o = await createUser(ctx, { username: 'pkg-outsider' });
    outsider = await login(ctx, o.username, o.password);
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('visibility: a member of one organisation sees none of the other, the instance admin both', async () => {
    const mine = await search(q('log4j'), member);
    expect(mine.rows.length).toBeGreaterThan(0);
    expect(new Set(mine.rows.map((r) => r.project.id))).toEqual(new Set([a1]));
    expect(mine.total).toBe(mine.rows.length);
    const all = await search(q('log4j'));
    expect(new Set(all.rows.map((r) => r.project.id))).toEqual(new Set([a1, b1]));
    const none = await search(q('log4j'), outsider);
    expect(none).toEqual({ rows: [], page: 1, pageSize: 50, total: 0, totalCapped: false });
    // Short names and purls go through the same filter.
    expect((await search(q('qs'), member)).rows.map((r) => r.project.key)).not.toContain('b1');
    const purl = await search(q('pkg:maven/org.apache.logging.log4j/log4j-core'), member);
    expect(purl.rows.map((r) => r.project.key)).not.toContain('b1');
  });

  it('a project token gets 403 TOKEN_NOT_ALLOWED, a personal token without read INSUFFICIENT_SCOPE', async () => {
    const projectToken = await createProjectToken(ctx, admin, a1);
    const byProject = await get(q('log4j'), bearer(projectToken));
    expect([byProject.statusCode, byProject.json().code]).toEqual([403, 'TOKEN_NOT_ALLOWED']);
    const token = async (scopes: string[]) => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: admin.headers,
        payload: { name: `pkg-${scopes.join('-')}`, scopes },
      });
      expect(res.statusCode, res.body).toBe(201);
      return bearer((res.json() as { token: string }).token);
    };
    const writeOnly = await get(q('log4j'), await token(['analysis:write']));
    expect([writeOnly.statusCode, writeOnly.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    const reader = await get(q('log4j'), await token(['read']));
    expect(reader.statusCode).toBe(200);
    expect((await get(q('log4j'), {})).statusCode).toBe(401);
  });

  it('order: name, version, project name, main, other branches, versions, then path', async () => {
    const answer = await search(q('log4j'));
    expect(
      answer.rows.map((r) => [
        r.name.slice(r.name.indexOf(':') + 1),
        r.version,
        r.project.name,
        r.target.kind,
        r.target.name,
        r.path,
      ]),
    ).toEqual([
      ['log4j-api', '2.14.1', 'Beta', 'branch', 'main', 'pom.xml'],
      ['log4j-core', '2.14.1', 'Alpha', 'branch', 'main', 'app/pom.xml'],
      ['log4j-core', '2.14.1', 'Alpha', 'branch', 'main', 'pom.xml'],
      ['log4j-core', '2.14.1', 'Alpha', 'branch', 'feature/x', 'pom.xml'],
      ['log4j-core', '2.14.1', 'Alpha', 'version', '1.0.0', 'pom.xml'],
      ['log4j-core', '2.14.1', 'Alpha', 'version', 'image-1', ''],
      ['log4j-core', '2.14.1', 'Beta', 'branch', 'main', 'pom.xml'],
      ['log4j-core', '2.17.1', 'Alpha', 'branch', 'main', 'sub/pom.xml'],
    ]);
    expect(answer).toMatchObject({ page: 1, pageSize: 50, total: 8, totalCapped: false });
    expect(answer.rows[2]).toEqual({
      project: { id: a1, key: 'a1', name: 'Alpha' },
      target: { kind: 'branch', id: mainA, name: 'main', main: true, source: null },
      ecosystem: 'pom',
      purlType: 'maven',
      name: LOG4J_CORE,
      version: '2.14.1',
      path: 'pom.xml',
      direct: true,
      distribution: null,
      vulnerabilities: 0,
    });
    expect(answer.rows[3]!.target).toEqual({
      kind: 'branch',
      id: featureA,
      name: 'feature/x',
      main: false,
      source: null,
    });
    expect(answer.rows[4]!.target).toEqual({
      kind: 'version',
      id: tagVersion,
      name: '1.0.0',
      main: false,
      source: 'tag',
    });
    const second = await search(`${q('log4j')}&page=2&pageSize=3`);
    expect(second.rows.map((r) => [r.target.name, r.path])).toEqual([
      ['feature/x', 'pom.xml'],
      ['1.0.0', 'pom.xml'],
      ['image-1', ''],
    ]);
    expect(second).toMatchObject({ page: 2, pageSize: 3, total: 8, totalCapped: false });
  });

  it('short names are exact, longer ones contain', async () => {
    expect(names(await search(q('qs'))).sort()).toEqual(['QS', 'qs', 'qs']);
    expect(names(await search(q('QS'))).sort()).toEqual(['QS', 'qs', 'qs']);
    expect(names(await search(q('qs-')))).toEqual(['qs-x']);
    expect(new Set(names(await search(q('log4j'))))).toEqual(new Set([LOG4J_API, LOG4J_CORE]));
    expect(new Set(names(await search(q('LOG4J-CORE'))))).toEqual(new Set([LOG4J_CORE]));
    // Trimmed before it is measured: ` qs ` is the short name qs.
    expect(names(await search(q(' qs '))).sort()).toEqual(['QS', 'qs', 'qs']);
  });

  it('wildcards are literal', async () => {
    expect(names(await search(q('%_')))).toEqual(['%_']);
    expect(names(await search(q('%_c')))).toEqual(['a%_c']);
    expect(names(await search(q('a_c')))).toEqual([]);
    expect(names(await search(q('a%c')))).toEqual([]);
    expect(names(await search(q('%')))).toEqual([]);
    expect(names(await search(q('\\')))).toEqual([]);
  });

  it('purl: the type covers its ecosystems, name and version match exactly', async () => {
    const pypi = await search(q('pkg:pypi/requests@2.31.0'));
    expect(pypi.rows.map((r) => [r.ecosystem, r.version, r.purlType]).sort()).toEqual([
      ['pip', '2.31.0', 'pypi'],
      ['poetry', '2.31.0', 'pypi'],
    ]);
    expect((await search(q('pkg:pypi/requests'))).total).toBe(3);
    // PyPI names compare as purlOf writes them: lowercase, `_` as `-` (ruling R1).
    expect(names(await search(q('pkg:pypi/pyyaml@6.0.1')))).toEqual(['PyYAML']);
    expect(names(await search(q('pkg:pypi/Typing_Extensions')))).toEqual(['typing_extensions']);
    expect(names(await search(q('pkg:pypi/typing-extensions@4.8.0')))).toEqual([
      'typing_extensions',
    ]);
    expect((await search(q('pkg:pypi/typingxextensions'))).total).toBe(0);
    // Exact, not contains, and case-sensitive outside PyPI.
    expect((await search(q('pkg:npm/q'))).total).toBe(0);
    expect(names(await search(q('pkg:npm/QS')))).toEqual(['QS']);
    const maven = await search(q('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'));
    expect(maven.total).toBe(6);
    expect(new Set(maven.rows.map((r) => r.ecosystem))).toEqual(new Set(['pom', 'maven']));
  });

  it('purl: an OS package matches the distribution family of its version (R7)', async () => {
    const debian = await search(q('pkg:deb/debian/libssl3'));
    expect(debian.rows.map((r) => [r.target.id, r.name, r.version])).toEqual([
      [imageVersion, 'libssl3', LIBSSL.version],
    ]);
    expect((await search(q('pkg:deb/ubuntu/libssl3'))).total).toBe(0);
    expect(
      (await search(q(`pkg:deb/debian/libssl3@${LIBSSL.version}?distro=debian-12`))).total,
    ).toBe(1);
    const rhel = await search(q('pkg:rpm/rhel/bash@4.4.20-5.el8'));
    expect(rhel.rows.map((r) => [r.target.id, r.name, r.distribution])).toEqual([
      [rhelVersion, 'bash', { family: 'redhat', version: '8.4' }],
    ]);
    const epoch = await search(q('pkg:rpm/redhat/x@1-1?epoch=2'));
    expect(epoch.rows.map((r) => [r.version, r.path])).toEqual([['2:1-1', '']]);
    expect((await search(q('pkg:rpm/redhat/x@1-1'))).rows.map((r) => r.version)).toEqual(['1-1']);
    expect((await search(q('pkg:rpm/redhat/x?epoch=0'))).total).toBe(2);
  });

  it('filters: ecosystem is a purl type, version is exact', async () => {
    const pypi = await search(`${q('requests')}&ecosystem=pypi`);
    expect(pypi.rows.map((r) => [r.ecosystem, r.version]).sort()).toEqual([
      ['pip', '2.30.0'],
      ['pip', '2.31.0'],
      ['poetry', '2.31.0'],
    ]);
    const narrowed = await search(`${q('requests')}&ecosystem=pypi&version=2.30.0`);
    expect(narrowed.rows.map((r) => r.path)).toEqual(['legacy/requirements.txt']);
    expect((await search(`${q('requests')}&ecosystem=npm`)).total).toBe(0);
    expect((await search(`${q('log4j')}&ecosystem=maven`)).total).toBe(8);
    expect((await search(`${q('log4j')}&version=2.17.1`)).total).toBe(1);
    expect((await search(`${q('pkg:pypi/requests')}&version=2.30.0`)).total).toBe(1);
  });

  it('merge requests are not searched (R8)', async () => {
    expect((await search(q('mr-only'))).total).toBe(0);
    const all = await search(q('log4j'));
    expect(all.rows.every((r) => r.target.name !== '7')).toBe(true);
  });

  it('vulnerabilities: open rows by the exact match key, null when unchecked', async () => {
    const one = async (query: string) => {
      const answer = await search(query);
      expect(answer.rows).toHaveLength(1);
      return answer.rows[0]!;
    };
    expect((await one(q('lodash'))).vulnerabilities).toBe(1);
    expect((await one(q('minimist'))).vulnerabilities).toBe(0);
    expect((await one(q('ignored-pkg'))).vulnerabilities).toBe(0);
    // The version has a check row, but no distribution: its deb package is not checked.
    expect((await one(q('libfoo'))).vulnerabilities).toBeNull();
    // The libssl3 row under its full key counts, the one under an older key form does not.
    expect((await one(q('libssl3'))).vulnerabilities).toBe(1);
    const log4j = await search(`${q('log4j-core')}&version=2.14.1`);
    const byTarget = new Map(log4j.rows.map((r) => [`${r.project.key} ${r.target.name}`, r]));
    expect(byTarget.get('a1 main')?.vulnerabilities).toBe(0);
    expect(byTarget.get('a1 image-1')?.vulnerabilities).toBe(0);
    // No re-check result for the feature branch, the tag version or b1.
    expect(byTarget.get('a1 feature/x')?.vulnerabilities).toBeNull();
    expect(byTarget.get('a1 1.0.0')?.vulnerabilities).toBeNull();
    expect(byTarget.get('b1 main')?.vulnerabilities).toBeNull();
  });

  describe('R22: null, not 0, where the count would be stale', () => {
    /** Only this project's rows hold the package. */
    const PACKAGE = 'r22-only';
    let project: string;
    let main: string;
    let mainAnalysis: string;
    let release: string;

    /** The package's count on each target of the project, by target name. */
    const counts = async () => {
      const rows = (await search(q(PACKAGE))).rows;
      return Object.fromEntries(rows.map((r) => [r.target.name, r.vulnerabilities]));
    };

    beforeAll(async () => {
      const org = await organizationId(ctx, 'default');
      project = (await createProject(ctx, admin, { organizationId: org, key: 'r22', name: 'R22' }))
        .id;
      main = await mainBranchId(ctx.db, project);
      mainAnalysis = await branchPackages(project, main, [{ name: PACKAGE }]);
      await ctx.db
        .update(branches)
        .set({ lastAnalysisId: mainAnalysis })
        .where(eq(branches.id, main));
      release = await version(project, '2.0.0', { source: 'tag' }, [{ name: PACKAGE }]);
      const baselineAt = new Date(Date.UTC(2026, 10, 2));
      await seedCheck(ctx.db, {
        projectId: project,
        branchId: main,
        baselineAt,
        basis: mainAnalysis,
      });
      await seedCheck(ctx.db, {
        projectId: project,
        versionId: release,
        baselineAt,
        basis: VERSION_BASIS,
      });
      for (const target of [{ branchId: main }, { versionId: release }]) {
        await seedTargetRow(ctx.db, {
          projectId: project,
          ...target,
          packageName: PACKAGE,
          vulnerabilityId: 'CVE-2026-0022',
        });
      }
    });

    it('counts a tracked target checked against its current basis', async () => {
      expect(await counts()).toEqual({ main: 1, '2.0.0': 1 });
    });

    it('null for a branch analysed again and a version uploaded again since their check', async () => {
      const newer = first(
        await ctx.db
          .insert(analyses)
          .values({ projectId: project, branchId: main, status: 'queued' })
          .returning({ id: analyses.id }),
      ).id;
      await ctx.db.update(branches).set({ lastAnalysisId: newer }).where(eq(branches.id, main));
      await ctx.db
        .update(projectVersions)
        .set({ analyzedAt: new Date(Date.UTC(2026, 10, 3)) })
        .where(eq(projectVersions.id, release));
      try {
        expect(await counts()).toEqual({ main: null, '2.0.0': null });
      } finally {
        await ctx.db
          .update(branches)
          .set({ lastAnalysisId: mainAnalysis })
          .where(eq(branches.id, main));
        await ctx.db
          .update(projectVersions)
          .set({ analyzedAt: new Date(VERSION_BASIS) })
          .where(eq(projectVersions.id, release));
      }
      expect(await counts()).toEqual({ main: 1, '2.0.0': 1 });
    });

    it("null while the project's monitoring is off", async () => {
      await ctx.db
        .insert(projectVulnerabilitySettings)
        .values({ projectId: project, enabled: false });
      try {
        expect(await counts()).toEqual({ main: null, '2.0.0': null });
      } finally {
        await ctx.db
          .delete(projectVulnerabilitySettings)
          .where(eq(projectVulnerabilitySettings.projectId, project));
      }
    });

    it('null while the instance switch is off', async () => {
      await writeVulndbSettings(ctx.db, { enabled: false }, ctx.config.secretKey);
      try {
        expect(await counts()).toEqual({ main: null, '2.0.0': null });
        // Every project's rows, not only this one's.
        expect((await search(q('lodash'))).rows[0]?.vulnerabilities).toBeNull();
      } finally {
        await writeVulndbSettings(ctx.db, { enabled: true }, ctx.config.secretKey);
      }
      expect(await counts()).toEqual({ main: 1, '2.0.0': 1 });
    });

    it('null for a version that is not tracked now: its rows are from when it was', async () => {
      await ctx.db
        .update(projectVersions)
        .set({ tracking: 'unsupported' })
        .where(eq(projectVersions.id, release));
      try {
        expect(await counts()).toEqual({ main: 1, '2.0.0': null });
      } finally {
        await ctx.db
          .update(projectVersions)
          .set({ tracking: 'auto' })
          .where(eq(projectVersions.id, release));
      }
    });

    it('null for a branch that no longer matches the tracked patterns', async () => {
      const other = first(
        await ctx.db
          .insert(branches)
          .values({ projectId: project, kind: 'branch', name: 'release/9' })
          .returning({ id: branches.id }),
      ).id;
      const analysis = await branchPackages(project, other, [{ name: PACKAGE }]);
      await ctx.db.update(branches).set({ lastAnalysisId: analysis }).where(eq(branches.id, other));
      await seedCheck(ctx.db, {
        projectId: project,
        branchId: other,
        baselineAt: new Date(Date.UTC(2026, 10, 2)),
        basis: analysis,
      });
      await ctx.db
        .insert(projectVulnerabilitySettings)
        .values({ projectId: project, branchPatterns: ['release/*'] });
      try {
        expect(await counts()).toEqual({ main: 1, 'release/9': 0, '2.0.0': 1 });
        await ctx.db
          .update(projectVulnerabilitySettings)
          .set({ branchPatterns: [] })
          .where(eq(projectVulnerabilitySettings.projectId, project));
        expect(await counts()).toEqual({ main: 1, 'release/9': null, '2.0.0': 1 });
      } finally {
        await ctx.db
          .delete(projectVulnerabilitySettings)
          .where(eq(projectVulnerabilitySettings.projectId, project));
      }
    });
  });

  it('distribution is set on SBOM version rows and null on branch rows', async () => {
    const answer = await search(q('log4j-core'));
    for (const row of answer.rows) {
      expect(row.distribution, `${row.target.name}`).toEqual(
        row.target.id === imageVersion ? { family: 'debian', version: '12.15' } : null,
      );
    }
    expect((await search(q('libfoo'))).rows[0]!.distribution).toBeNull();
  });

  it('names a version taken from a branch label as label (R24)', async () => {
    const org = await organizationId(ctx, 'default');
    const p = (await createProject(ctx, admin, { organizationId: org, key: 'labelled' })).id;
    const labelled = await version(p, '3.1.0', { source: 'label' }, [{ name: 'label-only-pkg' }]);
    const [row] = (await search(q('label-only-pkg'))).rows;
    expect(row?.target).toMatchObject({ kind: 'version', id: labelled, source: 'label' });
  });

  it('names the source of a version row: sbom, tag, or null on a branch', async () => {
    const rows = (await search(q('log4j-core'))).rows;
    for (const row of rows) {
      const expected =
        row.target.kind === 'branch' ? null : row.target.id === tagVersion ? 'tag' : 'sbom';
      expect(row.target.source, row.target.name).toBe(expected);
    }
    expect(rows.some((r) => r.target.id === imageVersion && r.target.source === 'sbom')).toBe(true);
  });

  it('paging and the cap: 100 pages of 100 reach exactly 10 000', async () => {
    for (const bad of ['pageSize=101', 'page=101', 'page=0', 'pageSize=0']) {
      const res = await get(`${q('log4j')}&${bad}`);
      expect([bad, res.statusCode, res.json().code]).toEqual([bad, 422, 'VALIDATION_FAILED']);
    }
    const analysisId = await branchPackages(b1, mainB, [{ name: 'seed-only' }]);
    await ctx.db.execute(sql`
      INSERT INTO branch_dependencies (branch_id, path, ecosystem, name, version, licenses, analysis_id)
      SELECT ${mainB}, 'lib/' || g || '/package-lock.json', 'npm', 'capped-pkg', '1.0.0', '{}', ${analysisId}
        FROM generate_series(1, 10001) AS g`);
    const capped = await search(q('capped-pkg'));
    expect(capped).toMatchObject({ page: 1, pageSize: 50, total: 10_000, totalCapped: true });
    expect(capped.rows).toHaveLength(50);
    const last = await search(`${q('capped-pkg')}&page=100&pageSize=100`);
    expect(last.rows).toHaveLength(100);
    expect(last).toMatchObject({ total: 10_000, totalCapped: true });
  });

  it('422 for an empty, too long or unparsable q', async () => {
    const refused = async (query: string) => {
      const res = await get(query);
      expect([query, res.statusCode, res.json().code]).toEqual([query, 422, 'VALIDATION_FAILED']);
      return (res.json() as { errors: { path: string }[] }).errors.map((e) => e.path);
    };
    expect(await refused('q=')).toEqual(['query.q']);
    expect(await refused(q('   '))).toEqual(['query.q']);
    expect(await refused('ecosystem=npm')).toEqual(['query.q']);
    expect(await refused(q('x'.repeat(301)))).toEqual(['query.q']);
    expect(await refused(q('pkg:npm/'))).toEqual(['query.q']);
    expect(await refused(q('pkg:rpm/redhat/x@1-1?epoch=two'))).toEqual(['query.q']);
    expect(await refused(q('pkg:deb/debian/x@1?epoch=1a'))).toEqual(['query.q']);
    expect(await refused(`${q('qs')}&ecosystem=NPM`)).toEqual(['query.ecosystem']);
    expect((await search(q('x'.repeat(300)))).total).toBe(0);
  });
});

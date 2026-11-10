import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { validateAgainst } from '../../test/export-schemas';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { seedTargetRow } from '../../test/vulnerabilities';
import {
  analyses,
  branchDependencies,
  branches,
  organizations,
  projectVersions,
  projectVulnerabilitySettings,
  versionDependencies,
  vulnerabilityDecisions,
} from '../db/schema';
import { fixedEdition } from '../license/edition';
import { communityLimits } from '../limits';

const licensed = () =>
  fixedEdition({
    ...communityLimits(),
    vulnerabilities: { priority: false, alerts: false, sbom: true },
  });

interface Seeded {
  id: string;
  key: string;
  token: string;
  main: string;
  release: string;
  mr: string;
  version: string;
  empty: string;
}

/** `GET /api/v0<path>` with `headers`. */
const getWith = (h: IngestHarness, path: string, headers: Record<string, string>) =>
  h.ctx.app.inject({ method: 'GET', url: `/api/v0${path}`, headers });

/** A project with an inventory on main, release/2.x and version 2.3.4+build.1. */
async function seed(h: IngestHarness, key: string): Promise<Seeded> {
  const p = await h.project(key);
  const db = h.ctx.db;
  const [mainRow] = await db
    .select({ id: branches.id })
    .from(branches)
    .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
  const branch = async (name: string, kind: 'branch' | 'merge_request' = 'branch') =>
    (await db.insert(branches).values({ projectId: p.id, kind, name }).returning())[0]!.id;
  const release = await branch('release/2.x');
  const mr = await branch('feature-mr', 'merge_request');
  const empty = await branch('no-inventory');
  const version = (
    await db
      .insert(projectVersions)
      .values({
        projectId: p.id,
        label: '2.3.4+build.1',
        source: 'tag',
        tag: '2.3.4+build.1',
        analyzedAt: new Date('2026-10-01T00:00:00Z'),
        hasInventory: true,
      })
      .returning()
  )[0]!.id;
  const analysis = (
    await db
      .insert(analyses)
      .values({ projectId: p.id, branchId: mainRow!.id, status: 'queued' })
      .returning()
  )[0]!.id;
  const row = (
    path: string,
    ecosystem: string,
    name: string,
    v: string,
    licenses: string[] = ['MIT'],
  ) => ({ path, ecosystem, name, version: v, licenses });
  const rows = [
    row('package.json', 'npm', 'lodash', '4.17.21'),
    // The same package in a second lockfile.
    row('web/package.json', 'npm', 'lodash', '4.17.21'),
    row('package.json', 'npm', 'a-pkg', '1.0.0', ['Apache-2.0']),
    row('Dockerfile', 'dockerfile', 'base-image', '1', []),
  ];
  await db
    .insert(branchDependencies)
    .values(rows.map((r) => ({ ...r, branchId: mainRow!.id, analysisId: analysis })));
  await db.insert(branchDependencies).values([
    {
      ...row('package.json', 'npm', 'only-release', '2.0.0'),
      branchId: release,
      analysisId: analysis,
    },
  ]);
  await db
    .insert(branchDependencies)
    .values([
      { ...row('package.json', 'npm', 'in-mr', '1.0.0'), branchId: mr, analysisId: analysis },
    ]);
  await db
    .insert(versionDependencies)
    .values([{ ...row('package.json', 'npm', 'only-version', '3.0.0'), versionId: version }]);
  await db
    .insert(projectVulnerabilitySettings)
    .values({ projectId: p.id, branchPatterns: ['release/*'] });
  return { id: p.id, key, token: p.token, main: mainRow!.id, release, mr, version, empty };
}

const SUFFIXES: Record<string, string> = {
  'sbom/cyclonedx': '.cdx.json',
  'sbom/spdx': '.spdx.json',
  'vex/cyclonedx': '.vex.cdx.json',
  'vex/openvex': '.openvex.json',
};
const suffix = (format: string, kind: 'sbom' | 'vex'): string => SUFFIXES[`${kind}/${format}`]!;

describe('the SBOM and VEX export routes (4c)', () => {
  let h: IngestHarness;
  let viewer: Session;
  let outsider: Session;
  let other: Session;
  let n = 0;

  beforeAll(async () => {
    h = await createIngestHarness({ edition: licensed() });
    const member = await createUser(h.ctx, { username: 'exp-viewer' });
    await addMember(h.ctx, h.organizationId, member.id, 'viewer');
    viewer = await login(h.ctx, member.username, member.password);
    const stranger = await createUser(h.ctx, { username: 'exp-stranger' });
    outsider = await login(h.ctx, stranger.username, stranger.password);
    // A viewer of another organisation.
    const [beta] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'exp-beta', name: 'Beta' })
      .returning();
    const foreign = await createUser(h.ctx, { username: 'exp-foreign' });
    await addMember(h.ctx, beta!.id, foreign.id, 'viewer');
    other = await login(h.ctx, foreign.username, foreign.password);
  });
  afterAll(async () => {
    await h.close();
  });

  const sbom = (query: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    getWith(h, `/projects/sbom?${query}`, headers);
  const vex = (query: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    getWith(h, `/projects/vex?${query}`, headers);
  const fresh = () => seed(h, `acme/exp-${++n}`);
  const personal = async (scopes: string[]): Promise<Record<string, string>> => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: h.orgAdmin.headers,
      payload: { name: `t${++n}`, scopes },
    });
    return bearer((res.json() as { token: string }).token);
  };

  describe('access', () => {
    it('lets a session with project.read download both, and hides the project from outsiders', async () => {
      const p = await fresh();
      for (const route of [sbom, vex]) {
        expect((await route(`projectKey=${p.key}`, viewer.headers)).statusCode).toBe(200);
        for (const session of [outsider, other]) {
          const res = await route(`projectKey=${p.key}`, session.headers);
          expect(res.statusCode).toBe(404);
          expect(res.json().code).toBe('PROJECT_NOT_FOUND');
        }
        const unknown = await route('projectKey=acme/none', outsider.headers);
        expect(unknown.statusCode).toBe(404);
        expect(unknown.json().code).toBe('PROJECT_NOT_FOUND');
      }
    });

    it('asks a personal token for the read scope', async () => {
      const p = await fresh();
      for (const route of [sbom, vex]) {
        expect((await route(`projectKey=${p.key}`, await personal(['read']))).statusCode).toBe(200);
        const denied = await route(`projectKey=${p.key}`, await personal(['analysis:write']));
        expect(denied.statusCode).toBe(403);
        expect(denied.json().code).toBe('INSUFFICIENT_SCOPE');
      }
    });

    it('lets a project token read its own project only', async () => {
      const p = await fresh();
      const q = await fresh();
      for (const route of [sbom, vex]) {
        expect((await route(`projectKey=${p.key}`, bearer(p.token))).statusCode).toBe(200);
        const denied = await route(`projectKey=${q.key}`, bearer(p.token));
        expect(denied.statusCode).toBe(404);
        expect(denied.json().code).toBe('PROJECT_NOT_FOUND');
      }
      // Nothing else opens up.
      const list = await getWith(h, `/projects/${p.id}/vulnerabilities`, bearer(p.token));
      expect(list.statusCode).toBe(403);
      expect(list.json().code).toBe('TOKEN_NOT_ALLOWED');
    });

    it('answers 401 without credentials', async () => {
      const p = await fresh();
      expect((await sbom(`projectKey=${p.key}`, {})).statusCode).toBe(401);
    });
  });

  describe('targets', () => {
    it('defaults to the main branch and takes a branch or a version', async () => {
      const p = await fresh();
      const names = async (query: string) =>
        ((await sbom(`projectKey=${p.key}&${query}`)).json().components as { name: string }[])
          .map((c) => c.name)
          .sort();
      const main = await sbom(`projectKey=${p.key}`);
      expect(main.json().metadata.component.version).toBe('main');
      expect(await names('')).toEqual(['a-pkg', 'base-image', 'lodash']);
      expect(await names('branch=release%2F2.x')).toEqual(['only-release']);
      expect(await names('version=2.3.4%2Bbuild.1')).toEqual(['only-version']);
    });

    it('refuses both targets, an unknown name, a merge request and a target without inventory', async () => {
      const p = await fresh();
      const both = await sbom(`projectKey=${p.key}&branch=main&version=2.3.4%2Bbuild.1`);
      expect(both.statusCode).toBe(422);
      expect(both.json().code).toBe('VALIDATION_FAILED');
      for (const query of ['branch=nope', 'version=9.9.9', 'branch=feature-mr']) {
        const res = await sbom(`projectKey=${p.key}&${query}`);
        expect(res.statusCode, query).toBe(404);
        expect(res.json().code).toBe('NOT_FOUND');
        expect((await vex(`projectKey=${p.key}&${query}`)).statusCode, query).toBe(404);
      }
      const none = await sbom(`projectKey=${p.key}&branch=no-inventory`);
      expect(none.statusCode).toBe(404);
      expect(none.json()).toMatchObject({
        code: 'NOT_FOUND',
        title: 'This branch has no dependency inventory yet',
      });
    });

    it('answers a 422 for the target only after the access checks', async () => {
      const p = await fresh();
      const both = `projectKey=${p.key}&branch=main&version=1`;
      expect((await sbom(both, outsider.headers)).statusCode).toBe(404);
    });

    it('turns the VEX off with monitoring, and keeps the SBOM', async () => {
      const p = await fresh();
      await h.ctx.db
        .update(projectVulnerabilitySettings)
        .set({ enabled: false })
        .where(eq(projectVulnerabilitySettings.projectId, p.id));
      const res = await vex(`projectKey=${p.key}`);
      expect(res.statusCode).toBe(404);
      expect(res.json()).toMatchObject({
        code: 'NOT_FOUND',
        title: 'Vulnerability monitoring is off for this project',
      });
      expect((await sbom(`projectKey=${p.key}`)).statusCode).toBe(200);
    });

    it('answers an empty VEX for a target without findings', async () => {
      const p = await fresh();
      const cdx = await vex(`projectKey=${p.key}`);
      expect(cdx.statusCode).toBe(200);
      expect(cdx.json().vulnerabilities).toEqual([]);
      expect(validateAgainst('cyclonedx', cdx.json())).toEqual([]);
      const open = await vex(`projectKey=${p.key}&format=openvex`);
      expect(open.statusCode).toBe(200);
      expect(open.json().statements).toEqual([]);
    });

    it('rejects an unknown format or query key', async () => {
      const p = await fresh();
      expect((await sbom(`projectKey=${p.key}&format=openvex`)).statusCode).toBe(422);
      expect((await vex(`projectKey=${p.key}&format=spdx`)).statusCode).toBe(422);
      expect((await sbom(`projectKey=${p.key}&extra=1`)).statusCode).toBe(422);
      expect((await sbom('')).statusCode).toBe(422);
    });
  });

  describe('headers', () => {
    it('sets the content type, no-store and the attachment name per format', async () => {
      const p = await fresh();
      const safe = p.key.replace(/[^A-Za-z0-9._-]/g, '-');
      const cases = [
        [sbom, 'cyclonedx', 'application/vnd.cyclonedx+json; version=1.6', 'sbom'],
        [sbom, 'spdx', 'application/spdx+json', 'sbom'],
        [vex, 'cyclonedx', 'application/vnd.cyclonedx+json; version=1.6', 'vex'],
        [vex, 'openvex', 'application/json', 'vex'],
      ] as const;
      for (const [route, format, type, kind] of cases) {
        const res = await route(`projectKey=${p.key}&format=${format}&branch=release%2F2.x`);
        expect(res.statusCode, `${kind}/${format}`).toBe(200);
        expect(res.headers['content-type']).toBe(type);
        expect(res.headers['cache-control']).toBe('no-store');
        expect(res.headers['content-disposition']).toBe(
          `attachment; filename="${safe}-release-2.x${suffix(format, kind)}"`,
        );
      }
      const byDefault = await sbom(`projectKey=${p.key}`);
      expect(byDefault.headers['content-type']).toBe('application/vnd.cyclonedx+json; version=1.6');
      const vexDefault = await vex(`projectKey=${p.key}&version=2.3.4%2Bbuild.1`);
      expect(vexDefault.headers['content-disposition']).toBe(
        `attachment; filename="${safe}-2.3.4-build.1.vex.cdx.json"`,
      );
    });
  });

  describe('content', () => {
    it('lists a package once and a package without a purl, in a valid SBOM of each format', async () => {
      const p = await fresh();
      // npm and yarn share a purl type: the same package, found by two ecosystems.
      const [known] = await h.ctx.db
        .select({ analysisId: branchDependencies.analysisId })
        .from(branchDependencies)
        .where(eq(branchDependencies.branchId, p.main));
      await h.ctx.db.insert(branchDependencies).values({
        branchId: p.main,
        path: 'yarn.lock',
        ecosystem: 'yarn',
        name: 'lodash',
        version: '4.17.21',
        licenses: ['MIT'],
        analysisId: known!.analysisId,
      });
      const cdx = (await sbom(`projectKey=${p.key}`)).json();
      expect(validateAgainst('cyclonedx', cdx)).toEqual([]);
      const comps = cdx.components as { name: string; purl?: string }[];
      expect(comps.map((c) => c.name)).toEqual(['a-pkg', 'base-image', 'lodash']);
      expect(comps.find((c) => c.name === 'base-image')?.purl).toBeUndefined();
      const spdx = (await sbom(`projectKey=${p.key}&format=spdx`)).json();
      expect(validateAgainst('spdx', spdx)).toEqual([]);
      const named = (spdx.packages as { name: string }[]).filter((x) => x.name === 'lodash');
      expect(named).toHaveLength(1);
    });

    it('names the organisation of the project as the author of the OpenVEX', async () => {
      const p = await fresh();
      const [org] = await h.ctx.db
        .select({ name: organizations.name })
        .from(organizations)
        .where(eq(organizations.id, h.organizationId));
      const open = (await vex(`projectKey=${p.key}&format=openvex`)).json();
      expect(open.author).toBe(org!.name);
    });

    it('has one entry per vulnerability and package, leaves out ignored rows, and validates', async () => {
      const p = await fresh();
      const row = (
        packageName: string,
        packageVersion: string,
        vulnerabilityId: string,
        ignored = false,
      ) =>
        seedTargetRow(h.ctx.db, {
          projectId: p.id,
          branchId: p.main,
          packageName,
          packageVersion,
          vulnerabilityId,
          ignored,
        });
      await row('lodash', '4.17.20', 'CVE-2026-0001');
      await row('lodash', '4.17.21', 'CVE-2026-0001');
      await row('a-pkg', '1.0.0', 'CVE-2026-0002', true);
      await row('a-pkg', '1.0.0', 'CVE-2026-0003');
      const cdx = (await vex(`projectKey=${p.key}`)).json();
      expect(validateAgainst('cyclonedx', cdx)).toEqual([]);
      const vulns = cdx.vulnerabilities as { id: string; affects: { ref: string }[] }[];
      expect(vulns.map((v) => v.id).sort()).toEqual(['CVE-2026-0001', 'CVE-2026-0003']);
      const lodash = vulns.find((v) => v.id === 'CVE-2026-0001')!;
      expect(lodash.affects.map((a) => a.ref)).toEqual([
        'pkg:npm/lodash@4.17.20',
        'pkg:npm/lodash@4.17.21',
      ]);
      const open = (await vex(`projectKey=${p.key}&format=openvex`)).json();
      expect(validateAgainst('openvex', open)).toEqual([]);
      expect(open.statements).toHaveLength(2);
    });

    it('prefers a version decision to the project-wide one on that version only', async () => {
      const p = await fresh();
      await seedTargetRow(h.ctx.db, {
        projectId: p.id,
        branchId: p.main,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-2026-0100',
      });
      await seedTargetRow(h.ctx.db, {
        projectId: p.id,
        versionId: p.version,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-2026-0100',
      });
      await h.ctx.db.insert(vulnerabilityDecisions).values([
        {
          projectId: p.id,
          packageName: 'lodash',
          vulnerabilityId: 'CVE-2026-0100',
          status: 'wont_fix',
          comment: 'project-wide',
        },
        {
          projectId: p.id,
          versionId: p.version,
          packageName: 'lodash',
          vulnerabilityId: 'CVE-2026-0100',
          status: 'false_positive',
          reason: 'component_not_present',
          comment: 'not in this version',
        },
      ]);
      const status = async (query: string) =>
        (
          (await vex(`projectKey=${p.key}&format=openvex&${query}`)).json().statements as {
            status: string;
          }[]
        ).map((s) => s.status);
      expect(await status('version=2.3.4%2Bbuild.1')).toEqual(['not_affected']);
      expect(await status('branch=main')).toEqual(['affected']);
    });
  });
});

describe('the export routes without the sbom feature', () => {
  let h: IngestHarness;
  let outsider: Session;
  beforeAll(async () => {
    h = await createIngestHarness();
    const stranger = await createUser(h.ctx, { username: 'nofeat-stranger' });
    outsider = await login(h.ctx, stranger.username, stranger.password);
  });
  afterAll(async () => {
    await h.close();
  });

  it('answers 403 FEATURE_NOT_LICENSED where it would be 200, and keeps every 404', async () => {
    const p = await seed(h, 'acme/nofeat-1');
    for (const path of ['sbom', 'vex']) {
      const refused = await getWith(h, `/projects/${path}?projectKey=${p.key}`, h.orgAdmin.headers);
      expect(refused.statusCode).toBe(403);
      expect(refused.json()).toMatchObject({
        code: 'FEATURE_NOT_LICENSED',
        title: 'The enterprise feature "sbom" is not licensed',
      });
      const project = await getWith(h, `/projects/${path}?projectKey=${p.key}`, bearer(p.token));
      expect(project.statusCode).toBe(403);
      expect(project.json().code).toBe('FEATURE_NOT_LICENSED');
      // The target is checked after the feature: an unknown branch is 403 too.
      const unknownBranch = await getWith(
        h,
        `/projects/${path}?projectKey=${p.key}&branch=nope`,
        h.orgAdmin.headers,
      );
      expect(unknownBranch.statusCode).toBe(403);
      for (const key of [p.key, 'acme/none']) {
        const hidden = await getWith(h, `/projects/${path}?projectKey=${key}`, outsider.headers);
        expect(hidden.statusCode).toBe(404);
        expect(hidden.json().code).toBe('PROJECT_NOT_FOUND');
      }
      const otherProject = await getWith(
        h,
        `/projects/${path}?projectKey=acme/none`,
        bearer(p.token),
      );
      expect(otherProject.statusCode).toBe(404);
    }
  });

  it('reports sbom false in the targets summary', async () => {
    const p = await seed(h, 'acme/nofeat-2');
    const res = await getWith(h, `/projects/${p.id}/vulnerabilities/targets`, h.orgAdmin.headers);
    expect(res.json().sbom).toBe(false);
  });
});

describe('the targets summary with the sbom feature', () => {
  let h: IngestHarness;
  beforeAll(async () => {
    h = await createIngestHarness({ edition: licensed() });
  });
  afterAll(async () => {
    await h.close();
  });

  it('reports sbom true', async () => {
    const p = await h.project('acme/feat-1');
    const res = await getWith(h, `/projects/${p.id}/vulnerabilities/targets`, h.orgAdmin.headers);
    expect(res.json().sbom).toBe(true);
  });
});

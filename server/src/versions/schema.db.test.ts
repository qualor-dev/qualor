import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, sqlStateOf, type TestDatabase } from '../../test/db';
import { PG_CHECK_VIOLATION } from '../db/errors';
import {
  analyses,
  organizations,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  versionDependencies,
} from '../db/schema';

/** drizzle wraps the driver error, so match the whole `cause` chain. */
async function expectRejection(action: PromiseLike<unknown>, pattern: RegExp): Promise<void> {
  const error: unknown = await Promise.resolve(action).then(
    () => null,
    (err: unknown) => err,
  );
  expect(error, 'expected the query to be rejected').not.toBeNull();
  const messages: string[] = [];
  let current: unknown = error;
  for (let depth = 0; depth < 5 && typeof current === 'object' && current !== null; depth++) {
    const message = (current as { message?: unknown }).message;
    if (typeof message === 'string') messages.push(message);
    current = (current as { cause?: unknown }).cause;
  }
  expect(messages.join('\n')).toMatch(pattern);
}

const REVISION = 'a'.repeat(40);

describe('migration 0020_versions', () => {
  let t: TestDatabase;
  let orgId: string;
  beforeAll(async () => {
    t = await createTestDatabase();
    const [org] = await t.db
      .insert(organizations)
      .values({ key: 'acme', name: 'Acme' })
      .returning();
    orgId = org!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  async function newProject(key: string): Promise<string> {
    const [project] = await t.db
      .insert(projects)
      .values({ organizationId: orgId, key, name: key })
      .returning();
    return project!.id;
  }

  async function newVersion(projectId: string, label: string) {
    const [version] = await t.db
      .insert(projectVersions)
      .values({ projectId, label, source: 'tag', tag: `v${label}`, analyzedAt: new Date() })
      .returning();
    return version!;
  }

  it('stores a version with its dependencies and defaults tracking to auto', async () => {
    const projectId = await newProject('acme/a');
    const version = await newVersion(projectId, '1.0.0');
    expect(version.tracking).toBe('auto');
    const [analysis] = await t.db.insert(analyses).values({ projectId }).returning();
    await t.db.insert(versionDependencies).values({
      versionId: version.id,
      path: 'package.json',
      ecosystem: 'npm',
      name: 'left-pad',
      version: '1.3.0',
      licenses: ['MIT'],
      direct: true,
      line: 4,
      analysisId: analysis!.id,
    });
    const rows = await t.db
      .select()
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, version.id));
    expect(rows).toHaveLength(1);
  });

  it('rejects a duplicate label in one project but allows it in another', async () => {
    const a = await newProject('acme/dup-a');
    const b = await newProject('acme/dup-b');
    await newVersion(a, '2.0.0');
    await expectRejection(newVersion(a, '2.0.0'), /project_versions_project_label|unique/i);
    await newVersion(b, '2.0.0');
  });

  it('rejects bad source, tracking and label values', async () => {
    const projectId = await newProject('acme/checks');
    const base = { projectId, label: 'x', source: 'tag', analyzedAt: new Date() } as const;
    await expectRejection(
      t.db.insert(projectVersions).values({ ...base, tracking: 'x' as 'auto' }),
      /project_versions_tracking_check/,
    );
    await expectRejection(
      t.db.insert(projectVersions).values({ ...base, source: 'x' as 'tag' }),
      /project_versions_source_check/,
    );
    await expectRejection(
      t.db.insert(projectVersions).values({ ...base, label: '' }),
      /project_versions_label_check/,
    );
    await expectRejection(
      t.db.insert(projectVersions).values({ ...base, label: 'l'.repeat(101) }),
      /project_versions_label_check/,
    );
  });

  it('keeps vulnerability settings per project with defaults and range checks', async () => {
    const projectId = await newProject('acme/settings');
    const [row] = await t.db.insert(projectVulnerabilitySettings).values({ projectId }).returning();
    expect(row).toMatchObject({
      enabled: true,
      branchPatterns: [],
      versionRule: 'lines',
      versionLines: 5,
      labelVersions: false,
    });
    const other = await newProject('acme/settings-2');
    await expectRejection(
      t.db.insert(projectVulnerabilitySettings).values({ projectId: other, versionLines: 21 }),
      /project_vulnerability_settings_lines_check/,
    );
    await expectRejection(
      t.db.insert(projectVulnerabilitySettings).values({ projectId: other, versionLines: 0 }),
      /project_vulnerability_settings_lines_check/,
    );
    await expectRejection(
      t.db
        .insert(projectVulnerabilitySettings)
        .values({ projectId: other, versionRule: 'x' as 'all' }),
      /project_vulnerability_settings_rule_check/,
    );
  });

  it('accepts a succeeded analysis with only a version and rejects a branch plus a version', async () => {
    const projectId = await newProject('acme/analysis');
    const version = await newVersion(projectId, '3.0.0');
    const complete = {
      projectId,
      status: 'succeeded' as const,
      revision: REVISION,
      analysisDate: new Date(),
      baselineStatus: 'first_analysis' as const,
      scannerVersion: '0.15.0',
    };
    const [ok] = await t.db
      .insert(analyses)
      .values({ ...complete, versionId: version.id, dependencyIgnores: [{ id: 'CVE-1' }] })
      .returning();
    expect(ok!.versionId).toBe(version.id);
    // A succeeded analysis with neither a branch nor a version stays invalid.
    await expectRejection(t.db.insert(analyses).values(complete), /analyses_succeeded_is_complete/);
    const branch = await t.pool.query<{ id: string }>(
      `INSERT INTO branches (id, project_id, kind, name) VALUES (gen_random_uuid(), $1, 'branch', 'main') RETURNING id`,
      [projectId],
    );
    await expectRejection(
      t.db
        .insert(analyses)
        .values({ projectId, versionId: version.id, branchId: branch.rows[0]!.id }),
      /analyses_one_target/,
    );
  });

  it('sets version_id and analysis_id to null when the other side is deleted', async () => {
    const projectId = await newProject('acme/setnull');
    const version = await newVersion(projectId, '4.0.0');
    const [analysis] = await t.db
      .insert(analyses)
      .values({ projectId, versionId: version.id })
      .returning();
    await t.db
      .update(projectVersions)
      .set({ analysisId: analysis!.id })
      .where(eq(projectVersions.id, version.id));
    await t.db.delete(projectVersions).where(eq(projectVersions.id, version.id));
    const [after] = await t.db.select().from(analyses).where(eq(analyses.id, analysis!.id));
    expect(after!.versionId).toBeNull();
  });

  it('keeps a version and its packages when their analysis is deleted, and stores ignores', async () => {
    const projectId = await newProject('acme/analysis-gone');
    const version = await newVersion(projectId, '4.1.0');
    const [analysis] = await t.db
      .insert(analyses)
      .values({ projectId, versionId: version.id })
      .returning();
    const ignores = [{ id: 'CVE-2026-9' }];
    await t.db
      .update(projectVersions)
      .set({ analysisId: analysis!.id, dependencyIgnores: ignores })
      .where(eq(projectVersions.id, version.id));
    await t.db.insert(versionDependencies).values({
      versionId: version.id,
      path: 'go.sum',
      ecosystem: 'gomod',
      name: 'golang.org/x/net',
      version: 'v0.30.0',
      licenses: ['BSD-3-Clause'],
      analysisId: analysis!.id,
    });
    await t.db.delete(analyses).where(eq(analyses.id, analysis!.id));
    const deps = await t.db
      .select()
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, version.id));
    expect(deps.map((d) => [d.name, d.analysisId])).toEqual([['golang.org/x/net', null]]);
    const [after] = await t.db
      .select()
      .from(projectVersions)
      .where(eq(projectVersions.id, version.id));
    expect(after).toMatchObject({ analysisId: null, dependencyIgnores: ignores });
  });

  it('cascades a project deletion to versions, dependencies and settings', async () => {
    const projectId = await newProject('acme/cascade');
    const version = await newVersion(projectId, '5.0.0');
    const [analysis] = await t.db.insert(analyses).values({ projectId }).returning();
    await t.db.insert(versionDependencies).values({
      versionId: version.id,
      path: 'pom.xml',
      ecosystem: 'maven',
      name: 'g:a',
      version: '1',
      licenses: [],
      analysisId: analysis!.id,
    });
    await t.db.insert(projectVulnerabilitySettings).values({ projectId });
    await t.db.delete(projects).where(eq(projects.id, projectId));
    const left = await t.db.execute(
      sql`SELECT (SELECT count(*) FROM project_versions WHERE project_id = ${projectId})::int AS v,
                 (SELECT count(*) FROM version_dependencies WHERE version_id = ${version.id})::int AS d,
                 (SELECT count(*) FROM project_vulnerability_settings WHERE project_id = ${projectId})::int AS s`,
    );
    expect(left.rows[0]).toEqual({ v: 0, d: 0, s: 0 });
  });

  it('accepts an SBOM version with its distribution', async () => {
    const projectId = await newProject('acme/sbom');
    const [row] = await t.db
      .insert(projectVersions)
      .values({
        projectId,
        label: 'sbom-1',
        source: 'sbom',
        analysisId: null,
        osFamily: 'debian',
        osVersion: '12.15',
        sbomFormat: 'CycloneDX 1.6',
        sbomSubject: 'registry.example/app:1',
        analyzedAt: new Date(),
      })
      .returning();
    expect(row).toMatchObject({ source: 'sbom', analysisId: null, osFamily: 'debian' });
    await t.db.insert(versionDependencies).values({
      versionId: row!.id,
      path: 'sbom',
      ecosystem: 'deb',
      name: 'libssl3',
      version: '3.0.0',
      licenses: [],
      sourceName: 'openssl',
      sourceVersion: '3.0.0-1',
    });
  });

  it('refuses half a distribution and overlong columns', async () => {
    const projectId = await newProject('acme/sbom-checks');
    const base = { projectId, source: 'sbom', analyzedAt: new Date() } as const;
    let n = 0;
    const version = (extra: Partial<typeof projectVersions.$inferInsert>) =>
      t.db.insert(projectVersions).values({ ...base, label: `c${++n}`, ...extra });
    expect(await sqlStateOf(version({ osFamily: 'debian' }))).toBe(PG_CHECK_VIOLATION);
    expect(await sqlStateOf(version({ osVersion: '12' }))).toBe(PG_CHECK_VIOLATION);
    expect(await sqlStateOf(version({ osFamily: 'd'.repeat(65), osVersion: '1' }))).toBe(
      PG_CHECK_VIOLATION,
    );
    expect(await sqlStateOf(version({ sbomFormat: 'f'.repeat(33) }))).toBe(PG_CHECK_VIOLATION);
    expect(await sqlStateOf(version({ sbomSubject: 's'.repeat(513) }))).toBe(PG_CHECK_VIOLATION);
    const ok = await newVersion(projectId, '9.0.0');
    const dep = (extra: Partial<typeof versionDependencies.$inferInsert>) =>
      t.db.insert(versionDependencies).values({
        versionId: ok.id,
        path: 'sbom',
        ecosystem: 'deb',
        name: 'x',
        version: '1',
        licenses: [],
        ...extra,
      });
    expect(await sqlStateOf(dep({ sourceName: 's'.repeat(513) }))).toBe(PG_CHECK_VIOLATION);
    expect(await sqlStateOf(dep({ sourceVersion: 'v'.repeat(257) }))).toBe(PG_CHECK_VIOLATION);
    // The package arch and the RPM modularity label (Task 9b): at most 64 and 256 characters.
    expect(await sqlStateOf(dep({ arch: 'a'.repeat(65) }))).toBe(PG_CHECK_VIOLATION);
    expect(await sqlStateOf(dep({ modularityLabel: 'l'.repeat(257) }))).toBe(PG_CHECK_VIOLATION);
    await dep({ name: 'at-bounds', arch: 'a'.repeat(64), modularityLabel: 'l'.repeat(256) });
    const [kept] = await t.db
      .select({ arch: versionDependencies.arch, label: versionDependencies.modularityLabel })
      .from(versionDependencies)
      .where(eq(versionDependencies.name, 'at-bounds'));
    expect(kept).toEqual({ arch: 'a'.repeat(64), label: 'l'.repeat(256) });
  });

  it("still refuses source 'other'", async () => {
    const projectId = await newProject('acme/sbom-other');
    expect(
      await sqlStateOf(
        t.db.insert(projectVersions).values({
          projectId,
          label: 'o',
          source: 'other' as 'tag',
          analyzedAt: new Date(),
        }),
      ),
    ).toBe(PG_CHECK_VIOLATION);
  });
});

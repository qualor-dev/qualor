import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import {
  branches,
  matchedPackages,
  organizations,
  projects,
  projectVersions,
  targetVulnerabilities,
  vulndbChunks,
  vulndbDatasets,
  vulnerabilityMatches,
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

const DIGEST = `sha256:${'a'.repeat(64)}`;
const PURL = 'pkg:npm/lodash@4.17.20';

describe('migration 0021_vulndb', () => {
  let t: TestDatabase;
  let orgId: string;
  let n = 0;
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

  async function newProject() {
    const key = `acme/vuln-${++n}`;
    const [project] = await t.db
      .insert(projects)
      .values({ organizationId: orgId, key, name: key })
      .returning();
    const [branch] = await t.db
      .insert(branches)
      .values({ projectId: project!.id, kind: 'branch', name: 'main', isMain: true })
      .returning();
    const [version] = await t.db
      .insert(projectVersions)
      .values({
        projectId: project!.id,
        label: '1.0.0',
        source: 'tag',
        tag: 'v1.0.0',
        analyzedAt: new Date(),
      })
      .returning();
    return { projectId: project!.id, branchId: branch!.id, versionId: version!.id };
  }

  const target = (
    projectId: string,
    extra: Partial<typeof targetVulnerabilities.$inferInsert>,
  ) => ({
    projectId,
    ecosystem: 'npm',
    packageName: 'lodash',
    packageVersion: '4.17.20',
    purl: PURL,
    vulnerabilityId: 'CVE-2021-23337',
    ...extra,
  });

  const dataset = (extra: Partial<typeof vulndbDatasets.$inferInsert> = {}) => ({
    kind: 'trivy' as const,
    digest: DIGEST,
    sizeBytes: 5_000_000_000,
    source: 'official' as const,
    status: 'ready' as const,
    ...extra,
  });

  it('stores a dataset with its chunks and removes the chunks with it', async () => {
    const [row] = await t.db.insert(vulndbDatasets).values(dataset()).returning();
    expect(row).toMatchObject({ chunkCount: 0, builtAt: null, sizeBytes: 5_000_000_000 });
    await t.db.insert(vulndbChunks).values([
      { datasetId: row!.id, seq: 0, data: Buffer.from('abc') },
      { datasetId: row!.id, seq: 1, data: Buffer.from('def') },
    ]);
    const chunks = await t.db
      .select()
      .from(vulndbChunks)
      .where(eq(vulndbChunks.datasetId, row!.id))
      .orderBy(vulndbChunks.seq);
    expect(chunks.map((c) => c.data.toString())).toEqual(['abc', 'def']);
    await expectRejection(
      t.db.insert(vulndbChunks).values({ datasetId: row!.id, seq: 0, data: Buffer.from('x') }),
      /duplicate key|pkey|unique/i,
    );
    await t.db.delete(vulndbDatasets).where(eq(vulndbDatasets.id, row!.id));
    expect(
      await t.db.select().from(vulndbChunks).where(eq(vulndbChunks.datasetId, row!.id)),
    ).toEqual([]);
  });

  it('rejects a bad kind, digest, source and status of a dataset', async () => {
    await expectRejection(
      t.db.insert(vulndbDatasets).values(dataset({ kind: 'x' as 'trivy' })),
      /vulndb_datasets_kind_check/,
    );
    await expectRejection(
      t.db.insert(vulndbDatasets).values(dataset({ digest: 'sha256:abc' })),
      /vulndb_datasets_digest_check/,
    );
    await expectRejection(
      t.db.insert(vulndbDatasets).values(dataset({ source: 'x' as 'mirror' })),
      /vulndb_datasets_source_check/,
    );
    await expectRejection(
      t.db.insert(vulndbDatasets).values(dataset({ status: 'x' as 'ready' })),
      /vulndb_datasets_status_check/,
    );
  });

  it('stores matches per package and vulnerability, and rejects a bad severity', async () => {
    const row = {
      purl: PURL,
      vulnerabilityId: 'CVE-2021-23337',
      severity: 'high' as const,
      title: 'Command injection',
      fixedVersion: '4.17.21',
      primaryUrl: 'https://avd.aquasec.com/nvd/cve-2021-23337',
      publishedAt: new Date('2021-02-15T00:00:00Z'),
    };
    await t.db.insert(vulnerabilityMatches).values(row);
    const [read] = await t.db
      .select()
      .from(vulnerabilityMatches)
      .where(eq(vulnerabilityMatches.purl, PURL));
    expect(read).toEqual(row);
    await expectRejection(
      t.db.insert(vulnerabilityMatches).values(row),
      /duplicate key|pkey|unique/i,
    );
    await expectRejection(
      t.db
        .insert(vulnerabilityMatches)
        .values({ purl: PURL, vulnerabilityId: 'CVE-2', severity: 'severe' as 'high' }),
      /vulnerability_matches_severity_check/,
    );
    await t.db
      .insert(vulnerabilityMatches)
      .values({ purl: PURL, vulnerabilityId: 'CVE-3', severity: 'unknown' });
  });

  it('records which database matched a package', async () => {
    const [row] = await t.db
      .insert(matchedPackages)
      .values({ purl: PURL, datasetDigest: DIGEST })
      .returning();
    expect(row!.matchedAt).toBeInstanceOf(Date);
  });

  it('stores a vulnerability of a branch or of a version, never of both or neither', async () => {
    const p = await newProject();
    const [onBranch] = await t.db
      .insert(targetVulnerabilities)
      .values(target(p.projectId, { branchId: p.branchId }))
      .returning();
    expect(onBranch).toMatchObject({ ignored: false, versionId: null });
    expect(onBranch!.firstSeenAt).toBeInstanceOf(Date);
    await t.db
      .insert(targetVulnerabilities)
      .values(target(p.projectId, { versionId: p.versionId }));
    await expectRejection(
      t.db
        .insert(targetVulnerabilities)
        .values(target(p.projectId, { branchId: p.branchId, versionId: p.versionId })),
      /target_vulnerabilities_one_target/,
    );
    await expectRejection(
      t.db.insert(targetVulnerabilities).values(target(p.projectId, {})),
      /target_vulnerabilities_one_target/,
    );
  });

  it('keeps a vulnerability once per branch and once per version', async () => {
    const p = await newProject();
    await t.db.insert(targetVulnerabilities).values(target(p.projectId, { branchId: p.branchId }));
    await expectRejection(
      t.db.insert(targetVulnerabilities).values(target(p.projectId, { branchId: p.branchId })),
      /target_vulnerabilities_branch_uq/,
    );
    // The same package and vulnerability on a version is another row.
    await t.db
      .insert(targetVulnerabilities)
      .values(target(p.projectId, { versionId: p.versionId }));
    await expectRejection(
      t.db.insert(targetVulnerabilities).values(target(p.projectId, { versionId: p.versionId })),
      /target_vulnerabilities_version_uq/,
    );
  });

  it('deletes the vulnerabilities with their branch, version and project', async () => {
    const count = async (projectId: string) =>
      (
        await t.db
          .select()
          .from(targetVulnerabilities)
          .where(eq(targetVulnerabilities.projectId, projectId))
      ).length;
    const p = await newProject();
    await t.db
      .insert(targetVulnerabilities)
      .values([
        target(p.projectId, { branchId: p.branchId }),
        target(p.projectId, { versionId: p.versionId }),
      ]);
    await t.db.delete(branches).where(eq(branches.id, p.branchId));
    expect(await count(p.projectId)).toBe(1);
    await t.db.delete(projectVersions).where(eq(projectVersions.id, p.versionId));
    expect(await count(p.projectId)).toBe(0);

    const q = await newProject();
    await t.db.insert(targetVulnerabilities).values(target(q.projectId, { branchId: q.branchId }));
    await t.db.delete(projects).where(eq(projects.id, q.projectId));
    expect(await count(q.projectId)).toBe(0);
  });

  it('defaults has_inventory of a version to false', async () => {
    const p = await newProject();
    const [version] = await t.db
      .select({ hasInventory: projectVersions.hasInventory })
      .from(projectVersions)
      .where(eq(projectVersions.id, p.versionId));
    expect(version!.hasInventory).toBe(false);
  });
});

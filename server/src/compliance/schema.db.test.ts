import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, sqlStateOf, type TestDatabase } from '../../test/db';
import { PG_CHECK_VIOLATION, PG_UNIQUE_VIOLATION } from '../db/errors';
import {
  complianceReports,
  branches,
  organizations,
  projectVersions,
  projects,
} from '../db/schema';

describe('compliance_reports (4E-1 §1)', () => {
  let tdb: TestDatabase;
  let org: string;
  let project: string;

  beforeAll(async () => {
    tdb = await createTestDatabase();
    const [o] = await tdb.db
      .insert(organizations)
      .values({ key: 'acme', name: 'Acme' })
      .returning();
    org = o!.id;
    const [p] = await tdb.db
      .insert(projects)
      .values({ organizationId: org, key: 'alpha', name: 'Alpha' })
      .returning();
    project = p!.id;
  });
  afterAll(() => tdb.close());

  const row = (over: Partial<typeof complianceReports.$inferInsert> = {}) => ({
    organizationId: org,
    scope: 'organization' as const,
    createdByName: 'Admin',
    standards: [],
    ...over,
  });

  it('allows one pending report per scope', async () => {
    await tdb.db.insert(complianceReports).values(row());
    expect(await sqlStateOf(tdb.db.insert(complianceReports).values(row()))).toBe(
      PG_UNIQUE_VIOLATION,
    );
    // a project scope of the same organisation is another scope
    await tdb.db.insert(complianceReports).values(row({ scope: 'project', projectId: project }));
    expect(
      await sqlStateOf(
        tdb.db.insert(complianceReports).values(row({ scope: 'project', projectId: project })),
      ),
    ).toBe(PG_UNIQUE_VIOLATION);
  });

  it('allows several finished reports per scope', async () => {
    await tdb.db.execute(sql`UPDATE compliance_reports SET status = 'failed', error = 'x'`);
    await tdb.db.insert(complianceReports).values(row());
    await tdb.db.execute(sql`UPDATE compliance_reports SET status = 'failed', error = 'x'`);
    await tdb.db.insert(complianceReports).values(row());
    const [{ n }] = (await tdb.db.execute(sql`SELECT count(*)::int AS n FROM compliance_reports`))
      .rows as [{ n: number }];
    expect(n).toBe(4);
  });

  it('checks scope against project_id, the status, and what ready needs', async () => {
    expect(
      await sqlStateOf(tdb.db.insert(complianceReports).values(row({ scope: 'project' }))),
    ).toBe(PG_CHECK_VIOLATION);
    expect(
      await sqlStateOf(tdb.db.insert(complianceReports).values(row({ projectId: project }))),
    ).toBe(PG_CHECK_VIOLATION);
    expect(
      await sqlStateOf(tdb.db.insert(complianceReports).values(row({ status: 'ready' }))),
    ).toBe(PG_CHECK_VIOLATION);
    expect(
      await sqlStateOf(
        tdb.db.insert(complianceReports).values(row({ status: 'failed', sha256: 'XYZ' })),
      ),
    ).toBe(PG_CHECK_VIOLATION);
  });

  it('refers to a version, set null when it goes, and refuses two targets', async () => {
    const [v] = await tdb.db
      .insert(projectVersions)
      .values({ projectId: project, label: '1.0', source: 'label', analyzedAt: new Date() })
      .returning({ id: projectVersions.id });
    const [b] = await tdb.db
      .insert(branches)
      .values({ projectId: project, kind: 'branch', name: 'dev' })
      .returning({ id: branches.id });
    await tdb.db.execute(sql`UPDATE compliance_reports SET status = 'failed', error = 'x'`);
    const [r] = await tdb.db
      .insert(complianceReports)
      .values(row({ scope: 'project', projectId: project, versionId: v!.id, status: 'failed' }))
      .returning({ id: complianceReports.id });
    expect(
      await sqlStateOf(
        tdb.db
          .insert(complianceReports)
          .values(row({ scope: 'project', projectId: project, versionId: v!.id, branchId: b!.id })),
      ),
    ).toBe(PG_CHECK_VIOLATION);
    await tdb.db.execute(sql`DELETE FROM project_versions WHERE id = ${v!.id}`);
    const [after] = (
      await tdb.db.execute(sql`SELECT version_id FROM compliance_reports WHERE id = ${r!.id}`)
    ).rows as [{ version_id: string | null }];
    expect(after.version_id).toBeNull();
  });

  it('keeps the SBOM and its hash together', async () => {
    const withSbom = (over: Partial<typeof complianceReports.$inferInsert>) =>
      tdb.db.insert(complianceReports).values(row({ status: 'failed', ...over }));
    expect(await sqlStateOf(withSbom({ sbom: Buffer.from('x') }))).toBe(PG_CHECK_VIOLATION);
    expect(await sqlStateOf(withSbom({ sbomSha256: 'a'.repeat(64) }))).toBe(PG_CHECK_VIOLATION);
    expect(await sqlStateOf(withSbom({ sbom: Buffer.from('x'), sbomSha256: 'XYZ' }))).toBe(
      PG_CHECK_VIOLATION,
    );
    await withSbom({ sbom: Buffer.from('x'), sbomSha256: 'a'.repeat(64) });
  });

  it('is deleted with its project', async () => {
    await tdb.db.execute(sql`DELETE FROM projects WHERE id = ${project}`);
    const [{ n }] = (
      await tdb.db.execute(
        sql`SELECT count(*)::int AS n FROM compliance_reports WHERE project_id IS NOT NULL`,
      )
    ).rows as [{ n: number }];
    expect(n).toBe(0);
  });
});

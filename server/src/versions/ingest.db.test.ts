import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bearer } from '../../test/app';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { reportWith } from '../../test/reports';
import {
  analyses,
  branchDependencies,
  issues,
  measures,
  mailMessages,
  projectVersions,
  versionDependencies,
  webhookDeliveries,
} from '../db/schema';
import { versionLabelOf } from './ingest';

const DEPS = [
  {
    path: 'package-lock.json',
    ecosystem: 'npm',
    name: 'left-pad',
    version: '1.3.0',
    licenses: ['MIT'],
  },
  {
    path: 'package-lock.json',
    ecosystem: 'npm',
    name: 'left-pad',
    version: '1.3.0',
    licenses: ['ISC'],
  },
  { path: 'package-lock.json', ecosystem: 'npm', name: 'zod', version: '4.0.0', licenses: ['MIT'] },
];

describe('tag scans as versions', () => {
  let h: IngestHarness;
  let n = 0;
  const project = (): Promise<IngestProject> => h.project(`acme/ver-${++n}`);
  const analysis = async (id: string) =>
    (await h.ctx.db.select().from(analyses).where(eq(analyses.id, id)))[0]!;
  const read = async (p: IngestProject, id: string) =>
    (
      await h.ctx.app.inject({
        method: 'GET',
        url: `/api/v0/analyses/${id}`,
        headers: bearer(p.token),
      })
    ).json();
  const tagReport = (p: IngestProject, extra: Parameters<typeof reportWith>[0] = {}) =>
    reportWith({
      projectKey: p.key,
      branch: null,
      tag: 'v2.3.4',
      findings: [],
      files: [],
      dependencies: DEPS,
      ...extra,
    });
  const versions = (p: IngestProject) =>
    h.ctx.db.select().from(projectVersions).where(eq(projectVersions.projectId, p.id));

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  it('labels a version with project.version, else the tag', () => {
    const tagged = (version?: string) => reportWith({ branch: null, tag: 'v2.3.4', version });
    expect(versionLabelOf(tagged('2.3.4'))).toBe('2.3.4');
    expect(versionLabelOf(tagged(''))).toBe('v2.3.4');
    expect(versionLabelOf(tagged(' 5.0 '))).toBe('5.0');
    expect(versionLabelOf(tagged())).toBe('1.0.0');
    expect(versionLabelOf(reportWith({ tag: null, version: '' }))).toBeNull();
  });

  it('stores a tag scan as a version and runs no stages', async () => {
    const p = await project();
    const id = await p.ingestOk(tagReport(p, { version: '' }));
    const row = await analysis(id);
    expect(row.status).toBe('succeeded');
    expect(row.gateStatus).toBe('none');
    expect(row.branchId).toBeNull();
    expect(row.finishedAt).not.toBeNull();
    const [version] = await versions(p);
    expect(version).toMatchObject({
      label: 'v2.3.4',
      source: 'tag',
      tag: 'v2.3.4',
      analysisId: id,
    });
    expect(row.versionId).toBe(version!.id);
    expect(row.versionLabel).toBe('v2.3.4');
    const dto = await read(p, id);
    expect(dto.branch).toBeNull();
    expect(dto.version).toEqual({ id: version!.id, label: 'v2.3.4' });
    const stored = await h.ctx.db
      .select()
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, version!.id));
    expect(stored.map((d) => [d.name, d.licenses]).sort()).toEqual([
      ['left-pad', ['ISC', 'MIT']],
      ['zod', ['MIT']],
    ]);
    expect(stored.every((d) => d.analysisId === id)).toBe(true);
    for (const table of [issues, measures, webhookDeliveries, mailMessages, branchDependencies]) {
      expect(await h.ctx.db.select().from(table).limit(1)).toEqual([]);
    }
    const branches = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/projects/${p.id}/branches`,
      headers: h.orgAdmin.headers,
    });
    expect(branches.json().items.map((b: { name: string }) => b.name)).toEqual(['main']);
  });

  it('takes the label from project.version and keeps the tag', async () => {
    const p = await project();
    await p.ingestOk(tagReport(p, { version: '2.3.4' }));
    const [version] = await versions(p);
    expect(version).toMatchObject({ label: '2.3.4', tag: 'v2.3.4', source: 'tag' });
  });

  it('replaces the inventory for a newer analysis of the same label, and fails an older one', async () => {
    const p = await project();
    await p.ingestOk(tagReport(p, { analysisDate: '2026-10-01T10:00:00Z' }));
    const newer = await p.ingestOk(
      tagReport(p, {
        analysisDate: '2026-10-02T10:00:00Z',
        dependencies: [DEPS[2]!],
      }),
    );
    const [version] = await versions(p);
    expect(version!.analysisId).toBe(newer);
    expect(
      (
        await h.ctx.db
          .select()
          .from(versionDependencies)
          .where(eq(versionDependencies.versionId, version!.id))
      ).map((d) => d.name),
    ).toEqual(['zod']);
    const older = await p.ingest(tagReport(p, { analysisDate: '2026-10-01T12:00:00Z' }));
    const row = await analysis(older);
    expect(row.status).toBe('failed');
    expect(row.error?.code).toBe('STALE_ANALYSIS');
    expect((await versions(p))[0]!.analysisId).toBe(newer);
  });

  it('stores a version without an inventory with a warning', async () => {
    const p = await project();
    const id = await p.ingestOk(tagReport(p, { dependencies: undefined }));
    const row = await analysis(id);
    expect(row.warnings.map((w) => w.code)).toContain('VERSION_WITHOUT_INVENTORY');
    const [version] = await versions(p);
    expect(
      await h.ctx.db
        .select()
        .from(versionDependencies)
        .where(eq(versionDependencies.versionId, version!.id)),
    ).toEqual([]);
  });

  it('stores dependencyIgnores for branch and version analyses; null when absent', async () => {
    const p = await project();
    const ignores = [{ id: 'CVE-2026-1' }, { id: 'CVE-2026-2', expiresAt: '2027-01-01' }];
    const v = await p.ingestOk(tagReport(p, { dependencyIgnores: ignores }));
    const b = await p.ingestOk(
      reportWith({ projectKey: p.key, branch: 'main', dependencyIgnores: ignores }),
    );
    const none = await p.ingestOk(reportWith({ projectKey: p.key, branch: 'other' }));
    expect((await analysis(v)).dependencyIgnores).toEqual(ignores);
    expect((await analysis(b)).dependencyIgnores).toEqual(ignores);
    expect((await analysis(none)).dependencyIgnores).toBeNull();
    expect((await analysis(b)).versionId).toBeNull();
    expect((await read(p, b)).version).toBeNull();
  });

  it('leaves the main branch overview and previous version alone', async () => {
    const p = await project();
    await p.ingestOk(reportWith({ projectKey: p.key, branch: 'main', version: '1.0.0' }));
    await p.ingestOk(tagReport(p, { version: '9.9.9' }));
    const [overview] = (
      await h.ctx.app.inject({
        method: 'GET',
        url: `/api/v0/projects/${p.id}/branches`,
        headers: h.orgAdmin.headers,
      })
    ).json().items;
    expect(overview.name).toBe('main');
    const rows = await h.ctx.db.select().from(analyses).where(eq(analyses.projectId, p.id));
    expect(rows.filter((r) => r.branchId !== null)).toHaveLength(1);
  });
});

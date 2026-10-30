import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bearer } from '../../test/app';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { reportWith, sampleReport } from '../../test/reports';
import {
  analyses,
  branches,
  issues,
  measures,
  projects,
  projectVersions,
  versionDependencies,
} from '../db/schema';
import { resolveBaseline } from '../newcode/baseline';
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
    // A finding in a scanned file: the stages, had they run, would measure it and open an issue.
    const { files, findings } = sampleReport();
    const id = await p.ingestOk(tagReport(p, { version: '', files, findings }));
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
    expect(await h.ctx.db.select().from(measures).where(eq(measures.analysisId, id))).toEqual([]);
    expect(await h.ctx.db.select().from(issues).where(eq(issues.projectId, p.id))).toEqual([]);
    const listed = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/projects/${p.id}/branches`,
      headers: h.orgAdmin.headers,
    });
    expect(listed.json().items.map((b: { name: string }) => b.name)).toEqual(['main']);
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

  it('keeps the packages and the analysis of a version when a re-scan carries no inventory', async () => {
    const p = await project();
    const ignores = [{ id: 'CVE-2026-3' }];
    const first = await p.ingestOk(
      tagReport(p, { analysisDate: '2026-10-01T10:00:00Z', dependencyIgnores: ignores }),
    );
    const again = await p.ingestOk(
      tagReport(p, { analysisDate: '2026-10-02T10:00:00Z', dependencies: undefined }),
    );
    const [version] = await versions(p);
    const stored = await h.ctx.db
      .select()
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, version!.id));
    expect(stored.map((d) => [d.name, d.analysisId]).sort()).toEqual([
      ['left-pad', first],
      ['zod', first],
    ]);
    const row = await analysis(again);
    expect(row.versionId).toBe(version!.id);
    expect(row.warnings.map((w) => w.code)).toContain('VERSION_WITHOUT_INVENTORY');
    expect(version).toMatchObject({ analysisId: first, dependencyIgnores: ignores });
    expect(version!.analyzedAt.toISOString()).toBe('2026-10-01T10:00:00.000Z');
  });

  it('fails a tag scan whose label is longer than 100 characters', async () => {
    const p = await project();
    const id = await p.ingest(tagReport(p, { version: '', tag: `v${'1'.repeat(100)}` }));
    const row = await analysis(id);
    expect(row.status).toBe('failed');
    expect(row.error?.code).toBe('VERSION_LABEL_INVALID');
    expect(await versions(p)).toEqual([]);
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
    // The version keeps its own snapshot of the ids, next to its inventory.
    expect((await versions(p))[0]!.dependencyIgnores).toEqual(ignores);
    const other = await project();
    await other.ingestOk(tagReport(other));
    expect((await versions(other))[0]!.dependencyIgnores).toBeNull();
  });

  it('leaves the main branch overview and previous version alone', async () => {
    const p = await project();
    await h.ctx.db
      .update(projects)
      .set({ newCodeDefinition: { type: 'previous_version' } })
      .where(eq(projects.id, p.id));
    const mainAnalysis = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: 'main',
        version: '1.0.0',
        analysisDate: '2026-10-01T10:00:00Z',
      }),
    );
    await p.ingestOk(tagReport(p, { version: '2.0.0', analysisDate: '2026-10-02T10:00:00Z' }));
    const [main] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.isMain, true)));
    expect(main!.lastAnalysisId).toBe(mainAnalysis);
    // previous_version reads the main branch's labels only: the tag scan's 2.0.0 is not one.
    const [row] = await h.ctx.db.select().from(projects).where(eq(projects.id, p.id));
    const latest = await resolveBaseline(h.ctx.db, row!, main!.id, undefined);
    expect(latest.warnings).toEqual(['NEW_CODE_DEFINITION_FALLBACK']);
    const next = await resolveBaseline(h.ctx.db, row!, main!.id, '1.1.0');
    expect(next).toMatchObject({ baseline: { id: mainAnalysis }, warnings: [] });
    const history = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/branches/${main!.id}/analyses`,
      headers: h.orgAdmin.headers,
    });
    expect(history.statusCode).toBe(200);
    expect(history.json().items.map((a: { id: string }) => a.id)).toEqual([mainAnalysis]);
  });
});

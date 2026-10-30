import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { reportWith, type ReportParts } from '../../test/reports';
import {
  branches,
  projectVersions,
  projectVulnerabilitySettings,
  versionDependencies,
} from '../db/schema';

const DEPS = [
  { path: 'package-lock.json', ecosystem: 'npm', name: 'zod', version: '4.0.0', licenses: ['MIT'] },
];
const TAG_DEPS = [
  { path: 'package-lock.json', ecosystem: 'npm', name: 'zod', version: '4.1.0', licenses: ['MIT'] },
];

describe('versions from project.version on branch analyses', () => {
  let h: IngestHarness;
  let n = 0;
  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterAll(async () => {
    await h.close();
  });

  async function project(
    settings: { labelVersions?: boolean; branchPatterns?: string[] } = { labelVersions: true },
  ): Promise<IngestProject> {
    const p = await h.project(`acme/lbl-${++n}`);
    await h.ctx.db.insert(projectVulnerabilitySettings).values({ projectId: p.id, ...settings });
    return p;
  }
  const branchReport = (p: IngestProject, parts: ReportParts = {}) =>
    reportWith({
      projectKey: p.key,
      branch: 'main',
      version: '2.3.4',
      dependencies: DEPS,
      ...parts,
    });
  const versions = (p: IngestProject) =>
    h.ctx.db.select().from(projectVersions).where(eq(projectVersions.projectId, p.id));

  it('creates a label version with the inventory from a tracked branch', async () => {
    const p = await project();
    const id = await p.ingestOk(branchReport(p));
    const [v] = await versions(p);
    expect(v).toMatchObject({ label: '2.3.4', source: 'label', tag: null, analysisId: id });
    const deps = await h.ctx.db
      .select()
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, v!.id));
    expect(deps.map((d) => d.name)).toEqual(['zod']);
  });

  it('records a label that is not a version number, trimmed', async () => {
    const p = await project();
    await p.ingestOk(branchReport(p, { version: ' build-42 ' }));
    expect((await versions(p)).map((v) => v.label)).toEqual(['build-42']);
  });

  it('runs on a branch that matches a pattern', async () => {
    const p = await project({ labelVersions: true, branchPatterns: ['release/*'] });
    await p.ingestOk(branchReport(p, { branch: 'release/2.3' }));
    expect(await versions(p)).toHaveLength(1);
  });

  const cases: [string, ReportParts, boolean, string[]][] = [
    ['a pre-release label', { version: '2.4.0-SNAPSHOT' }, true, []],
    ['an untracked branch', { branch: 'feature/x' }, true, []],
    [
      'a merge request',
      {
        branch: 'feature/x',
        mergeRequest: { id: '7', targetBranch: 'main', sourceBranch: 'feature/x' },
      },
      true,
      ['feature/*'],
    ],
    ['the setting off', {}, false, []],
    ['no inventory', { dependencies: undefined }, true, []],
    ['an empty label', { version: '' }, true, []],
  ];
  it.each(cases)('does nothing for %s', async (_name, parts, labelVersions, branchPatterns) => {
    const p = await project({ labelVersions, branchPatterns });
    await p.ingestOk(branchReport(p, parts));
    expect(await versions(p)).toEqual([]);
  });

  it('never overwrites a tag version of the same label', async () => {
    const p = await project();
    const tagId = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: null,
        tag: 'v2.3.4',
        version: '2.3.4',
        dependencies: [],
        analysisDate: '2026-10-01T10:00:00Z',
      }),
    );
    await p.ingestOk(branchReport(p, { analysisDate: '2026-10-02T10:00:00Z' }));
    const [v] = await versions(p);
    expect(v).toMatchObject({ source: 'tag', tag: 'v2.3.4', analysisId: tagId });
    expect(
      await h.ctx.db
        .select()
        .from(versionDependencies)
        .where(eq(versionDependencies.versionId, v!.id)),
    ).toEqual([]);
  });

  it('leaves a newer version alone and does not fail the branch analysis', async () => {
    const p = await project({ labelVersions: true, branchPatterns: ['release/*'] });
    await p.ingestOk(
      branchReport(p, { analysisDate: '2026-10-03T10:00:00Z', revision: 'c'.repeat(40) }),
    );
    const [before] = await versions(p);
    // Dated before the stored version: stale for the label, yet the branch analysis succeeds.
    await p.ingestOk(
      branchReport(p, {
        branch: 'release/2.3',
        analysisDate: '2026-10-03T09:00:00Z',
        revision: 'd'.repeat(40),
      }),
    );
    const [after] = await versions(p);
    expect(after!.analysisId).toBe(before!.analysisId);
    expect(after!.analyzedAt.toISOString()).toBe('2026-10-03T10:00:00.000Z');
  });

  it('keeps its packages and .trivyignore ids when the branch it came from is deleted', async () => {
    const p = await project({ labelVersions: true, branchPatterns: ['release/*'] });
    const ignores = [{ id: 'CVE-2026-7', expiresAt: '2027-01-01' }];
    await p.ingestOk(branchReport(p, { branch: 'release/2.3', dependencyIgnores: ignores }));
    const [before] = await versions(p);
    const [release] = await h.ctx.db
      .select({ id: branches.id })
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.name, 'release/2.3')));
    const res = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/branches/${release!.id}`,
      headers: h.orgAdmin.headers,
    });
    expect(res.statusCode).toBe(204);
    const deps = await h.ctx.db
      .select()
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, before!.id));
    expect(deps.map((d) => [d.name, d.analysisId])).toEqual([['zod', null]]);
    const [after] = await versions(p);
    expect(after).toMatchObject({ id: before!.id, analysisId: null, dependencyIgnores: ignores });
  });

  it('gives way to an older tag scan of the label, which keeps the tracking mark', async () => {
    const p = await project();
    await p.ingestOk(branchReport(p, { analysisDate: '2026-10-05T10:00:00Z' }));
    await h.ctx.db
      .update(projectVersions)
      .set({ tracking: 'pinned' })
      .where(eq(projectVersions.projectId, p.id));
    // The tag job started before the branch analysis and uploads after it.
    const tagId = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: null,
        tag: 'v2.3.4',
        version: '2.3.4',
        dependencies: TAG_DEPS,
        analysisDate: '2026-10-01T10:00:00Z',
      }),
    );
    const [v] = await versions(p);
    expect(v).toMatchObject({
      source: 'tag',
      tag: 'v2.3.4',
      analysisId: tagId,
      tracking: 'pinned',
    });
    expect(v!.analyzedAt.toISOString()).toBe('2026-10-01T10:00:00.000Z');
    const deps = await h.ctx.db
      .select()
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, v!.id));
    expect(deps.map((d) => [d.name, d.version])).toEqual([['zod', '4.1.0']]);
  });

  it('turns into a tag version when a tag scan of the label follows', async () => {
    const p = await project();
    await p.ingestOk(branchReport(p, { analysisDate: '2026-10-01T10:00:00Z' }));
    const tagId = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: null,
        tag: 'v2.3.4',
        version: '2.3.4',
        dependencies: DEPS,
        analysisDate: '2026-10-02T10:00:00Z',
      }),
    );
    const [v] = await versions(p);
    expect(v).toMatchObject({ source: 'tag', tag: 'v2.3.4', analysisId: tagId });
  });
});

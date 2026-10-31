import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { reportWith } from '../../test/reports';
import {
  branches,
  instanceSettings,
  projectVersions,
  projectVulnerabilitySettings,
} from '../db/schema';
import { writeVulndbSettings } from '../vulndb/settings';
import { trackedTargets, type Target } from './targets';

const BASE = Date.UTC(2026, 9, 1);

describe('tracked targets (vulnerability re-checks)', () => {
  let h: IngestHarness;
  let n = 0;

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  beforeEach(async () => {
    await h.ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
  });
  afterAll(async () => {
    await h.close();
  });

  const project = async (
    settings: Partial<typeof projectVulnerabilitySettings.$inferInsert> = {},
  ): Promise<IngestProject> => {
    const p = await h.project(`acme/tgt-${++n}`);
    await h.ctx.db.insert(projectVulnerabilitySettings).values({ projectId: p.id, ...settings });
    return p;
  };
  const branch = async (p: IngestProject, name: string, mr = false): Promise<void> => {
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: name,
        ...(mr ? { mergeRequest: { id: '7', targetBranch: 'main', sourceBranch: name } } : {}),
      }),
    );
  };
  const branchId = async (p: IngestProject, name: string): Promise<string> => {
    const [row] = await h.ctx.db
      .select({ id: branches.id })
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.name, name)));
    return row!.id;
  };
  const addVersions = async (p: IngestProject, labels: string[], tracking = 'auto' as const) => {
    const rows = await h.ctx.db
      .insert(projectVersions)
      .values(
        labels.map((label, i) => ({
          projectId: p.id,
          label,
          source: 'tag' as const,
          tag: label,
          analyzedAt: new Date(BASE + i * 60_000),
          tracking,
        })),
      )
      .returning({ id: projectVersions.id, label: projectVersions.label });
    return new Map(rows.map((r) => [r.label, r.id]));
  };
  const sorted = (targets: Target[]): string[] =>
    targets
      .map((t) => (t.kind === 'branch' ? `branch:${t.branchId}` : `version:${t.versionId}`))
      .sort();

  it('lists main, the branches matching a pattern and the tracked versions', async () => {
    const p = await project({
      branchPatterns: ['release/*'],
      versionRule: 'lines',
      versionLines: 1,
    });
    await branch(p, 'main');
    await branch(p, 'release/1.0');
    await branch(p, 'feature/x');
    await branch(p, 'release/2.0', true);
    const versions = await addVersions(p, ['1.0.0', '2.0.0', '2.0.1']);
    expect(sorted(await trackedTargets(h.ctx.db, p.id))).toEqual(
      [
        `branch:${await branchId(p, 'main')}`,
        `branch:${await branchId(p, 'release/1.0')}`,
        `version:${versions.get('2.0.1')!}`,
      ].sort(),
    );
  });

  it('follows pins and versions marked unsupported', async () => {
    const p = await project({ versionRule: 'lines', versionLines: 1 });
    const versions = await addVersions(p, ['1.0.0', '2.0.0']);
    await h.ctx.db
      .update(projectVersions)
      .set({ tracking: 'pinned' })
      .where(eq(projectVersions.id, versions.get('1.0.0')!));
    await h.ctx.db
      .update(projectVersions)
      .set({ tracking: 'unsupported' })
      .where(eq(projectVersions.id, versions.get('2.0.0')!));
    expect(await trackedTargets(h.ctx.db, p.id)).toEqual([
      { kind: 'branch', branchId: await branchId(p, 'main') },
      { kind: 'version', versionId: versions.get('1.0.0')! },
    ]);
  });

  it('is only the main branch for a new project', async () => {
    const p = await project();
    expect(await trackedTargets(h.ctx.db, p.id)).toEqual([
      { kind: 'branch', branchId: await branchId(p, 'main') },
    ]);
  });

  it('is empty when the project switch is off', async () => {
    const p = await project({ enabled: false });
    await branch(p, 'main');
    await addVersions(p, ['1.0.0']);
    expect(await trackedTargets(h.ctx.db, p.id)).toEqual([]);
  });

  it('is empty when the instance switch is off', async () => {
    const p = await project();
    await branch(p, 'main');
    await addVersions(p, ['1.0.0']);
    expect(await trackedTargets(h.ctx.db, p.id)).toHaveLength(2);
    await h.ctx.db.transaction((tx) =>
      writeVulndbSettings(tx, { enabled: false }, h.ctx.config.secretKey),
    );
    expect(await trackedTargets(h.ctx.db, p.id)).toEqual([]);
  });

  it('uses the defaults for a project without settings: main and the last 5 lines', async () => {
    const p = await h.project(`acme/tgt-${++n}`);
    await branch(p, 'main');
    const versions = await addVersions(p, ['1.0.0', '2.0.0', '3.0.0', '4.0.0', '5.0.0', '6.0.0']);
    const got = sorted(await trackedTargets(h.ctx.db, p.id));
    expect(got).toHaveLength(6);
    expect(got).not.toContain(`version:${versions.get('1.0.0')!}`);
  });
});

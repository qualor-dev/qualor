import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import { seedTargetRow } from '../../../test/vulnerabilities';
import { first } from '../../db/rows';
import {
  branches,
  organizations,
  projects,
  projectVersions,
  vulnerabilityAlertItems,
  vulnerabilityAlertTargets,
  vulnerabilityDecisions,
  vulnerabilityKev,
} from '../../db/schema';
import { alertRows } from './content';

describe('alertRows: the rows of an alert email', () => {
  let t: TestDatabase;
  let n = 0;

  beforeAll(async () => {
    t = await createTestDatabase();
  });
  afterAll(async () => {
    await t.close();
  });

  /** A project with main, release/2.x and version 2.3.4, and a helper to give each a row + item. */
  const setup = async () => {
    n += 1;
    const organizationId = first(
      await t.db
        .insert(organizations)
        .values({ key: `ctt${n}`, name: `Ctt ${n}` })
        .returning(),
    ).id;
    const projectId = first(
      await t.db
        .insert(projects)
        .values({ organizationId, key: `ctt${n}/api`, name: 'Api' })
        .returning(),
    ).id;
    const branch = async (name: string, isMain = false) =>
      first(
        await t.db.insert(branches).values({ projectId, kind: 'branch', name, isMain }).returning(),
      ).id;
    const main = await branch('main', true);
    const release = await branch('release/2.x');
    const version = first(
      await t.db
        .insert(projectVersions)
        .values({
          projectId,
          label: '2.3.4',
          source: 'tag',
          tag: '2.3.4',
          analyzedAt: new Date('2026-10-01T00:00:00Z'),
        })
        .returning(),
    ).id;
    const targetIds = new Map<string, string>();
    const targetOf = async (key: { branchId: string } | { versionId: string }) => {
      const k = 'branchId' in key ? key.branchId : key.versionId;
      const known = targetIds.get(k);
      if (known !== undefined) return known;
      const id = first(
        await t.db
          .insert(vulnerabilityAlertTargets)
          .values({
            projectId,
            branchId: 'branchId' in key ? key.branchId : null,
            versionId: 'versionId' in key ? key.versionId : null,
            dayOne: false,
          })
          .returning(),
      ).id;
      targetIds.set(k, id);
      return id;
    };
    /** A target row of the package and an alert item for it; the item's id. */
    const item = async (
      key: { branchId: string } | { versionId: string },
      vulnerabilityId: string,
      row: Partial<Parameters<typeof seedTargetRow>[1]> = {},
    ) => {
      await seedTargetRow(t.db, {
        projectId,
        ...key,
        packageName: 'lodash',
        vulnerabilityId,
        ...row,
      });
      return first(
        await t.db
          .insert(vulnerabilityAlertItems)
          .values({ targetId: await targetOf(key), vulnerabilityId, baseline: false })
          .onConflictDoUpdate({
            target: [vulnerabilityAlertItems.targetId, vulnerabilityAlertItems.vulnerabilityId],
            set: { baseline: false },
          })
          .returning(),
      ).id;
    };
    return { projectId, main, release, version, item };
  };

  it('puts critical first, then high, then the id, then the package', async () => {
    const p = await setup();
    const ids = [
      await p.item({ branchId: p.main }, 'CVE-2026-0003', { severity: 'low' }),
      await p.item({ branchId: p.main }, 'CVE-2026-0002', { severity: 'high' }),
      await p.item({ branchId: p.main }, 'CVE-2026-0001', { severity: 'high', packageName: 'zed' }),
      await p.item({ branchId: p.main }, 'CVE-2026-0009', { severity: 'critical' }),
      await p.item({ branchId: p.main }, 'CVE-2026-0004', { severity: 'unknown' }),
    ];
    const rows = (await alertRows(t.db, ids, { priority: false })).get(p.projectId);
    expect(rows?.map((r) => [r.vulnerabilityId, r.severity])).toEqual([
      ['CVE-2026-0009', 'critical'],
      ['CVE-2026-0001', 'high'],
      ['CVE-2026-0002', 'high'],
      ['CVE-2026-0003', 'low'],
      ['CVE-2026-0004', 'unknown'],
    ]);
  });

  it('leaves out triaged and ignored rows', async () => {
    const p = await setup();
    const ids = [
      await p.item({ branchId: p.main }, 'CVE-2026-0001'),
      await p.item({ branchId: p.main }, 'CVE-2026-0002'),
      await p.item({ branchId: p.main }, 'CVE-2026-0003', { ignored: true }),
    ];
    await t.db.insert(vulnerabilityDecisions).values({
      projectId: p.projectId,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-2026-0002',
      branchId: p.main,
      status: 'false_positive',
    });
    const rows = (await alertRows(t.db, ids, { priority: false })).get(p.projectId);
    expect(rows?.map((r) => r.vulnerabilityId)).toEqual(['CVE-2026-0001']);
  });

  it('gives one row for a vulnerability on main and 2.3.4, main first', async () => {
    const p = await setup();
    const ids = [
      await p.item({ versionId: p.version }, 'CVE-2026-0001', { packageVersion: '4.17.20' }),
      await p.item({ branchId: p.release }, 'CVE-2026-0001', { packageVersion: '4.17.21' }),
      await p.item({ branchId: p.main }, 'CVE-2026-0001', { packageVersion: '4.17.21' }),
    ];
    const rows = (await alertRows(t.db, ids, { priority: false })).get(p.projectId);
    expect(rows).toHaveLength(1);
    expect(rows?.[0]).toMatchObject({
      vulnerabilityId: 'CVE-2026-0001',
      packageName: 'lodash',
      installedVersions: ['4.17.20', '4.17.21'],
      targets: ['main', 'release/2.x', '2.3.4'],
    });
  });

  it('lists only the targets of the given items', async () => {
    const p = await setup();
    const main = await p.item({ branchId: p.main }, 'CVE-2026-0001');
    await p.item({ versionId: p.version }, 'CVE-2026-0001');
    const rows = (await alertRows(t.db, [main], { priority: false })).get(p.projectId);
    expect(rows?.[0]?.targets).toEqual(['main']);
  });

  it('shows the KEV entry only with priority', async () => {
    const p = await setup();
    const ids = [
      await p.item({ branchId: p.main }, 'CVE-2026-0001', {
        title: 'Prototype pollution',
        fixedVersion: '4.17.22',
      }),
      await p.item({ branchId: p.main }, 'CVE-2026-0002'),
    ];
    await t.db
      .insert(vulnerabilityKev)
      .values({ vulnerabilityId: 'CVE-2026-0001', dateAdded: '2026-10-30' })
      .onConflictDoNothing();
    const plain = (await alertRows(t.db, ids, { priority: false })).get(p.projectId);
    expect(plain?.map((r) => r.exploited)).toEqual([null, null]);
    const priority = (await alertRows(t.db, ids, { priority: true })).get(p.projectId);
    expect(priority?.map((r) => r.exploited)).toEqual([{ dateAdded: '2026-10-30' }, null]);
    expect(priority?.[0]).toMatchObject({ title: 'Prototype pollution', fixedVersion: '4.17.22' });
    expect(priority?.[1]).toMatchObject({ title: null, fixedVersion: null });
  });

  it('answers an empty map for no items', async () => {
    expect((await alertRows(t.db, [], { priority: true })).size).toBe(0);
  });
});

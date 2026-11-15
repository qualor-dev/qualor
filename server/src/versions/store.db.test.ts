import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import {
  analyses,
  organizations,
  projects,
  projectVersions,
  versionDependencies,
} from '../db/schema';
import { upsertVersion } from './store';

const DEP = {
  path: 'package-lock.json',
  ecosystem: 'npm',
  name: 'zod',
  version: '4.0.0',
  licenses: ['MIT'],
};

describe('upsertVersion', () => {
  let t: TestDatabase;
  let projectId: string;
  beforeAll(async () => {
    t = await createTestDatabase();
    const [org] = await t.db
      .insert(organizations)
      .values({ key: 'acme', name: 'Acme' })
      .returning();
    const [project] = await t.db
      .insert(projects)
      .values({ organizationId: org!.id, key: 'acme/store', name: 'Store' })
      .returning();
    projectId = project!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  /** The analysis the last {@link write} made. */
  let lastAnalysisId = '';
  async function write(
    label: string,
    source: 'tag' | 'label',
    extra: { dependencies?: (typeof DEP)[]; at?: string } = {},
  ) {
    const [analysis] = await t.db.insert(analyses).values({ projectId }).returning();
    lastAnalysisId = analysis!.id;
    return upsertVersion(t.db, {
      projectId,
      label,
      source,
      tag: source === 'tag' ? `v${label}` : null,
      analysisId: analysis!.id,
      analyzedAt: new Date(extra.at ?? '2026-10-01T10:00:00Z'),
      ...(extra.dependencies && {
        inventory: { dependencies: extra.dependencies, ignores: null },
      }),
    });
  }
  const read = async (label: string) =>
    (await t.db.select().from(projectVersions).where(eq(projectVersions.label, label)))[0]!;
  const packagesOf = async (versionId: string) =>
    t.db.select().from(versionDependencies).where(eq(versionDependencies.versionId, versionId));

  it('keeps a tag version when a label write meets it, with its inventory', async () => {
    const created = await write('1.0.0', 'tag', { dependencies: [DEP] });
    expect(created).not.toBe('kept');
    const before = await read('1.0.0');
    const result = await write('1.0.0', 'label', {
      dependencies: [],
      at: '2026-10-02T10:00:00Z',
    });
    expect(result).toBe('kept');
    expect(await read('1.0.0')).toEqual(before);
    expect(
      await t.db
        .select()
        .from(versionDependencies)
        .where(eq(versionDependencies.versionId, before.id)),
    ).toHaveLength(1);
  });

  it('keeps a tag version that committed while a label write waited on its row (M5)', async () => {
    const [analysis] = await t.db.insert(analyses).values({ projectId }).returning();
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let inserted!: () => void;
    const tagInserted = new Promise<void>((resolve) => {
      inserted = resolve;
    });
    const tagScan = t.db.transaction(async (tx) => {
      await upsertVersion(tx, {
        projectId,
        label: '5.0.0',
        source: 'tag',
        tag: 'v5.0.0',
        analysisId: analysis!.id,
        analyzedAt: new Date('2026-10-01T10:00:00Z'),
        inventory: { dependencies: [DEP], ignores: null },
      });
      inserted();
      await held;
    });
    await tagInserted;
    // The label write reads no row (the tag scan has not committed) and waits on its insert.
    const labelWrite = write('5.0.0', 'label', { dependencies: [], at: '2026-10-02T10:00:00Z' });
    for (let i = 0; i < 100; i++) {
      const waiting = await t.db.execute<{ n: number }>(
        sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`,
      );
      if ((waiting.rows[0]?.n ?? 0) > 0) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    release();
    await tagScan;
    expect(await labelWrite).toBe('kept');
    const version = await read('5.0.0');
    expect(version).toMatchObject({ source: 'tag', tag: 'v5.0.0' });
    expect(
      await t.db
        .select()
        .from(versionDependencies)
        .where(eq(versionDependencies.versionId, version.id)),
    ).toHaveLength(1);
  });

  it('sets has_inventory with an inventory, even an empty one', async () => {
    await write('2.0.0', 'tag', { dependencies: [] });
    expect((await read('2.0.0')).hasInventory).toBe(true);
    await write('2.1.0', 'tag', { dependencies: [DEP] });
    expect((await read('2.1.0')).hasInventory).toBe(true);
  });

  it('leaves has_inventory false for a first scan without an inventory, and keeps it true after one', async () => {
    await write('3.0.0', 'tag');
    expect((await read('3.0.0')).hasInventory).toBe(false);
    await write('3.0.0', 'tag', { dependencies: [DEP], at: '2026-10-02T10:00:00Z' });
    expect((await read('3.0.0')).hasInventory).toBe(true);
    await write('3.0.0', 'tag', { at: '2026-10-03T10:00:00Z' });
    expect((await read('3.0.0')).hasInventory).toBe(true);
  });

  it('sets has_inventory on a label version', async () => {
    await write('4.0.0', 'label', { dependencies: [DEP] });
    expect((await read('4.0.0')).hasInventory).toBe(true);
  });

  it('dates a version taken over by a tag scan without an inventory', async () => {
    for (const [label, tagAt] of [
      ['7.0.0', '2026-10-05T10:00:00Z'],
      // An older tag date: a takeover is never stale.
      ['7.1.0', '2026-09-20T10:00:00Z'],
    ] as const) {
      await write(label, 'label', { dependencies: [DEP], at: '2026-10-01T10:00:00Z' });
      const result = await write(label, 'tag', { at: tagAt });
      expect(result, label).not.toBe('stale');
      const version = await read(label);
      expect(version, label).toMatchObject({
        source: 'tag',
        tag: `v${label}`,
        analyzedAt: new Date(tagAt),
        analysisId: lastAnalysisId,
        hasInventory: true,
      });
      // The packages and ids stay those of the label scan.
      expect(await packagesOf(version.id), label).toHaveLength(1);
    }
  });

  it('keeps a tag version when a label write without inventory meets it', async () => {
    await write('6.0.0', 'tag', { dependencies: [DEP] });
    const before = await read('6.0.0');
    expect(await write('6.0.0', 'label', { at: '2026-10-02T10:00:00Z' })).toBe('kept');
    expect(await read('6.0.0')).toEqual(before);
    expect(await packagesOf(before.id)).toHaveLength(1);
  });
});

import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import type { Tx } from '../db/client';
import {
  analyses,
  organizations,
  projects,
  projectVersions,
  versionDependencies,
  type ProjectVersionRow,
  type VersionSource,
} from '../db/schema';
import { upsertVersion, type VersionDependencyEntry } from './store';

const DEP: VersionDependencyEntry = {
  path: 'package-lock.json',
  ecosystem: 'npm',
  name: 'zod',
  version: '4.0.0',
  licenses: ['MIT'],
};
/** An OS package of an image SBOM, built from the `openssl` source package. */
const LIBSSL: VersionDependencyEntry = {
  path: '',
  ecosystem: 'deb',
  name: 'libssl3',
  version: '3.0.15-1~deb12u1',
  licenses: [],
  sourceName: 'openssl',
  sourceVersion: '3.0.15-1~deb12u1',
};
const SBOM = {
  format: 'CycloneDX 1.6',
  subject: 'shop',
  distribution: { family: 'debian', version: '12.15' },
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

  /** The analysis the last {@link write} made (none for an SBOM). */
  let lastAnalysisId: string | null = null;
  async function write(
    label: string,
    source: VersionSource,
    extra: { dependencies?: VersionDependencyEntry[]; at?: string } = {},
  ) {
    lastAnalysisId =
      source === 'sbom'
        ? null
        : (await t.db.insert(analyses).values({ projectId }).returning())[0]!.id;
    return upsertVersion(t.db, {
      projectId,
      label,
      source,
      tag: source === 'tag' ? `v${label}` : null,
      analysisId: lastAnalysisId,
      analyzedAt: new Date(extra.at ?? '2026-10-01T10:00:00Z'),
      ...(extra.dependencies && {
        inventory: { dependencies: extra.dependencies, ignores: null },
      }),
      ...(source === 'sbom' && { sbom: SBOM }),
    });
  }
  const read = async (label: string) =>
    (await t.db.select().from(projectVersions).where(eq(projectVersions.label, label)))[0]!;
  const packagesOf = async (versionId: string) =>
    t.db.select().from(versionDependencies).where(eq(versionDependencies.versionId, versionId));
  const namesOf = async (versionId: string) =>
    (await packagesOf(versionId)).map((d) => d.name).sort();
  /** The SBOM and OS columns of a version. */
  const originOf = (v: ProjectVersionRow) => [v.osFamily, v.osVersion, v.sbomFormat, v.sbomSubject];
  /** Waits until a session of this database waits on a lock. */
  async function lockWaitSeen(): Promise<void> {
    for (let i = 0; i < 100; i++) {
      const waiting = await t.db.execute<{ n: number }>(
        sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`,
      );
      if ((waiting.rows[0]?.n ?? 0) > 0) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  /**
   * Runs `first` in a transaction that holds its write until `second`, started outside it, waits
   * on the version's row; then commits it. Returns what `second` answers.
   */
  async function whileHeld<T>(
    first: (tx: Tx) => Promise<unknown>,
    second: () => Promise<T>,
  ): Promise<T> {
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let written!: () => void;
    const firstWritten = new Promise<void>((resolve) => {
      written = resolve;
    });
    const holder = t.db.transaction(async (tx) => {
      await first(tx);
      written();
      await held;
    });
    await firstWritten;
    const waiting = second();
    await lockWaitSeen();
    release();
    await holder;
    return waiting;
  }

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
    await lockWaitSeen();
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

  describe('SBOM versions (0.16): tag > sbom > label', () => {
    it('an SBOM write creates a version', async () => {
      const created = await write('10.0.0', 'sbom', { dependencies: [] });
      expect(created).toMatchObject({ previous: null, version: { source: 'sbom' } });
      const version = await read('10.0.0');
      expect(version).toMatchObject({
        source: 'sbom',
        tag: null,
        analysisId: null,
        hasInventory: true,
        dependencyIgnores: null,
        osFamily: 'debian',
        osVersion: '12.15',
        sbomFormat: 'CycloneDX 1.6',
        sbomSubject: 'shop',
      });
      expect(await packagesOf(version.id)).toEqual([]);

      await write('10.1.0', 'sbom', { dependencies: [DEP, LIBSSL] });
      const rows = await packagesOf((await read('10.1.0')).id);
      expect(
        rows.map((d) => [d.ecosystem, d.name, d.sourceName, d.sourceVersion, d.analysisId]).sort(),
      ).toEqual([
        ['deb', 'libssl3', 'openssl', '3.0.15-1~deb12u1', null],
        ['npm', 'zod', null, null, null],
      ]);
    });

    it('an SBOM write replaces an SBOM version', async () => {
      await write('11.0.0', 'sbom', { dependencies: [DEP] });
      const before = await read('11.0.0');
      const replaced = await write('11.0.0', 'sbom', {
        dependencies: [LIBSSL],
        at: '2026-10-02T10:00:00Z',
      });
      expect(replaced).toMatchObject({ previous: 'sbom', version: { id: before.id } });
      expect(await namesOf(before.id)).toEqual(['libssl3']);
    });

    it('an SBOM write takes over a label version', async () => {
      await write('12.0.0', 'label', { dependencies: [DEP] });
      const before = await read('12.0.0');
      const taken = await write('12.0.0', 'sbom', { dependencies: [LIBSSL] });
      expect(taken).toMatchObject({ previous: 'label', version: { id: before.id } });
      expect(await read('12.0.0')).toMatchObject({
        source: 'sbom',
        analysisId: null,
        sbomFormat: 'CycloneDX 1.6',
      });
      expect(await namesOf(before.id)).toEqual(['libssl3']);
    });

    it('an SBOM write meets a tag version', async () => {
      await write('13.0.0', 'tag', { dependencies: [DEP] });
      const before = await read('13.0.0');
      expect(
        await write('13.0.0', 'sbom', { dependencies: [LIBSSL], at: '2026-10-02T10:00:00Z' }),
      ).toBe('taken');
      expect(await read('13.0.0')).toEqual(before);
      expect(await namesOf(before.id)).toEqual(['zod']);
    });

    it('a label write meets an SBOM version', async () => {
      await write('14.0.0', 'sbom', { dependencies: [LIBSSL] });
      const before = await read('14.0.0');
      expect(
        await write('14.0.0', 'label', { dependencies: [DEP], at: '2026-10-02T10:00:00Z' }),
      ).toBe('kept');
      expect(await read('14.0.0')).toEqual(before);
      expect(await namesOf(before.id)).toEqual(['libssl3']);
    });

    it('a tag write takes over an SBOM version', async () => {
      // The upload is dated later than the scan: a takeover is never stale.
      await write('15.0.0', 'sbom', { dependencies: [LIBSSL], at: '2026-10-05T10:00:00Z' });
      const before = await read('15.0.0');
      const taken = await write('15.0.0', 'tag', { dependencies: [DEP] });
      expect(taken).toMatchObject({ previous: 'sbom', version: { id: before.id } });
      const version = await read('15.0.0');
      expect(version).toMatchObject({
        source: 'tag',
        tag: 'v15.0.0',
        analysisId: lastAnalysisId,
        analyzedAt: new Date('2026-10-01T10:00:00Z'),
      });
      expect(originOf(version)).toEqual([null, null, null, null]);
      const rows = await packagesOf(before.id);
      expect(rows.map((d) => [d.name, d.sourceName, d.sourceVersion, d.analysisId])).toEqual([
        ['zod', null, null, lastAnalysisId],
      ]);
    });

    it('a tag write without inventory over an SBOM version (R5)', async () => {
      await write('16.0.0', 'sbom', { dependencies: [LIBSSL], at: '2026-10-05T10:00:00Z' });
      const before = await read('16.0.0');
      const taken = await write('16.0.0', 'tag');
      expect(taken).toMatchObject({ previous: 'sbom', version: { id: before.id } });
      const version = await read('16.0.0');
      expect(version).toMatchObject({
        source: 'tag',
        analysisId: lastAnalysisId,
        hasInventory: true,
      });
      expect(originOf(version)).toEqual([null, null, null, null]);
      // The packages stay the SBOM's, source packages included.
      const rows = await packagesOf(before.id);
      expect(rows.map((d) => [d.name, d.sourceName, d.analysisId])).toEqual([
        ['libssl3', 'openssl', null],
      ]);
    });

    it('an SBOM write is never stale (R5)', async () => {
      await write('17.0.0', 'sbom', { dependencies: [DEP], at: '2026-10-05T10:00:00Z' });
      const before = await read('17.0.0');
      const replaced = await write('17.0.0', 'sbom', {
        dependencies: [LIBSSL],
        at: '2026-10-01T10:00:00Z',
      });
      expect(replaced).toMatchObject({ previous: 'sbom', version: { id: before.id } });
      expect((await read('17.0.0')).analyzedAt).toEqual(new Date('2026-10-01T10:00:00Z'));
      expect(await namesOf(before.id)).toEqual(['libssl3']);
    });

    it('a tag version committed after the read still wins over an SBOM write', async () => {
      const [analysis] = await t.db.insert(analyses).values({ projectId }).returning();
      const answer = await whileHeld(
        (tx) =>
          upsertVersion(tx, {
            projectId,
            label: '18.0.0',
            source: 'tag',
            tag: 'v18.0.0',
            analysisId: analysis!.id,
            analyzedAt: new Date('2026-10-01T10:00:00Z'),
            inventory: { dependencies: [DEP], ignores: null },
          }),
        // The SBOM write reads no row (the tag scan has not committed) and waits on its insert.
        () => write('18.0.0', 'sbom', { dependencies: [LIBSSL], at: '2026-10-02T10:00:00Z' }),
      );
      expect(answer).toBe('taken');
      const version = await read('18.0.0');
      expect(version).toMatchObject({ source: 'tag', tag: 'v18.0.0', sbomFormat: null });
      expect(await namesOf(version.id)).toEqual(['zod']);
    });

    it('names the version a concurrent writer created after the read as the previous one', async () => {
      const sbomWrite = (tx: Tx, label: string) =>
        upsertVersion(tx, {
          projectId,
          label,
          source: 'sbom',
          tag: null,
          analysisId: null,
          analyzedAt: new Date('2026-10-05T10:00:00Z'),
          inventory: { dependencies: [LIBSSL], ignores: null },
          sbom: SBOM,
        });
      // Two uploads of one label: one creates the version, the other replaces it.
      const second = await whileHeld(
        (tx) => sbomWrite(tx, '19.0.0'),
        () => write('19.0.0', 'sbom', { dependencies: [DEP] }),
      );
      expect(second).toMatchObject({ previous: 'sbom' });
      expect(await namesOf((await read('19.0.0')).id)).toEqual(['zod']);
      // A tag scan that waited on an upload takes the SBOM version over, and says so.
      const tag = await whileHeld(
        (tx) => sbomWrite(tx, '19.1.0'),
        () => write('19.1.0', 'tag', { dependencies: [DEP] }),
      );
      expect(tag).toMatchObject({ previous: 'sbom' });
      expect(originOf(await read('19.1.0'))).toEqual([null, null, null, null]);
    });
  });
});

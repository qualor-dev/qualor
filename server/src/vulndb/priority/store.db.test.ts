import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import type { EpssFile, KevEntry } from './parse';
import { replaceEpss, replaceKev } from './store';

let t: TestDatabase;
beforeAll(async () => {
  t = await createTestDatabase();
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  await t.db.execute(sql`DELETE FROM vulnerability_kev`);
  await t.db.execute(sql`DELETE FROM vulnerability_epss`);
});

const kev = (n: number, ransomware = false): KevEntry => ({
  vulnerabilityId: `CVE-2024-${String(1000 + n)}`,
  dateAdded: '2026-02-03',
  ransomware,
});

describe('replaceKev', () => {
  it('replaces the catalog, keeping listed_at of the ids that stay', async () => {
    const [a, b, c] = [kev(1), kev(2), kev(3)] as [KevEntry, KevEntry, KevEntry];
    expect(await replaceKev(t.db, [a, b])).toEqual({ count: 2, added: 2, relisted: 0 });
    await t.db.execute(
      sql`UPDATE vulnerability_kev SET listed_at = '2020-01-01T00:00:00Z' WHERE vulnerability_id = ${b.vulnerabilityId}`,
    );
    expect(await replaceKev(t.db, [{ ...b, ransomware: true }, c])).toEqual({
      count: 2,
      added: 1,
      relisted: 0,
    });
    const { rows } = await t.db.execute<{
      vulnerability_id: string;
      ransomware: boolean;
      date_added: string;
      listed: string;
      delisted: string | null;
    }>(sql`SELECT vulnerability_id, ransomware, date_added::text AS date_added,
                  listed_at::text AS listed, delisted_at::text AS delisted
             FROM vulnerability_kev ORDER BY 1`);
    expect(
      rows.map((r) => [r.vulnerability_id, r.ransomware, r.date_added, r.delisted !== null]),
    ).toEqual([
      [a.vulnerabilityId, false, '2026-02-03', true],
      [b.vulnerabilityId, true, '2026-02-03', false],
      [c.vulnerabilityId, false, '2026-02-03', false],
    ]);
    expect(rows[1]?.listed).toMatch(/^2020-01-01/);
  });

  it('delists an id the file no longer has and relists it with its first listed_at', async () => {
    const [a, b] = [kev(1), kev(2)] as [KevEntry, KevEntry];
    await replaceKev(t.db, [a, b]);
    await t.db.execute(
      sql`UPDATE vulnerability_kev SET listed_at = '2020-01-01T00:00:00Z' WHERE vulnerability_id = ${a.vulnerabilityId}`,
    );
    expect(await replaceKev(t.db, [b])).toEqual({ count: 1, added: 0, relisted: 0 });
    const read = async () =>
      (
        await t.db.execute<{ listed: string; delisted: string | null }>(
          sql`SELECT listed_at::text AS listed, delisted_at::text AS delisted
                FROM vulnerability_kev WHERE vulnerability_id = ${a.vulnerabilityId}`,
        )
      ).rows[0];
    const gone = await read();
    expect(gone?.delisted).not.toBeNull();
    expect(gone?.listed).toMatch(/^2020-01-01/);
    // A second file without it leaves the first delisted_at alone.
    await replaceKev(t.db, [b]);
    expect((await read())?.delisted).toBe(gone?.delisted);
    expect(await replaceKev(t.db, [a, b])).toEqual({ count: 2, added: 0, relisted: 1 });
    const back = await read();
    expect(back?.delisted).toBeNull();
    expect(back?.listed).toMatch(/^2020-01-01/);
  });

  it('empties the catalog for an empty list', async () => {
    await replaceKev(t.db, [kev(1)]);
    expect(await replaceKev(t.db, [])).toEqual({ count: 0, added: 0, relisted: 0 });
    const { rows } = await t.db.execute<{ live: number }>(
      sql`SELECT count(*)::int AS live FROM vulnerability_kev WHERE delisted_at IS NULL`,
    );
    expect(rows[0]?.live).toBe(0);
  });
});

function epss(n: number, score = 0.5): EpssFile {
  return {
    scoreDate: null,
    modelVersion: null,
    ids: Array.from({ length: n }, (_, i) => `CVE-2024-${String(10_000 + i)}`),
    scores: Array.from({ length: n }, () => score),
    percentiles: Array.from({ length: n }, () => 0.25),
    skipped: 0,
  };
}

const countEpss = async (): Promise<number> =>
  (await t.db.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM vulnerability_epss`))
    .rows[0]?.n ?? -1;

describe('replaceEpss', () => {
  it('stores many rows in batches, then replaces them', async () => {
    expect(await replaceEpss(t.db, epss(12_000))).toEqual({ count: 12_000 });
    expect(await countEpss()).toBe(12_000);
    expect(await replaceEpss(t.db, epss(3, 0.9))).toEqual({ count: 3 });
    const { rows } = await t.db.execute<{ score: number; percentile: number }>(
      sql`SELECT score, percentile FROM vulnerability_epss`,
    );
    expect(rows).toHaveLength(3);
    expect(rows[0]?.score).toBeCloseTo(0.9, 5);
    expect(rows[0]?.percentile).toBeCloseTo(0.25, 5);
  });

  it('stores 1e-37, the smallest non-zero value the parser keeps; real refuses 1e-50', async () => {
    expect(await replaceEpss(t.db, epss(1, 1e-37))).toEqual({ count: 1 });
    const { rows } = await t.db.execute<{ score: number }>(
      sql`SELECT score FROM vulnerability_epss`,
    );
    expect(rows[0]?.score).toBeGreaterThan(0);
    await expect(replaceEpss(t.db, epss(1, 1e-50))).rejects.toThrow();
  });

  it('rolls everything back when a row breaks a check', async () => {
    await replaceEpss(t.db, epss(3));
    const bad = epss(6000);
    bad.scores[5500] = 2;
    await expect(replaceEpss(t.db, bad)).rejects.toThrow();
    expect(await countEpss()).toBe(3);
  });
});

describe('replaceKev at size and on failure', () => {
  it('stores more than one batch', async () => {
    const entries = Array.from({ length: 12_000 }, (_, i) => kev(i));
    expect(await replaceKev(t.db, entries)).toEqual({
      count: 12_000,
      added: 12_000,
      relisted: 0,
    });
    const { rows } = await t.db.execute<{ n: number }>(
      sql`SELECT count(*)::int AS n FROM vulnerability_kev`,
    );
    expect(rows[0]?.n).toBe(12_000);
  });

  it('rolls back when a later batch breaks a check', async () => {
    await replaceKev(t.db, [kev(1), kev(2)]);
    const entries = Array.from({ length: 6000 }, (_, i) => kev(100 + i));
    entries[5500] = { vulnerabilityId: 'not-a-cve', dateAdded: '2026-02-03', ransomware: false };
    await expect(replaceKev(t.db, entries)).rejects.toThrow();
    const { rows } = await t.db.execute<{ vulnerability_id: string }>(
      sql`SELECT vulnerability_id FROM vulnerability_kev ORDER BY 1`,
    );
    expect(rows.map((r) => r.vulnerability_id)).toEqual([
      kev(1).vulnerabilityId,
      kev(2).vulnerabilityId,
    ]);
  });
});

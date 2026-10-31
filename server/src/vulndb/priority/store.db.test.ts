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
    expect(await replaceKev(t.db, [a, b])).toEqual({ count: 2, added: 2 });
    await t.db.execute(
      sql`UPDATE vulnerability_kev SET listed_at = '2020-01-01T00:00:00Z' WHERE vulnerability_id = ${b.vulnerabilityId}`,
    );
    expect(await replaceKev(t.db, [{ ...b, ransomware: true }, c])).toEqual({
      count: 2,
      added: 1,
    });
    const { rows } = await t.db.execute<{
      vulnerability_id: string;
      ransomware: boolean;
      date_added: string;
      listed: string;
    }>(sql`SELECT vulnerability_id, ransomware, date_added::text AS date_added,
                  listed_at::text AS listed FROM vulnerability_kev ORDER BY 1`);
    expect(rows.map((r) => [r.vulnerability_id, r.ransomware, r.date_added])).toEqual([
      [b.vulnerabilityId, true, '2026-02-03'],
      [c.vulnerabilityId, false, '2026-02-03'],
    ]);
    expect(rows[0]?.listed).toMatch(/^2020-01-01/);
  });

  it('empties the table for an empty list', async () => {
    await replaceKev(t.db, [kev(1)]);
    expect(await replaceKev(t.db, [])).toEqual({ count: 0, added: 0 });
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
    expect(await replaceKev(t.db, entries)).toEqual({ count: 12_000, added: 12_000 });
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

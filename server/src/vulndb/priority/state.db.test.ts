import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import { instanceSettings } from '../../db/schema';
import {
  isPriorityStale,
  PRIORITY_STATE_KEY,
  priorityStatus,
  readPriorityState,
  updatePriorityState,
  type PriorityDatasetState,
} from './state';

let t: TestDatabase;
beforeAll(async () => {
  t = await createTestDatabase();
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  await t.db.delete(instanceSettings).where(eq(instanceSettings.key, PRIORITY_STATE_KEY));
});

const EMPTY: PriorityDatasetState = {
  source: null,
  dataDate: null,
  storedAt: null,
  refreshedAt: null,
  lastCheckAt: null,
  sizeBytes: null,
  count: null,
  digest: null,
  etag: null,
  lastModified: null,
  url: null,
  lastError: null,
  staleNotifiedDigest: null,
};
const now = new Date('2026-10-31T00:00:00Z');
const stored = (over: Partial<PriorityDatasetState>): PriorityDatasetState => ({
  ...EMPTY,
  source: 'official',
  storedAt: '2026-10-30T00:00:00Z',
  refreshedAt: '2026-10-30T00:00:00Z',
  ...over,
});

describe('priority state', () => {
  it('reads a missing row as two empty states', async () => {
    expect(await readPriorityState(t.db)).toEqual({ kev: EMPTY, epss: EMPTY });
  });

  it('reads a damaged key as null and keeps the rest', async () => {
    await t.db.insert(instanceSettings).values({
      key: PRIORITY_STATE_KEY,
      value: { kev: { count: 'x', digest: 'abc' } },
    });
    const s = await readPriorityState(t.db);
    expect(s.kev).toEqual({ ...EMPTY, digest: 'abc' });
    expect(s.epss).toEqual(EMPTY);
  });

  it('updates one dataset and leaves the other', async () => {
    await updatePriorityState(t.db, 'kev', (s) => ({ ...s, count: 5 }));
    const next = await updatePriorityState(t.db, 'epss', (s) => ({ ...s, count: 9 }));
    expect(next.count).toBe(9);
    const s = await readPriorityState(t.db);
    expect(s.kev.count).toBe(5);
    expect(s.epss.count).toBe(9);
  });
});

describe('isPriorityStale', () => {
  it('judges KEV by refreshedAt', () => {
    expect(isPriorityStale('kev', stored({ refreshedAt: '2026-10-27T23:00:00Z' }), now)).toBe(true);
    expect(isPriorityStale('kev', stored({ refreshedAt: '2026-10-28T01:00:00Z' }), now)).toBe(
      false,
    );
  });
  it('judges EPSS by the earlier of dataDate and storedAt', () => {
    expect(isPriorityStale('epss', stored({ dataDate: '2026-10-27T23:00:00Z' }), now)).toBe(true);
    expect(isPriorityStale('epss', stored({ dataDate: null }), now)).toBe(false);
    expect(
      isPriorityStale(
        'epss',
        stored({ dataDate: '2027-01-01T00:00:00Z', storedAt: '2026-10-27T23:00:00Z' }),
        now,
      ),
    ).toBe(true);
  });
  it('never calls an empty or unparsable state stale', () => {
    expect(isPriorityStale('kev', EMPTY, now)).toBe(false);
    expect(isPriorityStale('epss', EMPTY, now)).toBe(false);
    expect(isPriorityStale('kev', stored({ refreshedAt: 'junk' }), now)).toBe(false);
    expect(isPriorityStale('epss', stored({ storedAt: 'junk' }), now)).toBe(false);
  });
});

describe('priorityStatus', () => {
  const on = { enabled: true, running: false, now };
  const err = { code: 'X', message: 'm' };
  it('follows the vulndbStatus precedence', () => {
    expect(priorityStatus('kev', EMPTY, { ...on, enabled: false })).toBe('off');
    expect(priorityStatus('kev', EMPTY, { ...on, running: true })).toBe('updating');
    expect(priorityStatus('kev', EMPTY, on)).toBe('no_data');
    expect(priorityStatus('kev', { ...EMPTY, lastError: err }, on)).toBe('failed');
    expect(
      priorityStatus('kev', stored({ refreshedAt: '2026-10-01T00:00:00Z', lastError: err }), on),
    ).toBe('stale');
    expect(priorityStatus('kev', stored({ lastError: err }), on)).toBe('failed');
    expect(priorityStatus('kev', stored({}), on)).toBe('up_to_date');
  });
});

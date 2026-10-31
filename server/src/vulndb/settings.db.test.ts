import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, type TestContext } from '../../test/app';
import { instanceSettings } from '../db/schema';
import {
  DEFAULT_VULNDB_SETTINGS,
  readVulndbSettings,
  VULNDB_PASSWORD_AAD,
  writeVulndbSettings,
} from './settings';
import { readVulndbState, updateVulndbState, vulndbStatus, type VulndbState } from './state';
import type { DatasetRow } from './store';

const SECRET = 'k'.repeat(32);

describe('vulnerability database settings and state', () => {
  let ctx: TestContext;
  beforeAll(async () => {
    ctx = await createTestContext();
  });
  beforeEach(async () => {
    await ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
    await ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb_state'));
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('reads the defaults with no row', async () => {
    expect(await readVulndbSettings(ctx.db)).toEqual({
      enabled: true,
      source: { kind: 'official' },
      intervalHours: 6,
    });
    expect(DEFAULT_VULNDB_SETTINGS.intervalHours).toBe(6);
  });

  it('round-trips each source kind', async () => {
    const mirror = await ctx.db.transaction((tx) =>
      writeVulndbSettings(
        tx,
        {
          enabled: false,
          intervalHours: 24,
          source: {
            kind: 'mirror',
            repository: 'registry.corp:5000/mirror/trivy-db:2',
            username: 'u',
            password: 'p4ss',
          },
        },
        SECRET,
      ),
    );
    expect(mirror.before.source.kind).toBe('official');
    expect(await readVulndbSettings(ctx.db)).toMatchObject({
      enabled: false,
      intervalHours: 24,
      source: { kind: 'mirror', repository: 'registry.corp:5000/mirror/trivy-db:2', username: 'u' },
    });
    const [row] = await ctx.db
      .select()
      .from(instanceSettings)
      .where(eq(instanceSettings.key, 'vulndb'));
    expect(JSON.stringify(row?.value)).not.toContain('p4ss');
    expect(VULNDB_PASSWORD_AAD).toBe('instance_settings.vulndb.mirror.password');
    await ctx.db.transaction((tx) =>
      writeVulndbSettings(tx, { source: { kind: 'upload' } }, SECRET),
    );
    expect((await readVulndbSettings(ctx.db)).source).toEqual({ kind: 'upload' });
    await ctx.db.transaction((tx) =>
      writeVulndbSettings(tx, { source: { kind: 'official' } }, SECRET),
    );
    expect((await readVulndbSettings(ctx.db)).source).toEqual({ kind: 'official' });
  });

  it('keeps the password when absent and removes it with null', async () => {
    const mirror = { kind: 'mirror', repository: 'r.io/a/b:1' } as const;
    await ctx.db.transaction((tx) =>
      writeVulndbSettings(tx, { source: { ...mirror, password: 'x' } }, SECRET),
    );
    await ctx.db.transaction((tx) => writeVulndbSettings(tx, { source: { ...mirror } }, SECRET));
    const kept = (await readVulndbSettings(ctx.db)).source;
    expect(kept.kind === 'mirror' && kept.passwordEnc !== null).toBe(true);
    await ctx.db.transaction((tx) =>
      writeVulndbSettings(tx, { source: { ...mirror, password: null } }, SECRET),
    );
    const gone = (await readVulndbSettings(ctx.db)).source;
    expect(gone.kind === 'mirror' && gone.passwordEnc === null).toBe(true);
  });

  it('falls back per field on a damaged row', async () => {
    await ctx.db
      .insert(instanceSettings)
      .values({ key: 'vulndb', value: { enabled: false, intervalHours: 5, source: 'x' } });
    expect(await readVulndbSettings(ctx.db)).toEqual({
      enabled: false,
      source: { kind: 'official' },
      intervalHours: 6,
    });
  });

  it('reads and updates the state under its lock', async () => {
    expect(await readVulndbState(ctx.db)).toEqual({
      currentDatasetId: null,
      lastCheckAt: null,
      nextCheckAt: null,
      lastError: null,
      lastRecheckError: null,
      lastRecheck: null,
      staleNotifiedDigest: null,
    });
    await Promise.all(
      [1, 2, 3, 4].map((n) =>
        updateVulndbState(ctx.db, (s) => ({ ...s, lastCheckAt: s.lastCheckAt ?? `t${n}` })),
      ),
    );
    await updateVulndbState(ctx.db, (s) => ({ ...s, lastError: { code: 'X', message: 'm' } }));
    const s = await readVulndbState(ctx.db);
    expect(s.lastCheckAt).toMatch(/^t\d$/);
    expect(s.lastError).toEqual({ code: 'X', message: 'm' });
    // A damaged key reads as its empty value; the others survive.
    await updateVulndbState(ctx.db, (s) => ({ ...s, lastRecheckError: 'broken' as never }));
    expect(await readVulndbState(ctx.db)).toMatchObject({
      lastRecheckError: null,
      lastError: { code: 'X', message: 'm' },
    });
  });
});

describe('vulndbStatus', () => {
  const now = new Date('2026-11-01T12:00:00Z');
  const settings = { ...DEFAULT_VULNDB_SETTINGS };
  const state: VulndbState = {
    currentDatasetId: null,
    lastCheckAt: null,
    nextCheckAt: null,
    lastError: null,
    lastRecheckError: null,
    lastRecheck: null,
    staleNotifiedDigest: null,
  };
  const dataset = (daysOld: number): DatasetRow => ({
    id: 'd',
    kind: 'trivy',
    digest: `sha256:${'a'.repeat(64)}`,
    sizeBytes: 1,
    builtAt: new Date(now.getTime() - daysOld * 86_400_000),
    source: 'official',
    status: 'ready',
    chunkCount: 1,
    createdAt: now,
  });
  const err = { code: 'E', message: 'm' };
  const off = { ...settings, enabled: false };
  const failing = { ...state, lastError: err };
  const recheckFailing = { ...state, lastRecheckError: err };
  it.each([
    ['disabled', off, state, null, false, 'off'],
    ['disabled beats running', off, state, null, true, 'off'],
    ['no dataset', settings, state, null, false, 'no_data'],
    ['running', settings, state, null, true, 'updating'],
    ['running beats an error and a stale dataset', settings, failing, dataset(9), true, 'updating'],
    ['no dataset and an error', settings, failing, null, false, 'failed'],
    ['4 days old', settings, state, dataset(4), false, 'stale'],
    ['stale beats an error', settings, failing, dataset(4), false, 'stale'],
    ['an error with a fresh dataset', settings, failing, dataset(1), false, 'failed'],
    [
      'a re-check error with a fresh dataset',
      settings,
      recheckFailing,
      dataset(1),
      false,
      'failed',
    ],
    ['stale beats a re-check error', settings, recheckFailing, dataset(4), false, 'stale'],
    ['running beats a re-check error', settings, recheckFailing, dataset(1), true, 'updating'],
    ['fresh', settings, state, dataset(1), false, 'up_to_date'],
  ] as const)('%s', (_name, s, st, current, running, expected) => {
    expect(vulndbStatus(s, st, current, running, now)).toBe(expected);
  });
});

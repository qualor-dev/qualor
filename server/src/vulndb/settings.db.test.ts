import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, type TestContext } from '../../test/app';
import { instanceSettings } from '../db/schema';
import {
  DEFAULT_VULNDB_SETTINGS,
  OFFICIAL_EPSS_URL,
  OFFICIAL_KEV_URL,
  priorityUrl,
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
      scanners: { enabled: true, policy: 'daily' },
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
      scanners: { enabled: true, policy: 'daily' },
    });
  });

  it('reads the scanner defaults from a row without scanners', async () => {
    await ctx.db.insert(instanceSettings).values({
      key: 'vulndb',
      value: { enabled: false, intervalHours: 12, source: { kind: 'upload' } },
    });
    expect((await readVulndbSettings(ctx.db)).scanners).toEqual({ enabled: true, policy: 'daily' });
  });

  it('keeps scanners.enabled when only scanners.policy is damaged', async () => {
    await ctx.db
      .insert(instanceSettings)
      .values({ key: 'vulndb', value: { scanners: { enabled: false, policy: 'weekly' } } });
    expect((await readVulndbSettings(ctx.db)).scanners).toEqual({
      enabled: false,
      policy: 'daily',
    });
  });

  it('merges a scanners patch key by key', async () => {
    await ctx.db.transaction((tx) =>
      writeVulndbSettings(tx, { scanners: { enabled: false } }, SECRET),
    );
    const { after } = await ctx.db.transaction((tx) =>
      writeVulndbSettings(tx, { scanners: { policy: 'every' } }, SECRET),
    );
    expect(after.scanners).toEqual({ enabled: false, policy: 'every' });
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
  it('a build time in the future does not hide a dataset stored four days ago', () => {
    const future = {
      ...dataset(-30),
      createdAt: new Date(now.getTime() - 4 * 86_400_000),
    };
    expect(vulndbStatus(settings, state, future, false, now)).toBe('stale');
    const unknown = { ...future, builtAt: null };
    expect(vulndbStatus(settings, state, unknown, false, now)).toBe('stale');
  });
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

describe('mirror KEV and EPSS URLs', () => {
  let ctx: TestContext;
  beforeAll(async () => {
    ctx = await createTestContext();
  });
  beforeEach(async () => {
    await ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
  });
  afterAll(async () => {
    await ctx.close();
  });
  const mirror = { kind: 'mirror', repository: 'r.io/a/b:1' } as const;
  const write = (source: Parameters<typeof writeVulndbSettings>[1]['source']) =>
    ctx.db.transaction((tx) => writeVulndbSettings(tx, { source }, SECRET));

  it('stores kevUrl, keeps it when absent and clears it with null', async () => {
    await write({ ...mirror, kevUrl: 'https://m.corp/kev.json' });
    expect((await readVulndbSettings(ctx.db)).source).toMatchObject({
      kevUrl: 'https://m.corp/kev.json',
      epssUrl: null,
    });
    await write({ ...mirror });
    expect((await readVulndbSettings(ctx.db)).source).toMatchObject({
      kevUrl: 'https://m.corp/kev.json',
    });
    await write({ ...mirror, kevUrl: null });
    expect((await readVulndbSettings(ctx.db)).source).toMatchObject({ kevUrl: null });
  });

  it('starts a mirror with both null after the official source', async () => {
    await write({ kind: 'official' });
    await write({ ...mirror });
    expect((await readVulndbSettings(ctx.db)).source).toMatchObject({
      kevUrl: null,
      epssUrl: null,
    });
  });

  it('reads a damaged kevUrl as null and keeps the repository', async () => {
    await ctx.db.insert(instanceSettings).values({
      key: 'vulndb',
      value: { source: { kind: 'mirror', repository: 'r.io/a/b:1', kevUrl: 42 } },
    });
    expect((await readVulndbSettings(ctx.db)).source).toMatchObject({
      kind: 'mirror',
      repository: 'r.io/a/b:1',
      kevUrl: null,
    });
  });

  it('priorityUrl falls back to the official URL', async () => {
    expect(priorityUrl({ kind: 'official' }, 'kev')).toBe(OFFICIAL_KEV_URL);
    expect(priorityUrl({ kind: 'upload' }, 'epss')).toBe(OFFICIAL_EPSS_URL);
    await write({ ...mirror, kevUrl: 'https://m.corp/kev.json' });
    const { source } = await readVulndbSettings(ctx.db);
    expect(priorityUrl(source, 'kev')).toBe('https://m.corp/kev.json');
    expect(priorityUrl(source, 'epss')).toBe(OFFICIAL_EPSS_URL);
  });
});

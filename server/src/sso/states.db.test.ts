import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { createDatabase, type Database } from '../db/client';
import { uuidv7 } from '../db/ids';
import {
  FINISH_TTL_MS,
  FLOW_TTL_MS,
  pruneSsoStates,
  putState,
  samlCacheProvider,
  StateExists,
  stateKey,
  takeState,
} from './states';

describe('the SSO flow store (sso-scim.md §7.1)', () => {
  let database: TestDatabase;
  /** A second app instance: its own pool on the same database. */
  let replica: Database;
  let connectionId: string;
  beforeAll(async () => {
    database = await createTestDatabase();
    replica = createDatabase(database.url, { max: 10 });
    connectionId = uuidv7();
    await database.db.execute(
      sql`INSERT INTO sso_connections (id, name, protocol, config) VALUES (${connectionId}, 'c', 'oidc', '{}')`,
    );
  });
  afterAll(async () => {
    await replica.close();
    await database.close();
  });

  it('hashes secrets in keys', () => {
    expect(stateKey('oidc', 'the-state')).toMatch(/^oidc:[0-9a-f]{64}$/);
    expect(stateKey('oidc', 'the-state')).not.toContain('the-state');
    expect(stateKey('saml-request', '_abc')).toBe('saml-request:_abc');
  });

  it('pins the key format of every kind (sso-scim.md §7.1)', () => {
    // SHA-256("s") in hex.
    const s = '043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89';
    expect(stateKey('oidc', 's')).toBe(`oidc:${s}`);
    expect(stateKey('finish', 's')).toBe(`finish:${s}`);
    expect(stateKey('saml-request', '_0123abcd')).toBe('saml-request:_0123abcd');
    expect(stateKey('saml-assertion', 's', connectionId)).toBe(
      `saml-assertion:${connectionId}:${s}`,
    );
    // An assertion id is unique only per IdP: the same id from two connections is two keys.
    expect(stateKey('saml-assertion', 's', uuidv7())).not.toBe(
      stateKey('saml-assertion', 's', connectionId),
    );
    // Without its connection an assertion key would collide across IdPs: refused.
    expect(() => stateKey('saml-assertion', 's')).toThrow();
    expect(() => stateKey('saml-assertion', 's', '')).toThrow();
  });

  it('gives a flow once, even to two takers at the same moment', async () => {
    const key = stateKey('oidc', 's1');
    await putState(database.db, {
      key,
      kind: 'oidc',
      connectionId,
      payload: { a: 1 },
      ttlMs: 600_000,
    });
    const [x, y] = await Promise.all([takeState(database.db, key), takeState(database.db, key)]);
    expect([x, y].filter(Boolean)).toEqual([{ connectionId, payload: { a: 1 } }]);
  });

  it('gives a flow once across two app instances (two pools), however the race falls', async () => {
    const keys = Array.from({ length: 25 }, (_, i) => stateKey('oidc', `race-${i}`));
    await Promise.all(
      keys.map((key, i) =>
        putState(database.db, {
          key,
          kind: 'oidc',
          connectionId,
          payload: { i },
          ttlMs: FLOW_TTL_MS,
        }),
      ),
    );
    const results = await Promise.all(
      keys.map((key) => Promise.all([takeState(database.db, key), takeState(replica.db, key)])),
    );
    results.forEach(([x, y], i) => {
      expect([x, y].filter(Boolean)).toEqual([{ connectionId, payload: { i } }]);
    });
    // Nothing is left for a third taker on either instance.
    expect(await takeState(replica.db, keys[0]!)).toBeNull();
    expect(await takeState(database.db, keys[0]!)).toBeNull();
  });

  /** Waits until a backend of the database is blocked on a lock (the other instance's take). */
  async function untilBlockedOnLock(): Promise<void> {
    for (let i = 0; i < 500; i++) {
      const r = await database.db.execute<{ n: number }>(sql`
        SELECT count(*)::int AS n FROM pg_stat_activity
         WHERE datname = current_database() AND wait_event_type = 'Lock'`);
      if ((r.rows[0]?.n ?? 0) > 0) return;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error('the second take never waited on the lock');
  }

  it('is atomic: a take waiting on a committed take of another instance gets nothing', async () => {
    const key = stateKey('oidc', 'atomic-commit');
    await putState(database.db, {
      key,
      kind: 'oidc',
      connectionId,
      payload: {},
      ttlMs: FLOW_TTL_MS,
    });
    const a = await database.pool.connect();
    try {
      await a.query('BEGIN');
      const first = await a.query('DELETE FROM sso_states WHERE key = $1 RETURNING key', [key]);
      expect(first.rows).toEqual([{ key }]);
      const second = takeState(replica.db, key);
      await untilBlockedOnLock();
      await a.query('COMMIT');
      expect(await second).toBeNull();
    } finally {
      a.release();
    }
  });

  it('is atomic the other way too: after a rolled-back take, the waiting take gets the flow', async () => {
    const key = stateKey('oidc', 'atomic-rollback');
    await putState(database.db, {
      key,
      kind: 'oidc',
      connectionId,
      payload: { ok: true },
      ttlMs: FLOW_TTL_MS,
    });
    const a = await database.pool.connect();
    try {
      await a.query('BEGIN');
      await a.query('DELETE FROM sso_states WHERE key = $1 RETURNING key', [key]);
      const second = takeState(replica.db, key);
      await untilBlockedOnLock();
      await a.query('ROLLBACK');
      expect(await second).toEqual({ connectionId, payload: { ok: true } });
    } finally {
      a.release();
    }
  });

  it('finishes on one instance a flow another instance started', async () => {
    const key = stateKey('finish', 'cross');
    await putState(database.db, {
      key,
      kind: 'finish',
      connectionId,
      payload: { who: 'a' },
      ttlMs: FINISH_TTL_MS,
    });
    expect(await takeState(replica.db, key)).toEqual({ connectionId, payload: { who: 'a' } });
    expect(await takeState(database.db, key)).toBeNull();
  });

  it('refuses a second put under the same key (a replayed assertion id), on any instance', async () => {
    const key = stateKey('saml-assertion', 'id-1', connectionId);
    await putState(database.db, {
      key,
      kind: 'saml-assertion',
      connectionId,
      payload: {},
      ttlMs: 60_000,
    });
    await expect(
      putState(database.db, {
        key,
        kind: 'saml-assertion',
        connectionId,
        payload: {},
        ttlMs: 60_000,
      }),
    ).rejects.toBeInstanceOf(StateExists);
    await expect(
      putState(replica.db, {
        key,
        kind: 'saml-assertion',
        connectionId,
        payload: {},
        ttlMs: 60_000,
      }),
    ).rejects.toBeInstanceOf(StateExists);
  });

  it('expires a flow after 10 minutes', async () => {
    expect(FLOW_TTL_MS).toBe(10 * 60 * 1000);
    expect(FINISH_TTL_MS).toBe(60 * 1000);
    const start = new Date('2026-09-28T10:00:00Z');
    const key = stateKey('oidc', 'ten');
    await putState(database.db, {
      key,
      kind: 'oidc',
      connectionId,
      payload: {},
      ttlMs: FLOW_TTL_MS,
      now: start,
    });
    const row = await database.db.execute<{ expires_at: Date | string }>(
      sql`SELECT expires_at FROM sso_states WHERE key = ${key}`,
    );
    expect(new Date(row.rows[0]!.expires_at).getTime()).toBe(start.getTime() + 600_000);
    // At ten minutes it is gone; a millisecond before, it is still there.
    expect(await takeState(database.db, key, new Date(start.getTime() + 600_000))).toBeNull();
    expect(await takeState(database.db, key, new Date(start.getTime() + 599_999))).toEqual({
      connectionId,
      payload: {},
    });
  });

  it('never returns an expired flow, and prunes it', async () => {
    const key = stateKey('finish', 'f1');
    await putState(database.db, {
      key,
      kind: 'finish',
      connectionId,
      payload: {},
      ttlMs: 1_000,
      now: new Date(Date.now() - 5_000),
    });
    expect(await takeState(database.db, key)).toBeNull();
    await putState(database.db, {
      key: stateKey('finish', 'f2'),
      kind: 'finish',
      connectionId,
      payload: {},
      ttlMs: 1_000,
      now: new Date(Date.now() - 5_000),
    });
    const live = stateKey('oidc', 'live');
    await putState(database.db, {
      key: live,
      kind: 'oidc',
      connectionId,
      payload: {},
      ttlMs: FLOW_TTL_MS,
    });
    expect(await pruneSsoStates(database.db)).toBeGreaterThanOrEqual(1);
    const left = await database.db.execute<{ key: string }>(
      sql`SELECT key FROM sso_states WHERE expires_at <= now()`,
    );
    expect(left.rows).toEqual([]);
    expect(await takeState(database.db, live)).not.toBeNull();
  });

  it('backs node-saml request ids with rows every replica sees', async () => {
    const provider = samlCacheProvider(database.db, { connectionId, payload: { binding: 'h' } });
    await provider.saveAsync('_req1', '2026-09-28T10:00:00Z');
    const other = samlCacheProvider(replica.db, null);
    expect(await other.getAsync('_req1')).toBe('2026-09-28T10:00:00Z');
    expect(await other.getAsync('_unknown')).toBeNull();
    // removeAsync leaves the row: takeState is what consumes it (SS3).
    await other.removeAsync('_req1');
    const taken = await takeState<{ binding: string; issueInstant: string }>(
      replica.db,
      stateKey('saml-request', '_req1'),
    );
    expect(taken?.payload).toEqual({ binding: 'h', issueInstant: '2026-09-28T10:00:00Z' });
    expect(await other.getAsync('_req1')).toBeNull();
  });

  it('never answers an expired request id to node-saml', async () => {
    await putState(database.db, {
      key: stateKey('saml-request', '_old'),
      kind: 'saml-request',
      connectionId,
      payload: { issueInstant: '2026-09-28T09:00:00Z' },
      ttlMs: 1_000,
      now: new Date(Date.now() - 5_000),
    });
    expect(await samlCacheProvider(database.db, null).getAsync('_old')).toBeNull();
  });
});

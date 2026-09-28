import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { sessions, users } from '../db/schema';
import {
  createSession,
  csrfTokenFor,
  deleteSession,
  deleteUserSessions,
  resolveSession,
  safeEqual,
  sessionIdFor,
} from './sessions';

describe('sessions (data-model.md §4.1)', () => {
  let t: TestDatabase;
  let userId: string;
  const newSession = () =>
    createSession(t.db, { userId, ttlHours: 1, ip: '127.0.0.1', userAgent: 'vitest' });

  beforeAll(async () => {
    t = await createTestDatabase();
    const [user] = await t.db.insert(users).values({ username: 'sam' }).returning();
    userId = user!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  it('stores only the SHA-256 of the cookie value and resolves it to the user', async () => {
    const { secret, expiresAt } = await newSession();
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(expiresAt.getTime()).toBeGreaterThan(Date.now());
    const [row] = await t.db
      .select()
      .from(sessions)
      .where(eq(sessions.id, sessionIdFor(secret)));
    expect(row?.id.equals(Buffer.from(secret))).toBe(false);
    expect((await resolveSession(t.db, secret))?.id).toBe(userId);
  });

  it('rejects malformed, unknown, expired and deactivated sessions', async () => {
    expect(await resolveSession(t.db, 'not a session')).toBeNull();
    expect(await resolveSession(t.db, 'A'.repeat(43))).toBeNull();
    const expired = await newSession();
    await t.db
      .update(sessions)
      .set({ expiresAt: new Date(Date.now() - 1_000) })
      .where(eq(sessions.id, sessionIdFor(expired.secret)));
    expect(await resolveSession(t.db, expired.secret)).toBeNull();
    expect(
      await t.db
        .select()
        .from(sessions)
        .where(eq(sessions.id, sessionIdFor(expired.secret))),
    ).toEqual([]);
    const [inactive] = await t.db
      .insert(users)
      .values({ username: 'gone', active: false })
      .returning();
    const s = await createSession(t.db, {
      userId: inactive!.id,
      ttlHours: 1,
      ip: null,
      userAgent: null,
    });
    expect(await resolveSession(t.db, s.secret)).toBeNull();
  });

  it('deletes one session, or all of a user except the current one', async () => {
    const a = await newSession();
    const b = await newSession();
    const c = await newSession();
    await deleteSession(t.db, a.secret);
    expect(await resolveSession(t.db, a.secret)).toBeNull();
    await deleteUserSessions(t.db, userId, c.secret);
    expect(await resolveSession(t.db, b.secret)).toBeNull();
    expect((await resolveSession(t.db, c.secret))?.id).toBe(userId);
    await deleteUserSessions(t.db, userId);
    expect(await resolveSession(t.db, c.secret)).toBeNull();
  });

  it('touches last_seen_at at most once a minute', async () => {
    const s = await newSession();
    const old = new Date(Date.now() - 5 * 60_000);
    await t.db
      .update(sessions)
      .set({ lastSeenAt: old })
      .where(eq(sessions.id, sessionIdFor(s.secret)));
    await resolveSession(t.db, s.secret);
    const [row] = await t.db
      .select()
      .from(sessions)
      .where(eq(sessions.id, sessionIdFor(s.secret)));
    expect(row!.lastSeenAt.getTime()).toBeGreaterThan(old.getTime());
  });

  it('derives a CSRF token per session and per server key', () => {
    const one = csrfTokenFor('k'.repeat(32), 'session-one');
    expect(one).toBe(csrfTokenFor('k'.repeat(32), 'session-one'));
    expect(one).not.toBe(csrfTokenFor('k'.repeat(32), 'session-two'));
    expect(one).not.toBe(csrfTokenFor('j'.repeat(32), 'session-one'));
    expect(safeEqual(one, csrfTokenFor('k'.repeat(32), 'session-one'))).toBe(true);
    expect(safeEqual(one, `${one}x`)).toBe(false);
  });
});

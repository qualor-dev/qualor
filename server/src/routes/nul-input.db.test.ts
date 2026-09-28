import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createTestContext,
  createUser,
  login,
  nextIp,
  type Session,
  organizationId,
  type TestContext,
} from '../../test/app';
import { rbacContext } from '../../test/rbac';

/**
 * E1 wave: free-text fields stored in `text` columns reject NUL with a 422 on the field (Postgres
 * `text` cannot hold it, so it used to surface as a 500).
 */
describe('NUL in organisation names, display names and login usernames', () => {
  let t: TestContext;
  let admin: Session;
  let userId: string;

  beforeAll(async () => {
    t = await createTestContext();
    admin = await login(t, 'admin', ADMIN_PASSWORD);
    userId = (await createUser(t, { username: 'nul-target' })).id;
  });
  afterAll(async () => {
    await t.close();
  });

  const send = (method: 'POST' | 'PATCH', url: string, payload: unknown, session?: Session) =>
    t.app.inject({
      method,
      url: `/api/v0${url}`,
      payload: payload as Record<string, unknown>,
      remoteAddress: nextIp(),
      ...(session ? { headers: session.headers } : {}),
    });
  const expect422 = (res: Awaited<ReturnType<typeof send>>, path: string) => {
    expect(res.statusCode, res.body).toBe(422);
    const body = res.json() as { errors: { path: string }[] };
    expect(body.errors.map((e) => e.path)).toContain(path);
  };

  it('refuses an organisation name with NUL', async () => {
    expect422(
      await send('POST', '/organizations', { key: 'nul-org', name: 'a\u0000b' }, admin),
      'body.name',
    );
  });

  it('refuses a display name with NUL when a user is created or changed', async () => {
    expect422(
      await send(
        'POST',
        '/users',
        { username: 'nul-user', password: 'a perfectly fine passphrase', displayName: 'x\u0000' },
        admin,
      ),
      'body.displayName',
    );
    expect422(
      await send('PATCH', `/users/${userId}`, { displayName: 'x\u0000' }, admin),
      'body.displayName',
    );
  });

  it('refuses a login username with NUL', async () => {
    expect422(
      await send('POST', '/auth/login', { username: 'ad\u0000min', password: 'whatever' }),
      'body.username',
    );
  });
});

/**
 * Fix wave (decision 5): text that is not well-formed Unicode (a lone UTF-16 surrogate) is refused
 * on its field with 422, like U+0000, instead of reaching the audit chain (whose canonical JSON
 * refuses it: a 500) or the database (which would store U+FFFD instead). Audit-log is active here.
 */
describe('lone surrogates in free-text fields', () => {
  const LONE = ['a\ud83db', 'a\ude00b', 'a\ude00\ud83db', 'end\ud83d'];
  let t: TestContext;
  let admin: Session;
  let org: string;
  let userId: string;

  beforeAll(async () => {
    t = await rbacContext({ now: () => new Date('2027-01-01T00:00:00Z') });
    admin = await login(t, 'admin', ADMIN_PASSWORD);
    org = await organizationId(t, 'default');
    userId = (await createUser(t, { username: 'surrogate-target' })).id;
  });
  afterAll(async () => {
    await t.close();
  });

  const send = (method: 'POST' | 'PATCH', url: string, payload: unknown, session?: Session) =>
    t.app.inject({
      method,
      url: `/api/v0${url}`,
      payload: JSON.stringify(payload),
      headers: { 'content-type': 'application/json', ...(session ? session.headers : {}) },
      remoteAddress: nextIp(),
    });

  it.each(LONE)('refuses %j on its field with 422, never a 500', async (value) => {
    const cases: [Awaited<ReturnType<typeof send>>, string][] = [
      [await send('POST', '/organizations', { key: 'lone-org', name: value }, admin), 'body.name'],
      [
        await send('POST', '/projects', { organizationId: org, key: 'lone', name: value }, admin),
        'body.name',
      ],
      [
        await send('POST', '/quality-gates', { organizationId: org, name: value }, admin),
        'body.name',
      ],
      [await send('PATCH', `/users/${userId}`, { displayName: value }, admin), 'body.displayName'],
      [await send('POST', '/tokens', { name: value, scopes: ['read'] }, admin), 'body.name'],
      [
        await send('POST', '/auth/login', { username: value, password: 'whatever' }),
        'body.username',
      ],
    ];
    for (const [res, path] of cases) {
      expect([path, res.statusCode], res.body).toEqual([path, 422]);
      expect((res.json() as { errors: { path: string }[] }).errors.map((e) => e.path)).toContain(
        path,
      );
    }
  });

  it('accepts a proper surrogate pair (an emoji)', async () => {
    const res = await send(
      'POST',
      '/quality-gates',
      { organizationId: org, name: 'Gate \ud83d\ude00' },
      admin,
    );
    expect(res.statusCode, res.body).toBe(201);
  });
});

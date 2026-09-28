import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TestContext } from '../../test/app';
import { oidcConnection, scimDeps, ssoContext } from '../../test/sso';
import { SYSTEM_ACTOR } from '../audit/recorder';
import type { Db } from '../db/client';
import { handleScim, SCIM_AUTH_FAILURES_PER_MINUTE, type ScimDeps } from './handle';
import { createScimToken } from './tokens';

const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_TYPE = 'application/scim+json; charset=utf-8';

/** A database whose transactions throw `err` (every SCIM write runs in one). */
function failingDb(db: Db, err: unknown): Db {
  return new Proxy(db, {
    get(target, property, receiver) {
      if (property === 'transaction') {
        return () => Promise.reject(err);
      }
      return Reflect.get(target, property, receiver) as unknown;
    },
  });
}

describe('SCIM failures (sso-scim.md §12.1)', () => {
  let ctx: TestContext;
  let token: string;
  const logged: { obj: object; msg: string }[] = [];

  beforeAll(async () => {
    ctx = await ssoContext();
    const conn = await oidcConnection(ctx, {});
    token = (
      await createScimToken(scimDeps(ctx), SYSTEM_ACTOR, {
        connectionId: conn,
        name: 'failures',
        expiresAt: null,
      })
    ).token;
  });
  afterAll(async () => ctx.close());

  async function appWith(over: Partial<ScimDeps>): Promise<FastifyInstance> {
    const app = Fastify({ logger: false });
    app.removeAllContentTypeParsers();
    app.addContentTypeParser('application/scim+json', { parseAs: 'string' }, (_req, body, done) =>
      done(null, JSON.parse(body.toString()) as unknown),
    );
    const log = {
      error: (obj: object, msg: string) => logged.push({ obj, msg }),
      warn: (obj: object, msg: string) => logged.push({ obj, msg }),
      info() {},
      debug() {},
    };
    const deps: ScimDeps = { ...scimDeps(ctx), log: log as never, ...over };
    app.all('/scim/v2/*', (req, reply) => handleScim(deps, req, reply));
    await app.ready();
    return app;
  }

  const createUser = (app: FastifyInstance, remoteAddress = '127.0.0.1', auth = token) =>
    app.inject({
      method: 'POST',
      url: '/scim/v2/Users',
      remoteAddress,
      headers: { authorization: `Bearer ${auth}`, 'content-type': 'application/scim+json' },
      payload: JSON.stringify({ schemas: [USER], userName: 'canary@acme.example' }),
    });

  it('logs only the class of an unexpected error, never its message', async () => {
    const app = await appWith({
      db: failingDb(ctx.db, new TypeError('Invalid URL: canary@acme.example')),
    });
    try {
      const before = logged.length;
      const res = await createUser(app);
      expect(res.statusCode).toBe(500);
      expect(res.json()).toMatchObject({ status: '500', detail: 'Internal error' });
      const lines = logged.slice(before);
      expect(lines).toEqual([
        { obj: { component: 'scim', errorClass: 'TypeError' }, msg: 'scim request failed' },
      ]);
      expect(JSON.stringify(lines)).not.toContain('canary');
    } finally {
      await app.close();
    }
  });

  it.each([
    ['a deadlock', '40P01'],
    ['a serialization failure', '40001'],
  ])('answers %s with 503 and Retry-After, for the IdP to retry', async (_name, code) => {
    const err = Object.assign(new Error('Failed query'), {
      cause: Object.assign(new Error('deadlock detected'), { code }),
    });
    const app = await appWith({ db: failingDb(ctx.db, err) });
    try {
      const res = await createUser(app);
      expect(res.statusCode).toBe(503);
      expect(res.headers['content-type']).toBe(SCIM_TYPE);
      expect(res.headers['retry-after']).toBe('5');
      expect(res.json()).toMatchObject({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        status: '503',
      });
    } finally {
      await app.close();
    }
  });

  it(`refuses an address after ${String(SCIM_AUTH_FAILURES_PER_MINUTE)} failed authentications a minute (429)`, async () => {
    const app = await appWith({});
    try {
      const wrong = 'qlr_scim_' + 'x'.repeat(32);
      for (let i = 0; i < SCIM_AUTH_FAILURES_PER_MINUTE; i += 1) {
        expect((await createUser(app, '10.9.0.1', wrong)).statusCode).toBe(401);
      }
      const limited = await createUser(app, '10.9.0.1', wrong);
      expect(limited.statusCode).toBe(429);
      expect(limited.headers['retry-after']).toBe('60');
      expect(limited.json()).toMatchObject({ status: '429' });
      // A bad token stays refused at that address, even one never tried before.
      const other = 'qlr_scim_' + 'y'.repeat(32);
      expect((await createUser(app, '10.9.0.1', other)).statusCode).toBe(429);
      // A valid token from the same address (a shared cloud egress) is not held: it proceeds.
      expect((await createUser(app, '10.9.0.1')).statusCode).toBe(201);
      // Another address is not affected, and a valid token counts no failure.
      const elsewhere = await app.inject({
        method: 'GET',
        url: '/scim/v2/ServiceProviderConfig',
        remoteAddress: '10.9.0.2',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(elsewhere.statusCode).toBe(200);
      for (let i = 0; i < SCIM_AUTH_FAILURES_PER_MINUTE + 5; i += 1) {
        const ok = await app.inject({
          method: 'GET',
          url: '/scim/v2/ServiceProviderConfig',
          remoteAddress: '10.9.0.3',
          headers: { authorization: `Bearer ${token}` },
        });
        expect(ok.statusCode).toBe(200);
      }
    } finally {
      await app.close();
    }
  });
});

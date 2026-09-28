import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createTestContext,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import { signTest, testPayload, testSigner, verifyWith } from '../../test/license';
import { createEdition, fixedEdition } from '../license/edition';
import { DAY_MS, licenseState } from '../license/state';
import { verifyLicenseKey } from '../license/verify';
import { enqueue } from '../queue/queue';
import { runUntilIdle } from '../queue/worker';
import type { QualorPlugin } from './contract';
import { loadPlugins } from './loader';
import { freezePlugins, mountPluginRoutes, pluginJobHandlers, startPluginWorker } from './mount';
import { emptyRegistry, type PluginRegistry } from './registry';

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

const ran: unknown[] = [];
const fixture: QualorPlugin = {
  name: 'fixture',
  apiVersion: 1,
  features: ['fixture.echo'],
  register(ctx) {
    ctx.routes('fixture.echo', async (app) => {
      app.get('/fixture/echo', async () => ({ ok: true, customer: ctx.license.customer }));
      app.post('/fixture/echo', async () => ({ posted: true }));
      app.get('/fixture/throw', async () => {
        throw new Error('secret detail of a plugin failure');
      });
    });
    ctx.jobs('fixture.echo', {
      'ee.fixture': async (job) => {
        ran.push(job.payload);
      },
    });
    ctx.ui('fixture.echo', {
      point: 'settings.nav',
      id: 'echo',
      label: 'Echo',
      path: '/settings/ee/echo',
    });
  },
};

describe('plugins in the app (enterprise.md §10)', () => {
  const signer = testSigner();
  const license = testPayload({ features: ['fixture.echo'], expires: '2027-10-01T00:00:00Z' });
  const lapsed = new Date(Date.parse(license.expires) + 15 * DAY_MS);
  let now = new Date('2027-01-01T00:00:00Z');
  let ctx: TestContext;
  let session: Session;
  /** The registry exactly as the loader returned it, before the context froze its copy. */
  let loaded: PluginRegistry;

  beforeAll(async () => {
    const verification = verifyLicenseKey(signTest(signer, license), verifyWith(signer, now));
    const boot = { source: 'environment' as const, keyHash: 'h', verification };
    ctx = await createTestContext({
      pluginsFor: async (db) => {
        const plugins = await loadPlugins({
          paths: ['/virtual/fixture.js'],
          state: licenseState(verification, now),
          base: { serverVersion: '0.0.0', db, logger: quietLogger() },
          checkFile: async (path) => ({ ok: true, realPath: path }),
          importModule: async () => ({ default: fixture }),
        });
        loaded = plugins;
        // Built from the frozen copy the app mounts, as bootEnterprise does.
        return {
          plugins,
          edition: (frozen) => createEdition({ boot, plugins: frozen, now: () => now }),
        };
      },
    });
    session = await login(ctx, 'admin', ADMIN_PASSWORD);
  });
  afterAll(async () => ctx.close());

  it('serves a plugin route under /api/v0/ee while its feature is active', async () => {
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/ee/fixture/echo',
      headers: session.headers,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true, customer: 'Acme Corporation' });
  });

  it('authenticates plugin routes first (401 without credentials)', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/v0/ee/fixture/echo' });
    expect(res.statusCode).toBe(401);
  });

  it('checks the CSRF header on a plugin POST made with a session', async () => {
    const withoutCsrf = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/ee/fixture/echo',
      headers: { cookie: session.headers.cookie! },
    });
    expect(withoutCsrf.statusCode).toBe(403);
    expect(withoutCsrf.json()).toMatchObject({ code: 'CSRF_FAILED' });
    const withCsrf = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/ee/fixture/echo',
      headers: session.headers,
    });
    expect(withCsrf.statusCode).toBe(200);
  });

  it('answers a plugin route that throws with 500 and no message', async () => {
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/ee/fixture/throw',
      headers: session.headers,
    });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toMatchObject({ code: 'INTERNAL_ERROR' });
    expect(res.body).not.toContain('secret detail');
  });

  it('keeps a frozen copy: changing the loaded registry afterwards changes nothing', async () => {
    expect(Object.isFrozen(ctx.plugins!)).toBe(true);
    expect(Object.isFrozen(ctx.plugins!.routes)).toBe(true);
    expect(Object.isFrozen(ctx.plugins!.routes[0])).toBe(true);
    expect(Object.isFrozen(ctx.plugins!.jobs)).toBe(true);
    expect(Object.isFrozen(ctx.plugins!.jobs[0])).toBe(true);
    const late = { plugin: 'fixture', feature: 'fixture.echo', queue: 'ee.late' };
    loaded.jobs.push({ ...late, handler: async () => {} });
    loaded.jobs[0]!.handler = async () => {
      throw new Error('swapped');
    };
    loaded.features.add('fixture.late');
    expect(ctx.plugins!.jobs.map((j) => j.queue)).toEqual(['ee.fixture']);
    expect(ctx.plugins!.features.has('fixture.late')).toBe(false);
    expect(Object.keys(pluginJobHandlers(ctx.plugins!, ctx.edition!, quietLogger()))).toEqual([
      'ee.fixture',
    ]);
  });

  it('runs a plugin job while active and skips it once the licence lapsed', async () => {
    const handlers = pluginJobHandlers(ctx.plugins!, ctx.edition!, quietLogger());
    expect(Object.isFrozen(handlers)).toBe(true);
    await enqueue(ctx.db, { queue: 'ee.fixture', payload: { n: 1 } });
    await runUntilIdle(ctx.db, handlers, quietLogger());
    expect(ran).toEqual([{ n: 1 }]);
    now = lapsed;
    await enqueue(ctx.db, { queue: 'ee.fixture', payload: { n: 2 } });
    expect(await runUntilIdle(ctx.db, handlers, quietLogger())).toBe(1); // claimed and completed
    expect(ran).toEqual([{ n: 1 }]);
  });

  it('starts a plugin worker when a plugin registered jobs', async () => {
    const worker = startPluginWorker({
      db: ctx.db,
      plugins: ctx.plugins!,
      edition: ctx.edition!,
      logger: quietLogger(),
    });
    expect(worker).not.toBeNull();
    await worker?.stop();
  });

  it('answers 403 FEATURE_NOT_LICENSED and hides the extension after the grace period', async () => {
    now = lapsed;
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/ee/fixture/echo',
      headers: session.headers,
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
    // Authentication still comes first once the licence lapsed.
    const anonymous = await ctx.app.inject({ method: 'GET', url: '/api/v0/ee/fixture/echo' });
    expect(anonymous.statusCode).toBe(401);
    const info = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/system/info',
      headers: session.headers,
    });
    expect(info.json()).toMatchObject({ edition: 'community', features: [], extensions: [] });
  });
});

describe('plugins in the app without a licence (enterprise.md §12)', () => {
  let ctx: TestContext;
  let session: Session;
  let imported = 0;

  beforeAll(async () => {
    ctx = await createTestContext({
      pluginsFor: async (db) => {
        const plugins = await loadPlugins({
          paths: ['/virtual/fixture.js'],
          state: licenseState(null, new Date()),
          base: { serverVersion: '0.0.0', db, logger: quietLogger() },
          checkFile: async (path) => ({ ok: true, realPath: path }),
          importModule: async () => {
            imported += 1;
            return { default: fixture };
          },
        });
        const boot = { source: null, keyHash: null, verification: null };
        return { plugins, edition: createEdition({ boot, plugins }) };
      },
    });
    session = await login(ctx, 'admin', ADMIN_PASSWORD);
  });
  afterAll(async () => ctx.close());

  it('imports nothing, mounts no route under /api/v0/ee and has no plugin job', async () => {
    expect(imported).toBe(0);
    expect(ctx.plugins!.routes).toEqual([]);
    expect(ctx.app.printRoutes({ commonPrefix: false })).not.toContain('/api/v0/ee');
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/ee/fixture/echo',
      headers: session.headers,
    });
    expect(res.statusCode).toBe(404);
    expect(pluginJobHandlers(ctx.plugins!, ctx.edition!, quietLogger())).toEqual({});
    const worker = startPluginWorker({
      db: ctx.db,
      plugins: ctx.plugins!,
      edition: ctx.edition!,
      logger: quietLogger(),
    });
    expect(worker).toBeNull();
  });
});

describe('mountPluginRoutes (enterprise.md §10.2)', () => {
  it('registers nothing for an empty registry', async () => {
    const app = Fastify();
    await mountPluginRoutes(app, freezePlugins(emptyRegistry()), fixedEdition());
    await app.ready();
    expect(app.printRoutes({ commonPrefix: false })).not.toContain('/api/v0/ee');
    await app.close();
  });

  it('mounts what the registry held when it was called, not what was added later', async () => {
    const registry = emptyRegistry();
    registry.routes.push({
      plugin: 'fixture',
      feature: 'fixture.echo',
      routes: async (scope) => {
        scope.get('/first', async () => ({ ok: true }));
      },
    });
    const app = Fastify();
    const mounting = mountPluginRoutes(app, registry, fixedEdition());
    registry.routes.push({
      plugin: 'fixture',
      feature: 'fixture.echo',
      routes: async (scope) => {
        scope.get('/late', async () => ({ ok: true }));
      },
    });
    await mounting;
    await app.ready();
    expect(app.printRoutes({ commonPrefix: false })).toContain('/api/v0/ee/first');
    expect(app.printRoutes({ commonPrefix: false })).not.toContain('late');
    await app.close();
  });
});

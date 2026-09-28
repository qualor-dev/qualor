import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { signTest, testPayload, testSigner, verifyWith } from '../../test/license';
import { installErrorHandling } from '../http/problem';
import { createEdition } from '../license/edition';
import { licenseState } from '../license/state';
import { verifyLicenseKey } from '../license/verify';
import type { QualorPlugin } from './contract';
import { loadPlugins } from './loader';
import {
  dropPluginsThatFailToMount,
  freezePlugins,
  mountPluginRoutes,
  pluginJobHandlers,
} from './mount';
import { PluginError } from './registry';

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

const signer = testSigner();
const now = new Date('2027-01-01T00:00:00Z');

/** Loads the given plugins (one virtual path each) under a licence listing `features`. */
async function load(plugins: QualorPlugin[], features: string[]) {
  const license = testPayload({ features });
  const verification = verifyLicenseKey(signTest(signer, license), verifyWith(signer, now));
  const registry = await loadPlugins({
    paths: plugins.map((p) => `/virtual/${p.name}.js`),
    state: licenseState(verification, now),
    base: { serverVersion: '0.0.0', db: {} as never, logger: quietLogger() },
    checkFile: async (path) => ({ ok: true, realPath: path }),
    importModule: async (url) => ({
      default: plugins.find((p) => url.endsWith(`/${p.name}.js`)),
    }),
  });
  const boot = { source: 'environment' as const, keyHash: 'h', verification };
  return {
    registry,
    boot,
    edition: (frozen = freezePlugins(registry)) =>
      createEdition({ boot, plugins: frozen, now: () => now }),
  };
}

const claimed = (queue: string) => ({ id: 'j1', queue, payload: { n: 1 }, attempts: 1 }) as never;

describe('a plugin with two features, one of them licensed (enterprise.md §10.2, §10.3)', () => {
  const ran: string[] = [];
  const duo: QualorPlugin = {
    name: 'duo',
    apiVersion: 1,
    features: ['duo.on', 'duo.off'],
    register(ctx) {
      ctx.routes('duo.on', async (app) => {
        app.get('/duo/on', async () => ({ ok: true }));
      });
      ctx.routes('duo.off', async (app) => {
        app.get('/duo/off', async () => ({ ok: true }));
      });
      ctx.jobs('duo.on', { 'ee.duo.on': async () => void ran.push('on') });
      ctx.jobs('duo.off', { 'ee.duo.off': async () => void ran.push('off') });
    },
  };

  it('serves the licensed feature and answers 403 for the other, route by route and job by job', async () => {
    const { registry, edition } = await load([duo], ['duo.on']);
    const app = Fastify();
    installErrorHandling(app);
    const frozen = freezePlugins(registry);
    await mountPluginRoutes(app, frozen, edition(frozen));
    await app.ready();
    expect((await app.inject({ url: '/api/v0/ee/duo/on' })).statusCode).toBe(200);
    const off = await app.inject({ url: '/api/v0/ee/duo/off' });
    expect(off.statusCode).toBe(403);
    expect(off.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
    await app.close();

    const handlers = pluginJobHandlers(frozen, edition(frozen), quietLogger());
    await handlers['ee.duo.on']!(claimed('ee.duo.on'));
    await handlers['ee.duo.off']!(claimed('ee.duo.off'));
    expect(ran).toEqual(['on']);
  });
});

describe('the frozen registry (enterprise.md §10)', () => {
  it('refuses to add or remove a feature, and the edition keeps its own copy', async () => {
    const one: QualorPlugin = {
      name: 'one',
      apiVersion: 1,
      features: ['one.x'],
      register: () => {},
    };
    const { registry, boot } = await load([one], ['one.x', 'one.y']);
    const frozen = freezePlugins(registry);
    const features = frozen.features as Set<string>;
    expect(() => features.add('one.y')).toThrow(TypeError);
    expect(() => features.delete('one.x')).toThrow(TypeError);
    expect(() => features.clear()).toThrow(TypeError);
    expect([...frozen.features]).toEqual(['one.x']);
    // The edition copies what it was given: a later change to the source set changes nothing.
    const source = new Set(['one.x']);
    const copy = createEdition({ boot, plugins: { ...frozen, features: source }, now: () => now });
    source.add('one.y');
    expect(copy.activeFeatures()).toEqual(['one.x']);
  });
});

describe('plugin routes that fail to mount (ruling R-MOUNT)', () => {
  const route = (name: string, path: string, extra: Partial<QualorPlugin> = {}): QualorPlugin => ({
    name,
    apiVersion: 1,
    features: [`${name}.x`],
    register(ctx) {
      ctx.routes(`${name}.x`, async (app) => {
        app.get(path, async () => ({ plugin: name }));
      });
      ctx.jobs(`${name}.x`, { [`ee.${name}`]: async () => {} });
      ctx.limits(`${name}.x`, { llm: { maxFixPerOrganizationPerDay: 99 } });
      ctx.ui(`${name}.x`, {
        point: 'settings.nav',
        id: name,
        label: name,
        path: `/settings/ee/${name}`,
      });
    },
    ...extra,
  });
  let enqueueOfBroken: ((queue: string, payload: unknown) => Promise<string>) | undefined;
  const broken: QualorPlugin = {
    name: 'broken',
    apiVersion: 1,
    features: ['broken.x'],
    register(ctx) {
      enqueueOfBroken = ctx.enqueue;
      ctx.routes('broken.x', async (app) => {
        app.get('/broken', async () => ({ plugin: 'broken' }));
        throw new Error('boom at mount');
      });
      ctx.jobs('broken.x', { 'ee.broken': async () => {} });
      ctx.limits('broken.x', { llm: { maxFixPerOrganizationPerDay: 500 } });
      ctx.ui('broken.x', {
        point: 'settings.nav',
        id: 'broken',
        label: 'Broken',
        path: '/settings/ee/broken',
      });
    },
  };

  it('drops a throwing plugin and a duplicate path as a whole, reports them failed, and boots', async () => {
    const plugins = [
      route('first', '/same'),
      broken,
      route('second', '/same'),
      route('third', '/third'),
    ];
    const { registry, edition } = await load(plugins, [
      'first.x',
      'broken.x',
      'second.x',
      'third.x',
    ]);
    const errors: unknown[] = [];
    await dropPluginsThatFailToMount(registry, {
      error: (fields: unknown) => errors.push(fields),
    } as never);
    expect(registry.reports.map((r) => [r.name, r.state])).toEqual([
      ['first', 'loaded'],
      ['broken', 'failed'],
      ['second', 'failed'],
      ['third', 'loaded'],
    ]);
    expect(registry.reports[1]!.error).toBe('its routes failed to mount: boom at mount');
    expect(registry.reports[2]!.error).toMatch(
      /GET \/api\/v0\/ee\/same is already declared by the plugin first/,
    );
    expect(errors).toHaveLength(2);
    expect(registry.routes.map((r) => r.plugin)).toEqual(['first', 'third']);
    expect(registry.jobs.map((j) => j.queue)).toEqual(['ee.first', 'ee.third']);
    expect(registry.extensions.map((e) => e.extension.id)).toEqual(['first', 'third']);
    expect(registry.limitOverrides.map((o) => o.feature)).toEqual(['first.x', 'third.x']);
    expect([...registry.features].sort()).toEqual(['first.x', 'third.x']);
    await expect(enqueueOfBroken!('ee.broken', {})).rejects.toThrow(PluginError);

    const frozen = freezePlugins(registry);
    const ed = edition(frozen);
    expect(ed.activeFeatures()).toEqual(['first.x', 'third.x']);
    expect(ed.limits().llm.maxFixPerOrganizationPerDay).toBe(99);
    const app = Fastify();
    installErrorHandling(app);
    await mountPluginRoutes(app, frozen, ed);
    await app.ready();
    expect((await app.inject({ url: '/api/v0/ee/same' })).json()).toEqual({ plugin: 'first' });
    expect((await app.inject({ url: '/api/v0/ee/third' })).statusCode).toBe(200);
    expect((await app.inject({ url: '/api/v0/ee/broken' })).statusCode).toBe(404);
    await app.close();
  });
});

describe('plugin job time limit (enterprise.md §10.3)', () => {
  it('fails a job that outlives its deadline and aborts its signal', async () => {
    let signal: AbortSignal | undefined;
    const hanging: QualorPlugin = {
      name: 'hang',
      apiVersion: 1,
      features: ['hang.x'],
      register(ctx) {
        ctx.jobs('hang.x', {
          'ee.hang': (job) => {
            signal = job.signal;
            return new Promise(() => {});
          },
        });
      },
    };
    const { registry, edition } = await load([hanging], ['hang.x']);
    const frozen = freezePlugins(registry);
    const handlers = pluginJobHandlers(frozen, edition(frozen), quietLogger(), { timeoutMs: 20 });
    await expect(handlers['ee.hang']!(claimed('ee.hang'))).rejects.toThrow(/did not finish within/);
    expect(signal?.aborted).toBe(true);
  });
});

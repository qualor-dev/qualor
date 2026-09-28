import { sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { testPayload, testSigner, verifyWith } from '../../test/license';
import type { LicenseState } from '../license/state';
import { verifyLicenseKey } from '../license/verify';
import type { PluginContext, QualorPlugin } from './contract';
import { loadPlugins } from './loader';
import { emptyRegistry, PluginError, StagedPlugin, validatePlugin } from './registry';

const quiet = { debug() {}, info() {}, warn() {}, error() {} };
const base = { serverVersion: '0.0.0', db: {} as never, logger: quiet, license: testPayload() };
const plugin = (over: Partial<QualorPlugin> = {}): QualorPlugin => ({
  name: 'fixture',
  apiVersion: 1,
  features: ['fixture.echo'],
  register: () => {},
  ...over,
});

describe('validatePlugin (enterprise.md §10)', () => {
  it.each([
    ['not an object', 42],
    ['a bad name', plugin({ name: 'Fixture' })],
    ['another API version', { ...plugin(), apiVersion: 2 }],
    ['a bad feature name', plugin({ features: ['Echo'] })],
    ['no feature at all', plugin({ features: [] })],
    ['a features array with a fractional length', { ...plugin(), features: { length: 1.5 } }],
    ['a features list that is not an array', { ...plugin(), features: { length: 1, 0: 'x' } }],
    ['no register function', { ...plugin(), register: 'nope' }],
  ])('rejects %s', (_what, value) => {
    expect(() => validatePlugin(value)).toThrow(PluginError);
  });

  it('keeps a plain copy, reading each field once', () => {
    let reads = 0;
    const tricky = {
      apiVersion: 1,
      features: ['fixture.echo'],
      register: () => {},
      get name() {
        reads += 1;
        return reads === 1 ? 'fixture' : 'Not A Valid Name';
      },
    };
    const valid = validatePlugin(tricky);
    expect(valid.name).toBe('fixture');
    expect(valid.name).toBe('fixture');
    expect(reads).toBe(1);
    expect(Object.isFrozen(valid)).toBe(true);
    expect(Object.isFrozen(valid.features)).toBe(true);
  });

  it('copies the features, so a later change to the array changes nothing', () => {
    const features = ['fixture.echo'];
    const valid = validatePlugin(plugin({ features }));
    features.push('Bad Feature');
    expect(valid.features).toEqual(['fixture.echo']);
  });
});

describe('StagedPlugin (ruling EE4)', () => {
  it('stages every kind of registration and commits them together', () => {
    const registry = emptyRegistry();
    const staged = new StagedPlugin(plugin(), registry);
    const ctx = staged.context(base, registry);
    ctx.routes('fixture.echo', async () => {});
    ctx.jobs('fixture.echo', { 'ee.fixture': async () => {} });
    ctx.limits('fixture.echo', { llm: { maxFixPerOrganizationPerDay: 500 } });
    ctx.ui('fixture.echo', {
      point: 'settings.nav',
      id: 'echo',
      label: 'Echo',
      path: '/settings/ee/echo',
    });
    expect(registry.routes).toHaveLength(0);
    staged.commit(registry);
    expect(registry.routes).toHaveLength(1);
    expect(registry.jobs.map((j) => j.queue)).toEqual(['ee.fixture']);
    expect(registry.limitOverrides).toHaveLength(1);
    expect(registry.extensions).toHaveLength(1);
    expect([...registry.features]).toEqual(['fixture.echo']);
    expect(registry.reports).toEqual([
      { name: 'fixture', state: 'loaded', features: ['fixture.echo'], error: null },
    ]);
  });

  it.each<[string, (ctx: PluginContext) => void]>([
    ['a feature it does not declare', (ctx) => ctx.routes('sso', async () => {})],
    ['a queue outside ee.*', (ctx) => ctx.jobs('fixture.echo', { analysis: async () => {} })],
    [
      'an extension path outside /settings/ee',
      (ctx) =>
        ctx.ui('fixture.echo', { point: 'settings.nav', id: 'x', label: 'X', path: '/admin' }),
    ],
    [
      'a limit other than llm (the retired organisation limit)',
      (ctx) => ctx.limits('fixture.echo', { organizations: 99 } as never),
    ],
    [
      'a fix quota over 100 000',
      (ctx) => ctx.limits('fixture.echo', { llm: { maxFixPerOrganizationPerDay: 100_001 } }),
    ],
    [
      'a negative fix quota',
      (ctx) => ctx.limits('fixture.echo', { llm: { maxFixPerOrganizationPerDay: -1 } }),
    ],
    [
      'a fractional fix quota',
      (ctx) => ctx.limits('fixture.echo', { llm: { maxFixPerOrganizationPerDay: 1.5 } }),
    ],
    [
      'a fix quota that is a string',
      (ctx) => ctx.limits('fixture.echo', { llm: { maxFixPerOrganizationPerDay: '5' } } as never),
    ],
    [
      'an unknown llm limit',
      (ctx) => ctx.limits('fixture.echo', { llm: { maxTokens: 5 } } as never),
    ],
    [
      'a non-boolean automaticFixSuggestions',
      (ctx) => ctx.limits('fixture.echo', { llm: { automaticFixSuggestions: 1 } } as never),
    ],
    ['an override that is not an object', (ctx) => ctx.limits('fixture.echo', null as never)],
    ['llm that is not an object', (ctx) => ctx.limits('fixture.echo', { llm: 5 } as never)],
    ['routes that are not a function', (ctx) => ctx.routes('fixture.echo', 'x' as never)],
    [
      'a job handler that is not a function',
      (ctx) => ctx.jobs('fixture.echo', { 'ee.fixture': 'x' } as never),
    ],
    [
      'a label longer than 40 characters',
      (ctx) =>
        ctx.ui('fixture.echo', {
          point: 'settings.nav',
          id: 'echo',
          label: 'x'.repeat(41),
          path: '/settings/ee/echo',
        }),
    ],
    [
      'an unknown extension point',
      (ctx) =>
        ctx.ui('fixture.echo', {
          point: 'admin.nav',
          id: 'echo',
          label: 'Echo',
          path: '/settings/ee/echo',
        } as never),
    ],
  ])('refuses %s when it is registered', (_what, call) => {
    const registry = emptyRegistry();
    const ctx = new StagedPlugin(plugin(), registry).context(base, registry);
    expect(() => call(ctx)).toThrow(PluginError);
  });

  it('reads an LLM limit override once and keeps a plain copy (a getter cannot change it later)', () => {
    const registry = emptyRegistry();
    const staged = new StagedPlugin(plugin(), registry);
    const ctx = staged.context(base, registry);
    let reads = 0;
    const llm = {
      get maxFixPerOrganizationPerDay() {
        reads += 1;
        return reads === 1 ? 500 : 1_000_000_000;
      },
    };
    let llmReads = 0;
    const override = {
      get llm() {
        llmReads += 1;
        return llm;
      },
    };
    ctx.limits('fixture.echo', override);
    staged.commit(registry);
    const stored = registry.limitOverrides[0]!.override;
    expect(stored.llm?.maxFixPerOrganizationPerDay).toBe(500);
    expect(stored.llm?.maxFixPerOrganizationPerDay).toBe(500);
    expect(reads).toBe(1);
    expect(llmReads).toBe(1);
    expect(Object.getOwnPropertyDescriptor(stored.llm, 'maxFixPerOrganizationPerDay')).toEqual(
      expect.objectContaining({ value: 500, writable: false }),
    );
  });

  it('refuses a getter that returns a bad value on its one read', () => {
    const registry = emptyRegistry();
    const ctx = new StagedPlugin(plugin(), registry).context(base, registry);
    const llm = {
      get maxFixPerOrganizationPerDay() {
        return 1_000_000_000;
      },
    };
    expect(() => ctx.limits('fixture.echo', { llm })).toThrow(PluginError);
  });

  it('keeps a plain copy of a UI extension', () => {
    const registry = emptyRegistry();
    const staged = new StagedPlugin(plugin(), registry);
    const ctx = staged.context(base, registry);
    let reads = 0;
    const extension = {
      point: 'settings.nav' as const,
      label: 'Echo',
      path: '/settings/ee/echo',
      get id() {
        reads += 1;
        return reads === 1 ? 'echo' : 'Bad Id';
      },
    };
    ctx.ui('fixture.echo', extension);
    staged.commit(registry);
    expect(registry.extensions[0]!.extension).toEqual({
      point: 'settings.nav',
      id: 'echo',
      label: 'Echo',
      path: '/settings/ee/echo',
    });
    expect(reads).toBe(1);
  });

  it('refuses a second plugin with the same name or feature', () => {
    const registry = emptyRegistry();
    new StagedPlugin(plugin(), registry).commit(registry);
    expect(() => new StagedPlugin(plugin(), registry)).toThrow(/name/);
    expect(() => new StagedPlugin(plugin({ name: 'other' }), registry)).toThrow(/fixture\.echo/);
  });

  it('refuses a queue another plugin already registered', () => {
    const registry = emptyRegistry();
    const first = new StagedPlugin(plugin(), registry);
    first.context(base, registry).jobs('fixture.echo', { 'ee.shared': async () => {} });
    first.commit(registry);
    const second = new StagedPlugin(
      plugin({ name: 'other', features: ['other.echo'] }),
      registry,
    ).context(base, registry);
    expect(() => second.jobs('other.echo', { 'ee.shared': async () => {} })).toThrow(PluginError);
  });

  it('refuses registrations after it was committed or discarded', () => {
    const registry = emptyRegistry();
    const committed = new StagedPlugin(plugin(), registry);
    const ctx = committed.context(base, registry);
    committed.commit(registry);
    expect(() => ctx.routes('fixture.echo', async () => {})).toThrow(PluginError);
    expect(registry.routes).toHaveLength(0);

    const discarded = new StagedPlugin(plugin({ name: 'late', features: ['late.x'] }), registry);
    const late = discarded.context(base, registry);
    late.routes('late.x', async () => {});
    discarded.discard();
    expect(() => late.routes('late.x', async () => {})).toThrow(PluginError);
    expect(() => discarded.commit(registry)).toThrow(PluginError);
    expect(registry.routes).toHaveLength(0);
  });

  it('gives the plugin a frozen licence, its features included', () => {
    const ctx = new StagedPlugin(plugin(), emptyRegistry()).context(base, emptyRegistry());
    expect(Object.isFrozen(ctx.license)).toBe(true);
    expect(Object.isFrozen(ctx.license.features)).toBe(true);
    expect(() => (ctx.license.features as string[]).push('sso')).toThrow(TypeError);
    expect(base.license.features).toEqual(['llm.fix-quota']);
  });

  it('owns a queue by its committed instance, not by its name', async () => {
    const registry = emptyRegistry();
    // A first instance named "fixture" stages ee.fixture, then fails (discarded).
    const failed = new StagedPlugin(plugin(), registry);
    const failedCtx = failed.context(base, registry);
    failedCtx.jobs('fixture.echo', { 'ee.fixture': async () => {} });
    failed.discard();
    // A second instance with the same name registers the same queue and is committed.
    const loaded = new StagedPlugin(plugin(), registry);
    loaded.context(base, registry).jobs('fixture.echo', { 'ee.fixture': async () => {} });
    loaded.commit(registry);
    expect(registry.jobs.map((j) => j.queue)).toEqual(['ee.fixture']);
    await expect(failedCtx.enqueue('ee.fixture', {})).rejects.toThrow(PluginError);
  });

  it('lets a plugin enqueue only on its own queues', async () => {
    const registry = emptyRegistry();
    const staged = new StagedPlugin(plugin(), registry);
    const ctx = staged.context(base, registry);
    ctx.jobs('fixture.echo', { 'ee.fixture': async () => {} });
    staged.commit(registry);
    await expect(ctx.enqueue('analysis', {})).rejects.toThrow(PluginError);
    await expect(ctx.enqueue('ee.other', {})).rejects.toThrow(PluginError);
  });
});

const licensed: LicenseState = {
  state: 'active',
  reason: null,
  kid: 'test-a',
  license: testPayload(),
  graceEndsAt: new Date(),
  expiresSoon: false,
  licensed: true,
};

/** Runs the loader on one plugin, as main.ts does, without services (a core test's base). */
function load(value: QualorPlugin) {
  return loadPlugins({
    paths: ['/virtual/plugin.js'],
    state: licensed,
    base: {
      serverVersion: '0.0.0',
      db: {} as never,
      logger: { ...quiet, child: () => ({ ...quiet }) } as never,
    },
    checkFile: async (path) => ({ ok: true, realPath: path }),
    importModule: async () => ({ default: value }),
  });
}

describe('the licence a plugin sees (enterprise.md §3.1, §17 item 9)', () => {
  it('ctx.license of a pre-5A key carries no organizations', async () => {
    // A key signed over a payload with the retired member, as keys were before 5A.
    const signer = testSigner();
    const payload = testPayload();
    const body = Buffer.from(JSON.stringify({ ...payload, organizations: 10 })).toString(
      'base64url',
    );
    const input = `QLK1.${signer.kid}.${body}`;
    const key = `${input}.${sign(null, Buffer.from(input), signer.privateKey).toString('base64url')}`;
    const verified = verifyLicenseKey(key, verifyWith(signer));
    if (!verified.ok) throw new Error(`the pre-5A key did not verify: ${verified.reason}`);

    let seen: PluginContext['license'] | undefined;
    await loadPlugins({
      paths: ['/virtual/plugin.js'],
      state: { ...licensed, kid: verified.kid, license: verified.license },
      base: {
        serverVersion: '0.0.0',
        db: {} as never,
        logger: { ...quiet, child: () => ({ ...quiet }) } as never,
      },
      checkFile: async (path) => ({ ok: true, realPath: path }),
      importModule: async () => ({
        default: plugin({
          register(ctx) {
            seen = ctx.license;
          },
        }),
      }),
    });
    expect(seen).toEqual(payload);
    expect(Object.keys(seen!)).not.toContain('organizations');
  });
});

describe('plugin contract additions (rbac-audit.md §15)', () => {
  it('stages a schedule of one of the plugin’s own queues, within 10 s and a day', async () => {
    const plugin: QualorPlugin = {
      name: 'sched',
      apiVersion: 1,
      features: ['f'],
      register(ctx) {
        ctx.jobs('f', { 'ee.tick': async () => {} });
        ctx.schedule('f', 'ee.tick', 10);
      },
    };
    const registry = await load(plugin);
    expect(registry.schedules).toEqual([
      { plugin: 'sched', feature: 'f', queue: 'ee.tick', everySeconds: 10 },
    ]);
  });

  it('accepts a queue registered after its schedule, in the same register', async () => {
    const registry = await load({
      name: 'sched',
      apiVersion: 1,
      features: ['f'],
      register(ctx) {
        ctx.schedule('f', 'ee.tick', 86_400);
        ctx.jobs('f', { 'ee.tick': async () => {} });
      },
    });
    expect(registry.reports[0]).toMatchObject({ state: 'loaded' });
    expect(registry.schedules).toEqual([
      { plugin: 'sched', feature: 'f', queue: 'ee.tick', everySeconds: 86_400 },
    ]);
  });

  it.each<[string, (ctx: PluginContext) => void]>([
    ['a queue it did not register', (ctx) => ctx.schedule('f', 'ee.other', 60)],
    [
      'an interval below 10 s',
      (ctx) => {
        ctx.jobs('f', { 'ee.tick': async () => {} });
        ctx.schedule('f', 'ee.tick', 9);
      },
    ],
    [
      'an interval above a day',
      (ctx) => {
        ctx.jobs('f', { 'ee.tick': async () => {} });
        ctx.schedule('f', 'ee.tick', 86_401);
      },
    ],
    [
      'a fractional interval',
      (ctx) => {
        ctx.jobs('f', { 'ee.tick': async () => {} });
        ctx.schedule('f', 'ee.tick', 10.5);
      },
    ],
    [
      'a feature it does not declare',
      (ctx) => {
        ctx.jobs('f', { 'ee.tick': async () => {} });
        ctx.schedule('g', 'ee.tick', 60);
      },
    ],
    [
      'the same queue scheduled twice',
      (ctx) => {
        ctx.jobs('f', { 'ee.tick': async () => {} });
        ctx.schedule('f', 'ee.tick', 60);
        ctx.schedule('f', 'ee.tick', 120);
      },
    ],
  ])('fails the plugin for %s', async (_what, register) => {
    const registry = await load({ name: 'sched', apiVersion: 1, features: ['f'], register });
    expect(registry.reports[0]).toMatchObject({ state: 'failed' });
    expect(registry.schedules).toEqual([]);
    expect(registry.jobs).toEqual([]);
  });

  it('loads a 4B plugin that uses none of the new members, without services', async () => {
    const registry = await load({
      name: 'old',
      apiVersion: 1,
      features: ['f'],
      register(ctx) {
        ctx.routes('f', async () => {});
        ctx.jobs('f', { 'ee.old': async () => {} });
      },
    });
    expect(registry.reports).toEqual([
      { name: 'old', state: 'loaded', features: ['f'], error: null },
    ]);
    expect(registry.schedules).toEqual([]);
  });

  it('names the missing service when a plugin uses one the context was not given', async () => {
    let caught: unknown;
    const registry = await load({
      name: 'svc',
      apiVersion: 1,
      features: ['f'],
      register(ctx) {
        expect(Object.isFrozen(ctx.access)).toBe(true);
        try {
          ctx.audit.head();
        } catch (err) {
          caught = err;
        }
        ctx.sso.listConnections();
      },
    });
    expect(caught).toBeInstanceOf(PluginError);
    expect((caught as Error).message).toBe('the audit service is not available in this context');
    expect(registry.reports[0]).toMatchObject({
      state: 'failed',
      error: expect.stringContaining('the sso service is not available'),
    });
  });

  it('passes the services of the base through, as they are', () => {
    const services = Object.freeze({
      access: Object.freeze({}),
      audit: Object.freeze({}),
      sso: Object.freeze({}),
      scim: Object.freeze({}),
    }) as never;
    const registry = emptyRegistry();
    const ctx = new StagedPlugin(plugin(), registry).context({ ...base, services }, registry);
    expect(ctx.access).toBe((services as { access: unknown }).access);
    // rbac-audit.md §15: no rbac service since 5B.
    expect('rbac' in ctx).toBe(false);
    expect(ctx.audit).toBe((services as { audit: unknown }).audit);
    expect(ctx.sso).toBe((services as { sso: unknown }).sso);
    expect(ctx.scim).toBe((services as { scim: unknown }).scim);
    expect(Object.isFrozen(ctx)).toBe(true);
  });
});

describe('plugin contract additions (sso-scim.md §17.1)', () => {
  it('fails a plugin that uses ctx.sso without services, naming sso', async () => {
    const registry = await load({
      name: 'sso-user',
      apiVersion: 1,
      features: ['sso'],
      register(ctx) {
        void ctx.sso.listConnections();
      },
    });
    expect(registry.reports[0]).toMatchObject({
      state: 'failed',
      error: expect.stringContaining('the sso service is not available in this context'),
    });
  });

  it('gives stand-ins for every member of ctx.sso and ctx.scim, each throwing', async () => {
    let sso: Record<string, unknown> = {};
    let scim: Record<string, unknown> = {};
    const registry = await load({
      name: 'sso-probe',
      apiVersion: 1,
      features: ['sso', 'scim'],
      register(ctx) {
        sso = { ...ctx.sso };
        scim = { ...ctx.scim };
        expect(Object.isFrozen(ctx.sso)).toBe(true);
        expect(Object.isFrozen(ctx.scim)).toBe(true);
      },
    });
    expect(registry.reports[0]).toMatchObject({ state: 'loaded' });
    expect(Object.keys(sso).sort()).toEqual(
      [
        'listConnections',
        'getConnection',
        'createConnection',
        'updateConnection',
        'deleteConnection',
        'testConnection',
        'readSamlMetadata',
        'mappings',
        'replaceMappings',
        'signInSettings',
        'updateSignInSettings',
        'userIdentities',
        'unlinkIdentity',
        'spMetadata',
        'start',
        'startLink',
        'oidcCallback',
        'samlAcs',
        'finish',
      ].sort(),
    );
    expect(Object.keys(scim).sort()).toEqual(
      ['handle', 'listTokens', 'createToken', 'revokeToken'].sort(),
    );
    for (const [name, fn] of [
      ...Object.entries(sso).map(([k, v]) => [`sso.${k}`, v] as const),
      ...Object.entries(scim).map(([k, v]) => [`scim.${k}`, v] as const),
    ]) {
      const service = name.split('.')[0] ?? '';
      expect(() => (fn as () => unknown)(), name).toThrow(
        `the ${service} service is not available in this context`,
      );
    }
  });
});

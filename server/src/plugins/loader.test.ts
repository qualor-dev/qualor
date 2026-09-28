import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { testPayload } from '../../test/license';
import type { LicenseState } from '../license/state';
import type { QualorPlugin } from './contract';
import { describePluginError, loadPlugins, REGISTER_TIMEOUT_MS } from './loader';

const license = testPayload();
const licensed: LicenseState = {
  state: 'active',
  reason: null,
  kid: 'test-a',
  license,
  graceEndsAt: new Date(),
  expiresSoon: false,
  licensed: true,
};
const grace: LicenseState = { ...licensed, state: 'grace' };
const unlicensed: [string, LicenseState][] = [
  ['no licence', { ...licensed, state: 'none', license: null, licensed: false }],
  [
    'an invalid licence',
    { ...licensed, state: 'invalid', reason: 'bad-signature', license: null, licensed: false },
  ],
  ['an expired licence', { ...licensed, state: 'expired', licensed: false }],
  // A verified signature, so the licence is known, but the key is refused (enterprise.md §9.1).
  [
    'a revoked licence',
    { ...licensed, state: 'invalid', reason: 'revoked', license, licensed: false },
  ],
  [
    'a licence that is not valid yet',
    { ...licensed, state: 'invalid', reason: 'not-yet-valid', license, licensed: false },
  ],
];
function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}
const base = { serverVersion: '0.0.0', db: {} as never, logger: quietLogger() };
const PATH = '/opt/plugins/fixture.js';
const fixture: QualorPlugin = {
  name: 'fixture',
  apiVersion: 1,
  features: ['fixture.echo'],
  register: (ctx) => ctx.routes('fixture.echo', async () => {}),
};
const isFile = async (path: string) => ({ ok: true as const, realPath: path });

describe('loadPlugins (enterprise.md §10, §12)', () => {
  it('gives register 10 s', () => {
    expect(REGISTER_TIMEOUT_MS).toBe(10_000);
  });

  it.each(unlicensed)('with %s, never stats or imports a plugin path', async (_what, state) => {
    const importModule = vi.fn();
    const checkFile = vi.fn();
    const registry = await loadPlugins({ paths: [PATH], state, base, importModule, checkFile });
    expect(importModule).not.toHaveBeenCalled();
    expect(checkFile).not.toHaveBeenCalled();
    expect(registry.reports).toEqual([]);
  });

  it('never trusts a state that claims to be licensed without being active or in grace', async () => {
    const importModule = vi.fn();
    const checkFile = vi.fn();
    const odd: LicenseState = { ...licensed, state: 'expired', licensed: true };
    await loadPlugins({ paths: [PATH], state: odd, base, importModule, checkFile });
    await loadPlugins({
      paths: [PATH],
      state: { ...licensed, license: null },
      base,
      importModule,
      checkFile,
    });
    expect(importModule).not.toHaveBeenCalled();
    expect(checkFile).not.toHaveBeenCalled();
  });

  it('loads a plugin by file URL while licensed or in grace', async () => {
    for (const state of [licensed, grace]) {
      const importModule = vi.fn(async () => ({ default: fixture }));
      const registry = await loadPlugins({
        paths: [PATH],
        state,
        base,
        importModule,
        checkFile: isFile,
      });
      expect(importModule).toHaveBeenCalledWith(expect.stringMatching(/^file:\/\/.*fixture\.js$/));
      expect(registry.reports).toEqual([
        { name: 'fixture', state: 'loaded', features: ['fixture.echo'], error: null },
      ]);
      expect(registry.routes).toHaveLength(1);
    }
  });

  it('refuses a path that is not an absolute .js or .mjs file, before touching it', async () => {
    const importModule = vi.fn();
    const checkFile = vi.fn(isFile);
    const registry = await loadPlugins({
      paths: ['relative/plugin.js', '/opt/plugins/plugin.ts', '/opt/plugins/a\0.js'],
      state: licensed,
      base,
      importModule,
      checkFile,
    });
    expect(registry.reports.map((r) => r.state)).toEqual(['failed', 'failed', 'failed']);
    expect(checkFile).not.toHaveBeenCalled();
    expect(importModule).not.toHaveBeenCalled();
  });

  it('refuses more than 8 paths', async () => {
    const importModule = vi.fn(async () => ({ default: fixture }));
    const paths = Array.from({ length: 9 }, (_, i) => `/opt/plugins/p${i}.js`);
    await expect(
      loadPlugins({ paths, state: licensed, base, importModule, checkFile: isFile }),
    ).rejects.toThrow(/at most 8/);
    expect(importModule).not.toHaveBeenCalled();
  });

  it('reports a missing file, a bad module and a throwing register, and applies nothing of them', async () => {
    const throwing: QualorPlugin = {
      ...fixture,
      name: 'throwing',
      register: (ctx) => {
        ctx.routes('fixture.echo', async () => {});
        throw new Error('boom');
      },
    };
    const byName: Record<string, unknown> = {
      'bad.js': { default: { name: 'x' } },
      'throwing.js': { default: throwing },
    };
    const registry = await loadPlugins({
      paths: ['/p/missing.js', '/p/bad.js', '/p/throwing.js'],
      state: licensed,
      base,
      checkFile: async (p: string) =>
        p.endsWith('missing.js')
          ? { ok: false, reason: 'the plugin file does not exist or cannot be resolved' }
          : { ok: true, realPath: p },
      importModule: async (url: string) => byName[url.split('/').at(-1)!],
    });
    expect(registry.reports.map((r) => [r.name, r.state])).toEqual([
      ['missing.js', 'failed'],
      ['bad.js', 'failed'],
      ['throwing', 'failed'],
    ]);
    expect(registry.reports[2]!.error).toContain('boom');
    expect(registry.routes).toEqual([]);
  });

  it('fails a register that does not finish within the timeout', async () => {
    const hanging: QualorPlugin = { ...fixture, register: () => new Promise(() => {}) };
    const registry = await loadPlugins({
      paths: [PATH],
      state: licensed,
      base,
      checkFile: isFile,
      importModule: async () => ({ default: hanging }),
      timeoutMs: 20,
    });
    expect(registry.reports[0]!.state).toBe('failed');
    expect(registry.reports[0]!.error).toContain('did not register within');
  });

  it('leaves no partial registration from a slow plugin, even when it registers after the timeout', async () => {
    let late: (() => void) | undefined;
    let lateRefused = false;
    const slow: QualorPlugin = {
      name: 'slow',
      apiVersion: 1,
      features: ['slow.x'],
      register: (ctx) => {
        ctx.routes('slow.x', async () => {});
        ctx.limits('slow.x', { llm: { maxFixPerOrganizationPerDay: 5 } });
        return new Promise<void>((resolve) => {
          late = () => {
            try {
              ctx.routes('slow.x', async () => {});
              ctx.jobs('slow.x', { 'ee.slow': async () => {} });
            } catch {
              lateRefused = true;
            } finally {
              resolve();
            }
          };
        });
      },
    };
    const registry = await loadPlugins({
      paths: ['/p/slow.js', PATH],
      state: licensed,
      base,
      checkFile: isFile,
      importModule: async (url: string) => ({
        default: url.endsWith('slow.js') ? slow : fixture,
      }),
      timeoutMs: 20,
    });
    late?.();
    await Promise.resolve();
    expect(lateRefused).toBe(true);
    expect(registry.reports.map((r) => [r.name, r.state])).toEqual([
      ['slow', 'failed'],
      ['fixture', 'loaded'],
    ]);
    expect(registry.routes.map((r) => r.plugin)).toEqual(['fixture']);
    expect(registry.jobs).toEqual([]);
    expect(registry.limitOverrides).toEqual([]);
    expect(registry.features.has('slow.x')).toBe(false);
  });

  it('imports the resolved path, and skips a refused file without importing it (R-PLUGINPATH)', async () => {
    const importModule = vi.fn(async () => ({ default: fixture }));
    const errors: unknown[] = [];
    const logger = {
      debug() {},
      info() {},
      warn() {},
      error: (fields: unknown) => errors.push(fields),
      child: () => quietLogger(),
    } as never;
    const registry = await loadPlugins({
      paths: ['/etc/qualor/plugins/link.js', '/opt/plugins/writable.js'],
      state: licensed,
      base: { ...base, logger },
      importModule,
      checkFile: async (p: string) =>
        p.endsWith('link.js')
          ? { ok: true, realPath: '/opt/plugins/target.js' }
          : { ok: false, reason: 'the plugin file is writable by group or others' },
    });
    expect(importModule).toHaveBeenCalledTimes(1);
    expect(importModule).toHaveBeenCalledWith(
      expect.stringMatching(/^file:\/\/.*\/opt\/plugins\/target\.js$/),
    );
    expect(registry.reports.map((r) => [r.name, r.state, r.error])).toEqual([
      ['fixture', 'loaded', null],
      ['writable.js', 'failed', 'the plugin file is writable by group or others'],
    ]);
    expect(errors).toEqual([
      {
        plugin: 'writable.js',
        path: '/opt/plugins/writable.js',
        err: 'the plugin file is writable by group or others',
      },
    ]);
  });

  it('reports a database error of a plugin without its SQL or parameters (like the logger)', async () => {
    const leaky: QualorPlugin = {
      ...fixture,
      register: () => {
        const err = Object.assign(
          new Error('Failed query: insert into t values ($1)\nparams: hunter2-secret'),
          { query: 'insert into t values ($1)', params: ['hunter2-secret'] },
        );
        Object.assign(err, { cause: Object.assign(new Error('x'), { code: '23505' }) });
        throw err;
      },
    };
    const registry = await loadPlugins({
      paths: [PATH],
      state: licensed,
      base,
      checkFile: isFile,
      importModule: async () => ({ default: leaky }),
    });
    expect(registry.reports[0]!.error).toBe('database query failed (SQLSTATE 23505)');
    expect(describePluginError(new Error('plain'))).toBe('plain');
    expect(describePluginError('x'.repeat(600))).toHaveLength(501);
  });

  it('reports a thrown value with a hostile message getter without crashing', async () => {
    const hostile: QualorPlugin = {
      ...fixture,
      register: () => {
        throw {
          get message(): string {
            throw new Error('nope');
          },
        };
      },
    };
    const registry = await loadPlugins({
      paths: [PATH],
      state: licensed,
      base,
      checkFile: isFile,
      importModule: async () => ({ default: hostile }),
    });
    expect(registry.reports[0]!.state).toBe('failed');
  });
});

describe('a real plugin file on disk (enterprise.md §12: no enterprise code runs without a key)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qualor-plugin-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  /** A module whose top-level code writes a marker file the moment it is imported. */
  function markerPlugin(name: string): { path: string; marker: string } {
    const marker = join(dir, `${name}.imported`);
    const path = join(dir, `${name}.mjs`);
    writeFileSync(
      path,
      [
        "import { writeFileSync } from 'node:fs';",
        `writeFileSync(${JSON.stringify(marker)}, 'imported');`,
        'export default {',
        `  name: ${JSON.stringify(name)},`,
        '  apiVersion: 1,',
        "  features: ['marker.echo'],",
        "  register(ctx) { ctx.routes('marker.echo', async () => {}); },",
        '};',
      ].join('\n'),
    );
    return { path, marker };
  }

  it.each(unlicensed.map(([what, state], i) => [what, state, i] as const))(
    'with %s, the module is never imported (its top-level code does not run)',
    async (_what, state, i) => {
      const { path, marker } = markerPlugin(`unlicensed-${i}`);
      const registry = await loadPlugins({ paths: [path], state, base });
      expect(existsSync(marker)).toBe(false);
      expect(registry.reports).toEqual([]);
    },
  );

  it('with an active licence, imports it by file URL and runs register', async () => {
    const { path, marker } = markerPlugin('licensed');
    const registry = await loadPlugins({ paths: [path], state: licensed, base });
    expect(existsSync(marker)).toBe(true);
    expect(registry.reports).toEqual([
      { name: 'licensed', state: 'loaded', features: ['marker.echo'], error: null },
    ]);
    expect(registry.routes).toHaveLength(1);
  });

  it('refuses a directory', async () => {
    mkdirSync(join(dir, 'dir.js'));
    const registry = await loadPlugins({ paths: [join(dir, 'dir.js')], state: licensed, base });
    expect(registry.reports[0]!.state).toBe('failed');
  });
});

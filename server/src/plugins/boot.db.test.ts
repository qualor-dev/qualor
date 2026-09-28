import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { testConfig } from '../../test/config';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { signTest, testPayload, testSigner, verifyWith } from '../../test/license';
import { createLogger } from '../http/logger';
import { LicenseFileError } from '../license/source';
import { keyHash } from '../license/token';
import { bootEnterprise } from './boot';
import type { PluginContext } from './contract';

const REJECTED = 'QLK1.test-a.bm90LWEta2V5.AAAA';

/**
 * enterprise.md §6, §10, §12: what main.ts does between the migrations and buildApp. The licensed
 * case imports a real plugin file through the loader's default import(), so this is the path the
 * server takes, not a stub of it.
 */
describe('bootEnterprise (main.ts wiring)', () => {
  const signer = testSigner();
  const now = new Date('2027-01-01T00:00:00Z');
  const license = testPayload({ features: ['fixture.boot'] });
  const key = signTest(signer, license);
  let database: TestDatabase;
  let dir: string;
  let pluginPath: string;
  let marker: string;

  beforeAll(async () => {
    database = await createTestDatabase();
    dir = mkdtempSync(join(tmpdir(), 'qualor-boot-'));
    marker = join(dir, 'imported');
    pluginPath = join(dir, `boot-plugin-${randomBytes(4).toString('hex')}.mjs`);
    writeFileSync(
      pluginPath,
      [
        "import { writeFileSync } from 'node:fs';",
        `writeFileSync(${JSON.stringify(marker)}, 'imported');`,
        'export default {',
        "  name: 'boot-fixture',",
        '  apiVersion: 1,',
        "  features: ['fixture.boot'],",
        '  register(ctx) {',
        "    ctx.routes('fixture.boot', async (app) => { app.get('/boot', async () => ({ ok: true })); });",
        "    ctx.jobs('fixture.boot', { 'ee.boot': async () => {} });",
        '  },',
        '};',
        '',
      ].join('\n'),
    );
  });
  afterAll(async () => {
    rmSync(dir, { recursive: true, force: true });
    await database.close();
  });

  function capture(): { logger: ReturnType<typeof createLogger>; lines: string[] } {
    const lines: string[] = [];
    const logger = createLogger('info', { write: (line: string) => void lines.push(line) });
    return { logger, lines };
  }

  it('reads the key once, loads the plugin and logs the edition with the loaded plugins', async () => {
    const { logger, lines } = capture();
    const result = await bootEnterprise({
      config: testConfig({ license: { text: key, file: null }, pluginPaths: [pluginPath] }),
      db: database.db,
      logger,
      serverVersion: '0.0.0',
      verifyOptions: (at) => verifyWith(signer, at),
      now: () => now,
    });
    expect(existsSync(marker)).toBe(true);
    expect(result.edition.edition()).toBe('enterprise');
    expect(result.edition.activeFeatures()).toEqual(['fixture.boot']);
    expect(result.plugins.reports).toEqual([
      { name: 'boot-fixture', state: 'loaded', features: ['fixture.boot'], error: null },
    ]);
    expect(result.plugins.routes.map((r) => r.feature)).toEqual(['fixture.boot']);
    expect(result.plugins.jobs.map((j) => j.queue)).toEqual(['ee.boot']);
    expect(Object.isFrozen(result.plugins)).toBe(true);
    expect(Object.isFrozen(result.plugins.routes)).toBe(true);
    const line = lines
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .find((l) => l['component'] === 'licence');
    expect(line).toMatchObject({
      level: 30,
      msg: 'running as the enterprise edition',
      licence: 'active',
      edition: 'enterprise',
      source: 'environment',
      plugins: ['boot-fixture'],
    });
    const all = lines.join('\n');
    for (const secret of [...key.split('.').slice(1), keyHash(key), license.id, license.customer]) {
      expect(all).not.toContain(secret);
    }
    rmSync(marker, { force: true });
  });

  it('reports a plugin whose routes throw at mount as failed, drops all of it, and boots (R-MOUNT)', async () => {
    const { logger, lines } = capture();
    const throwing = {
      name: 'mount-fails',
      apiVersion: 1,
      features: ['fixture.boot'],
      register(ctx: PluginContext) {
        ctx.routes('fixture.boot', async () => {
          throw new Error('cannot mount');
        });
        ctx.jobs('fixture.boot', { 'ee.mount': async () => {} });
      },
    };
    const result = await bootEnterprise({
      config: testConfig({ license: { text: key, file: null }, pluginPaths: ['/virtual/m.js'] }),
      db: database.db,
      logger,
      serverVersion: '0.0.0',
      verifyOptions: (at) => verifyWith(signer, at),
      now: () => now,
      checkFile: async (p) => ({ ok: true, realPath: p }),
      importModule: async () => ({ default: throwing }),
    });
    expect(result.plugins.reports).toEqual([
      {
        name: 'mount-fails',
        state: 'failed',
        features: [],
        error: 'its routes failed to mount: cannot mount',
      },
    ]);
    expect(result.plugins.routes).toEqual([]);
    expect(result.plugins.jobs).toEqual([]);
    expect(result.edition.activeFeatures()).toEqual([]);
    const line = lines
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .find((l) => l['component'] === 'licence');
    expect(line).toMatchObject({ plugins: [], failedPlugins: ['mount-fails'] });
  });

  it('gives the plugin ctx.sso and ctx.scim bound to the edition, refused while it registers', async () => {
    const { logger } = capture();
    const ssoKey = signTest(signer, testPayload({ features: ['sso', 'scim'] }));
    let captured: PluginContext | undefined;
    let duringRegister: unknown;
    const plugin = {
      name: 'sso-boot',
      apiVersion: 1,
      features: ['sso', 'scim'],
      async register(ctx: PluginContext) {
        captured = ctx;
        duringRegister = await ctx.sso.listConnections().catch((err: unknown) => err);
      },
    };
    const result = await bootEnterprise({
      config: testConfig({ license: { text: ssoKey, file: null }, pluginPaths: ['/virtual/s.js'] }),
      db: database.db,
      logger,
      serverVersion: '0.0.0',
      verifyOptions: (at) => verifyWith(signer, at),
      now: () => now,
      checkFile: async (p) => ({ ok: true, realPath: p }),
      importModule: async () => ({ default: plugin }),
    });
    expect(result.edition.activeFeatures()).toEqual(['scim', 'sso']);
    expect(duringRegister).toBeInstanceOf(Error);
    expect((duringRegister as Error).message).toBe('the edition does not exist yet');
    await expect(captured!.sso.listConnections()).resolves.toEqual([]);
    await expect(captured!.scim.listTokens()).resolves.toEqual([]);
  });

  it.each([
    ['without a licence', null, /running as the community edition/, 30],
    ['with a rejected licence', REJECTED, /licence key rejected/, 50],
  ])(
    '%s: runs as community and never touches a plugin path',
    async (_what, text, message, level) => {
      rmSync(marker, { force: true });
      const { logger, lines } = capture();
      const checkFile = vi.fn();
      const importModule = vi.fn();
      const result = await bootEnterprise({
        config: testConfig({ license: { text, file: null }, pluginPaths: [pluginPath] }),
        db: database.db,
        logger,
        serverVersion: '0.0.0',
        verifyOptions: (at) => verifyWith(signer, at),
        now: () => now,
        checkFile,
        importModule,
      });
      expect(checkFile).not.toHaveBeenCalled();
      expect(importModule).not.toHaveBeenCalled();
      expect(existsSync(marker)).toBe(false);
      expect(result.edition.edition()).toBe('community');
      expect(result.plugins.reports).toEqual([]);
      expect(result.plugins.routes).toEqual([]);
      expect(result.plugins.jobs).toEqual([]);
      const line = lines
        .map((l) => JSON.parse(l) as Record<string, unknown>)
        .find((l) => l['component'] === 'licence');
      expect(line?.['msg']).toMatch(message);
      expect(line?.['level']).toBe(level);
      expect(line?.['plugins']).toEqual([]);
      if (text) {
        expect(line?.['reason']).toBe('malformed');
        expect(lines.join('\n')).not.toContain('bm90LWEta2V5');
      }
    },
  );

  it('throws LicenseFileError, naming the variable and no key text, when the file is not there', async () => {
    const { logger } = capture();
    const importModule = vi.fn();
    const missing = join(dir, 'no-such-licence');
    const boot = bootEnterprise({
      config: testConfig({ license: { text: null, file: missing }, pluginPaths: [pluginPath] }),
      db: database.db,
      logger,
      serverVersion: '0.0.0',
      verifyOptions: (at) => verifyWith(signer, at),
      now: () => now,
      importModule,
    });
    await expect(boot).rejects.toBeInstanceOf(LicenseFileError);
    await expect(boot).rejects.toThrow(/^QUALOR_LICENSE_FILE: /);
    expect(importModule).not.toHaveBeenCalled();
  });

  it('never shows the file content in the error of an oversized licence file', async () => {
    const { logger } = capture();
    const big = join(dir, 'big-licence');
    writeFileSync(big, `${key}\n${'x'.repeat(17 * 1024)}`);
    const boot = bootEnterprise({
      config: testConfig({ license: { text: null, file: big }, pluginPaths: [] }),
      db: database.db,
      logger,
      serverVersion: '0.0.0',
      verifyOptions: (at) => verifyWith(signer, at),
      now: () => now,
    });
    const err = (await boot.catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(LicenseFileError);
    expect(err.message).toMatch(/QUALOR_LICENSE_FILE: .* is larger than 16 KiB/);
    expect(err.message).not.toContain(key.split('.')[2]);
  });
});

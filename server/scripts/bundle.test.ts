import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { buildPluginFileCheck, buildServer } from './bundle';

describe('server bundle', () => {
  it('builds a runnable ESM file that refuses to start with bad configuration', async () => {
    const outfile = fileURLToPath(new URL('../.tmp/bundle-test/main.js', import.meta.url));
    await buildServer({ outfile });
    const result = spawnSync(process.execPath, [outfile], {
      env: { ...process.env, DATABASE_URL: 'mysql://x', QUALOR_SECRET_KEY: '' },
      encoding: 'utf8',
      timeout: 20_000,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('DATABASE_URL');
    expect(result.stderr).toContain('QUALOR_SECRET_KEY');
    // The licence notice of the patterns adapted from Gitleaks survives bundling (llm.md §5.2).
    expect(readFileSync(outfile, 'utf8')).toContain('Copyright (c) 2019 Zachary Rice');
  }, 60_000);

  it('names DATABASE_URL, not its password, when PostgreSQL cannot be reached (plan 1G)', async () => {
    const outfile = fileURLToPath(new URL('../.tmp/bundle-test/main.js', import.meta.url));
    await buildServer({ outfile });
    const result = spawnSync(process.execPath, [outfile], {
      env: {
        ...process.env,
        // Nothing listens on port 1: the connection is refused at once.
        DATABASE_URL: 'postgres://qualor:hunter2-password@127.0.0.1:1/qualor',
        QUALOR_SECRET_KEY: 'bundle-test-secret-key-of-at-least-32-characters',
        QUALOR_UI_DIR: '',
        QUALOR_TELEMETRY: 'false',
      },
      encoding: 'utf8',
      timeout: 20_000,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('cannot use the database DATABASE_URL names');
    expect(result.stderr).toContain('ECONNREFUSED');
    expect(result.stderr).not.toContain('hunter2-password');
  }, 60_000);

  it('bundles no enterprise code and no test licence key (enterprise.md §12, §14.2)', async () => {
    const outfile = fileURLToPath(new URL('../.tmp/bundle-test/main.js', import.meta.url));
    const { inputs } = await buildServer({ outfile });
    expect(inputs.length).toBeGreaterThan(100);
    expect(inputs.filter((i) => /(^|[\\/])enterprise[\\/]/.test(i))).toEqual([]);
    const text = readFileSync(outfile, 'utf8');
    expect(text).not.toMatch(/"test-[a-z0-9-]+":/);
    // The define always replaces the name, so a release build never reads a global of that name
    // (a preloaded script could set one): see main.db.test.ts for the boot proof.
    expect(text).not.toContain('__QUALOR_TEST_LICENSE_KEYS__');
  }, 60_000);

  it('embeds the test licence keys of a test bundle', async () => {
    const outfile = fileURLToPath(new URL('../.tmp/bundle-test/test-keys.js', import.meta.url));
    await buildServer({ outfile, testLicenseKeys: { 'test-bundle': 'eHh4' } });
    const text = readFileSync(outfile, 'utf8');
    expect(text).toMatch(/\{\\?"test-bundle\\?":\\?"eHh4\\?"\}/);
    expect(text).not.toContain('__QUALOR_TEST_LICENSE_KEYS__');
  }, 60_000);

  it.each<Record<string, string>>([
    { k2026: 'AAAA' },
    { 'test-a': 'AAAA', production: 'BBBB' },
    { 'Test-a': 'AAAA' },
  ])(
    'refuses test licence keys whose kid does not start with test- (%o)',
    async (testLicenseKeys) => {
      const outfile = fileURLToPath(new URL('../.tmp/bundle-test/bad-keys.js', import.meta.url));
      await expect(buildServer({ outfile, testLicenseKeys })).rejects.toThrow(/test-/);
    },
  );
});

describe('the plugin file check command (enterprise.md §10.1.1)', () => {
  it('bundles only the check, and answers 0 for an accepted file and 1 for a refused one', async () => {
    const outfile = fileURLToPath(
      new URL('../.tmp/bundle-test/check-plugin-file.js', import.meta.url),
    );
    const { inputs } = await buildPluginFileCheck({ outfile });
    expect(inputs.sort()).toEqual(['src/check-plugin-file.ts', 'src/plugins/plugin-file.ts']);
    const dir = mkdtempSync(path.join(tmpdir(), 'qualor-check-plugin-'));
    try {
      const plugin = path.join(dir, 'plugin.js');
      writeFileSync(plugin, 'export default {};\n', { mode: 0o644 });
      chmodSync(dir, 0o755);
      const run = (arg: string) =>
        spawnSync(process.execPath, [outfile, arg], { encoding: 'utf8', timeout: 20_000 });
      const accepted = run(plugin);
      expect(accepted.status, accepted.stderr).toBe(0);
      expect(JSON.parse(accepted.stdout)).toEqual({
        ok: true,
        realPath: realpathSync.native(plugin),
      });
      const refused = run(path.join(dir, 'missing.js'));
      expect(refused.status).toBe(1);
      expect(JSON.parse(refused.stdout)).toMatchObject({ ok: false, reason: expect.any(String) });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});

import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { redactLongText } from '@qualor/shared';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { budgetMs } from '../test/perf';
import {
  buildFixCheckWorker,
  buildPluginFileCheck,
  buildReviewMaskWorker,
  buildServer,
} from './bundle';

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

describe('the review mask worker bundle (6I-3)', () => {
  const dir = fileURLToPath(new URL('../.tmp/bundle-test/', import.meta.url));

  it('is built next to the server bundle, where the masker looks for it', async () => {
    const outfile = path.join(dir, 'with-worker', 'main.js');
    await buildServer({ outfile });
    expect(existsSync(path.join(path.dirname(outfile), 'review-mask-worker.js'))).toBe(true);
    // 0.16 fix MRs: the fix upload check's worker too (fixes/checker.ts).
    expect(existsSync(path.join(path.dirname(outfile), 'fix-check-worker.js'))).toBe(true);
    expect(existsSync(path.join(path.dirname(outfile), 'main.js'))).toBe(true);
  }, 60_000);

  it('bundles the shared redaction and nothing else of the server', async () => {
    const outfile = path.join(dir, 'worker-only', 'review-mask-worker.js');
    const { inputs } = await buildReviewMaskWorker({ outfile });
    expect(inputs.filter((input) => input.startsWith('src/'))).toEqual([
      'src/review/mask-worker.ts',
    ]);
    expect(inputs.some((input) => input.endsWith('packages/shared/src/llm/redact-long.ts'))).toBe(
      true,
    );
    expect(inputs.filter((input) => /(^|[\\/])enterprise[\\/]/.test(input))).toEqual([]);
  }, 60_000);

  it('is found by a masker that is bundled beside it, and masks as the shared redaction does', async () => {
    const outDir = path.join(dir, 'masker-beside-worker');
    await buildReviewMaskWorker({ outfile: path.join(outDir, 'review-mask-worker.js') });
    // The masker as the server bundles it: its worker is looked for next to the bundle.
    await build({
      absWorkingDir: fileURLToPath(new URL('..', import.meta.url)),
      entryPoints: ['src/review/masker.ts'],
      outfile: path.join(outDir, 'masker.js'),
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node22',
      logLevel: 'warning',
    });
    const token = ['gh', 'p_', 'a1B2'.repeat(9)].join('');
    const sample = `const t = "${token}";\nok();\n`;
    const script = (close: boolean) => `
      import { Masker } from ${JSON.stringify(pathToFileURL(path.join(outDir, 'masker.js')).href)};
      const masker = new Masker();
      const result = await masker.mask(${JSON.stringify(sample)});
      process.stdout.write(JSON.stringify({ result, workers: masker.workersStarted }));
      ${close ? 'await masker.close();' : ''}
    `;
    const run = spawnSync(process.execPath, ['--input-type=module', '-e', script(true)], {
      encoding: 'utf8',
      timeout: 30_000,
    });
    expect(run.status, run.stderr).toBe(0);
    expect(JSON.parse(run.stdout)).toEqual({
      result: { kind: 'masked', ...redactLongText(sample) },
      workers: 1,
    });

    // A masker nobody closed does not keep the process alive: its worker and its timers let go.
    const started = performance.now();
    const left = spawnSync(process.execPath, ['--input-type=module', '-e', script(false)], {
      encoding: 'utf8',
      timeout: 30_000,
    });
    expect(left.status, left.stderr).toBe(0);
    expect(JSON.parse(left.stdout)).toMatchObject({ workers: 1 });
    expect(performance.now() - started).toBeLessThan(budgetMs(8_000));
  }, 60_000);
});

describe('the fix check worker bundle (0.16 fix MRs, rulings T3g, T3k)', () => {
  const dir = fileURLToPath(new URL('../.tmp/bundle-test/', import.meta.url));

  it('bundles the shared fix checks and nothing else of the server', async () => {
    const outfile = path.join(dir, 'fix-worker-only', 'fix-check-worker.js');
    const { inputs } = await buildFixCheckWorker({ outfile });
    expect(inputs.filter((input) => input.startsWith('src/'))).toEqual([
      'src/fixes/check-worker.ts',
    ]);
    expect(inputs.some((input) => input.endsWith('packages/shared/src/fix/check/upload.ts'))).toBe(
      true,
    );
    expect(inputs.filter((input) => /(^|[\\/])enterprise[\\/]/.test(input))).toEqual([]);
  }, 60_000);

  it('is found by a checker that is bundled beside it, and checks an upload in it', async () => {
    const outDir = path.join(dir, 'checker-beside-worker');
    await buildFixCheckWorker({ outfile: path.join(outDir, 'fix-check-worker.js') });
    // The checker as the server bundles it: its worker is looked for next to the bundle.
    await build({
      absWorkingDir: fileURLToPath(new URL('..', import.meta.url)),
      entryPoints: ['src/fixes/checker.ts'],
      outfile: path.join(outDir, 'checker.js'),
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node22',
      logLevel: 'warning',
    });
    const manifest = (range: string, extra = '') =>
      `{\n  "name": "app",\n  "dependencies": {\n    "qf-a": "${range}"\n  }${extra}\n}\n`;
    const job = (next: string) => ({
      family: 'js',
      packageName: 'qf-a',
      targets: [],
      files: [{ path: 'package.json', base: manifest('^1.2.5'), next }],
    });
    const script = `
      import { checkUploadInWorker } from ${JSON.stringify(pathToFileURL(path.join(outDir, 'checker.js')).href)};
      const good = await checkUploadInWorker(${JSON.stringify(job(manifest('^1.2.6')))});
      const bad = await checkUploadInWorker(${JSON.stringify(job(manifest('^1.2.6', ',\n  "scripts": { "postinstall": "x" }')))});
      process.stdout.write(JSON.stringify({ good, bad }));
    `;
    const started = performance.now();
    const run = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
      encoding: 'utf8',
      timeout: 30_000,
    });
    expect(run.status, run.stderr).toBe(0);
    expect(JSON.parse(run.stdout)).toEqual({
      good: { ok: true, additions: [] },
      bad: { ok: false, rule: 'other_change', path: 'package.json' },
    });
    // Each check's worker is stopped after it: nothing keeps the process alive.
    expect(performance.now() - started).toBeLessThan(budgetMs(15_000));
  }, 60_000);
});

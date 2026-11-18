import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { testKeysFrom } from '../src/license/public-keys';

const serverRoot = fileURLToPath(new URL('..', import.meta.url));

/** The npm dependencies of the server stay external to its bundles; workspace packages are inlined. */
function externalDependencies(): string[] {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    dependencies?: Record<string, string>;
  };
  return Object.keys(pkg.dependencies ?? {})
    .filter((name) => !name.startsWith('@qualor/'))
    .flatMap((name) => [name, `${name}/*`]);
}

/** The file the review's masker starts its worker thread from, next to the server bundle. */
export const REVIEW_MASK_WORKER = 'review-mask-worker.js';
/** The file the fix upload check starts its worker thread from (fixes/checker.ts), next to it. */
export const FIX_CHECK_WORKER = 'fix-check-worker.js';

/**
 * Bundles src/main.ts, and next to it the worker threads of the review's masker
 * (`buildReviewMaskWorker`) and of the fix upload check (`buildFixCheckWorker`), where each is
 * looked for; npm dependencies stay external, workspace packages are inlined. Returns the bundle's inputs (esbuild's metafile, relative to server/) for the boundary
 * test (enterprise.md §12).
 *
 * `__QUALOR_TEST_LICENSE_KEYS__` is always defined (enterprise.md §14.2): as the test keys in a
 * test bundle (every kid must start with `test-`), and as the literal `undefined` in every other
 * build, so a production bundle never reads a global of that name that something set before it.
 */
export async function buildServer(
  options: { outfile?: string; testLicenseKeys?: Record<string, string> } = {},
): Promise<{ inputs: string[] }> {
  const keys = options.testLicenseKeys;
  // The same check the bundle runs at start (public-keys.ts), so a bad kid fails the build.
  const testKeys =
    keys === undefined ? undefined : JSON.stringify(testKeysFrom(JSON.stringify(keys)));
  const outfile = options.outfile ?? 'dist/main.js';
  const result = await build({
    absWorkingDir: serverRoot,
    entryPoints: ['src/main.ts'],
    outfile,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    sourcemap: true,
    metafile: true,
    external: externalDependencies(),
    define: {
      __QUALOR_TEST_LICENSE_KEYS__: testKeys === undefined ? 'undefined' : JSON.stringify(testKeys),
    },
    logLevel: 'warning',
  });
  const outDir = path.dirname(path.resolve(serverRoot, outfile));
  await buildReviewMaskWorker({ outfile: path.join(outDir, REVIEW_MASK_WORKER) });
  await buildFixCheckWorker({ outfile: path.join(outDir, FIX_CHECK_WORKER) });
  return { inputs: Object.keys(result.metafile.inputs) };
}

/**
 * `dist/review-mask-worker.js`: the worker thread the review's masker runs the secret redaction in
 * (src/review/mask-worker.ts), so that masking a hostile text never stops the server. The masker
 * starts it from the directory of the server bundle. It bundles the shared redaction and nothing
 * else of the server.
 */
export async function buildReviewMaskWorker(
  options: { outfile?: string } = {},
): Promise<{ inputs: string[] }> {
  const result = await build({
    absWorkingDir: serverRoot,
    entryPoints: ['src/review/mask-worker.ts'],
    outfile: options.outfile ?? `dist/${REVIEW_MASK_WORKER}`,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    sourcemap: true,
    metafile: true,
    external: externalDependencies(),
    logLevel: 'warning',
  });
  return { inputs: Object.keys(result.metafile.inputs) };
}

/**
 * `dist/fix-check-worker.js` (0.16 fix MRs, rulings T3g, T3k): the worker thread a fix upload is
 * checked by content in (src/fixes/check-worker.ts), so that reading a lockfile of up to 32 MiB
 * never stops the server. The checker (src/fixes/checker.ts) starts it from the directory of the
 * server bundle. It bundles the shared fix checks and nothing else of the server.
 */
export async function buildFixCheckWorker(
  options: { outfile?: string } = {},
): Promise<{ inputs: string[] }> {
  const result = await build({
    absWorkingDir: serverRoot,
    entryPoints: ['src/fixes/check-worker.ts'],
    outfile: options.outfile ?? `dist/${FIX_CHECK_WORKER}`,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    sourcemap: true,
    metafile: true,
    external: externalDependencies(),
    logLevel: 'warning',
  });
  return { inputs: Object.keys(result.metafile.inputs) };
}

/**
 * `dist/check-plugin-file.js` (enterprise.md §10.1.1): the loader's plugin file check as a small
 * command, for the image smoke test and for operators. It bundles nothing but that check.
 */
export async function buildPluginFileCheck(
  options: { outfile?: string } = {},
): Promise<{ inputs: string[] }> {
  const result = await build({
    absWorkingDir: serverRoot,
    entryPoints: ['src/check-plugin-file.ts'],
    outfile: options.outfile ?? 'dist/check-plugin-file.js',
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    metafile: true,
    logLevel: 'warning',
  });
  return { inputs: Object.keys(result.metafile.inputs) };
}

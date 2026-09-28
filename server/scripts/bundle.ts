import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { testKeysFrom } from '../src/license/public-keys';

const serverRoot = fileURLToPath(new URL('..', import.meta.url));

/**
 * Bundles src/main.ts; npm dependencies stay external, workspace packages are inlined. Returns the
 * bundle's inputs (esbuild's metafile, relative to server/) for the boundary test (enterprise.md
 * §12).
 *
 * `__QUALOR_TEST_LICENSE_KEYS__` is always defined (enterprise.md §14.2): as the test keys in a
 * test bundle (every kid must start with `test-`), and as the literal `undefined` in every other
 * build, so a production bundle never reads a global of that name that something set before it.
 */
export async function buildServer(
  options: { outfile?: string; testLicenseKeys?: Record<string, string> } = {},
): Promise<{ inputs: string[] }> {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    dependencies?: Record<string, string>;
  };
  const external = Object.keys(pkg.dependencies ?? {})
    .filter((name) => !name.startsWith('@qualor/'))
    .flatMap((name) => [name, `${name}/*`]);
  const keys = options.testLicenseKeys;
  // The same check the bundle runs at start (public-keys.ts), so a bad kid fails the build.
  const testKeys =
    keys === undefined ? undefined : JSON.stringify(testKeysFrom(JSON.stringify(keys)));
  const result = await build({
    absWorkingDir: serverRoot,
    entryPoints: ['src/main.ts'],
    outfile: options.outfile ?? 'dist/main.js',
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    sourcemap: true,
    metafile: true,
    external,
    define: {
      __QUALOR_TEST_LICENSE_KEYS__: testKeys === undefined ? 'undefined' : JSON.stringify(testKeys),
    },
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

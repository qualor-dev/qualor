// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = fileURLToPath(new URL('..', import.meta.url));

/**
 * enterprise.md §12, an allowlist: every input of the enterprise bundle is a file of
 * enterprise/src. Core (server/, packages/) reaches it only as types, and npm dependencies stay
 * external (resolved from /app/node_modules), so anything else means a second copy of core or of
 * a package was bundled. The error names each such input.
 */
export function assertEnterpriseInputs(inputs: readonly string[]): void {
  const outside = inputs.filter(
    (input) => !input.startsWith('src/') || input.includes('\\') || /(^|\/)\.\.(\/|$)/.test(input),
  );
  if (outside.length > 0) {
    throw new Error(
      `the enterprise bundle may hold only enterprise/src (enterprise.md §12); it also holds ` +
        `${outside.length} other input(s): ${outside.slice(0, 10).join(', ')}` +
        (outside.length > 10 ? ', …' : ''),
    );
  }
}

/** Bundles src/plugin.ts (checked by {@link assertEnterpriseInputs}); runtime dependencies stay external (resolved from /app/node_modules). */
export async function buildEnterprise(
  options: { outfile?: string } = {},
): Promise<{ inputs: string[] }> {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    dependencies?: Record<string, string>;
  };
  const external = Object.keys(pkg.dependencies ?? {}).flatMap((n) => [n, `${n}/*`]);
  const result = await build({
    absWorkingDir: root,
    entryPoints: ['src/plugin.ts'],
    outfile: options.outfile ?? 'dist/plugin.js',
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    sourcemap: true,
    metafile: true,
    external,
    logLevel: 'warning',
    // Checked before anything is written: a refused bundle never reaches dist/.
    write: false,
  });
  const inputs = Object.keys(result.metafile.inputs);
  assertEnterpriseInputs(inputs);
  for (const file of result.outputFiles) {
    mkdirSync(path.dirname(file.path), { recursive: true });
    writeFileSync(file.path, file.contents);
  }
  return { inputs };
}

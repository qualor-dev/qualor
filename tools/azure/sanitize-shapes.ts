/**
 * Applies the recorder's synthetic-id mapping (`withSyntheticIds`) to existing recordings in place,
 * so recordings written before the mapping existed match new ones. The mapping is deterministic and
 * idempotent: running this twice changes nothing the second time.
 *
 * Usage: tsx tools/azure/sanitize-shapes.ts [dir ...]
 * (default: server/test/azure-shapes/server and server/test/azure-shapes/services). The salt is
 * `AZURE_PROBE_ID_SALT`, the probe's: from the environment or the files in `AZURE_PROBE_ENV_FILES`.
 *
 * It prints file counts only, never a value.
 */
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import { withSyntheticIds } from './record.js';
import { loadEnvFiles } from './targets.js';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const DEFAULT_DIRS = ['server', 'services'].map((t) =>
  path.join(ROOT, 'server/test/azure-shapes', t),
);

/** Rewrites one recording; true when its content changed. */
export async function sanitizeFile(file: string, salt: string): Promise<boolean> {
  const before = await readFile(file, 'utf8');
  const text = JSON.stringify(withSyntheticIds(JSON.parse(before), salt), null, 2);
  const options = (await resolveConfig(file)) ?? {};
  const after = await format(text, { ...options, filepath: file });
  if (after === before) return false;
  await writeFile(file, after, 'utf8');
  return true;
}

async function main(): Promise<void> {
  if (process.env['AZURE_PROBE_ENV_FILES']) loadEnvFiles();
  const salt = process.env['AZURE_PROBE_ID_SALT'];
  if (!salt) throw new Error('AZURE_PROBE_ID_SALT is not set (the salt of the recordings)');
  const dirs = process.argv.length > 2 ? process.argv.slice(2) : DEFAULT_DIRS;
  for (const dir of dirs) {
    const files = (await readdir(dir)).filter((f) => f.endsWith('.json')).sort();
    let changed = 0;
    for (const f of files) if (await sanitizeFile(path.join(dir, f), salt)) changed++;
    console.log(
      `${path.relative(ROOT, dir) || dir}: ${files.length} recordings, ${changed} changed`,
    );
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err: unknown) => {
    console.error((err as Error).message);
    process.exitCode = 1;
  });
}

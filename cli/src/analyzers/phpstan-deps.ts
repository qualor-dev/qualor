import { lstatSync, mkdirSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { staysInside } from './binary';
import { readPlainFile } from './checked-copy';
import { readRepoConfigBytes, repoEntryExists, WeblintConfigError } from './weblint';

/** config.md §6 "Dependencies" (plan 9A decision 2). */
export const DEPENDENCIES_NOT_INSTALLED =
  'PHP dependencies are not installed (composer.json requires packages; run composer install before the scan; Qualor reads vendor/, never runs it)';
const BAD_VENDOR_DIR =
  'composer.json config.vendor-dir must be a relative path inside the repository';
const MAX_COMPOSER_JSON_BYTES = 1024 * 1024;
/** At most this many dependency files are copied (config.md §6). */
export const MAX_DEPENDENCY_FILES = 200_000;
/** At most this many bytes of dependency files are copied in all (ruling A9-14). */
export const MAX_DEPENDENCY_BYTES = 1024 * 1024 * 1024;
/**
 * The skip reason when the dependencies exceed `MAX_DEPENDENCY_BYTES` (ruling A9-14): PHPStan with
 * only part of the symbols would report false positives, so it does not run at all.
 */
export const DEPENDENCIES_TOO_LARGE =
  'PHP dependencies are larger than 1 GiB (the .php files below vendor/); PHPStan is skipped rather than run with part of them';

export type PhpDependencies =
  { kind: 'none' } | { kind: 'installed'; vendorDir: string } | { kind: 'skip'; reason: string };

/** A regular file at `rel`, not a link, inside the repository after resolving links. */
function plainFile(root: string, rel: string): boolean {
  const abs = path.join(root, ...rel.split('/'));
  try {
    return lstatSync(abs).isFile() && staysInside(root, abs);
  } catch {
    return false;
  }
}

/** `config.vendor-dir` as a repository-relative POSIX path, `vendor` by default, or null when unusable. */
function vendorDirOf(json: Record<string, unknown>): string | null {
  const config = json['config'];
  const raw =
    typeof config === 'object' && config !== null && !Array.isArray(config)
      ? (config as Record<string, unknown>)['vendor-dir']
      : undefined;
  if (raw === undefined) return 'vendor';
  if (typeof raw !== 'string') return null;
  const dir = raw.replace(/\/+$/, '');
  const segments = dir.split('/');
  if (
    dir === '' ||
    dir.startsWith('/') ||
    /^[A-Za-z]:/.test(dir) ||
    /[\\$~{}\r\n]/.test(dir) ||
    segments.some((s) => s === '' || s === '.' || s === '..')
  ) {
    return null;
  }
  return dir;
}

/** Whether `require` names a package: Composer's platform packages (php, ext-*, lib-*) have no `/`. */
function requiresPackages(json: Record<string, unknown>): boolean {
  const require = json['require'];
  return (
    typeof require === 'object' &&
    require !== null &&
    Object.keys(require).some((name) => name.includes('/'))
  );
}

/**
 * The root composer.json, read as data (never run): whether PHPStan gets the installed
 * dependencies, runs without, or is skipped because they are required but not installed.
 */
export function phpDependencies(root: string): PhpDependencies {
  // repoEntryExists (weblint.ts) is lstat-based: a dangling or outside link still "exists", so
  // readRepoConfigBytes below turns it into a skip reason instead of a silent "none".
  if (!repoEntryExists(path.join(root, 'composer.json'))) return { kind: 'none' };
  let text: string;
  try {
    text = readRepoConfigBytes(root, 'composer.json', MAX_COMPOSER_JSON_BYTES).toString('utf8');
  } catch (err) {
    return {
      kind: 'skip',
      reason: err instanceof WeblintConfigError ? err.message : 'composer.json cannot be read',
    };
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { kind: 'skip', reason: 'composer.json is not valid JSON' };
  }
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    return { kind: 'skip', reason: 'composer.json is not a JSON object' };
  }
  const object = json as Record<string, unknown>;
  const vendorDir = vendorDirOf(object);
  if (vendorDir === null) return { kind: 'skip', reason: BAD_VENDOR_DIR };
  if (plainFile(root, `${vendorDir}/composer/installed.json`))
    return { kind: 'installed', vendorDir };
  return requiresPackages(object)
    ? { kind: 'skip', reason: DEPENDENCIES_NOT_INSTALLED }
    : { kind: 'none' };
}

/**
 * config.md §6: the `.php` files below `<root>/<vendorDir>`, without its top-level `composer/` and
 * `bin/` directories and its `autoload.php`, copied the checked way (`readPlainFile`: a regular
 * file, no link anywhere on its path, at most 1 MiB) to `<target>/<vendorDir>/`. No link is
 * followed while walking. PHPStan only scans this copy for symbols; it never lives at
 * `<cwd>/vendor`, where PHPStan would `require` an autoloader (fact P4). Past `maxBytes` in all
 * (ruling A9-14) the partial copy is removed and `tooLarge` is set: the caller skips PHPStan with
 * `DEPENDENCIES_TOO_LARGE`.
 */
export function copyDependencies(
  root: string,
  vendorDir: string,
  target: string,
  limit: number = MAX_DEPENDENCY_FILES,
  maxBytes: number = MAX_DEPENDENCY_BYTES,
): { files: number; skipped: number; truncated: boolean; tooLarge: boolean } {
  let realRoot: string;
  try {
    realRoot = realpathSync(root);
  } catch {
    return { files: 0, skipped: 0, truncated: false, tooLarge: false };
  }
  const base = path.join(root, ...vendorDir.split('/'));
  let files = 0;
  let skipped = 0;
  let truncated = false;
  let bytesCopied = 0;
  const stack: string[] = [''];
  while (stack.length > 0 && !truncated) {
    const rel = stack.pop() as string;
    const dir = rel === '' ? base : path.join(base, ...rel.split('/'));
    let entries;
    try {
      if (!lstatSync(dir).isDirectory()) continue;
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (rel === '' && (e.name === 'composer' || e.name === 'bin' || e.name === 'autoload.php'))
        continue;
      const childRel = rel === '' ? e.name : `${rel}/${e.name}`;
      // A Dirent of a link is neither a directory nor a file: links are never followed.
      if (e.isDirectory()) {
        stack.push(childRel);
        continue;
      }
      if (!e.isFile() || !e.name.endsWith('.php')) continue;
      if (files >= limit) {
        truncated = true;
        break;
      }
      const bytes = readPlainFile(root, realRoot, path.join(dir, e.name));
      if (bytes === null) {
        skipped++;
        continue;
      }
      bytesCopied += bytes.length;
      if (bytesCopied > maxBytes) {
        // Ruling A9-14: no partial copy is left for PHPStan to scan; the caller skips it.
        rmSync(path.join(target, ...vendorDir.split('/')), { recursive: true, force: true });
        return { files: 0, skipped, truncated: false, tooLarge: true };
      }
      const out = path.join(target, ...vendorDir.split('/'), ...childRel.split('/'));
      try {
        mkdirSync(path.dirname(out), { recursive: true });
        writeFileSync(out, bytes, { flag: 'wx' });
        files++;
      } catch {
        skipped++;
      }
    }
  }
  return { files, skipped, truncated, tooLarge: false };
}

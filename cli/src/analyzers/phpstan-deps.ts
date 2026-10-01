import {
  lstatSync,
  mkdirSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
  type Dirent,
} from 'node:fs';
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

/** The entries of `<vendorDir>/` that are Composer's own, never copied (config.md §6). */
const EXCLUDED_TOP_LEVEL: ReadonlySet<string> = new Set(['bin', 'autoload.php']);
/**
 * `<vendorDir>/composer/` holds Composer's own files (its autoloader, `installed.php`,
 * `platform_check.php`), never copied, and the packages of the `composer` vendor (`composer/pcre`,
 * `composer/semver`, …) as subdirectories, copied like any other package.
 */
const COMPOSER_DIR = 'composer';

export type PhpDependencies =
  | { kind: 'none' }
  /**
   * `requiresPackages`: composer.json's `require` names a package (not only php, ext-*, lib-*);
   * the caller then needs dependency files to run (ruling A9-17).
   */
  | { kind: 'installed'; vendorDir: string; requiresPackages: boolean }
  | { kind: 'skip'; reason: string };

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
  const required = requiresPackages(object);
  if (plainFile(root, `${vendorDir}/composer/installed.json`))
    return { kind: 'installed', vendorDir, requiresPackages: required };
  return required ? { kind: 'skip', reason: DEPENDENCIES_NOT_INSTALLED } : { kind: 'none' };
}

/** Whether a directory entry of `<vendorDir>/<rel>` is Composer's own (config.md §6). */
function composerOwn(rel: string, name: string, isDirectory: boolean): boolean {
  // Compared case-insensitively (ruling A9-15): on a case-insensitive file system
  // `Autoload.php` is the file Composer writes.
  const lower = name.toLowerCase();
  if (rel === '' && EXCLUDED_TOP_LEVEL.has(lower)) return true;
  // Composer's own files directly in <vendorDir>/composer/ (or a file of that name); its
  // subdirectories are packages.
  if (rel === '' && lower === COMPOSER_DIR) return !isDirectory;
  return rel.toLowerCase() === COMPOSER_DIR && !isDirectory;
}

const joinRel = (rel: string, name: string) => (rel === '' ? name : `${rel}/${name}`);

function directoryEntries(dir: string): Dirent[] {
  try {
    return lstatSync(dir).isDirectory() ? readdirSync(dir, { withFileTypes: true }) : [];
  } catch {
    return [];
  }
}

/** The `.php` files below `base` to copy, `/`-separated and relative to it; no link followed. */
function* vendorPhpFiles(base: string): Generator<string> {
  const stack: string[] = [''];
  while (stack.length > 0) {
    const rel = stack.pop() as string;
    const dir = path.join(base, ...rel.split('/').filter((s) => s !== ''));
    for (const e of directoryEntries(dir)) {
      if (composerOwn(rel, e.name, e.isDirectory())) continue;
      const childRel = joinRel(rel, e.name);
      // A Dirent of a link is neither a directory nor a file: links are never followed.
      if (e.isDirectory()) stack.push(childRel);
      if (e.isFile() && e.name.endsWith('.php')) yield childRel;
    }
  }
}

function writeNew(out: string, bytes: Buffer): boolean {
  try {
    mkdirSync(path.dirname(out), { recursive: true });
    writeFileSync(out, bytes, { flag: 'wx' });
    return true;
  } catch {
    return false;
  }
}

/**
 * config.md §6: the `.php` files below `<root>/<vendorDir>`, without the files directly in its
 * `composer/` directory (its subdirectories are `composer/*` packages), its `bin/` directory and
 * its `autoload.php`, copied the checked way (`readPlainFile`: a regular file, no link anywhere on
 * its path, at most 1 MiB) to `<target>/<vendorDir>/`. No link is followed while walking. PHPStan
 * only scans this copy for symbols; it never lives at `<cwd>/vendor`, where PHPStan would
 * `require` an autoloader (fact P4). Past `maxBytes` in all (ruling A9-14) the partial copy is
 * removed and `tooLarge` is set: the caller skips PHPStan with `DEPENDENCIES_TOO_LARGE`.
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
  const outBase = path.join(target, ...vendorDir.split('/'));
  let files = 0;
  let skipped = 0;
  let bytesCopied = 0;
  for (const rel of vendorPhpFiles(base)) {
    if (files >= limit) return { files, skipped, truncated: true, tooLarge: false };
    const bytes = readPlainFile(root, realRoot, path.join(base, ...rel.split('/')));
    if (bytes === null) {
      skipped++;
      continue;
    }
    bytesCopied += bytes.length;
    if (bytesCopied > maxBytes) {
      // Ruling A9-14: no partial copy is left for PHPStan to scan; the caller skips it.
      rmSync(outBase, { recursive: true, force: true });
      return { files: 0, skipped, truncated: false, tooLarge: true };
    }
    if (writeNew(path.join(outBase, ...rel.split('/')), bytes)) files++;
    else skipped++;
  }
  return { files, skipped, truncated: false, tooLarge: false };
}

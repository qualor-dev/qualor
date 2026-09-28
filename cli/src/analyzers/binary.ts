import { realpathSync, statSync } from 'node:fs';
import path from 'node:path';

/** Where the `qualor/scanner` image installs analyzers (config.md §6). */
const IMAGE_BIN_DIRS: readonly string[] = ['/opt/qualor/bin'];

export interface ResolveBinaryOptions {
  /** The repository being scanned: nothing under it is ever resolved (ruling V3). */
  root: string;
  env: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
}

/** POSIX: any execute bit. Mode bits (not `access(X_OK)`) keep the check identical on every host. */
export function executable(file: string, platform: NodeJS.Platform = process.platform): boolean {
  try {
    const stat = statSync(file);
    return stat.isFile() && (platform === 'win32' || (stat.mode & 0o111) !== 0);
  } catch {
    return false;
  }
}

/** `file` is `root` or below it (both already absolute). `<root>/..x` is inside; `<root>/../x` is not. */
export function within(root: string, file: string): boolean {
  const rel = path.relative(root, file);
  if (rel === '') return true;
  if (path.isAbsolute(rel)) return false;
  return rel !== '..' && !rel.startsWith(`..${path.sep}`);
}

/**
 * The real path of `p`; for a path that does not exist (yet), the real path of its longest
 * existing prefix with the rest appended, so a missing entry below a link into the repository
 * still counts as inside it.
 */
export function real(p: string): string {
  const abs = path.resolve(p);
  const rest: string[] = [];
  let current = abs;
  for (;;) {
    try {
      return path.join(realpathSync(current), ...rest);
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return abs;
      rest.unshift(path.basename(current));
      current = parent;
    }
  }
}

/** True when `file` is inside `root` as written or after resolving symlinks (either counts). */
export function isInside(root: string, file: string): boolean {
  return within(path.resolve(root), path.resolve(file)) || within(real(root), real(file));
}

/**
 * True when `file` stays inside `root` both as written and after resolving symlinks (a missing
 * file is judged by its written path).
 */
export function staysInside(root: string, file: string): boolean {
  return within(path.resolve(root), path.resolve(file)) && within(real(root), real(file));
}

function candidates(name: string, o: ResolveBinaryOptions): { dirs: string[]; names: string[] } {
  const platform = o.platform ?? process.platform;
  const names = platform === 'win32' ? [`${name}.exe`, `${name}.com`] : [name];
  const pathVar = o.env['PATH'] ?? o.env['Path'] ?? '';
  const dirs = pathVar.split(platform === 'win32' ? ';' : ':').filter((d) => d !== '');
  return { dirs, names };
}

/**
 * config.md §6, ruling V3: `PATH`, then the scanner image. A binary is never taken from the
 * repository: not from `node_modules/.bin`, not from a relative `PATH` entry, and not from any
 * candidate whose path or symlink target lies under `root`. A checkout must not be able to replace
 * a program the CLI starts (the analyzer child keeps CI tokens such as CI_JOB_TOKEN). Ruling C19:
 * on Windows only `.exe`/`.com` files qualify (Node cannot spawn `.cmd` shims without a shell).
 */
export function resolveBinary(name: string, o: ResolveBinaryOptions): string | null {
  const platform = o.platform ?? process.platform;
  const { dirs, names } = candidates(name, o);
  for (const dir of [...dirs.filter((d) => path.isAbsolute(d)), ...IMAGE_BIN_DIRS]) {
    for (const file of names) {
      const candidate = path.join(dir, file);
      if (executable(candidate, platform) && !isInside(o.root, candidate)) return candidate;
    }
  }
  return null;
}

/**
 * A binary of that name the repository itself provides (its `node_modules/.bin`, a relative
 * `PATH` entry or a `PATH` directory inside the checkout). Never run: it only lets a skip reason
 * say why that copy was not used.
 */
export function findRepoBinary(name: string, o: ResolveBinaryOptions): string | null {
  const platform = o.platform ?? process.platform;
  const { dirs, names } = candidates(name, o);
  for (const dir of [path.join(o.root, 'node_modules', '.bin'), ...dirs]) {
    const abs = path.resolve(o.root, dir);
    for (const file of names) {
      const candidate = path.join(abs, file);
      if (executable(candidate, platform) && (!path.isAbsolute(dir) || isInside(o.root, candidate)))
        return candidate;
    }
  }
  return null;
}

import { realpath, stat } from 'node:fs/promises';
import path from 'node:path';

/** What `checkPluginFile` needs from the file system and the process (tests pass fakes). */
export interface PluginFileSystem {
  realpath(path: string): Promise<string>;
  stat(path: string): Promise<{
    isFile(): boolean;
    mode: number;
    uid: number;
  }>;
  /** `process.platform`: the path rules, and whether the owner and mode checks apply (POSIX). */
  platform: NodeJS.Platform;
  /** The server's own uid (`process.getuid()`); null where there is none (Windows). */
  uid: number | null;
}

export type PluginFileCheck = { ok: true; realPath: string } | { ok: false; reason: string };

const nodeFileSystem = (): PluginFileSystem => ({
  realpath: (p) => realpath(p),
  stat: (p) => stat(p),
  platform: process.platform,
  uid: typeof process.getuid === 'function' ? process.getuid() : null,
});

const PLUGIN_EXTENSIONS = ['.js', '.mjs'];
/** Group- or world-writable (enterprise.md §10.1.1). */
const WRITABLE_BY_OTHERS = 0o022;

/** A UNC path (two slashes or backslashes) or a Win32 device path (`\\?\`, `\\.\`). */
function isUncOrDevicePath(p: string): boolean {
  return /^[\\/]{2}/.test(p);
}

function ownerProblem(
  what: string,
  info: { mode: number; uid: number },
  fs: PluginFileSystem,
): string | null {
  if ((info.mode & WRITABLE_BY_OTHERS) !== 0) return `${what} is writable by group or others`;
  if (info.uid !== 0 && info.uid !== fs.uid) {
    return `${what} is not owned by root or the server's user`;
  }
  return null;
}

/**
 * enterprise.md §10.1.1 (ruling R-PLUGINPATH): whether a QUALOR_PLUGIN_PATHS entry may be
 * imported. The path is resolved (symbolic links are allowed, so a ConfigMap mount works); a UNC
 * or device path is refused before and after resolving; the target must be a regular .js or .mjs
 * file; on POSIX it and its directory must not be group- or world-writable and must be owned by
 * root or the server's own user. The reason never holds file content.
 */
export async function checkPluginFile(
  file: string,
  fs: PluginFileSystem = nodeFileSystem(),
): Promise<PluginFileCheck> {
  // The path rules of the platform the check is about (a test may fake the other one).
  const { dirname, extname, isAbsolute } = fs.platform === 'win32' ? path.win32 : path.posix;
  if (typeof file !== 'string' || file.includes('\0') || !isAbsolute(file)) {
    return { ok: false, reason: 'a plugin path must be absolute' };
  }
  if (isUncOrDevicePath(file)) {
    return { ok: false, reason: 'a plugin path must not be a UNC or device path' };
  }
  let realPath: string;
  try {
    realPath = await fs.realpath(file);
  } catch {
    return { ok: false, reason: 'the plugin file does not exist or cannot be resolved' };
  }
  if (isUncOrDevicePath(realPath)) {
    return { ok: false, reason: 'the plugin path resolves to a UNC or device path' };
  }
  if (!PLUGIN_EXTENSIONS.includes(extname(realPath))) {
    return { ok: false, reason: 'the plugin path does not resolve to a .js or .mjs file' };
  }
  let target: Awaited<ReturnType<PluginFileSystem['stat']>>;
  let directory: Awaited<ReturnType<PluginFileSystem['stat']>>;
  try {
    target = await fs.stat(realPath);
    directory = await fs.stat(dirname(realPath));
  } catch {
    return { ok: false, reason: 'the plugin file cannot be read' };
  }
  if (!target.isFile()) return { ok: false, reason: 'the plugin path is not a regular file' };
  if (fs.platform !== 'win32') {
    const problem =
      ownerProblem('the plugin file', target, fs) ??
      ownerProblem("the plugin file's directory", directory, fs);
    if (problem) return { ok: false, reason: problem };
  }
  return { ok: true, realPath };
}

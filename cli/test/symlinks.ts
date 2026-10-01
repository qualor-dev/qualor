import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * A *file* symlink (unlike a directory junction) needs Developer Mode or elevation on Windows.
 * Probing once lets file-symlink tests run wherever the platform allows it (every POSIX CI runner,
 * the analyzers toolbox, Windows in Developer Mode) and show as skipped where it does not.
 */
export function canCreateFileSymlinks(): boolean {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-symlink-check-'));
  try {
    const target = path.join(dir, 'target.txt');
    writeFileSync(target, 'x');
    symlinkSync(target, path.join(dir, 'link.txt'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach } from 'vitest';

/** Returns a factory of temporary directories that are removed after each test. */
export function useTempDirs(): (prefix?: string) => string {
  const dirs: string[] = [];
  afterEach(() => {
    // Retries cover Windows' short delay between a killed process exiting and its handles closing.
    for (const dir of dirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    }
  });
  return (prefix = 'qualor-cli-') => {
    const dir = realpathSync.native(mkdtempSync(path.join(os.tmpdir(), prefix)));
    dirs.push(dir);
    return dir;
  };
}

/** Writes `files` (repo-relative, `/`-separated) under `root`, creating directories. */
export function writeTree(root: string, files: Record<string, string | Uint8Array>): void {
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, ...rel.split('/'));
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
}

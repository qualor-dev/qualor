import { mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const LEASE_NAME = /^[0-9a-f]{32}$/;
const MAX_AGE_MS = 24 * 3600_000;

/**
 * Ruling D10 as amended by the final review (R9): beside the hook, derived from the same MSBuild
 * user directory, so every job whose builds read that hook sees every other job's lease, whatever
 * each sets `QUALOR_CACHE_DIR` to. In the parent of `ImportBefore/`, never inside it: MSBuild
 * imports every file there.
 */
export function leaseDir(userDir: string): string {
  return path.join(userDir, 'Current', 'Microsoft.Common.targets', '.qualor-leases');
}

export function addLease(dir: string, id: string, root: string, now: Date): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, id), `${JSON.stringify({ root, startedAt: now.toISOString() })}\n`);
}

/** Removes this session's lease and every stale one; returns how many live leases remain. */
export function releaseLeases(dir: string, id: string, now: Date): number {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return 0;
  }
  let live = 0;
  for (const name of names) {
    if (!LEASE_NAME.test(name)) continue;
    const file = path.join(dir, name);
    let stale = name === id;
    if (!stale) {
      try {
        stale = now.getTime() - statSync(file).mtimeMs > MAX_AGE_MS;
      } catch {
        continue;
      }
    }
    if (stale) rmSync(file, { force: true });
    else live += 1;
  }
  return live;
}

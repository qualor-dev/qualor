import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import ignore, { type Ignore } from 'ignore';
import type { Warnings } from '../warnings';

/** Rules of one ignore file; `base` is its directory as a repo path ('' for the root). */
export interface IgnoreLayer {
  base: string;
  rules: Ignore;
}

/** A `.gitignore`/`.git/info/exclude` larger than this is skipped rather than read in full. */
export const MAX_IGNORE_FILE_BYTES = 1024 * 1024;

/**
 * Reads one ignore file's rules. `lstatSync` (never `statSync`/`existsSync`, which follow
 * symlinks) decides what the path is: a missing path contributes no rules, silently, like git. A
 * symlink or junction is never followed — not even to check whether it points at a regular file —
 * because the global constraint that symlinks are never followed applies to `.gitignore` itself,
 * not just to the files it would otherwise exclude. Anything that is not a regular file (a
 * directory, FIFO, device, ...), and anything over `MAX_IGNORE_FILE_BYTES`, is skipped the same
 * way rather than opened, so a crafted repo can't make a scan read outside itself, block on a
 * device, or exhaust memory on an oversized ignore file. Each skip is warned once.
 */
export function readIgnoreLayer(
  absFile: string,
  base: string,
  warnings: Warnings,
): IgnoreLayer | null {
  let stat;
  try {
    stat = lstatSync(absFile);
  } catch {
    // Missing (or unreadable metadata): this layer contributes no rules, as git does.
    return null;
  }
  if (stat.isSymbolicLink()) {
    warnings.add('SYMLINK_SKIPPED', 'symbolic links and junctions are not followed');
    return null;
  }
  if (!stat.isFile()) {
    warnings.add('GITIGNORE_UNREADABLE', 'a .gitignore file could not be read and was skipped');
    return null;
  }
  if (stat.size > MAX_IGNORE_FILE_BYTES) {
    warnings.add('GITIGNORE_UNREADABLE', 'a .gitignore file could not be read and was skipped');
    return null;
  }
  try {
    return { base, rules: ignore().add(readFileSync(absFile, 'utf8')) };
  } catch {
    // An unreadable ignore file ignores nothing, as git does.
    return null;
  }
}

/**
 * Ruling C16: `.git/info/exclude` and `.gitignore` of the scan root. Parent directories of a
 * sub-folder scan and the global excludes file are not read.
 */
export function rootIgnoreLayers(root: string, warnings: Warnings): IgnoreLayer[] {
  return [
    readIgnoreLayer(path.join(root, '.git', 'info', 'exclude'), '', warnings),
    readIgnoreLayer(path.join(root, '.gitignore'), '', warnings),
  ].filter((l): l is IgnoreLayer => l !== null);
}

/** Deeper layers override shallower ones, including negations (`!keep.ts`). */
export function isIgnored(
  layers: readonly IgnoreLayer[],
  repoPath: string,
  isDirectory: boolean,
): boolean {
  let ignored = false;
  for (const { base, rules } of layers) {
    if (base !== '' && !repoPath.startsWith(`${base}/`)) continue;
    const rel = base === '' ? repoPath : repoPath.slice(base.length + 1);
    const result = rules.test(isDirectory ? `${rel}/` : rel);
    if (result.ignored) ignored = true;
    else if (result.unignored) ignored = false;
  }
  return ignored;
}

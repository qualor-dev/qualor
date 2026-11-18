/**
 * B1 for JS lockfiles (spec §12): npm (`package-lock.json`, `npm-shrinkwrap.json`, v1 to v3),
 * pnpm (`pnpm-lock.yaml`, v5 to v9) and Yarn (`yarn.lock`, classic and Berry) are read into
 * {@link LockEntry} lists, one module per format, then checked by {@link checkLockEntries} and
 * {@link lockfileBelowTarget}. The readers throw on a file they cannot read;
 * {@link checkJsLockfile} answers `unparsable`.
 */
import { checkLockEntries, lockfileBelowTarget, newLockEntries } from './lock-entries';
import { parseNpmLock } from './lock-npm';
import { parsePnpmLock } from './lock-pnpm';
import { readBoth, type ReadLock } from './lock-read';
import { parseYarnBerry } from './lock-yarn-berry';
import { isYarnClassic, parseYarnClassic } from './lock-yarn-classic';
import {
  FIX_CHECK_OK,
  fixRefused,
  type FixCheckContext,
  type FixCheckResult,
  type FixFileChange,
  type LockEntry,
} from './types';
import { stripBom } from './values';

export { readNpmLock } from './lock-npm';
export { readPnpmLock } from './lock-pnpm';

function parseYarnLock(text: string): ReadLock {
  const source = stripBom(text);
  return isYarnClassic(source) ? parseYarnClassic(source) : parseYarnBerry(source);
}

/** `yarn.lock`: classic (`# yarn lockfile v1`) by a line parser, Berry (`__metadata`) as YAML. */
export function readYarnLock(text: string): LockEntry[] {
  return parseYarnLock(text).entries;
}

/** The public registries of npm, pnpm and Yarn. */
const JS_PUBLIC_REGISTRIES = ['https://registry.npmjs.org', 'https://registry.yarnpkg.com'];

const READERS: ReadonlyMap<string, (text: string) => ReadLock> = new Map([
  ['package-lock.json', parseNpmLock],
  ['npm-shrinkwrap.json', parseNpmLock],
  ['pnpm-lock.yaml', parsePnpmLock],
  ['yarn.lock', parseYarnLock],
]);

function readerFor(path: string): ((text: string) => ReadLock) | undefined {
  return READERS.get(path.slice(path.lastIndexOf('/') + 1));
}

/**
 * Ruling T3i: the entries a JS lockfile change adds, each with its slot, name and version, for the
 * MR body; null for a file that is not a JS lockfile or cannot be read in one format.
 */
export function jsLockfileAdditions(change: FixFileChange): LockEntry[] | null {
  const read = readerFor(change.path);
  const both = read === undefined ? null : readBoth(read, change);
  return both === null ? null : newLockEntries(both[0], both[1]);
}

/**
 * B1 for a JS lockfile: both sides are read in one format (`unparsable` otherwise), every new
 * entry passes {@link checkLockEntries} (the npm and Yarn public registries allowed; integrity
 * required when a base registry entry has one; new entries reachable from the package), and the
 * package's versions reach their targets in this lockfile (`below_target`).
 */
export function checkJsLockfile(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const read = readerFor(change.path);
  if (read === undefined) return fixRefused('other_change', change.path);
  const both = readBoth(read, change);
  if (both === null) return fixRefused('unparsable', change.path);
  const [base, next] = both;
  const integrityRequired = base.some((e) => e.kind === 'registry' && (e.integrity ?? '') !== '');
  const options = {
    lockfile: change.path,
    publicHosts: JS_PUBLIC_REGISTRIES,
    integrityRequired,
    reachableOnly: true,
  };
  const entries = checkLockEntries(base, next, { ...ctx, ...options });
  if (!entries.ok) return entries;
  if (lockfileBelowTarget(base, next, ctx, change.path)) {
    return fixRefused('below_target', change.path);
  }
  return FIX_CHECK_OK;
}

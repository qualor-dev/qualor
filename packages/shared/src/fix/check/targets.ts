/**
 * The target rules of a fix upload (R7's local part, R30, rulings T9c, T9g–T9i): one function, run
 * by the server's result route and by the CLI before it uploads, so the two never drift.
 */
import { fixFileKind, type FixFamily } from '../families';
import { greatestVersion } from '../target';
import { isGreater, sameVersion, schemeOf, type VersionScheme } from '../versions';
import type { FixTarget } from './types';

/** What the target rules read of an upload. */
export interface FixTargetFields {
  targets: readonly FixTarget[];
  /** The MR's lockfile lines; only their paths are read. */
  lockfiles: readonly { path: string }[];
  targetVersion: string;
  installedVersion: string;
}

/** The rule a target check failed and the file it failed on ('' when it names none). */
export interface FixTargetProblem {
  rule: 'no_targets' | 'target_mismatch';
  path: string;
}

const mismatch = (path: string): FixTargetProblem => ({ rule: 'target_mismatch', path });

/** The directory part of a path, with its slash ('' at the root). */
const directoryOf = (path: string): string => path.slice(0, path.lastIndexOf('/') + 1);

/**
 * Ruling T9i: an uploaded lockfile of the family no target names (F14 skips `below_target` on one
 * that is not, so it could move the package anywhere); a `go.sum` through the `go.mod` beside it.
 * Manifests need none.
 */
function unnamedLockfile(
  family: FixFamily,
  targets: readonly FixTarget[],
  paths: readonly string[],
): string | undefined {
  const named = new Set(targets.map((t) => t.lockfile));
  return paths.find((p) => {
    if (fixFileKind(family, p) !== 'lockfile') return false;
    const isGoSum = p.slice(p.lastIndexOf('/') + 1) === 'go.sum';
    return !named.has(isGoSum ? `${directoryOf(p)}go.mod` : p);
  });
}

/**
 * Rulings T9g, T9h: each target above its installed version and in an uploaded file, each
 * lockfile line an uploaded file.
 */
function outsideUpload(
  scheme: VersionScheme,
  upload: FixTargetFields,
  uploaded: ReadonlySet<string>,
): FixTargetProblem | null {
  const notAbove = upload.targets.find((t) => !isGreater(scheme, t.target, t.installed));
  if (notAbove !== undefined) return mismatch(notAbove.lockfile);
  const outside = upload.targets.find((t) => !uploaded.has(t.lockfile));
  if (outside !== undefined) return mismatch(outside.lockfile);
  const line = upload.lockfiles.find((l) => !uploaded.has(l.path));
  return line === undefined ? null : mismatch(line.path);
}

/** R30: `targetVersion` is the greatest target, and `installedVersion` that of a target reaching it. */
function topMismatch(scheme: VersionScheme, upload: FixTargetFields): boolean {
  const greatest = greatestVersion(
    scheme,
    upload.targets.map((t) => t.target),
  );
  const named = upload.targets.some(
    (t) =>
      sameVersion(scheme, t.target, upload.targetVersion) &&
      sameVersion(scheme, t.installed, upload.installedVersion),
  );
  return greatest === null || !sameVersion(scheme, greatest, upload.targetVersion) || !named;
}

/**
 * The target rules of an upload of the files `paths`, in the server's order: `no_targets` without
 * a target; then `target_mismatch` for a target not above its installed version, a target or a
 * lockfile line naming no uploaded file, an uploaded lockfile no target names (a `go.sum` through
 * its `go.mod`), or a `targetVersion` that is not the greatest target with an `installedVersion`
 * of a target reaching it. The first problem, or null.
 */
export function fixTargetProblem(
  family: FixFamily,
  upload: FixTargetFields,
  paths: readonly string[],
): FixTargetProblem | null {
  if (upload.targets.length === 0) return { rule: 'no_targets', path: '' };
  const scheme = schemeOf(family);
  const outside = outsideUpload(scheme, upload, new Set(paths));
  if (outside !== null) return outside;
  const unnamed = unnamedLockfile(family, upload.targets, paths);
  if (unnamed !== undefined) return mismatch(unnamed);
  return topMismatch(scheme, upload) ? mismatch('') : null;
}

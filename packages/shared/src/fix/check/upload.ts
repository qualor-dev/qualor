/**
 * B1 (spec §12): the one entry point the server calls on a fix upload. Each file goes to the
 * check of its family and basename; the first failure wins, in file order.
 */
import type { FixFamily } from '../families';
import { checkGoMod, checkGoSum } from './go';
import { checkJsLockfile } from './js-lockfiles';
import { checkPackageJson, checkPnpmWorkspace } from './js-manifest';
import { checkPom } from './maven';
import { checkPyproject, checkPythonLock } from './python';
import {
  FIX_CHECK_OK,
  fixRefused,
  type FixCheckContext,
  type FixCheckResult,
  type FixFileChange,
} from './types';

/** What the server checks: the fix and the uploaded files, each with its text at `baseSha`. */
export interface FixUploadCheck extends FixCheckContext {
  files: readonly FixFileChange[];
}

type FileCheck = (change: FixFileChange, ctx: FixCheckContext) => FixCheckResult;

/** The check of each file a family may change (§6.7, `FIX_FILES`), by basename. */
const CHECKS: Readonly<Record<FixFamily, ReadonlyMap<string, FileCheck>>> = {
  js: new Map([
    ['package.json', checkPackageJson],
    ['pnpm-workspace.yaml', checkPnpmWorkspace],
    ['package-lock.json', checkJsLockfile],
    ['npm-shrinkwrap.json', checkJsLockfile],
    ['pnpm-lock.yaml', checkJsLockfile],
    ['yarn.lock', checkJsLockfile],
  ]),
  go: new Map([
    ['go.mod', checkGoMod],
    ['go.sum', checkGoSum],
  ]),
  maven: new Map([['pom.xml', checkPom]]),
  python: new Map([
    ['pyproject.toml', checkPyproject],
    ['uv.lock', checkPythonLock],
    ['poetry.lock', checkPythonLock],
  ]),
};

/** One file: `other_change` for a name the family has no check for; a throw is `unparsable`. */
function checkFile(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const checks = Object.hasOwn(CHECKS, ctx.family) ? CHECKS[ctx.family] : undefined;
  const check = checks?.get(change.path.slice(change.path.lastIndexOf('/') + 1));
  if (check === undefined) return fixRefused('other_change', change.path);
  try {
    return check(change, ctx);
  } catch {
    return fixRefused('unparsable', change.path);
  }
}

/**
 * B1 for a whole upload: each file by its family and basename (`package.json`, `go.mod`,
 * `pom.xml`, `uv.lock`, …; any other name is `other_change`); the first failing file, in file
 * order, names the rule and its path. The paths themselves (relative, allowlisted, existing at
 * `baseSha`) are checked before, by the caller.
 */
export function checkFixUpload(input: FixUploadCheck): FixCheckResult {
  const ctx: FixCheckContext = {
    family: input.family,
    packageName: input.packageName,
    targets: input.targets,
  };
  for (const change of input.files) {
    const result = checkFile(change, ctx);
    if (!result.ok) return result;
  }
  return FIX_CHECK_OK;
}

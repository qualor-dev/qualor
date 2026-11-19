import { lstatSync } from 'node:fs';
import path from 'node:path';
import {
  checkFixUpload,
  chooseTargets,
  FIX_LIMITS,
  FIX_MAX_DEPENDENTS,
  FIX_RULE_TEXT,
  fixPathProblem,
  fixTargetProblem,
  greatestVersion,
  sameVersion,
  schemeOf,
  urlCredentialCount,
  type FixClaimItem,
  type FixFailureCode,
  type FixFamily,
  type FixFileChange,
  type FixLockfile,
  type FixTargetFields,
  type FixTarget,
  type FixUpload,
  type NoFixReason,
} from '@qualor/shared/fix';
import { gitText, type Git } from '../git/git';
import type {
  AppliedFix,
  FixAdapter,
  FixPlan,
  FixStop,
  FixWorkspace,
  InstalledAt,
} from './adapter';
import { listed } from './files';
import { MissingToolError, ToolTimeoutError } from './runner';
import { changedPaths, committedForm, inScratch } from './workspace';

/**
 * One fix, prepared in its scratch copy (spec §6.5 steps 1–6, B1, B3, B4): where the package is
 * installed, the targets, the adapter's edit, what changed, the same content check the server
 * runs, the adapter's verify, and the files form of the result. Anything the server would refuse
 * is refused here first, as `unplanned_change` naming the rule (rulings T9c, T9i, T9l), so a CLI
 * bug never reaches the server as a refusal.
 */

/** A fix's result without its claim (generation, lease token): the files, a failure or no fix. */
export type FixOutcome =
  | Omit<FixUpload, 'generation' | 'leaseToken'>
  | { failure: { code: FixFailureCode; message: string } }
  | { noFix: { reason: NoFixReason; message: string } };

const failure = (code: FixFailureCode, message: string): FixOutcome => ({
  failure: { code, message },
});
const noFix = (reason: NoFixReason, message: string): FixOutcome => ({
  noFix: { reason, message },
});

function fromStop(stop: FixStop): FixOutcome {
  return stop.kind === 'failure'
    ? failure(stop.code, stop.message)
    : noFix(stop.reason, stop.message);
}

// ─── Upload rules checked before the upload ────────────────────────────────

/**
 * The server's route rules (server/src/fixes/result.ts `UPLOAD_RULES`) this side checks too, and
 * `secret_in_file`, which only this side can check (B9: no secret reaches an uploaded text).
 */
type LocalRule =
  | 'secret_in_file'
  | 'new_file'
  | 'not_a_file'
  | 'path_not_allowed'
  | 'too_many_files'
  | 'too_large'
  | 'not_utf8'
  | 'no_targets'
  | 'target_mismatch';

const LOCAL_RULE_TEXT: Readonly<Record<LocalRule, string>> = {
  secret_in_file:
    "A changed file holds a credential of the job's environment (the project token, a registry token or password), or a URL with a credential, that its text on the main branch does not.",
  new_file: 'The fix added a file; a fix only changes files that exist on the main branch.',
  not_a_file: 'A changed path is no longer a regular file (deleted, or a link).',
  path_not_allowed: 'A changed file is not a manifest or lockfile of the package family.',
  too_many_files: `The fix changed more than ${FIX_LIMITS.maxFiles} files.`,
  too_large: 'The changed files are larger than 32 MiB together.',
  not_utf8: 'A changed file is not UTF-8 text, or holds a NUL character.',
  no_targets: 'The fix names no target version.',
  target_mismatch:
    'The targets do not match the changed files: each target must be above its installed version, each target and lockfile line must name a changed file, each changed lockfile must have a target, and the target version must be the greatest target.',
};

/** `failure unplanned_change` naming the rule (local or B1's) and the paths it failed on. */
function unplanned(rule: string, text: string, paths: readonly string[]): FixOutcome {
  const files = paths.length === 0 ? '' : ` (${listed(paths)})`;
  return failure('unplanned_change', `The fix breaks the upload rule ${rule}: ${text}${files}`);
}

const local = (rule: LocalRule, paths: readonly string[]): FixOutcome =>
  unplanned(rule, LOCAL_RULE_TEXT[rule], paths);

/** How often `part` occurs in `text`. */
function occurrences(text: string, part: string): number {
  let n = 0;
  for (let at = text.indexOf(part); at !== -1; at = text.indexOf(part, at + part.length)) n += 1;
  return n;
}

/**
 * B9, §6.9, I1: the first changed file that holds one of the job's credentials (the project token,
 * credential-like values of the environment: `fixJobSecrets`) or a URL with a credential (any
 * http(s) userinfo, an ssh one with a password: `urlCredentialCount`, ruling T12l) more often than
 * its text at HEAD, so a package manager that wrote a registry credential into a lockfile never has
 * it uploaded. Ordinary text (`true`, a project key, `git@`) is no credential.
 */
function secretFile(
  files: readonly FixFileChange[],
  credentials: readonly string[],
): string | undefined {
  const known = credentials.filter((s) => s.length >= 4);
  return files.find(
    (f) =>
      urlCredentialCount(f.next) > urlCredentialCount(f.base) ||
      known.some((s) => occurrences(f.next, s) > occurrences(f.base, s)),
  )?.path;
}

// ─── Steps ─────────────────────────────────────────────────────────────────

/**
 * Step 1: each lockfile's installed versions of the package that the claim names as vulnerable,
 * each once; lockfiles without one are left out.
 */
async function vulnerableInstalls(
  fix: FixClaimItem,
  adapter: FixAdapter,
  ws: FixWorkspace,
): Promise<InstalledAt[]> {
  const scheme = schemeOf(fix.family);
  const claimed = (v: string) => fix.installedVersions.some((w) => sameVersion(scheme, v, w));
  const byLockfile = new Map<string, string[]>();
  for (const at of await adapter.installed(ws, fix.packageName)) {
    const versions = byLockfile.get(at.lockfile) ?? [];
    for (const v of at.versions.filter(claimed)) {
      if (!versions.some((known) => sameVersion(scheme, known, v))) versions.push(v);
    }
    if (versions.length > 0) byLockfile.set(at.lockfile, versions);
  }
  return [...byLockfile].map(([lockfile, versions]) => ({ lockfile, versions }));
}

/** Step 2 (B3): a target per vulnerable installed version and lockfile, and the unfixable ids. */
function targetsOf(
  fix: FixClaimItem,
  installs: readonly InstalledAt[],
): Omit<FixPlan, 'greatest' | 'installed'> {
  const scheme = schemeOf(fix.family);
  const targets: FixTarget[] = [];
  const unfixable = new Set<string>();
  let majorJump = false;
  for (const at of installs) {
    for (const choice of chooseTargets(scheme, at.versions, fix.vulnerabilities)) {
      for (const id of choice.unfixable) unfixable.add(id);
      if (choice.target === null) continue;
      targets.push({ installed: choice.installed, target: choice.target, lockfile: at.lockfile });
      majorJump ||= choice.majorJump;
    }
  }
  return { targets, unfixable: [...unfixable], majorJump };
}

/**
 * Step 2: the plan, or no fix: no target at all (`no_fixed_version`), or a greatest target a
 * person declined before (B4, `declined`).
 */
function planFix(fix: FixClaimItem, installs: readonly InstalledAt[]): FixPlan | FixOutcome {
  const scheme = schemeOf(fix.family);
  const found = targetsOf(fix, installs);
  const greatest = greatestVersion(
    scheme,
    found.targets.map((t) => t.target),
  );
  const top =
    greatest === null
      ? undefined
      : found.targets.find((t) => sameVersion(scheme, t.target, greatest));
  if (greatest === null || top === undefined) {
    const installed = installs.flatMap((at) => at.versions);
    return noFix(
      'no_fixed_version',
      `No fixed version of ${fix.packageName} is above the installed ${listed(installed)}.`,
    );
  }
  if (fix.declinedTarget !== null && sameVersion(scheme, greatest, fix.declinedTarget)) {
    return noFix(
      'declined',
      `A merge request to ${fix.packageName} ${greatest} was declined before; Qualor does not propose that version again.`,
    );
  }
  return { ...found, greatest, installed: top.installed };
}

const isPlan = (value: FixPlan | FixOutcome): value is FixPlan => 'greatest' in value;

/** A lockfile line as the result schema takes it: its four fields, at most 5 dependents (R6). */
const lockfileLine = (l: FixLockfile): FixLockfile => ({
  path: l.path,
  relation: l.relation,
  mechanism: l.mechanism,
  dependents: l.dependents.slice(0, FIX_MAX_DEPENDENTS),
});
const isStop = (value: AppliedFix | FixStop): value is FixStop => 'kind' in value;

/** A file's size when it is a regular file (not deleted, not a link), else null. */
function regularFileSize(abs: string): number | null {
  try {
    const stat = lstatSync(abs);
    return stat.isFile() ? stat.size : null;
  } catch {
    return null;
  }
}

/** `fatal`: invalid UTF-8 throws; `ignoreBOM`: a byte order mark stays in the text, as the server reads it. */
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** The file's text, or null when it is not UTF-8 text or holds U+0000 (ruling T9l). */
function utf8Text(bytes: Uint8Array): string | null {
  try {
    const text = UTF8.decode(bytes);
    return text.includes('\u0000') ? null : text;
  } catch {
    return null;
  }
}

/** Each path a regular file of at most 32 MiB together in the working tree; the first problem. */
function workingTreeProblem(root: string, paths: readonly string[]): FixOutcome | null {
  let total = 0;
  for (const p of paths) {
    const size = regularFileSize(path.join(root, ...p.split('/')));
    if (size === null) return local('not_a_file', [p]);
    total += size;
    if (total > FIX_LIMITS.maxTotalBytes) return local('too_large', [p]);
  }
  return null;
}

/**
 * Steps 4–5: each changed file's new text as a commit holds it (ruling T12e: staged, so
 * `.gitattributes` line endings are undone; 32 MiB together, UTF-8 without NUL) and its text at HEAD
 * (`git show HEAD:<path>`), in path order.
 */
async function readChanges(
  root: string,
  git: Git,
  paths: readonly string[],
): Promise<FixFileChange[] | FixOutcome> {
  const problem = workingTreeProblem(root, paths);
  if (problem !== null) return problem;
  const blobs = await committedForm(git, { root }, paths);
  if (blobs.reduce((n, b) => n + b.length, 0) > FIX_LIMITS.maxTotalBytes) {
    return local('too_large', []);
  }
  const changes: FixFileChange[] = [];
  for (const [i, p] of paths.entries()) {
    const next = utf8Text(blobs[i] ?? Buffer.alloc(0));
    if (next === null) return local('not_utf8', [p]);
    const base = await gitText(git, inScratch(root, ['show', `HEAD:${p}`]));
    changes.push({ path: p, base, next });
  }
  return changes;
}

/**
 * Step 4: what the tools changed, as the upload's shape rules see it (§6.7, R16): no added file,
 * at least one changed file, at most 50, each a manifest or lockfile of the family; then read.
 */
async function changedFiles(
  family: FixFamily,
  ws: FixWorkspace,
  git: Git,
): Promise<FixFileChange[] | FixOutcome> {
  const { changed, added } = await changedPaths(git, ws);
  if (added.length > 0) return local('new_file', added.toSorted());
  if (changed.length === 0) {
    return failure('verify_failed', 'The package manager changed no manifest or lockfile.');
  }
  const paths = changed.toSorted();
  if (paths.length > FIX_LIMITS.maxFiles) return local('too_many_files', []);
  const outside = paths.filter((p) => fixPathProblem(family, p) !== null);
  if (outside.length > 0) return local('path_not_allowed', outside);
  return readChanges(ws.root, git, paths);
}

/**
 * Steps 5–6: no secret in a file (B9), the target rules (T9c, T9i), then the shared content check
 * (B1), as the server runs them.
 */
function uploadProblem(
  fix: FixClaimItem,
  upload: FixTargetFields,
  files: readonly FixFileChange[],
  credentials: readonly string[],
): FixOutcome | null {
  const leaked = secretFile(files, credentials);
  if (leaked !== undefined) return local('secret_in_file', [leaked]);
  const paths = files.map((f) => f.path);
  // Rulings T9c, T9i, I2: the server's own target check (`@qualor/shared/fix`).
  const targets = fixTargetProblem(fix.family, upload, paths);
  if (targets !== null) return local(targets.rule, targets.path === '' ? [] : [targets.path]);
  const content = checkFixUpload({
    family: fix.family,
    packageName: fix.packageName,
    targets: upload.targets,
    files,
  });
  return content.ok ? null : unplanned(content.rule, FIX_RULE_TEXT[content.rule], [content.path]);
}

/** A throw from an adapter or a tool: `missing_tool` for a tool that is gone (B7), else `package_manager`. */
function stopped(fix: FixClaimItem, err: unknown): FixOutcome {
  if (err instanceof MissingToolError) return failure('missing_tool', err.message);
  if (err instanceof ToolTimeoutError) return failure('timeout', err.message);
  const why = err instanceof Error ? err.message : String(err);
  return failure('package_manager', `The ${fix.family} fix of ${fix.packageName} stopped: ${why}`);
}

async function prepare(
  fix: FixClaimItem,
  adapter: FixAdapter,
  ws: FixWorkspace,
  job: { git: Git; credentials: readonly string[] },
): Promise<FixOutcome> {
  const { git } = job;
  const installs = await vulnerableInstalls(fix, adapter, ws);
  if (installs.length === 0) {
    return noFix(
      'not_installed',
      `No lockfile of this checkout resolves ${fix.packageName} to ${listed(fix.installedVersions)}.`,
    );
  }
  const plan = planFix(fix, installs);
  if (!isPlan(plan)) return plan;
  const applied = await adapter.apply(ws, fix, plan);
  if (isStop(applied)) return fromStop(applied);
  const files = await changedFiles(fix.family, ws, git);
  if (!Array.isArray(files)) return files;
  // Ruling T12i: the targets as checked, a copy no later step of the adapter can change.
  const upload = {
    targets: plan.targets.map((t) => ({
      installed: t.installed,
      target: t.target,
      lockfile: t.lockfile,
    })),
    lockfiles: applied.lockfiles.map(lockfileLine),
    targetVersion: plan.greatest,
    installedVersion: plan.installed,
  };
  const problem = uploadProblem(fix, upload, files, job.credentials);
  if (problem !== null) return problem;
  const verified = (await adapter.verify?.(ws, fix, plan)) ?? null;
  if (verified !== null) return fromStop(verified);
  const baseSha = (
    await gitText(git, inScratch(ws.root, ['rev-parse', '--verify', 'HEAD^{commit}']))
  ).trim();
  return {
    baseSha,
    ...upload,
    files: files.map((f) => ({
      path: f.path,
      content: Buffer.from(f.next, 'utf8').toString('base64'),
    })),
    unfixable: plan.unfixable,
  };
}

/**
 * Prepares one claimed fix in its workspace (spec §6.5), in this order: `installed` (none of the
 * claim's versions → `noFix not_installed`); the targets per lockfile (`chooseTargets`; none →
 * `noFix no_fixed_version`; the greatest equal to `declinedTarget` → `noFix declined`); `apply`;
 * what changed (an added file → `failure unplanned_change`); the base texts (`git show HEAD:<path>`);
 * the target rules and `checkFixUpload` (a rule → `failure unplanned_change` naming it); `verify`;
 * the files form. `git` is the checkout's; it reads the workspace with `-C`, hooks off (T12d).
 * `o.credentials` are the job's credentials (B9, I1: `fixJobSecrets`): a changed file that gains
 * one, or a URL with a password, is `unplanned_change` (`secret_in_file`). Never throws for an
 * adapter or a tool: a throw is a failure (`missing_tool` or `package_manager`).
 */
export async function prepareFix(
  fix: FixClaimItem,
  adapter: FixAdapter,
  ws: FixWorkspace,
  git: Git,
  o: { credentials?: readonly string[] } = {},
): Promise<FixOutcome> {
  try {
    return await prepare(fix, adapter, ws, { git, credentials: o.credentials ?? [] });
  } catch (err) {
    return stopped(fix, err);
  }
}

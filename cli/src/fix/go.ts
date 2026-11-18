import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import {
  compareVersions,
  greatestVersion,
  readGoMod,
  readGoSum,
  sameVersion,
  type FixClaimItem,
  type FixLockfile,
  type FixTarget,
  type GoModFile,
} from '@qualor/shared/fix';
import type {
  AppliedFix,
  FixAdapter,
  FixPlan,
  FixStop,
  FixWorkspace,
  InstalledAt,
} from './adapter';
import { toolFailure, type ToolResult } from './runner';

/**
 * The Go family (spec §6.5, R3, R24): Go modules. In the folder of each `go.mod` whose `require`
 * of the package is a vulnerable version, `go get <module>@v<target>` then `go mod tidy`, both
 * with `GOTOOLCHAIN=local` (a target that needs a newer Go fails instead of fetching a toolchain)
 * and `GOFLAGS=-mod=mod`. Go raises the `require` line itself, `// indirect` kept, and writes the
 * new `go.sum` lines; the job's own `GOPROXY`, `GONOSUMDB`, … apply, as in the customer's build.
 *
 * - **Relation:** direct when the `require` line is not `// indirect`, else transitive; Go needs
 *   no pin, so there is no mechanism.
 * - **Refused before any `go` runs** (`manifest_unsupported`): a module with a tracked
 *   `vendor/modules.txt` (R24: Qualor does not re-vendor), a `go.mod` or `go.sum` that is a link,
 *   and a `replace` of the package for every version (the `require` would move while the build
 *   kept the replacement).
 * - **Target lockfile:** each target names the `go.mod` it changes; its `go.sum` is covered
 *   through that `go.mod` (ruling T9i).
 */

/** R24: the variables of both `go` calls. */
const GO_ENV: Readonly<Record<string, string>> = Object.freeze({
  GOTOOLCHAIN: 'local',
  GOFLAGS: '-mod=mod',
});

const INCOMPATIBLE = '+incompatible';
/** A module path that ends in its major version (`/v2`, `/v25`). */
const MAJOR_SUFFIX = /\/v\d+$/;

/**
 * The version `go get` takes for a target (ruling T1d): with Go's `v`; and when the installed
 * version is `+incompatible`, the target has no suffix and the module path has no `/vN`, with
 * `+incompatible` (advisories drop it, and `go get` refuses a bare `v25.0.6` on such a path).
 */
export function goGetVersion(modulePath: string, installed: string, target: string): string {
  const version = target.startsWith('v') ? target : `v${target}`;
  const incompatible =
    installed.endsWith(INCOMPATIBLE) &&
    !version.endsWith(INCOMPATIBLE) &&
    !MAJOR_SUFFIX.test(modulePath);
  return incompatible ? `${version}${INCOMPATIBLE}` : version;
}

/** One module of the repository that the fix changes. */
interface Module {
  /** '' at the repository root, else the folder with a trailing `/`. */
  dir: string;
  goMod: string;
  relation: 'direct' | 'transitive';
  /** `<module>@<version>` for `go get`. */
  spec: string;
}

const isStop = (v: unknown): v is FixStop => typeof v === 'object' && v !== null && 'kind' in v;
const unsupported = (message: string): FixStop => ({
  kind: 'failure',
  code: 'manifest_unsupported',
  message,
});
const verifyFailed = (message: string): FixStop => ({
  kind: 'failure',
  code: 'verify_failed',
  message,
});

// ─── Files ──────────────────────────────────────────────────────────────────

const basename = (p: string) => p.slice(p.lastIndexOf('/') + 1);
/** A repository path's folder with its slash ('' at the root). */
const dirOf = (p: string) => p.slice(0, p.lastIndexOf('/') + 1);
/** A `go.mod` of a vendored copy, not a module of the repository. */
const inVendor = (p: string) => p.split('/').slice(0, -1).includes('vendor');

const absolute = (ws: FixWorkspace, rel: string) => path.join(ws.root, ...rel.split('/'));
const readText = (ws: FixWorkspace, rel: string) => readFileSync(absolute(ws, rel), 'utf8');
const where = (dir: string) => (dir === '' ? 'the repository root' : dir);

/** Whether a repository path is a regular file of the scratch copy: not a link, not missing. */
function isRegularFile(ws: FixWorkspace, rel: string): boolean {
  try {
    return lstatSync(absolute(ws, rel)).isFile();
  } catch {
    return false;
  }
}

/** The `go.mod` read (Task 4's reader); a file it cannot read throws, naming it. */
function goModAt(ws: FixWorkspace, file: string): GoModFile {
  try {
    return readGoMod(readText(ws, file));
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    throw new Error(`cannot read ${file}: ${why}`, { cause: err });
  }
}

/** The package's `require` lines of a `go.mod`. */
const requiresOf = (file: GoModFile, packageName: string) =>
  file.requires.filter((r) => r.path === packageName);

// ─── Modules ────────────────────────────────────────────────────────────────

/** A `replace` of the package without a version on its left: it replaces every version. */
function replacesEveryVersion(file: GoModFile, packageName: string): boolean {
  return file.directives.some(
    ({ verb, text }) => verb === 'replace' && text.startsWith(`${packageName} => `),
  );
}

/** What stops a module before any `go` runs (R24, links, a replace), or null. */
function moduleStop(
  ws: FixWorkspace,
  tracked: ReadonlySet<string>,
  goMod: string,
  packageName: string,
): FixStop | null {
  const dir = dirOf(goMod);
  const vendor = `${dir}vendor/modules.txt`;
  if (tracked.has(vendor)) {
    return unsupported(
      `${vendor} is tracked: a vendored module, whose vendor folder Qualor does not update.`,
    );
  }
  const goSum = `${dir}go.sum`;
  const link = [goMod, ...(tracked.has(goSum) ? [goSum] : [])].find((f) => !isRegularFile(ws, f));
  if (link !== undefined) {
    return unsupported(`${link} is not a regular file (a link?); Qualor edits only regular files.`);
  }
  if (replacesEveryVersion(goModAt(ws, goMod), packageName)) {
    return unsupported(
      `${goMod} has a replace of ${packageName} for every version; Qualor changes only require lines, and the build would keep the replacement.`,
    );
  }
  return null;
}

/** The module of one `go.mod` and its targets: its relation, and what `go get` fetches. */
function moduleOf(
  ws: FixWorkspace,
  goMod: string,
  packageName: string,
  targets: readonly FixTarget[],
): Module {
  const requires = requiresOf(goModAt(ws, goMod), packageName);
  const greatest = greatestVersion(
    'go',
    targets.map((t) => t.target),
  );
  const top = targets.find((t) => greatest !== null && sameVersion('go', t.target, greatest));
  const target = top ?? targets[0];
  const version = goGetVersion(packageName, target?.installed ?? '', target?.target ?? '');
  const dir = dirOf(goMod);
  return {
    dir,
    goMod,
    relation: requires.some((r) => !r.indirect) ? 'direct' : 'transitive',
    spec: `${packageName}@${version}`,
  };
}

function groupByLockfile(targets: readonly FixTarget[]): Map<string, FixTarget[]> {
  const out = new Map<string, FixTarget[]>();
  for (const t of targets) out.set(t.lockfile, [...(out.get(t.lockfile) ?? []), t]);
  return out;
}

/** The modules of the plan's targets, in path order, or why one cannot be changed. */
function modulesOf(ws: FixWorkspace, packageName: string, plan: FixPlan): Module[] | FixStop {
  const tracked = new Set(ws.files);
  const byGoMod = [...groupByLockfile(plan.targets)].toSorted(([a], [b]) => a.localeCompare(b));
  const modules: Module[] = [];
  for (const [goMod, targets] of byGoMod) {
    const stop = moduleStop(ws, tracked, goMod, packageName);
    if (stop !== null) return stop;
    modules.push(moduleOf(ws, goMod, packageName, targets));
  }
  return modules;
}

// ─── go ─────────────────────────────────────────────────────────────────────

const timeLeft = (ws: FixWorkspace) => Math.max(0, ws.deadline - Date.now());
const succeeded = (r: ToolResult) => r.exitCode === 0 && !r.timedOut;

function go(ws: FixWorkspace, module: Module, args: readonly string[]): Promise<ToolResult> {
  return ws.run('go', args, {
    cwd: absolute(ws, module.dir),
    env: GO_ENV,
    timeoutMs: timeLeft(ws),
  });
}

/** What a proxy or `go` prints when the requested version does not exist. */
const NOT_FOUND = [
  '404 Not Found',
  '410 Gone',
  'no such file or directory',
  'The system cannot find the file specified',
  'The system cannot find the path specified',
];
const INFO_ERROR = '.info: ';

/**
 * Ruling F36: `go get` reports that the target itself does not exist: a line
 * `go: <module>@<version>: ` followed by `invalid version: unknown revision …` (a VCS or a proxy's
 * answer), or by `reading <proxy>/@v/<version>.info: ` and a not-found answer (404, 410, or a
 * `file://` proxy's missing file). A missing version of another module is a failure.
 */
function targetNotFound(stderr: string, spec: string): boolean {
  const head = `go: ${spec}: `;
  return stderr.split(/\r?\n/).some((line) => {
    if (!line.startsWith(head)) return false;
    const reason = line.slice(head.length);
    if (reason.startsWith('invalid version: unknown revision')) return true;
    const at = reason.lastIndexOf(INFO_ERROR);
    const answer = reason.slice(at + INFO_ERROR.length);
    return reason.startsWith('reading ') && at >= 0 && NOT_FOUND.some((t) => answer.startsWith(t));
  });
}

/** `go get` that did not succeed: `no_fix unresolvable` (F36), else its failure. */
function getStop(r: ToolResult, spec: string): FixStop | null {
  if (succeeded(r)) return null;
  const failure = toolFailure('go', r, []);
  if (!r.timedOut && targetNotFound(r.stderr, spec)) {
    return { kind: 'no_fix', reason: 'unresolvable', message: failure.message };
  }
  return { kind: 'failure', ...failure };
}

/** One module: `go get <module>@v<target>`, then `go mod tidy`. */
async function update(ws: FixWorkspace, module: Module): Promise<FixStop | null> {
  ws.log.debug(`go fix in ${where(module.dir)}: go get ${module.spec}, then go mod tidy`);
  const got = getStop(await go(ws, module, ['get', module.spec]), module.spec);
  if (got !== null) return got;
  const tidied = await go(ws, module, ['mod', 'tidy']);
  return succeeded(tidied) ? null : { kind: 'failure', ...toolFailure('go', tidied, []) };
}

// ─── Verify ─────────────────────────────────────────────────────────────────

/** A go.sum's `/go.mod` lines with an `h1:` hash, as `<module> <version>`. */
function goModHashes(ws: FixWorkspace, goSum: string): Set<string> {
  let text: string;
  try {
    text = readText(ws, goSum);
  } catch {
    return new Set();
  }
  return new Set(
    readGoSum(text)
      .filter((e) => e.integrity !== null && e.version.endsWith('/go.mod'))
      .map((e) => `${e.name} ${e.version.slice(0, -'/go.mod'.length)}`),
  );
}

/**
 * One `go.mod` after `go`: each `require` of the package at least the greatest target of that
 * file, and its `go.sum` holding the `h1:` hash of that version's `go.mod` (else the build fails
 * with a missing go.sum entry). A `// indirect` require that `go mod tidy` dropped is fine.
 */
function goModProblems(
  ws: FixWorkspace,
  goMod: string,
  packageName: string,
  targets: readonly FixTarget[],
): string[] {
  const greatest = greatestVersion(
    'go',
    targets.map((t) => t.target),
  );
  const hashes = goModHashes(ws, `${dirOf(goMod)}go.sum`);
  const problems: string[] = [];
  for (const { version } of requiresOf(goModAt(ws, goMod), packageName)) {
    if (greatest !== null && (compareVersions('go', version, greatest) ?? -1) < 0) {
      problems.push(`${goMod} still requires ${version}, below ${greatest}`);
    } else if (!hashes.has(`${packageName} ${version}`)) {
      problems.push(`${dirOf(goMod)}go.sum has no h1: line for ${packageName} ${version}/go.mod`);
    }
  }
  return problems;
}

/** Re-reads each target's `go.mod` and `go.sum`: null when every one reached its target. */
function verifyStop(ws: FixWorkspace, fix: FixClaimItem, plan: FixPlan): FixStop | null {
  const problems = [...groupByLockfile(plan.targets)].flatMap(([goMod, targets]) =>
    goModProblems(ws, goMod, fix.packageName, targets),
  );
  if (problems.length === 0) return null;
  return verifyFailed(`go did not leave ${fix.packageName} as planned: ${problems.join('; ')}.`);
}

// ─── The adapter ────────────────────────────────────────────────────────────

/** R6: a changed `go.mod`, with its relation; Go has no pin and no dependents list. */
const lockfileLine = (module: Module): FixLockfile => ({
  path: module.goMod,
  relation: module.relation,
  mechanism: null,
  dependents: [],
});

async function apply(
  ws: FixWorkspace,
  fix: FixClaimItem,
  plan: FixPlan,
): Promise<AppliedFix | FixStop> {
  const modules = modulesOf(ws, fix.packageName, plan);
  if (isStop(modules)) return modules;
  const before = new Map(modules.map((m) => [m.goMod, readText(ws, m.goMod)]));
  for (const module of modules) {
    const stop = await update(ws, module);
    if (stop !== null) return stop;
  }
  const changed = modules.filter((m) => readText(ws, m.goMod) !== before.get(m.goMod));
  return { lockfiles: changed.map(lockfileLine) };
}

/** A `go.mod`'s `require` versions of the package; none, with a warning, for one it cannot read. */
function installedIn(ws: FixWorkspace, goMod: string, packageName: string): string[] {
  try {
    const versions = requiresOf(goModAt(ws, goMod), packageName).map((r) => r.version);
    return [...new Set(versions)];
  } catch (err) {
    // A fixture or a broken go.mod elsewhere in the repository must not stop every Go fix.
    ws.log.warn(`skipping ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}

/**
 * Every tracked `go.mod`'s `require` versions of the package (not in a `vendor/` folder, not a
 * link), by Task 4's reader.
 */
function installed(ws: FixWorkspace, packageName: string): Promise<InstalledAt[]> {
  const found = ws.files
    .filter((p) => basename(p) === 'go.mod' && !inVendor(p) && isRegularFile(ws, p))
    .toSorted()
    .map((goMod) => ({ lockfile: goMod, versions: installedIn(ws, goMod, packageName) }))
    .filter((at) => at.versions.length > 0);
  return Promise.resolve(found);
}

/** The Go family's adapter (Task 14): `go get` and `go mod tidy` per module. */
export const goAdapter: FixAdapter = {
  family: 'go',
  installed,
  apply,
  verify: (ws, fix, plan) => Promise.resolve(verifyStop(ws, fix, plan)),
};

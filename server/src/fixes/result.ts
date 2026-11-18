import {
  chooseTargets,
  compareVersions,
  FIX_LIMITS,
  FIX_RULE_TEXT,
  FIX_RULES,
  fixFileKind,
  fixPathProblem,
  greatestVersion,
  schemeOf,
  scrubToolOutput,
  type FixFamily,
  type FixFileChange,
  type FixResultBody,
  type FixUpload,
  type VersionScheme,
} from '@qualor/shared/fix';
import { and, eq, sql } from 'drizzle-orm';
import { isStorableText, toStorableText } from '../audit/canonical';
import type { Db } from '../db/client';
import {
  dependencyFixes,
  type FixLockfileAdditions,
  type FixPreparedValue,
  type FixState,
} from '../db/schema';
import { conflict, ProblemError } from '../http/problem';
import type { ProjectRow } from '../projects/access';
import { ScmError } from '../scm/provider';
import { retryable } from '../scm/runtime';
import { claimVulnerabilities, hasOpenMr, leaseHash, leaseMatches } from './claim';
import {
  checkUploadInWorker,
  fixCheckGate,
  type FixCheckBusy,
  type FixCheckGate,
  type FixCheckGiveUp,
  type FixCheckLimits,
} from './checker';
import { mainVulnerabilities, type MainVulnerability } from './eligibility';
import { enqueueFixJob } from './jobs';
import {
  FIX_REPOSITORY_PROBLEM_TEXT,
  openFixRepository,
  type FixRepository,
  type FixScmDeps,
} from './repository';
import { lockFix, lockProject } from './requests';
import type { DependencyFixRow } from './rows';

/**
 * The fix job's result (0.16 fix MRs §6.7, B1, R6–R8, R16): a failure, a no-fix, a released
 * claim, or the files of a prepared fix, which are checked by shape, by target, against the base
 * the server reads itself from the SCM, and by content in a worker thread before the commit job
 * is queued. A refused upload fails the fix (`upload_refused`) and writes nothing to the SCM.
 */

/** The rules an upload can fail: the content rules (B1), then those of the route (§6.7, R7). */
export const UPLOAD_RULES = [
  ...FIX_RULES,
  'path_not_allowed',
  'duplicate_path',
  'too_many_files',
  'too_large',
  'not_utf8',
  'new_file',
  'base_not_on_main',
  'base_outdated',
  'no_targets',
  'target_mismatch',
  'not_vulnerable',
] as const;
export type UploadRule = (typeof UPLOAD_RULES)[number];

/** The fixed text of each rule, the title of its 422 `UPLOAD_REFUSED`. */
export const UPLOAD_RULE_TEXT: Readonly<Record<UploadRule, string>> = Object.freeze({
  ...FIX_RULE_TEXT,
  path_not_allowed:
    'A file is not a manifest or lockfile of the package family, or its path is not relative and normalised.',
  duplicate_path: 'A file is uploaded twice.',
  too_many_files: `The upload has more than ${FIX_LIMITS.maxFiles} files.`,
  too_large: 'The files are larger than 32 MiB together.',
  not_utf8: 'A file is not UTF-8 text.',
  new_file: 'A file does not exist on the main branch at the base commit.',
  base_not_on_main: "The base commit is not the main branch's head or one of its ancestors.",
  base_outdated:
    'Main changed this file after the fix was prepared; the next run starts from the new main.',
  no_targets: 'The upload names no target version.',
  target_mismatch:
    'The targets do not match the upload: each target must be above its installed version, the target version must be the greatest target, each target and each lockfile line must name an uploaded file, and each uploaded lockfile must have a target.',
  not_vulnerable: 'An installed version of a target has no vulnerability on the main branch.',
});

/** Ruling T9e: the longest the SCM reads of one upload may take together. */
export const FIX_READ_DEADLINE_MS = 120_000;

/** The first failing rule of an upload and the file it failed on ('' when it names none). */
interface Refusal {
  rule: UploadRule;
  path: string;
}

/** An uploaded file, decoded. */
interface UploadedFile {
  path: string;
  text: string;
}

type Lease = Pick<FixResultBody, 'generation' | 'leaseToken'>;

export interface AcceptOptions {
  /** The worker's limits (ruling T3k); a test makes them tiny. */
  check?: Partial<FixCheckLimits>;
  /** The admission of the checks (rulings T9a, T9e); the process's own unless a test gives one. */
  gate?: FixCheckGate;
  /** The bytes the base files may have together (fix round 1, I1); `FIX_LIMITS.maxTotalBytes`. */
  maxBaseBytes?: number;
  /** The SCM reads' deadline (ruling T9e); {@link FIX_READ_DEADLINE_MS}. */
  readDeadlineMs?: number;
  /** How the repository is opened; a test holds a read with it (ruling T9k). */
  openRepository?: typeof openFixRepository;
  /** Known secrets a stored message is scrubbed of: the request's own token (ruling T9j). */
  secrets?: readonly string[];
  /** Where a check that was given up is reported (no file content, no token). */
  log?: { warn(fields: object, message: string): void };
}

/** One result's fix, the claim it holds and the secrets its messages are scrubbed of. */
interface Attempt {
  db: Db;
  fix: DependencyFixRow;
  lease: Lease;
  secrets: readonly string[];
}

/**
 * Ruling T9k: the SCM reads of one upload: the signal that gives them up at the deadline, and the
 * reads still in flight then, which the upload's place in the checks waits for.
 */
interface ReadPhase {
  controller: AbortController;
  /** Settles once the reads given up at the deadline have stopped; null before the deadline. */
  abandoned: Promise<void> | null;
}

/** A path as a message or the log shows it: at most this many characters. */
const SHOWN_PATH_CHARS = 1024;

const leaseLost = (): ProblemError =>
  conflict(
    'FIX_LEASE_LOST',
    'This job no longer holds the fix: its lease expired or was released, or the fix was cancelled or claimed again',
  );

/**
 * spec §6.7: the claim still holds: the fix is `preparing` at the claim's generation, its lease
 * has not expired and the token's hash is the stored one (compared in constant time).
 */
function requireLease(fix: DependencyFixRow, lease: Lease): void {
  const live =
    fix.state === 'preparing' &&
    fix.generation === lease.generation &&
    fix.leaseUntil !== null &&
    fix.leaseUntil.getTime() > Date.now() &&
    leaseMatches(fix.leaseTokenHash, lease.leaseToken);
  if (!live) throw leaseLost();
}

/** The fence of every write of a result: the claim's fix, generation and lease, still preparing. */
const leaseFence = (fixId: string, lease: Lease) =>
  and(
    eq(dependencyFixes.id, fixId),
    eq(dependencyFixes.generation, lease.generation),
    eq(dependencyFixes.state, 'preparing'),
    eq(dependencyFixes.leaseTokenHash, leaseHash(lease.leaseToken)),
  );

/**
 * B9: a message as it is stored: storable text, scrubbed again (the known secrets too, ruling
 * T9j), its last 2 KiB.
 */
const storedMessage = (message: string, secrets: readonly string[]): string =>
  scrubToolOutput(toStorableText(message), secrets);

/**
 * spec §6.4, R8: the fix ends `failed` or `no_fix` with `failure`, or, with an MR Qualor keeps,
 * stays `open` with the failure shown and `refresh` off; the lease is cleared. One statement,
 * fenced on the claim; 409 when the claim no longer holds.
 */
async function endFix(
  attempt: Attempt,
  state: 'failed' | 'no_fix',
  failure: { code: string; message: string },
): Promise<FixState> {
  const { fix, lease } = attempt;
  const next: FixState = hasOpenMr(fix) ? 'open' : state;
  const [ended] = await attempt.db
    .update(dependencyFixes)
    .set({
      state: next,
      refresh: false,
      failure: { code: failure.code, message: storedMessage(failure.message, attempt.secrets) },
      leaseTokenHash: null,
      leaseUntil: null,
      updatedAt: sql`now()`,
    })
    .where(leaseFence(fix.id, lease))
    .returning({ id: dependencyFixes.id });
  if (!ended) throw leaseLost();
  return next;
}

/**
 * R6, R8: the job hands the claim back: `requested` again, or `open` with `refresh` for a fix with
 * an MR; `generation` + 1 either way, the lease cleared. Under the project row lock, then the fix
 * row's (ruling T2a, the requests' lock order).
 */
async function releaseFix(db: Db, fix: DependencyFixRow, lease: Lease): Promise<FixState> {
  return db.transaction(async (tx) => {
    await lockProject(tx, fix.projectId);
    const current = await lockFix(tx, fix.id);
    const holds =
      current !== null &&
      current.state === 'preparing' &&
      current.generation === lease.generation &&
      leaseMatches(current.leaseTokenHash, lease.leaseToken);
    if (!holds) throw leaseLost();
    const next: FixState = hasOpenMr(current) ? 'open' : 'requested';
    await tx
      .update(dependencyFixes)
      .set({
        state: next,
        refresh: next === 'open',
        generation: sql`${dependencyFixes.generation} + 1`,
        leaseTokenHash: null,
        leaseUntil: null,
        updatedAt: sql`now()`,
      })
      .where(eq(dependencyFixes.id, current.id));
    return next;
  });
}

const shownPath = (path: string): string =>
  path.length > SHOWN_PATH_CHARS ? `${path.slice(0, SHOWN_PATH_CHARS)}…` : path;

/**
 * §6.7, B1: a refused upload fails the fix `upload_refused` (R8: an MR Qualor keeps stays `open`
 * with the failure shown) in its own statement, fenced on the claim, and answers 422
 * `UPLOAD_REFUSED`: the rule's fixed text, `reason` the rule, `detail` the file. Nothing is
 * written to the SCM and no job is queued.
 */
async function refuse(attempt: Attempt, refusal: Refusal): Promise<never> {
  const path = refusal.path === '' ? '' : storedMessage(shownPath(refusal.path), attempt.secrets);
  const text = UPLOAD_RULE_TEXT[refusal.rule];
  await endFix(attempt, 'failed', {
    code: 'upload_refused',
    message: path === '' ? text : `${text} File: ${path}`,
  });
  throw new ProblemError(422, 'UPLOAD_REFUSED', text, {
    extensions: { reason: refusal.rule },
    ...(path === '' ? {} : { detail: path }),
  });
}

// ─── Shape (count, size, UTF-8, path, duplicates) ───────────────────────────

/** The bytes a padded base64 text decodes to. */
function base64Bytes(content: string): number {
  let padding = 0;
  if (content.endsWith('=')) padding += 1;
  if (content.endsWith('==')) padding += 1;
  return (content.length / 4) * 3 - padding;
}

/** §6.7: 32 MiB of files together at most; the file that passes it. */
function sizeProblem(files: FixUpload['files']): Refusal | null {
  let total = 0;
  for (const file of files) {
    total += base64Bytes(file.content);
    if (total > FIX_LIMITS.maxTotalBytes) return { rule: 'too_large', path: file.path };
  }
  return null;
}

/** `fatal`: invalid UTF-8 throws; `ignoreBOM`: a byte order mark stays in the text (Review Focus 1). */
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** A file's text, or null when it is not UTF-8 text (or holds U+0000, which no manifest does). */
function utf8Text(content: string): string | null {
  try {
    const text = UTF8.decode(Buffer.from(content, 'base64'));
    return text.includes('\u0000') ? null : text;
  } catch {
    return null;
  }
}

/** §6.7: each path is a storable, relative, normalised path of a file the family may change. */
function pathProblem(family: FixFamily, files: FixUpload['files']): Refusal | null {
  const bad = files.find((f) => !isStorableText(f.path) || fixPathProblem(family, f.path) !== null);
  return bad === undefined ? null : { rule: 'path_not_allowed', path: bad.path };
}

function duplicateProblem(files: FixUpload['files']): Refusal | null {
  const seen = new Set<string>();
  for (const file of files) {
    if (seen.has(file.path)) return { rule: 'duplicate_path', path: file.path };
    seen.add(file.path);
  }
  return null;
}

/**
 * §6.7, R16: the shape of the upload, in this order: at most 50 files, 32 MiB together, each
 * UTF-8 text, each path allowed, no path twice. The decoded files, or the first refusal.
 */
function shapeOf(family: FixFamily, files: FixUpload['files']): UploadedFile[] | Refusal {
  const extra = files[FIX_LIMITS.maxFiles];
  if (extra !== undefined) return { rule: 'too_many_files', path: extra.path };
  const tooLarge = sizeProblem(files);
  if (tooLarge !== null) return tooLarge;
  const decoded: UploadedFile[] = [];
  for (const file of files) {
    const text = utf8Text(file.content);
    if (text === null) return { rule: 'not_utf8', path: file.path };
    decoded.push({ path: file.path, text });
  }
  return pathProblem(family, files) ?? duplicateProblem(files) ?? decoded;
}

// ─── Targets (R7, rulings T9g–T9i) ──────────────────────────────────────────

/** The same version by the scheme's order, or the same text when either does not parse (T1c). */
function sameVersion(scheme: VersionScheme, a: string, b: string): boolean {
  const c = compareVersions(scheme, a, b);
  return c === null ? a === b : c === 0;
}

const mismatch = (path: string): Refusal => ({ rule: 'target_mismatch', path });

/** The directory part of a path, with its slash ('' at the root). */
const directoryOf = (path: string): string => path.slice(0, path.lastIndexOf('/') + 1);

/**
 * Ruling T9i: every uploaded lockfile of the family is named by a target (F14 skips `below_target`
 * on one that is not, so it could move the package anywhere); a `go.sum` through the `go.mod`
 * beside it. Manifests need none.
 */
function unnamedLockfile(
  family: FixFamily,
  upload: FixUpload,
  files: readonly UploadedFile[],
): Refusal | null {
  const named = new Set(upload.targets.map((t) => t.lockfile));
  const unnamed = files.find((f) => {
    if (fixFileKind(family, f.path) !== 'lockfile') return false;
    const isGoSum = f.path.slice(f.path.lastIndexOf('/') + 1) === 'go.sum';
    const by = isGoSum ? `${directoryOf(f.path)}go.mod` : f.path;
    return !named.has(by);
  });
  return unnamed === undefined ? null : mismatch(unnamed.path);
}

/**
 * Where the targets and the MR's lines must point (rulings T9g, T9h): each target above its
 * installed version and in an uploaded file, each lockfile line an uploaded file.
 */
function outsideUpload(
  scheme: VersionScheme,
  upload: FixUpload,
  paths: ReadonlySet<string>,
): Refusal | null {
  const notAbove = upload.targets.find(
    (t) => (compareVersions(scheme, t.target, t.installed) ?? 0) <= 0,
  );
  if (notAbove !== undefined) return mismatch(notAbove.lockfile);
  const outside = upload.targets.find((t) => !paths.has(t.lockfile));
  if (outside !== undefined) return mismatch(outside.lockfile);
  const line = upload.lockfiles.find((l) => !paths.has(l.path));
  return line === undefined ? null : mismatch(line.path);
}

/**
 * R30, R6, rulings T9g–T9i: the targets agree with the upload: each above its installed version
 * and in an uploaded file, each lockfile line an uploaded file, each uploaded lockfile named by a
 * target, `targetVersion` the greatest target and `installedVersion` the installed version of a
 * target that reaches it.
 */
function targetMismatch(
  family: FixFamily,
  upload: FixUpload,
  files: readonly UploadedFile[],
): Refusal | null {
  const scheme = schemeOf(family);
  const outside = outsideUpload(scheme, upload, new Set(files.map((f) => f.path)));
  if (outside !== null) return outside;
  const unnamed = unnamedLockfile(family, upload, files);
  if (unnamed !== null) return unnamed;
  const greatest = greatestVersion(
    scheme,
    upload.targets.map((t) => t.target),
  );
  const named = upload.targets.some(
    (t) =>
      sameVersion(scheme, t.target, upload.targetVersion) &&
      sameVersion(scheme, t.installed, upload.installedVersion),
  );
  const top = greatest !== null && sameVersion(scheme, greatest, upload.targetVersion);
  return top && named ? null : mismatch('');
}

/**
 * R7: an installed version main has (`not_vulnerable` otherwise), raised at least to the server's
 * own choice for it from main's current rows (`below_target`; equality is not required).
 */
function targetProblem(
  scheme: VersionScheme,
  target: FixUpload['targets'][number],
  rows: readonly MainVulnerability[],
  facts: ReturnType<typeof claimVulnerabilities>,
): UploadRule | null {
  if (!rows.some((r) => sameVersion(scheme, r.packageVersion, target.installed))) {
    return 'not_vulnerable';
  }
  const choice = chooseTargets(scheme, [target.installed], facts)[0]?.target ?? null;
  if (choice === null) return null;
  const c = compareVersions(scheme, target.target, choice);
  return c === null || c < 0 ? 'below_target' : null;
}

/**
 * R7, R30: the upload's targets against main's current rows of the package; those rows when they
 * agree (their ids keep the upload's `unfixable` list honest, ruling T9h).
 */
async function checkTargets(
  db: Db,
  fix: DependencyFixRow,
  upload: FixUpload,
  files: readonly UploadedFile[],
): Promise<MainVulnerability[] | Refusal> {
  if (upload.targets.length === 0) return { rule: 'no_targets', path: '' };
  const disagrees = targetMismatch(fix.family, upload, files);
  if (disagrees !== null) return disagrees;
  const scheme = schemeOf(fix.family);
  const rows = await mainVulnerabilities(db, fix.projectId, fix.family, fix.packageName);
  const facts = claimVulnerabilities(fix.family, rows);
  for (const target of upload.targets) {
    const rule = targetProblem(scheme, target, rows, facts);
    if (rule !== null) return { rule, path: target.lockfile };
  }
  return rows;
}

// ─── The base, read from the SCM (§6.7, rulings T3h, T9d, T9e) ──────────────

/** R16: the SCM could not answer now; the fix stays `preparing` and the job tries again. */
function scmUnavailable(retryAfterSeconds: number | null): ProblemError {
  return new ProblemError(503, 'SCM_UNAVAILABLE', 'The repository could not be read; try again', {
    headers: { 'retry-after': String(retryAfterSeconds ?? 10) },
  });
}

/**
 * Ruling T9d: an SCM failure no retry mends (a refused token, a refused request, a missing project,
 * a connection no client can be made for). It ends the attempt with its failure, so the fix is not
 * claimed, refused and expired again and again without anybody seeing why.
 */
class AttemptEnded extends Error {
  constructor(readonly failure: { code: 'scm_permission' | 'scm_refused'; message: string }) {
    super(failure.message);
    this.name = 'AttemptEnded';
  }
}

/**
 * Ruling T9d: an SCM failure as the answer: a transient one (`retryable`: down, a timeout, a rate
 * limit) is 503 and the fix stays `preparing` (R16); any other ends the attempt, `scm_permission`
 * for a refused token or permission, `scm_refused` otherwise, with the client's fixed text.
 */
function scmFailure(err: ScmError): ProblemError | AttemptEnded {
  if (retryable(err)) return scmUnavailable(err.retryAfterSeconds);
  return new AttemptEnded({
    code: err.kind === 'auth' ? 'scm_permission' : 'scm_refused',
    message: `The repository could not be read to check the upload: ${err.message}`,
  });
}

/** An SCM failure as {@link scmFailure} says; anything else (the database, a bug) as it is. */
async function throughScm<T>(read: () => Promise<T>): Promise<T> {
  try {
    return await read();
  } catch (err) {
    throw err instanceof ScmError ? scmFailure(err) : err;
  }
}

/**
 * The project's repository now. A project unbound, or a connection that no longer allows fix MRs
 * (B2), meanwhile is 409 and the fix stays `preparing` (its lease runs out; the claim no longer
 * hands it out). A connection no client can be made for ends the attempt (`scm_refused`, T9d).
 */
async function repositoryOf(
  deps: FixScmDeps,
  project: ProjectRow,
  signal: AbortSignal,
  options: AcceptOptions,
): Promise<FixRepository> {
  const open = options.openRepository ?? openFixRepository;
  const repo = await throughScm(() => open(deps, project, { signal }));
  if (!('problem' in repo)) return repo;
  if (repo.problem === 'scm_not_bound') {
    throw conflict('SCM_NOT_BOUND', FIX_REPOSITORY_PROBLEM_TEXT.scm_not_bound);
  }
  if (repo.problem === 'fixes_disabled') {
    throw conflict('FIX_MRS_NOT_ALLOWED', FIX_REPOSITORY_PROBLEM_TEXT.fixes_disabled);
  }
  throw new AttemptEnded({
    code: 'scm_refused',
    message: FIX_REPOSITORY_PROBLEM_TEXT.connection,
  });
}

/**
 * Each file at `baseSha` and at main's head, read by the server (never taken from the request):
 * a file main does not have at `baseSha` is `new_file`; one main changed since is `base_outdated`
 * (ruling T3h: an older base cannot widen the hosts or sources a lockfile may use). The base files
 * may have `maxBaseBytes` together (fix round 1, I1): past it the reading stops, `too_large`. The
 * head's copy of a file is held only for its comparison. No read starts once `signal` has aborted
 * (ruling T9k).
 */
async function readBases(
  repo: FixRepository,
  upload: { baseSha: string; head: string },
  files: readonly UploadedFile[],
  limits: { maxBaseBytes: number; signal: AbortSignal },
): Promise<FixFileChange[] | Refusal> {
  const { baseSha, head } = upload;
  const changes: FixFileChange[] = [];
  let total = 0;
  for (const file of files) {
    limits.signal.throwIfAborted();
    const base = await repo.fileAt(file.path, baseSha);
    if (base === null) return { rule: 'new_file', path: file.path };
    total += Buffer.byteLength(base);
    if (total > limits.maxBaseBytes) return { rule: 'too_large', path: file.path };
    limits.signal.throwIfAborted();
    if (head !== baseSha && (await repo.fileAt(file.path, head)) !== base) {
      return { rule: 'base_outdated', path: file.path };
    }
    changes.push({ path: file.path, base, next: file.text });
  }
  return changes;
}

/** §6.7: `baseSha` is main's head or an ancestor of it, and every file's base as main has it. */
async function withBases(
  deps: FixScmDeps,
  project: ProjectRow,
  upload: FixUpload,
  files: readonly UploadedFile[],
  read: { options: AcceptOptions; signal: AbortSignal },
): Promise<FixFileChange[] | Refusal> {
  const { options, signal } = read;
  const repo = await repositoryOf(deps, project, signal, options);
  return throughScm<FixFileChange[] | Refusal>(async () => {
    const head = await repo.branchHead(repo.mainBranch);
    signal.throwIfAborted();
    if (head === null || !(await repo.isAncestor(upload.baseSha, head))) {
      return { rule: 'base_not_on_main', path: '' };
    }
    const maxBaseBytes = options.maxBaseBytes ?? FIX_LIMITS.maxTotalBytes;
    return readBases(repo, { baseSha: upload.baseSha, head }, files, { maxBaseBytes, signal });
  });
}

/**
 * Rulings T9e, T9k: `read`, or 503 `SCM_UNAVAILABLE` once `ms` have passed (the fix stays
 * `preparing`). Then the reads are given up through the phase's signal (the request in flight is
 * cut, no later one is sent), and `phase.abandoned` settles once they have stopped; the upload
 * keeps its place in the checks until then. Nothing they answer is used.
 */
async function withinDeadline<T>(read: Promise<T>, ms: number, phase: ReadPhase): Promise<T> {
  read.catch(() => undefined);
  let timer: NodeJS.Timeout | undefined;
  const passed = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(scmUnavailable(null));
      phase.abandoned = read.then(
        () => undefined,
        () => undefined,
      );
      phase.controller.abort();
    }, ms);
  });
  try {
    return await Promise.race([read, passed]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The base files, or the end of the attempt (ruling T9d): a permanent SCM failure fails the fix
 * with its code (R8: one with an MR stays `open` with the failure shown), fenced on the claim.
 */
async function basesOrEnd(
  deps: FixScmDeps,
  attempt: Attempt,
  project: ProjectRow,
  upload: FixUpload,
  files: readonly UploadedFile[],
  read: { options: AcceptOptions; phase: ReadPhase },
): Promise<FixFileChange[] | Refusal | { ended: FixState }> {
  const { options, phase } = read;
  const reading = withBases(deps, project, upload, files, {
    options,
    signal: phase.controller.signal,
  });
  try {
    return await withinDeadline(reading, options.readDeadlineMs ?? FIX_READ_DEADLINE_MS, phase);
  } catch (err) {
    if (!(err instanceof AttemptEnded)) throw err;
    return { ended: await endFix(attempt, 'failed', err.failure) };
  }
}

// ─── Accepting ────────────────────────────────────────────────────────────

/**
 * §6.7: the accepted files are kept on the row (`prepared`, with the lockfiles' new entries,
 * ruling T3i, and only the `unfixable` ids that are the package's main vulnerabilities, ruling
 * T9h) with the base, the targets and the versions; the fix becomes `committing`, its lease
 * cleared, and one commit job is queued, in one transaction fenced on the claim.
 */
async function storeAccepted(
  attempt: Attempt,
  upload: FixUpload,
  accepted: {
    changes: readonly FixFileChange[];
    additions: FixLockfileAdditions[];
    rows: readonly MainVulnerability[];
  },
): Promise<FixState> {
  const known = new Set(accepted.rows.map((r) => r.vulnerabilityId));
  const prepared: FixPreparedValue = {
    baseSha: upload.baseSha,
    files: accepted.changes.map((c) => ({ path: c.path, content: c.next })),
    lockfiles: upload.lockfiles,
    unfixable: upload.unfixable.filter((id) => known.has(id)),
    additions: accepted.additions,
  };
  await attempt.db.transaction(async (tx) => {
    const [stored] = await tx
      .update(dependencyFixes)
      .set({
        state: 'committing',
        prepared,
        baseSha: upload.baseSha,
        targets: upload.targets,
        targetVersion: upload.targetVersion,
        installedVersion: upload.installedVersion,
        failure: null,
        leaseTokenHash: null,
        leaseUntil: null,
        updatedAt: sql`now()`,
      })
      .where(leaseFence(attempt.fix.id, upload))
      .returning({ id: dependencyFixes.id, generation: dependencyFixes.generation });
    if (!stored) throw leaseLost();
    await enqueueFixJob(tx, {
      kind: 'commit',
      fixId: stored.id,
      generation: stored.generation,
      attempt: 0,
    });
  });
  return 'committing';
}

const isRefusal = (value: unknown): value is Refusal =>
  typeof value === 'object' && value !== null && 'rule' in value;

/**
 * The files of a prepared fix, checked in this order, the first failure answering: the shape,
 * the targets (R7), the SCM (main's head, the ancestry of `baseSha`, each file's base), then the
 * content (B1) in a worker thread.
 */
async function checkedUpload(
  deps: FixScmDeps,
  attempt: Attempt,
  project: ProjectRow,
  upload: FixUpload,
  read: { options: AcceptOptions; phase: ReadPhase },
): Promise<FixState> {
  const { options } = read;
  const { fix } = attempt;
  const files = shapeOf(fix.family, upload.files);
  if (isRefusal(files)) return refuse(attempt, files);
  const rows = await checkTargets(attempt.db, fix, upload, files);
  if (isRefusal(rows)) return refuse(attempt, rows);
  const changes = await basesOrEnd(deps, attempt, project, upload, files, read);
  if ('ended' in changes) return changes.ended;
  if (isRefusal(changes)) return refuse(attempt, changes);
  const checked = await checkUploadInWorker(
    { family: fix.family, packageName: fix.packageName, targets: upload.targets, files: changes },
    options.check,
  );
  if (!checked.ok) {
    if (checked.gaveUp !== undefined) logGiveUp(options, fix, checked.gaveUp);
    return refuse(attempt, checked);
  }
  return storeAccepted(attempt, upload, { changes, additions: checked.additions, rows });
}

/** Rulings T9a, T9e: 503 for an upload the checks do not admit now; nothing is read or changed. */
function checkBusy(why: FixCheckBusy): ProblemError {
  return new ProblemError(
    503,
    'FIX_CHECK_BUSY',
    why === 'organization'
      ? "Another upload of this organisation's fixes is being checked; try again in a few seconds"
      : 'The server is checking other uploads; try again in a few seconds',
    { headers: { 'retry-after': '10' } },
  );
}

/**
 * The files of a prepared fix, admitted first (rulings T9a, T9e): one upload per organisation and
 * at most eight waiting behind the running check, else 503 `FIX_CHECK_BUSY` before any SCM call or
 * state change (the fix stays `preparing`, its lease valid). The place is held until the upload is
 * answered, {@link checkedUpload} in between, and past it while reads given up at the SCM read
 * deadline are still stopping (ruling T9k).
 */
async function acceptUpload(
  deps: FixScmDeps,
  attempt: Attempt,
  project: ProjectRow,
  upload: FixUpload,
  options: AcceptOptions,
): Promise<FixState> {
  const admitted = (options.gate ?? fixCheckGate).admit(project.organizationId);
  if ('busy' in admitted) throw checkBusy(admitted.busy);
  const phase: ReadPhase = { controller: new AbortController(), abandoned: null };
  try {
    return await checkedUpload(deps, attempt, project, upload, { options, phase });
  } finally {
    // Ruling T9k: reads given up at the deadline keep the place until they have stopped.
    if (phase.abandoned === null) admitted.release();
    else void phase.abandoned.then(admitted.release);
  }
}

function logGiveUp(options: AcceptOptions, fix: DependencyFixRow, why: FixCheckGiveUp): void {
  options.log?.warn(
    { fixId: fix.id, gaveUp: why },
    why === 'timeout'
      ? 'the fix upload check passed its time cap; refused as unparsable'
      : 'the fix upload check failed (heap or crash); refused as unparsable',
  );
}

/**
 * `PUT /fixes/{id}/result` (spec §6.5 step 6, §6.7, R6, R8): checks the claim first (409
 * `FIX_LEASE_LOST`), then takes the body's form: a failure (`failed`, its message scrubbed again,
 * B9, of the request's own token too, T9j), a no-fix (`no_fix`), a released claim (`requested`, or
 * `open` with `refresh`), or the files of a prepared fix ({@link acceptUpload}, `committing`).
 * Throws the problems; answers the state.
 */
export async function acceptFixResult(
  deps: FixScmDeps,
  fix: DependencyFixRow,
  project: ProjectRow,
  body: FixResultBody,
  options: AcceptOptions = {},
): Promise<{ state: FixState }> {
  requireLease(fix, body);
  const attempt: Attempt = { db: deps.db, fix, lease: body, secrets: options.secrets ?? [] };
  if ('released' in body) return { state: await releaseFix(deps.db, fix, body) };
  if ('failure' in body) return { state: await endFix(attempt, 'failed', body.failure) };
  if ('noFix' in body) {
    const { reason, message } = body.noFix;
    return { state: await endFix(attempt, 'no_fix', { code: reason, message }) };
  }
  return { state: await acceptUpload(deps, attempt, project, body, options) };
}

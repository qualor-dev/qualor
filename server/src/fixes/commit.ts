import { releaseLine, schemeOf, scrubToolOutput, type FixFamily } from '@qualor/shared/fix';
import { and, eq, sql } from 'drizzle-orm';
import type { PgUpdateSetSource } from 'drizzle-orm/pg-core';
import { toStorableText } from '../audit/canonical';
import type { Db } from '../db/client';
import {
  dependencyFixes,
  projects,
  type FixFailure,
  type FixPreparedValue,
  type FixState,
  type FixTargetValue,
} from '../db/schema';
import { vulnerabilitiesUrl } from '../jira/content';
import type { ProjectRow } from '../projects/access';
import { BUSY_DEFER_SECONDS } from '../scm/decorate';
import { ScmError } from '../scm/provider';
import { decorationRetryDelaySeconds, MAX_DECORATION_ATTEMPTS } from '../scm/queue';
import { retryable } from '../scm/runtime';
import { cancelComment, fixBody, fixTitle, type FixBodyVulnerability } from './body';
import { claimVulnerabilities } from './claim';
import { mainVulnerabilities } from './eligibility';
import { enqueueFixJob, type FixJobPayload } from './jobs';
import {
  FIX_REPOSITORY_PROBLEM_TEXT,
  openFixRepository,
  type ChangeRequest,
  type FixRepository,
  type FixRepositoryProblem,
} from './repository';
import type { DependencyFixRow, DependencyFixRowWithFiles } from './rows';
import type { FixJobDeps } from './run';

/**
 * The commit and close jobs of a fix (0.16 fix MRs §6.7, B10, R8, R10, R13, R17, rulings F7, F8,
 * F10, T8c, T10d). Every state write is fenced on the job's `(id, generation)` and the state it
 * read, so a job of a fix that a person re-armed or cancelled meanwhile changes nothing; a write
 * whose fence misses stops the job before any further SCM write ({@link FixMovedOn}).
 */

/** One `commit` or `close` job: its fix, the generation it was queued for, the attempts before it. */
export interface FixJob {
  fixId: string;
  generation: number;
  /** Ruling F10: 0 for the first attempt. */
  attempt: number;
}

type JobPayload = Extract<FixJobPayload, { kind: 'commit' | 'close' }>;

/** A fix the commit job writes: `committing`, so with its prepared files. */
type CommittingFix = DependencyFixRow & { prepared: FixPreparedValue };

interface Loaded<Row extends DependencyFixRow = DependencyFixRow> {
  row: Row;
  project: ProjectRow;
}

/**
 * The job's fix with its project when it is still at the job's generation in `state`; null when a
 * re-arm, a cancel or an end moved it on (ruling T8c: such a job drops quietly). The one read of a
 * fix with its accepted files (`prepared`; every other read leaves them out, ruling FW3).
 */
async function fixOfJob(
  db: Db,
  job: FixJob,
  state: FixState,
): Promise<Loaded<DependencyFixRowWithFiles> | null> {
  const [found] = await db
    .select({ row: dependencyFixes, project: projects })
    .from(dependencyFixes)
    .innerJoin(projects, eq(projects.id, dependencyFixes.projectId))
    .where(
      and(
        eq(dependencyFixes.id, job.fixId),
        eq(dependencyFixes.generation, job.generation),
        eq(dependencyFixes.state, state),
      ),
    );
  return found ?? null;
}

/**
 * The fence of a job's writes: its fix, at its generation, still in the state it read (the sync
 * pass fences its writes the same way, ruling T8c).
 */
export const fence = (row: Pick<DependencyFixRow, 'id' | 'generation' | 'state'>) =>
  and(
    eq(dependencyFixes.id, row.id),
    eq(dependencyFixes.generation, row.generation),
    eq(dependencyFixes.state, row.state),
  );

/** B9: a failure as it is stored: storable text, scrubbed again, its last 2 KiB. */
const stored = (failure: FixFailure): FixFailure => ({
  code: failure.code,
  message: scrubToolOutput(toStorableText(failure.message), []),
});

/** A repository problem as the fix's failure (Review Focus 5: the job fails closed). */
const PROBLEM_CODE: Readonly<Record<FixRepositoryProblem, string>> = Object.freeze({
  scm_not_bound: 'scm_not_bound',
  fixes_disabled: 'fixes_disabled',
  connection: 'scm_refused',
});

const problemFailure = (problem: FixRepositoryProblem): FixFailure => ({
  code: PROBLEM_CODE[problem],
  message: FIX_REPOSITORY_PROBLEM_TEXT[problem],
});

/**
 * An SCM failure no retry mends, or the last retry's: `scm_permission` for a refused token or
 * permission, `scm_unavailable` when the provider stayed down or limiting, `scm_refused` otherwise;
 * the client's fixed text, never the provider's words.
 */
function scmFailure(err: ScmError): FixFailure {
  let code = 'scm_refused';
  if (err.kind === 'auth') code = 'scm_permission';
  else if (retryable(err)) code = 'scm_unavailable';
  return { code, message: `The fix branch or MR could not be written: ${err.message}` };
}

// ─── The commit job's state writes ───────────────────────────────────────────

/**
 * Ruling T10d: a fenced write matched no row: the fix moved on (a re-arm, a cancel, an end) while
 * the job ran. The job stops there, with no further SCM write.
 */
class FixMovedOn extends Error {
  constructor(readonly fixId: string) {
    super(`fix ${fixId} moved on while its job ran`);
    this.name = 'FixMovedOn';
  }
}

/** One write of the job, fenced ({@link fence}); the state it left, or {@link FixMovedOn}. */
async function fencedWrite(
  db: Db,
  row: DependencyFixRow,
  set: PgUpdateSetSource<typeof dependencyFixes>,
): Promise<FixState> {
  const [written] = await db
    .update(dependencyFixes)
    .set({ ...set, updatedAt: sql`now()` })
    .where(fence(row))
    .returning({ state: dependencyFixes.state });
  if (written === undefined) throw new FixMovedOn(row.id);
  return written.state;
}

/**
 * Ends the commit with `set`: the prepared files cleared, `refresh` off. Fenced on the job's
 * generation while `committing`.
 */
const settle = (
  db: Db,
  row: CommittingFix,
  set: Pick<typeof dependencyFixes.$inferInsert, 'state'> &
    Partial<typeof dependencyFixes.$inferInsert>,
): Promise<FixState> =>
  fencedWrite(db, row, { refresh: false, prepared: null, failure: null, ...set });

/**
 * R8 (`hasOpenMr`) as a statement's new state, read from the row as it is stored now, not from a
 * job's first read (an MR adopted by its branch during the job counts, ruling T10d): `open` for a
 * fix with an MR Qualor keeps, else `otherwise`. The sync pass ends lapsed leases and dead commits
 * with it too.
 */
export const openWithMrElse = (otherwise: 'failed' | 'requested') =>
  sql<FixState>`CASE WHEN ${dependencyFixes.mrNumber} IS NOT NULL
    AND ${dependencyFixes.headSha} IS NOT NULL THEN 'open' ELSE ${otherwise}::text END`;

const OPEN_WITH_MR = openWithMrElse('failed');

/**
 * The commit failed: `failed` with its failure, or (R8, ruling F7) for a fix with an MR Qualor
 * keeps, `open` with the failure shown, so the MR is neither orphaned nor left to a failed row.
 */
const failCommit = (db: Db, row: CommittingFix, failure: FixFailure): Promise<FixState> =>
  fencedWrite(db, row, {
    state: OPEN_WITH_MR,
    refresh: false,
    prepared: null,
    failure: stored(failure),
  });

/** R13: Qualor's commit is on the branch before the MR is written; its sha is stored at once. */
async function storeHead(db: Db, row: CommittingFix, sha: string): Promise<void> {
  await fencedWrite(db, row, { headSha: sha });
}

/**
 * Ruling T10d: an MR adopted by its branch (the fix had no number) is the fix's at once, before
 * any branch write, so a failure after it keeps the fix `open` with it (F7, R8).
 */
async function storeChange(db: Db, row: CommittingFix, change: ChangeRequest): Promise<void> {
  await fencedWrite(db, row, { mrNumber: change.number, mrUrl: change.url });
}

// ─── The MR text ─────────────────────────────────────────────────────────────

/**
 * R30: the title of the upload's greatest target: the commit message without `provider`, the MR
 * title with it (ruling FW2: GitLab's holds the package name in a code span).
 */
const titleOf = (row: DependencyFixRow, provider?: FixRepository['provider']): string =>
  fixTitle(row.packageName, row.installedVersion ?? '', row.targetVersion ?? '', provider);

/** The targets that leave their installed version's release line, each pair once. */
function majorJumps(family: FixFamily, targets: readonly FixTargetValue[]): FixTargetValue[] {
  const scheme = schemeOf(family);
  const seen = new Set<string>();
  return targets.filter((t) => {
    const line = releaseLine(scheme, t.installed);
    const key = JSON.stringify([t.installed, t.target]);
    if ((line !== null && releaseLine(scheme, t.target) === line) || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * spec §6.7: the MR body from server data: the package's main vulnerabilities among the ones the
 * claim handed out (`vulnerability_ids`), those of the upload's `unfixable` listed apart, and the
 * prepared lockfiles, targets and new entries.
 */
async function bodyOf(
  deps: FixJobDeps,
  { row, project }: Loaded<CommittingFix>,
  provider: FixRepository['provider'],
): Promise<string> {
  const handled = new Set(row.vulnerabilityIds);
  const rows = await mainVulnerabilities(deps.db, row.projectId, row.family, row.packageName);
  const listed: FixBodyVulnerability[] = claimVulnerabilities(
    row.family,
    rows.filter((r) => handled.has(r.vulnerabilityId)),
  ).map((v) => ({ id: v.id, severity: v.severity, title: v.title, url: v.url }));
  const unfixable = new Set(row.prepared.unfixable);
  return fixBody({
    provider,
    targets: row.targets,
    vulnerabilities: listed.filter((v) => !unfixable.has(v.id)),
    unfixable: listed.filter((v) => unfixable.has(v.id)),
    lockfiles: row.prepared.lockfiles,
    additions: row.prepared.additions,
    majorJumps: majorJumps(row.family, row.targets),
    vulnerabilitiesUrl: vulnerabilitiesUrl(deps.publicUrl, project.id),
  });
}

// ─── The commit ──────────────────────────────────────────────────────────────

/**
 * Ruling F8: the fix's MR before any branch write: its own (`mr_number`), else the open one from
 * its branch (a crash after the MR was opened, or a re-armed fix whose MR is still open, T8c).
 * Ruling T10a: one found by its branch is the fix's only when its head is Qualor's last commit
 * (the stored `head_sha`, read before the write): an MR someone else opened from a branch of that
 * name is never written and its state never ends the fix; a new MR is opened instead.
 */
async function currentChange(
  repo: FixRepository,
  row: DependencyFixRow,
): Promise<ChangeRequest | null> {
  if (row.mrNumber !== null) return repo.readChange(row.mrNumber);
  const found = await repo.findChange(row.branch);
  const ours = found !== null && found.headSha !== null && found.headSha === row.headSha;
  return ours ? found : null;
}

/**
 * Ruling F8, §11.2: how the fix ends before anything is written: a merged MR (`merged`), one a
 * person closed (`declined`, its target kept, B3/B4), or a branch head that is not Qualor's last
 * commit (`taken_over`). Otherwise the head the commit expects: Qualor's commit, or null for a
 * branch to make.
 */
async function endBeforeWrite(
  db: Db,
  repo: FixRepository,
  row: CommittingFix,
  change: ChangeRequest | null,
): Promise<{ ended: FixState } | { head: string | null }> {
  if (change?.state === 'merged') return { ended: await settle(db, row, { state: 'merged' }) };
  if (change?.state === 'closed') {
    const declinedTarget = row.targetVersion;
    return { ended: await settle(db, row, { state: 'declined', declinedTarget }) };
  }
  const head = await repo.branchHead(row.branch);
  if (head !== null && head !== row.headSha) {
    return { ended: await settle(db, row, { state: 'taken_over' }) };
  }
  return { head };
}

/** The open MR updated with the title and body, or a new one opened from the branch. */
async function writeChange(
  repo: FixRepository,
  row: DependencyFixRow,
  change: ChangeRequest | null,
  text: { title: string; body: string },
): Promise<ChangeRequest> {
  if (change === null) return repo.openChange({ branch: row.branch, ...text });
  await repo.updateChange(change.number, text);
  return change;
}

/**
 * spec §6.7: the MR read first (F8), the branch head checked (§11.2), the one commit written on
 * `baseSha` (the head re-read inside, B10), its sha stored (R13), then the MR updated or opened;
 * the fix is `open` with its MR, the prepared files cleared.
 */
async function writeFix(
  deps: FixJobDeps,
  loaded: Loaded<CommittingFix>,
  repo: FixRepository,
): Promise<FixState> {
  const { row } = loaded;
  const change = await currentChange(repo, row);
  if (change !== null && row.mrNumber === null) await storeChange(deps.db, row, change);
  const before = await endBeforeWrite(deps.db, repo, row, change);
  if ('ended' in before) return before.ended;
  const written = await repo.commit({
    branch: row.branch,
    baseSha: row.prepared.baseSha,
    files: row.prepared.files,
    message: titleOf(row),
    expectedHead: before.head,
  });
  if ('takenOver' in written) return settle(deps.db, row, { state: 'taken_over' });
  await storeHead(deps.db, row, written.sha);
  const body = await bodyOf(deps, loaded, repo.provider);
  const title = titleOf(row, repo.provider);
  const open = await writeChange(repo, row, change, { title, body });
  return settle(deps.db, row, { state: 'open', mrNumber: open.number, mrUrl: open.url });
}

/**
 * Ruling T10d: runs the job; one whose fix moved on ({@link FixMovedOn}) stops with one info line
 * and no further write.
 */
async function untilMovedOn(
  deps: FixJobDeps,
  payload: JobPayload,
  run: () => Promise<void>,
): Promise<void> {
  try {
    await run();
  } catch (err) {
    if (!(err instanceof FixMovedOn)) throw err;
    deps.logger?.info(
      { fixId: payload.fixId, kind: payload.kind },
      'fix job stopped: the fix moved on while it ran',
    );
  }
}

// ─── Slots and retries (R17) ─────────────────────────────────────────────────

/**
 * R17: `work` holds one of the organisation's SCM slots; with none free the same attempt runs
 * again in {@link BUSY_DEFER_SECONDS}, with no SCM call.
 */
async function withSlot(
  deps: FixJobDeps,
  project: ProjectRow,
  payload: JobPayload,
  work: () => Promise<void>,
): Promise<void> {
  const { slots } = deps.runtime;
  if (!slots.tryTake(project.organizationId)) {
    await enqueueFixJob(deps.db, payload, BUSY_DEFER_SECONDS);
    return;
  }
  try {
    await work();
  } finally {
    slots.release(project.organizationId);
  }
}

/**
 * R17, ruling F10: a transient or rate-limited failure is tried again, attempt `attempt + 1` after
 * `decorationRetryDelaySeconds(attempt + 1)` or the provider's `Retry-After` when longer, while
 * fewer than {@link MAX_DECORATION_ATTEMPTS} attempts were made; any other failure, or the last
 * one, is given up (`giveUp`).
 */
async function retryOrGiveUp(
  deps: FixJobDeps,
  payload: JobPayload,
  err: ScmError,
  giveUp: () => Promise<unknown>,
): Promise<void> {
  const next = payload.attempt + 1;
  const what = { fixId: payload.fixId, kind: payload.kind, errorKind: err.kind };
  if (retryable(err) && next < MAX_DECORATION_ATTEMPTS) {
    const delay = Math.max(decorationRetryDelaySeconds(next), err.retryAfterSeconds ?? 0);
    await enqueueFixJob(deps.db, { ...payload, attempt: next }, delay);
    deps.logger?.info({ ...what, attempt: next, retryInSeconds: delay }, 'fix job retried');
    return;
  }
  await giveUp();
  // What the SCM said, never its message (which may quote what was sent).
  deps.logger?.warn({ ...what, httpStatus: err.status, request: err.request }, 'fix job failed');
}

/**
 * Runs `work` against the project's repository as it is mapped now: a project unbound, or a
 * connection that no longer allows fix MRs (B2), is `problem` before any SCM call (Review Focus 5);
 * an SCM failure is retried or given up ({@link retryOrGiveUp}).
 */
async function againstRepository(
  deps: FixJobDeps,
  loaded: Loaded,
  payload: JobPayload,
  handlers: {
    work: (repo: FixRepository) => Promise<unknown>;
    fail: (failure: FixFailure) => Promise<unknown>;
  },
): Promise<void> {
  try {
    const repo = await openFixRepository(deps, loaded.project);
    if (!('problem' in repo)) {
      await handlers.work(repo);
      return;
    }
    await handlers.fail(problemFailure(repo.problem));
    deps.logger?.warn(
      { fixId: payload.fixId, kind: payload.kind, problem: repo.problem },
      'fix job ended: the repository cannot be used',
    );
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    await retryOrGiveUp(deps, payload, err, () => handlers.fail(scmFailure(err)));
  }
}

/**
 * The `commit` job (spec §6.7): a `committing` fix at the job's generation (any other drops
 * quietly) is written to its branch and MR ({@link writeFix}) under the organisation's slot. It
 * ends `open`, `merged`, `declined` or `taken_over`, or with a failure ({@link failCommit}); a
 * transient SCM failure queues the next attempt and leaves it `committing`.
 */
export async function runFixCommit(deps: FixJobDeps, job: FixJob): Promise<void> {
  const loaded = await fixOfJob(deps.db, job, 'committing');
  if (loaded === null || loaded.row.prepared === null) return;
  const committing = {
    row: { ...loaded.row, prepared: loaded.row.prepared },
    project: loaded.project,
  };
  const payload: JobPayload = { kind: 'commit', ...job };
  await untilMovedOn(deps, payload, () =>
    withSlot(deps, loaded.project, payload, () =>
      againstRepository(deps, loaded, payload, {
        work: async (repo) => {
          const state = await writeFix(deps, committing, repo);
          deps.logger?.info({ fixId: job.fixId, state }, 'fix commit job');
        },
        fail: (failure) => failCommit(deps.db, committing.row, failure),
      }),
    ),
  );
}

// ─── The close job (R10) ─────────────────────────────────────────────────────

/** A close that could not be done is shown on the cancelled fix (its MR may still be open). */
async function noteCloseFailure(db: Db, row: DependencyFixRow, failure: FixFailure): Promise<void> {
  await fencedWrite(db, row, { failure: stored(failure) });
}

/**
 * How {@link closeFixChange} left a fix's MR: closed by Qualor, found merged or closed by a person
 * (`declined`), or `taken_over` (a person's head on the branch, which is kept).
 */
export type ClosedAs = 'closed' | 'merged' | 'declined' | 'taken_over';

const CLOSED_AS: Readonly<Record<ChangeRequest['state'], ClosedAs>> = Object.freeze({
  open: 'closed',
  merged: 'merged',
  closed: 'declined',
});

/**
 * R10, B10, spec §6.7: the one close path of a fix's MR, for a cancel (the close job) and for a
 * vulnerability gone from main (the sync pass). The head is read first; a person's head leaves
 * the MR and the branch alone (`taken_over`). Otherwise an open MR gets `comment` and is closed,
 * then the branch is deleted when its head is still Qualor's commit (re-read right before the
 * delete; a person's push in between keeps the branch: `taken_over`). A delete the provider refuses
 * for good keeps the branch (`branchKept`, ruling FW4) and ends the close as if it were deleted.
 */
export async function closeFixChange(
  repo: FixRepository,
  row: DependencyFixRow,
  mrNumber: number,
  comment: string,
): Promise<{ as: ClosedAs; branchKept: boolean }> {
  const head = await repo.branchHead(row.branch);
  if (head !== null && head !== row.headSha) return { as: 'taken_over', branchKept: false };
  const change = await repo.readChange(mrNumber);
  if (change.state === 'open') await repo.closeChange(mrNumber, comment);
  const deleted = head === null ? 'gone' : await repo.deleteBranch(row.branch, head);
  const as = deleted === 'taken_over' ? 'taken_over' : CLOSED_AS[change.state];
  return { as, branchKept: deleted === 'kept' };
}

/**
 * The `close` job (R10): a `cancelled` fix with an MR, at the job's generation, has its MR closed
 * with the cancel comment (R29) and its branch deleted ({@link closeFixChange}). A fix re-armed
 * (Retry) since the cancel has a new generation: the job drops quietly, and the re-armed fix's
 * commit finds the MR still open by its branch and updates it (ruling T8c).
 */
export async function runFixClose(deps: FixJobDeps, job: FixJob): Promise<void> {
  const loaded = await fixOfJob(deps.db, job, 'cancelled');
  const mrNumber = loaded?.row.mrNumber ?? null;
  if (loaded === null || mrNumber === null) return;
  const payload: JobPayload = { kind: 'close', ...job };
  await untilMovedOn(deps, payload, () =>
    withSlot(deps, loaded.project, payload, () =>
      againstRepository(deps, loaded, payload, {
        work: async (repo) => {
          const closed = await closeFixChange(
            repo,
            loaded.row,
            mrNumber,
            cancelComment(repo.provider),
          );
          if (closed.branchKept) {
            deps.logger?.warn(
              { fixId: job.fixId, kind: payload.kind },
              'fix close job: the repository refused the branch delete; the branch is kept',
            );
          }
        },
        fail: (failure) => noteCloseFailure(deps.db, loaded.row, failure),
      }),
    ),
  );
}

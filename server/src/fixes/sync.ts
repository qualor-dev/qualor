import {
  chooseTargets,
  isGreater,
  sameVersion,
  schemeOf,
  type VersionScheme,
} from '@qualor/shared/fix';
import { and, eq, lt, sql, type SQL } from 'drizzle-orm';
import type { PgUpdateSetSource } from 'drizzle-orm/pg-core';
import type { Db, Executor } from '../db/client';
import { dependencyFixes, projects, type FixFailure } from '../db/schema';
import type { ProjectRow } from '../projects/access';
import { ScmError } from '../scm/provider';
import { retryable } from '../scm/runtime';
import { monitoringOn } from '../vulnerabilities/targets';
import { runFixAuto } from './auto';
import { goneComment } from './body';
import { claimVulnerabilities } from './claim';
import { closeFixChange, fence, openWithMrElse, readOwnChange, type ClosedAs } from './commit';
import { mainVulnerabilities, packageOnMain, type MainVulnerability } from './eligibility';
import { FIX_QUEUE } from './jobs';
import { openTrackingRepository, type BranchDelete, type FixRepository } from './repository';
import { fixColumns, type DependencyFixRow } from './rows';
import type { FixJobDeps } from './run';

/**
 * The fix sync pass (0.16 fix MRs §6.7, R8, R18, B10, rulings T8c, T10c): one job per
 * organisation every 15 minutes, its steps in order: 1 expire leases (and end commits whose job
 * died), 2 read the open MRs, 3 presence on main, 4 the automatic mode. Every state write is
 * fenced on the fix, its generation and the state the pass read; no transaction is held across an
 * SCM call.
 */

/** The open fixes whose MR one pass reads (step 2) and judges on main (step 3), at most. */
export const FIX_READS_PER_PASS = 200;
/** Ruling T10c: a `committing` fix with no commit job queued or running is ended this long after. */
export const STUCK_COMMIT_SECONDS = 3_600;

export interface FixPassOutcome {
  /** Lapsed leases ended (R8), and commits whose job died (ruling T10c). */
  expired: number;
  merged: number;
  declined: number;
  takenOver: number;
  /** MRs closed because main no longer has a vulnerable package. */
  fixed: number;
  /** Open fixes given `refresh` (a conflict, a higher version needed). */
  refreshed: number;
  /** Fixes the automatic mode requested (step 4). */
  requested: number;
  /**
   * Why the pass ended early: a 429 or a transient SCM failure ends it; `budget` says a project's
   * request budget ended that project's part while the pass went on.
   */
  stop: null | 'rate_limited' | 'budget' | 'transient';
  /** The provider's `Retry-After` when a 429 ended the pass (ruling T11b); null otherwise. */
  retryAfterSeconds: number | null;
}

/** Ruling T10c: the failure of a commit whose job died (a DB failure, a bug) with no answer. */
const STUCK_COMMIT: FixFailure = Object.freeze({
  code: 'scm_unavailable',
  message: 'The fix branch or MR could not be written: its commit job stopped without finishing',
});

/** The fixes of the organisation's projects, as an update's condition. */
const ofOrganization = (organizationId: string): SQL =>
  sql`${dependencyFixes.projectId} IN (SELECT p.id FROM projects p WHERE p.organization_id = ${organizationId})`;

/**
 * spec §6.7 step 1, R8: the organisation's `preparing` fixes past their lease, back to `requested`,
 * or (a fix with an MR Qualor keeps) to `open` with `refresh`; `generation` + 1, so a late upload
 * gets 409, and the lease cleared. One statement; returns how many it ended.
 */
export async function expireLeases(db: Executor, organizationId: string): Promise<number> {
  const expired = await db
    .update(dependencyFixes)
    .set({
      state: openWithMrElse('requested'),
      refresh: sql`${dependencyFixes.mrNumber} IS NOT NULL AND ${dependencyFixes.headSha} IS NOT NULL`,
      generation: sql`${dependencyFixes.generation} + 1`,
      leaseTokenHash: null,
      leaseUntil: null,
      updatedAt: sql`now()`,
    })
    .where(
      and(
        eq(dependencyFixes.state, 'preparing'),
        lt(dependencyFixes.leaseUntil, sql`now()`),
        ofOrganization(organizationId),
      ),
    )
    .returning({ id: dependencyFixes.id });
  return expired.length;
}

/**
 * Ruling T10c: the organisation's `committing` fixes that no write moved for
 * {@link STUCK_COMMIT_SECONDS} (every write of a fix sets `updated_at`) and that have no commit job
 * of their generation queued or running (the queue's last attempt threw): `failed`
 * `scm_unavailable`, or (F7, R8) `open` with that failure for a fix with an MR; the prepared files
 * cleared. One statement, fenced on the row's state and generation; returns how many it ended.
 */
export async function endStuckCommits(db: Executor, organizationId: string): Promise<number> {
  const ended = await db
    .update(dependencyFixes)
    .set({
      state: openWithMrElse('failed'),
      refresh: false,
      prepared: null,
      failure: STUCK_COMMIT,
      updatedAt: sql`now()`,
    })
    .where(
      and(
        eq(dependencyFixes.state, 'committing'),
        lt(dependencyFixes.updatedAt, sql`now() - make_interval(secs => ${STUCK_COMMIT_SECONDS})`),
        ofOrganization(organizationId),
        sql`NOT EXISTS (
          SELECT 1 FROM jobs j
           WHERE j.queue = ${FIX_QUEUE} AND j.status IN ('queued', 'running')
             AND j.concurrency_key = 'fix:' || dependency_fixes.id::text
             AND j.payload->>'kind' = 'commit'
             AND j.payload->>'generation' = dependency_fixes.generation::text)`,
      ),
    )
    .returning({ id: dependencyFixes.id });
  return ended.length;
}

// ─── The pass ────────────────────────────────────────────────────────────────

/** A project's repository for the pass, `writable` while its connection allows fix MRs (R18). */
interface Tracking {
  repo: FixRepository;
  writable: boolean;
}

/** A project's open fixes that this pass reads. */
interface Part {
  project: ProjectRow;
  fixIds: string[];
}

interface Pass {
  readonly deps: FixJobDeps;
  readonly organizationId: string;
  readonly outcome: FixPassOutcome;
  parts: Part[];
  /** Each project's repository, opened once per pass (one request budget each); null: none. */
  readonly repositories: Map<string, Tracking | null>;
  /** Projects whose part of the pass has ended (their request budget, a refused token). */
  readonly ended: Set<string>;
  /** Whether vulnerability monitoring is on for each project, read once per pass. */
  readonly monitoring: Map<string, boolean>;
}

/** A 429 or a transient failure has ended the pass. */
const halted = (pass: Pass): boolean =>
  pass.outcome.stop === 'rate_limited' || pass.outcome.stop === 'transient';

/** Where an SCM call of the pass was made, for its part and its log line. */
interface Where {
  projectId: string;
  fixId: string | null;
}

/**
 * The pass ends on a 429 (keeping the provider's `Retry-After` for the next pass, ruling T11b) or
 * on a transient failure.
 */
function halt(pass: Pass, err: ScmError): void {
  if (err.kind === 'rate_limited') {
    pass.outcome.stop = 'rate_limited';
    pass.outcome.retryAfterSeconds = err.retryAfterSeconds;
  } else {
    pass.outcome.stop = 'transient';
  }
}

/**
 * A failed SCM call: a 429 or a transient failure ends the pass; the request budget or a refused
 * token ends the project's part; any other failure (an MR or branch not found, a refusal, an
 * answer not understood) skips that fix until the next pass. One warning with what the SCM said,
 * never its message.
 */
function noteFailure(pass: Pass, where: Where, err: ScmError): void {
  if (retryable(err)) {
    halt(pass, err);
  } else if (err.kind === 'budget' || err.kind === 'auth') {
    pass.ended.add(where.projectId);
    if (err.kind === 'budget' && pass.outcome.stop === null) pass.outcome.stop = 'budget';
  }
  pass.deps.logger?.warn(
    {
      organizationId: pass.organizationId,
      ...where,
      errorKind: err.kind,
      httpStatus: err.status,
      request: err.request,
    },
    'fix sync pass: an SCM request failed',
  );
}

/** One SCM call of the pass: its answer, or null when it failed ({@link noteFailure}). */
async function scmCall<T>(pass: Pass, where: Where, call: () => Promise<T>): Promise<T | null> {
  try {
    return await call();
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    noteFailure(pass, where, err);
    return null;
  }
}

/**
 * The project's repository as the pass uses it, opened on first use and kept for the pass (one
 * request budget per project); null when the project's part has ended, or when it has no usable
 * repository (unmapped, or a connection no client can be made for), which is logged once.
 */
async function trackingOf(pass: Pass, project: ProjectRow): Promise<Tracking | null> {
  if (pass.ended.has(project.id)) return null;
  const known = pass.repositories.get(project.id);
  if (known !== undefined) return known;
  const where = { projectId: project.id, fixId: null };
  const opened = await scmCall(pass, where, () => openTrackingRepository(pass.deps, project));
  if (opened !== null && 'problem' in opened) {
    pass.deps.logger?.warn(
      { organizationId: pass.organizationId, ...where, problem: opened.problem },
      'fix sync pass: the repository cannot be used',
    );
  }
  const tracking = opened === null || 'problem' in opened ? null : opened;
  pass.repositories.set(project.id, tracking);
  return tracking;
}

/**
 * One fenced write of the pass (ruling T8c): the fix at the generation and in the state the pass
 * read, and `extra` when given; false when it moved on (a cancel, a claim, a re-arm), so the
 * write is dropped.
 */
async function passWrite(
  db: Db,
  row: DependencyFixRow,
  set: PgUpdateSetSource<typeof dependencyFixes>,
  extra?: SQL,
): Promise<boolean> {
  const [written] = await db
    .update(dependencyFixes)
    .set({ ...set, updatedAt: sql`now()` })
    .where(and(fence(row), extra))
    .returning({ id: dependencyFixes.id });
  return written !== undefined;
}

/** The ends of an open fix the pass records, and the count each adds to. */
const END_COUNT = Object.freeze({
  merged: 'merged',
  declined: 'declined',
  taken_over: 'takenOver',
  fixed: 'fixed',
} as const);
type PassEnd = keyof typeof END_COUNT;

/**
 * An open fix ends `state` (its failure and `refresh` cleared); `declined` keeps the target a
 * person declined (B3, B4, ruling T10e).
 */
async function endFix(pass: Pass, row: DependencyFixRow, state: PassEnd): Promise<void> {
  const declined = state === 'declined' ? { declinedTarget: row.targetVersion } : {};
  const set = { state, refresh: false, failure: null, ...declined };
  if (await passWrite(pass.deps.db, row, set)) pass.outcome[END_COUNT[state]] += 1;
}

/** spec §6.4: an open fix whose MR a job must rebuild from the current main; counted once. */
async function markRefresh(pass: Pass, row: DependencyFixRow): Promise<void> {
  const set = { refresh: true };
  if (await passWrite(pass.deps.db, row, set, eq(dependencyFixes.refresh, false))) {
    pass.outcome.refreshed += 1;
  }
}

/** The fix as it is stored now, when it is still open; null when it moved on. */
async function openFixOf(db: Db, fixId: string): Promise<DependencyFixRow | null> {
  const [row] = await db
    .select(fixColumns)
    .from(dependencyFixes)
    .where(and(eq(dependencyFixes.id, fixId), eq(dependencyFixes.state, 'open')));
  return row ?? null;
}

// ─── Step 2: the open MRs ────────────────────────────────────────────────────

/**
 * The organisation's open fixes this pass reads, at most {@link FIX_READS_PER_PASS} in a random
 * order (an organisation with more is read in turns), by project, so each project's repository
 * is opened once.
 */
async function openParts(db: Db, organizationId: string): Promise<Part[]> {
  const rows = await db
    .select({ id: dependencyFixes.id, project: projects })
    .from(dependencyFixes)
    .innerJoin(projects, eq(projects.id, dependencyFixes.projectId))
    .where(and(eq(projects.organizationId, organizationId), eq(dependencyFixes.state, 'open')))
    .orderBy(sql`random()`)
    .limit(FIX_READS_PER_PASS);
  const parts = new Map<string, Part>();
  for (const { id, project } of rows) {
    const part = parts.get(project.id) ?? { project, fixIds: [] };
    part.fixIds.push(id);
    parts.set(project.id, part);
  }
  return [...parts.values()];
}

/** Whether vulnerability monitoring is on for the project (instance and project), once a pass. */
async function monitored(pass: Pass, projectId: string): Promise<boolean> {
  const known = pass.monitoring.get(projectId);
  if (known !== undefined) return known;
  const on = await monitoringOn(pass.deps.db, projectId);
  pass.monitoring.set(projectId, on);
  return on;
}

/**
 * Ruling T11a: main no longer has the fix's package (`packageOnMain`, the Jira presence rule on
 * the main target), judged only while monitoring is on (spec §6.7: else nothing is gone).
 */
async function isGone(pass: Pass, row: DependencyFixRow): Promise<boolean> {
  return (await monitored(pass, row.projectId)) && !(await packageOnMain(pass.deps.db, row));
}

/**
 * Ruling FW4: the provider refused the branch delete for good (a ruleset, a protected branch); the
 * fix ends anyway with its branch kept, and the project's part of the pass goes on. One warning.
 */
function noteBranchKept(pass: Pass, row: DependencyFixRow): void {
  pass.deps.logger?.warn(
    { organizationId: pass.organizationId, projectId: row.projectId, fixId: row.id },
    'fix sync pass: the repository refused the branch delete; the fix ended with its branch kept',
  );
}

/**
 * Finding I1: an MR closed without a merge. While main still has the package, a person declined
 * it: `declined`, its target kept. Once the package is gone (Qualor's gone-close cut short before
 * the branch delete, or a person's close that no longer matters): `fixed`, with the branch
 * deleted through the B10 path (`deleteBranch` re-reads the head; a person's head keeps the
 * branch, `taken_over`). Nothing is deleted while the connection does not allow fix MRs (R18).
 * A delete the provider refuses for good keeps the branch and still ends the fix `fixed`, with one
 * warning (ruling FW4), as the read-only case does.
 */
async function endClosed(pass: Pass, tracking: Tracking, row: DependencyFixRow): Promise<void> {
  if (!(await isGone(pass, row))) return endFix(pass, row, 'declined');
  let deleted: BranchDelete = 'gone';
  if (tracking.writable && row.headSha !== null) {
    deleted = await tracking.repo.deleteBranch(row.branch, row.headSha);
  }
  if (deleted === 'kept') noteBranchKept(pass, row);
  return endFix(pass, row, deleted === 'taken_over' ? 'taken_over' : 'fixed');
}

/**
 * spec §6.7 step 2, §11.2: what became of the fix's MR. Merged → `merged`; closed → `declined`,
 * or `fixed` when the package is gone ({@link endClosed}); a branch head that is not Qualor's last
 * commit → `taken_over` (a branch a person deleted is not theirs, as for the commit job); a
 * conflict → `refresh`. Ruling FW14: an MR the provider no longer has (deleted) ends as a closed
 * one does.
 */
async function trackChange(pass: Pass, tracking: Tracking, row: DependencyFixRow): Promise<void> {
  if (row.mrNumber === null) return;
  const { repo } = tracking;
  const change = await readOwnChange(repo, row.mrNumber);
  if (change === 'deleted' || change.state === 'closed') return endClosed(pass, tracking, row);
  if (change.state === 'merged') return endFix(pass, row, 'merged');
  const head = await repo.branchHead(row.branch);
  if (head !== null && head !== row.headSha) return endFix(pass, row, 'taken_over');
  if (change.conflict) await markRefresh(pass, row);
}

/** One project's open MRs read, until the pass halts or the project's part ends. */
async function readPart(pass: Pass, part: Part): Promise<void> {
  const tracking = await trackingOf(pass, part.project);
  if (tracking === null) return;
  for (const fixId of part.fixIds) {
    const row = await openFixOf(pass.deps.db, fixId);
    if (row !== null) {
      await scmCall(pass, { projectId: row.projectId, fixId }, () =>
        trackChange(pass, tracking, row),
      );
    }
    if (halted(pass) || pass.ended.has(part.project.id)) return;
  }
}

/**
 * spec §6.7 step 2 (R18: also for projects whose fixes are switched off, and with a connection
 * that no longer allows fix MRs, read only).
 */
async function readChanges(pass: Pass): Promise<void> {
  pass.parts = await openParts(pass.deps.db, pass.organizationId);
  for (const part of pass.parts) {
    await readPart(pass, part);
    if (halted(pass)) return;
  }
}

// ─── Step 3: presence on main ────────────────────────────────────────────────

/** The MR's target for an installed version (B3): the lowest of its lockfiles'; null without one. */
function targetOf(row: DependencyFixRow, scheme: VersionScheme, installed: string): string | null {
  const own = row.targets.filter((t) => sameVersion(scheme, t.installed, installed));
  if (own.length === 0) return row.targets.length === 0 ? row.targetVersion : null;
  return own.reduce((low, t) => (isGreater(scheme, low.target, t.target) ? t : low)).target;
}

/**
 * spec §6.7 step 3, B3: whether a vulnerability of the package on main now needs a version above
 * the MR's target for its installed version (each installed version's target chosen as the job
 * chooses it, `chooseTargets`). An installed version the MR names no target for is left alone, so
 * a version the job cannot reach never refreshes the MR again and again.
 */
export function needsHigherTarget(
  row: DependencyFixRow,
  rows: readonly MainVulnerability[],
): boolean {
  const scheme = schemeOf(row.family);
  const installed = [...new Set(rows.map((r) => r.packageVersion))];
  return chooseTargets(scheme, installed, claimVulnerabilities(row.family, rows)).some((t) => {
    const current = targetOf(row, scheme, t.installed);
    return t.target !== null && current !== null && isGreater(scheme, t.target, current);
  });
}

/**
 * How a gone fix ends after {@link closeFixChange}: an MR found closed is `fixed` too (I1: the
 * package is gone, so no person declined a fix that still mattered).
 */
const GONE_END: Readonly<Record<ClosedAs, PassEnd>> = Object.freeze({
  closed: 'fixed',
  merged: 'merged',
  declined: 'fixed',
  taken_over: 'taken_over',
});

/**
 * spec §6.7 step 3, B10: main no longer has a vulnerable package: the MR is closed with the gone
 * comment and the branch deleted through the close path of a cancel (`closeFixChange`: each after
 * a head re-read; a person's head keeps both, `taken_over`), then `fixed`. Nothing is written
 * while the connection does not allow fix MRs (R18). A branch delete the provider refuses for
 * good keeps the branch and still ends the fix (ruling FW4).
 */
async function closeGone(pass: Pass, project: ProjectRow, row: DependencyFixRow): Promise<void> {
  const tracking = await trackingOf(pass, project);
  const mrNumber = row.mrNumber;
  if (tracking === null || !tracking.writable || mrNumber === null) return;
  const { repo } = tracking;
  const comment = goneComment(row.packageName, repo.mainBranch);
  const closed = await scmCall(pass, { projectId: project.id, fixId: row.id }, () =>
    closeFixChange(repo, row, mrNumber, comment),
  );
  if (closed === null) return;
  if (closed.branchKept) noteBranchKept(pass, row);
  await endFix(pass, row, GONE_END[closed.as]);
}

/**
 * One open fix judged on main, read again right before (ruling T8c). The package gone from main by
 * the Jira presence rule (ruling T11a: an ignored or triaged row keeps it present) →
 * {@link closeGone}. Otherwise a higher version needed by a vulnerability that needs a fix (B5:
 * effective-open, not ignored; a Python package by its PEP 503 name, T8b) → `refresh`.
 *
 * The claim decides "still on main" differently, by design (claim.ts `stopRefresh`, R31: open,
 * not ignored rows only): a package whose rows are all ignored or triaged is present here, so its
 * MR stays open, and gone there, so the claim clears its `refresh` instead of handing it out
 * (ruling FW16).
 */
async function judgeOnMain(pass: Pass, project: ProjectRow, fixId: string): Promise<void> {
  const { db } = pass.deps;
  const row = await openFixOf(db, fixId);
  if (row === null) return;
  if (!(await packageOnMain(db, row))) return closeGone(pass, project, row);
  const rows = await mainVulnerabilities(db, row.projectId, row.family, row.packageName);
  if (needsHigherTarget(row, rows)) await markRefresh(pass, row);
}

/** spec §6.7 step 3; monitoring off for the project skips it (as in the Jira pass). */
async function presence(pass: Pass): Promise<void> {
  for (const { project, fixIds } of pass.parts) {
    if (pass.ended.has(project.id) || !(await monitored(pass, project.id))) continue;
    for (const fixId of fixIds) {
      await judgeOnMain(pass, project, fixId);
      if (halted(pass) || pass.ended.has(project.id)) break;
    }
    if (halted(pass)) return;
  }
}

// ─── Steps 1 and 4 ───────────────────────────────────────────────────────────

/** spec §6.7 step 1 (R8), with ruling T10c's dead commits. */
async function expire(pass: Pass): Promise<void> {
  const { db } = pass.deps;
  const leases = await expireLeases(db, pass.organizationId);
  pass.outcome.expired = leases + (await endStuckCommits(db, pass.organizationId));
}

/** spec §6.7 step 4: the automatic mode, but not for a project whose part has ended. */
async function automatic(pass: Pass): Promise<void> {
  pass.outcome.requested = await runFixAuto(pass.deps, pass.organizationId, { skip: pass.ended });
}

/** The pass's steps, in the order of spec §6.7. */
const STEPS: readonly ((pass: Pass) => Promise<void>)[] = [
  expire,
  readChanges,
  presence,
  automatic,
];

/**
 * spec §6.7: one fix sync pass of the organisation, steps 1 to 4 in order. A 429 or a transient
 * SCM failure ends the pass; the request budget ends that project's part. One info line per pass,
 * with its counts and duration.
 */
export async function runFixSyncPass(
  deps: FixJobDeps,
  organizationId: string,
): Promise<FixPassOutcome> {
  const started = Date.now();
  const pass: Pass = {
    deps,
    organizationId,
    outcome: {
      expired: 0,
      merged: 0,
      declined: 0,
      takenOver: 0,
      fixed: 0,
      refreshed: 0,
      requested: 0,
      stop: null,
      retryAfterSeconds: null,
    },
    parts: [],
    repositories: new Map(),
    ended: new Set(),
    monitoring: new Map(),
  };
  for (const step of STEPS) {
    await step(pass);
    if (halted(pass)) break;
  }
  deps.logger?.info(
    { organizationId, durationMs: Date.now() - started, ...pass.outcome },
    'fix sync pass',
  );
  return pass.outcome;
}

import type { FixFamily } from '@qualor/shared/fix';
import { and, eq, inArray, sql } from 'drizzle-orm';
import type { Executor } from '../db/client';
import {
  ACTIVE_FIX_STATES,
  dependencyFixes,
  projects,
  type FixOrigin,
  type FixState,
} from '../db/schema';
import { conflict } from '../http/problem';
import type { ProjectRow } from '../projects/access';
import { enqueueFixJob } from './jobs';
import { fixBranchName, fixPackageName, type DependencyFixRow } from './rows';
import { fixCounts } from './settings';

/**
 * Requests, re-arms and cancels (spec §6.3, §6.4, B4, R9-R11, R32).
 *
 * Lock order: the project row (`FOR NO KEY UPDATE`, {@link lockProject}), then the fix row
 * (`FOR UPDATE`), then the audit chain, then the fix job schedule. Branch names are unique per
 * project only in code (ruling T2a: no unique index), so every caller of {@link uniqueBranch} holds
 * the project row lock in the same transaction, and requests of one project run one at a time.
 */

/** R11, B4: the terminal states; Create and Retry re-arm each of them (`taken_over` on a new branch). */
export const REARMABLE_FIX_STATES = [
  'failed',
  'no_fix',
  'merged',
  'fixed',
  'declined',
  'taken_over',
  'cancelled',
] as const satisfies readonly FixState[];

/** Whether the fix is in flight: it counts against the cap (R9) and answers a request as it is. */
export const isActiveFix = (state: FixState): boolean =>
  (ACTIVE_FIX_STATES as readonly FixState[]).includes(state);

/** R9: the project's fixes that count against its cap (`requested` to `open`, `committing` too). */
export async function activeFixCount(db: Executor, projectId: string): Promise<number> {
  const counts = await fixCounts(db, projectId);
  return counts.requested + counts.preparing + counts.committing + counts.open;
}

/**
 * The project row, locked `FOR NO KEY UPDATE` for the rest of the transaction: fix requests of
 * the project wait on each other (ruling T2a), as the settings save does. Null when it is gone.
 */
export async function lockProject(tx: Executor, projectId: string): Promise<ProjectRow | null> {
  const [row] = await tx
    .select()
    .from(projects)
    .where(eq(projects.id, projectId))
    .for('no key update');
  return row ?? null;
}

/** The fix row, locked `FOR UPDATE` for the rest of the transaction; null when it is gone. */
export async function lockFix(tx: Executor, fixId: string): Promise<DependencyFixRow | null> {
  const [row] = await tx
    .select()
    .from(dependencyFixes)
    .where(eq(dependencyFixes.id, fixId))
    .for('update');
  return row ?? null;
}

/**
 * The package's fix row in the project, locked `FOR UPDATE`; null when it has none. A Python
 * package is found under its PEP 503 name, whichever spelling asks ({@link fixPackageName}).
 */
export async function lockPackageFix(
  tx: Executor,
  projectId: string,
  family: FixFamily,
  packageName: string,
): Promise<DependencyFixRow | null> {
  const [row] = await tx
    .select()
    .from(dependencyFixes)
    .where(
      and(
        eq(dependencyFixes.projectId, projectId),
        eq(dependencyFixes.family, family),
        eq(dependencyFixes.packageName, fixPackageName(family, packageName)),
      ),
    )
    .for('update');
  return row ?? null;
}

/** The candidates {@link uniqueBranch} checks per query. */
const BRANCH_BATCH = 20;

/**
 * R32: the first of `fixBranchName(family, packageName, n)` for n = `from`, `from` + 1, … that
 * no fix of the project stores, so two packages that slug alike (`@a/b`, `a-b`) get `-2`, `-3`.
 *
 * Precondition (ruling T2a): the caller holds the project row lock ({@link lockProject}) in the
 * transaction `tx`; without it two requests could pick the same name.
 */
export async function uniqueBranch(
  tx: Executor,
  projectId: string,
  family: FixFamily,
  packageName: string,
  from: number,
): Promise<string> {
  for (let start = from; ; start += BRANCH_BATCH) {
    const names = Array.from({ length: BRANCH_BATCH }, (_, i) =>
      fixBranchName(family, packageName, start + i),
    );
    const taken = await tx
      .select({ branch: dependencyFixes.branch })
      .from(dependencyFixes)
      .where(and(eq(dependencyFixes.projectId, projectId), inArray(dependencyFixes.branch, names)));
    const used = new Set(taken.map((r) => r.branch));
    const free = names.find((name) => !used.has(name));
    if (free !== undefined) return free;
  }
}

/** The `n` of the row's branch (`…-<n>`), 1 for the package's first name. */
function branchNumber(row: DependencyFixRow): number {
  const n = Number(/-(\d{1,9})$/.exec(row.branch)?.[1] ?? '1');
  return n > 1 && fixBranchName(row.family, row.packageName, n) === row.branch ? n : 1;
}

/**
 * B4, R11: an ended fix back to `requested` for a new attempt: `generation` + 1 (an upload of the
 * old one gets 409), `refresh` false; the failure, the lease, the prepared files and the MR number
 * and URL cleared; `head_sha` and `base_sha` kept, so a branch still at Qualor's commit can be
 * force-updated. A fix a person took over (`taken_over`) gets the next unique branch, so theirs is
 * never touched. Requested by `userId` (null for the automatic mode) with `origin`.
 *
 * Precondition (ruling T2a): the caller holds the project row lock ({@link lockProject}) and the
 * row is locked and in one of {@link REARMABLE_FIX_STATES}.
 */
export async function rearmFix(
  tx: Executor,
  row: DependencyFixRow,
  input: { userId: string | null; origin: FixOrigin },
): Promise<DependencyFixRow> {
  const branch =
    row.state === 'taken_over'
      ? await uniqueBranch(tx, row.projectId, row.family, row.packageName, branchNumber(row) + 1)
      : row.branch;
  const [rearmed] = await tx
    .update(dependencyFixes)
    .set({
      state: 'requested',
      generation: sql`${dependencyFixes.generation} + 1`,
      refresh: false,
      origin: input.origin,
      requestedBy: input.userId,
      failure: null,
      leaseTokenHash: null,
      leaseUntil: null,
      prepared: null,
      mrNumber: null,
      mrUrl: null,
      branch,
      updatedAt: sql`now()`,
    })
    .where(
      and(
        eq(dependencyFixes.id, row.id),
        inArray(dependencyFixes.state, [...REARMABLE_FIX_STATES]),
      ),
    )
    .returning();
  if (!rearmed) throw new Error(`fix ${row.id} is not in a state a request re-arms`);
  return rearmed;
}

/**
 * spec §6.3, B4: the package's fix as a request leaves it: a new `requested` row on its first
 * unique branch (`created`), an ended one re-armed (`rearmed`, {@link rearmFix}), or an active
 * one as it is (`active`, no duplicate). The insert is `ON CONFLICT DO NOTHING`; a loser re-reads
 * the row. It checks no setting, cap or eligibility: the callers do, in their order. A Python
 * package's fix is named and found by its PEP 503 name (ruling T8b). `current` is the package's
 * row the caller has already locked with {@link lockPackageFix} (null: it has none), so it is not
 * read twice; without it the row is locked here.
 *
 * Precondition (ruling T2a): the caller holds the project row lock ({@link lockProject}) in `tx`.
 */
export async function requestFix(
  tx: Executor,
  input: {
    project: ProjectRow;
    family: FixFamily;
    packageName: string;
    userId: string | null;
    origin: FixOrigin;
    current?: DependencyFixRow | null;
  },
): Promise<{ row: DependencyFixRow; outcome: 'created' | 'rearmed' | 'active' }> {
  const { project, family } = input;
  const packageName = fixPackageName(family, input.packageName);
  const answer = async (row: DependencyFixRow) =>
    isActiveFix(row.state)
      ? { row, outcome: 'active' as const }
      : { row: await rearmFix(tx, row, input), outcome: 'rearmed' as const };

  const existing =
    input.current === undefined
      ? await lockPackageFix(tx, project.id, family, packageName)
      : input.current;
  if (existing) return answer(existing);
  const [created] = await tx
    .insert(dependencyFixes)
    .values({
      projectId: project.id,
      family,
      packageName,
      state: 'requested',
      origin: input.origin,
      requestedBy: input.userId,
      branch: await uniqueBranch(tx, project.id, family, packageName, 1),
    })
    .onConflictDoNothing({
      target: [dependencyFixes.projectId, dependencyFixes.family, dependencyFixes.packageName],
    })
    .returning();
  if (created) return { row: created, outcome: 'created' };
  const winner = await lockPackageFix(tx, project.id, family, packageName);
  if (!winner) throw new Error(`fix of ${packageName} vanished after a conflict`);
  return answer(winner);
}

/** R10, ruling F1: 409 for a fix whose branch and MR the server is writing now. */
export function requireCancellable(row: DependencyFixRow): void {
  if (row.state === 'committing') {
    throw conflict(
      'FIX_BUSY',
      'The fix is being written to the repository; cancel it again in a few seconds',
    );
  }
}

/**
 * R10: cancels an active fix: `cancelled`, `generation` + 1 (an upload in flight gets 409), the
 * lease cleared. A fix with an MR keeps its number, URL and head, and a `close` job is queued to
 * comment, close the MR and delete the branch (each after a head re-read): an `open` one, and one
 * a job is refreshing (`preparing` with its MR, R8), whose MR the sync pass would never read
 * again. `committing` is 409 `FIX_BUSY` ({@link requireCancellable}); an ended fix is answered
 * as it is.
 *
 * The caller holds the fix row lock ({@link lockFix}) and records the audit event first: the
 * audit chain before the job schedule, the settings save's order.
 */
export async function cancelFix(tx: Executor, row: DependencyFixRow): Promise<DependencyFixRow> {
  requireCancellable(row);
  if (!isActiveFix(row.state)) return row;
  const [cancelled] = await tx
    .update(dependencyFixes)
    .set({
      state: 'cancelled',
      generation: sql`${dependencyFixes.generation} + 1`,
      refresh: false,
      leaseTokenHash: null,
      leaseUntil: null,
      updatedAt: sql`now()`,
    })
    .where(and(eq(dependencyFixes.id, row.id), eq(dependencyFixes.state, row.state)))
    .returning();
  if (!cancelled) throw new Error(`fix ${row.id} changed while it was locked`);
  if (cancelled.mrNumber !== null) {
    await enqueueFixJob(tx, {
      kind: 'close',
      fixId: cancelled.id,
      generation: cancelled.generation,
      attempt: 0,
    });
  }
  return cancelled;
}

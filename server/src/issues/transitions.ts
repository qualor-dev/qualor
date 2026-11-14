import { sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import type { AuditActorContext, AuditEventInput, AuditRecorder } from '../audit/recorder';
import { projectRefs, type AuditRef } from '../audit/refs';
import type { AccessContext } from '../auth/access';
import { projectFacts } from '../auth/facts';
import { projectPermissions } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import type { UserRow } from '../auth/sessions';
import { uuidList } from '../db/bulk';
import type { Db, Executor, Tx } from '../db/client';
import { uuidv7 } from '../db/ids';
import { withConflictRetry } from '../db/retry';
import type { OrganizationRole, ProjectRole } from '../db/schema';
import { enqueueReevaluations } from '../gates/reevaluate';
import type { IssueStatus } from '../tracking/plan';
import { vulnerabilitySettingsOf } from '../versions/settings';
import {
  branchDecisionKeys,
  lockDecisionPairs,
  pairIssueIds,
  recordDecision,
  writeDecision,
  type DecisionInput,
  type DecisionPair,
  type DecisionResult,
  type VexJustification,
} from '../vulnerabilities/decisions';
import { decidingIssues, type DecidingIssue } from '../vulnerabilities/trivy-issues';
import {
  USER_STATUSES,
  writeStatus,
  writeStatusLog,
  type StatusLogRow,
  type UserStatus,
} from './status-writes';

export { USER_STATUSES, type UserStatus };

/**
 * data-model.md §6 as a table (ruling I2): an open issue can be resolved, accepted (`wont_fix`)
 * or marked `false_positive`; each of those can only be reopened. A `closed` issue belongs to the
 * system (it reopens when re-detected), and setting the current status again is not a transition.
 */
const ALLOWED: Record<IssueStatus, readonly UserStatus[]> = {
  open: ['resolved', 'wont_fix', 'false_positive'],
  resolved: ['open'],
  wont_fix: ['open'],
  false_positive: ['open'],
  closed: [],
};

export function transitionAllowed(from: IssueStatus, to: UserStatus): boolean {
  return ALLOWED[from].includes(to);
}

/** data-model.md §6: a comment is required for `wont_fix` and `false_positive`. */
export function commentRequired(to: UserStatus): boolean {
  return to === 'wont_fix' || to === 'false_positive';
}

/** A user transition waits at most this long for a row an ingestion holds (then 503). */
export const TRANSITION_LOCK_TIMEOUT_MS = 5_000;

/**
 * `SET LOCAL lock_timeout` for the rest of the transaction (ruling I4), bound as a parameter:
 * a row lock waited on longer than this fails the statement with SQLSTATE 55P03.
 */
export async function setLockTimeout(tx: Executor, ms: number): Promise<void> {
  if (!Number.isSafeInteger(ms) || ms <= 0) throw new RangeError(`Invalid lock timeout: ${ms}`);
  const timeout = `${ms}ms`;
  await tx.execute(sql`SELECT set_config('lock_timeout', ${timeout}, true)`);
}

export interface TransitionFailure {
  id: string;
  /**
   * NOT_FOUND: the issue does not exist or the caller cannot read it; FORBIDDEN: it can read it
   * but its role does not allow triage (rbac-audit.md §5, a viewer); REASON_REQUIRED: it is a
   * false positive that writes the project's vulnerability decision, and no reason was given
   * (vuln plan 2b, D9).
   */
  code: 'NOT_FOUND' | 'FORBIDDEN' | 'INVALID_TRANSITION' | 'REASON_REQUIRED';
  /** The status the issue has (INVALID_TRANSITION only). */
  from?: IssueStatus;
}

/** A vulnerability decision a transition wrote (vuln plan 2b), with what its event records. */
export interface WrittenDecision {
  input: DecisionInput;
  result: DecisionResult;
}

export interface TransitionResult {
  /** Requested ids whose status changed, in request order (mirrored duplicates not listed). */
  succeeded: string[];
  failed: TransitionFailure[];
  /**
   * The vulnerability decisions the transition wrote. With `audit` their events are recorded
   * already; without, a caller that records them does so after its last transition
   * (`recordDecision`), so no re-evaluation lock follows the audit chain's.
   */
  decisions: WrittenDecision[];
  /**
   * The issues whose branches' gates are evaluated again: the changed ones and those the
   * decisions changed. Queued already, unless the transition ran with `deferReevaluation`: then
   * the caller queues them ({@link enqueueReevaluations}), before any audit event it records.
   */
  reevaluate: string[];
}

export type LockedIssue = {
  id: string;
  status: IssueStatus;
  duplicate_of_issue_id: string | null;
};

/**
 * Locks `ids`, their duplicates and the issues `also` names `FOR NO KEY UPDATE` in one statement,
 * in id order (step 2 below): the one lock order every transition and ingestion
 * (tracking/writes.ts `lockPlannedRows`) follows, so none of them wait on each other in a cycle.
 * Taking a lock again later in the same transaction is free, so a caller that runs several
 * transitions in one transaction locks all of their issues here first ({@link lockForTransition}).
 */
export async function lockIssues(
  tx: Executor,
  ids: readonly string[],
  also: readonly string[] = [],
): Promise<LockedIssue[]> {
  if (ids.length === 0 && also.length === 0) return [];
  return (
    await tx.execute<LockedIssue>(sql`
      SELECT id, status, duplicate_of_issue_id FROM issues
       WHERE id IN ${uuidList(ids)}
          OR duplicate_of_issue_id IN ${uuidList(ids)}
          ${also.length > 0 ? sql`OR id IN ${uuidList(also)}` : sql``}
       ORDER BY id
         FOR NO KEY UPDATE`)
  ).rows;
}

/**
 * A pair a transition must lock appeared after it locked its issues: an ingestion committed a
 * package name (or a new duplicate) between the transition's first read and its issue locks.
 * SQLSTATE 40001 like a serialisation failure, so {@link withConflictRetry} runs the whole
 * transaction again (it rolled back; nothing was written or charged), and a request that runs
 * out of attempts answers 503 `CONCURRENCY_CONFLICT`.
 */
export class DecisionPairsChanged extends Error {
  readonly code = '40001';

  constructor() {
    super('A vulnerability decision pair appeared after the transition locked its issues');
    this.name = 'DecisionPairsChanged';
  }
}

/** What a transition holds of each pair: the pair itself, project included. */
const pairKey = (pair: DecisionPair): string =>
  JSON.stringify([pair.projectId, pair.packageName, pair.vulnerabilityId]);

/** What a transition locked: its issues, the issues whose triage writes a decision, the ids held. */
export interface TransitionLocks {
  locked: LockedIssue[];
  deciding: Map<string, DecidingIssue>;
  held: string[];
}

/**
 * Everything a transition of `ids` locks, before it changes anything, in the order every writer
 * of issues and decisions follows (vuln plan 2b):
 *
 * 1. Read without locks: the issues of `ids` and their duplicates whose triage writes a
 *    vulnerability decision (`decidingIssues`), unless `decisions` is false (`resolved`).
 * 2. The advisory lock of each of their pairs, in one statement in ascending key order
 *    (`lockDecisionPairs`), which every decision writer takes first and an ingestion takes shared
 *    before it reads the decisions.
 * 3. `ids`, their duplicates and every Trivy issue of those pairs, in ONE id-ordered statement
 *    ({@link lockIssues}): the decisions then change only rows already held.
 * 4. The deciding issues read again, now that their rows are held (D2-3). A pair step 1 did not
 *    see is never locked now, after the issue locks: {@link DecisionPairsChanged} aborts the
 *    transaction, and its retry locks that pair in step 2.
 *
 * Answers the locked rows, the deciding issues of step 4 and the ids held.
 */
export async function lockForTransition(
  tx: Executor,
  ids: readonly string[],
  decisions: boolean,
): Promise<TransitionLocks> {
  if (!decisions) {
    const locked = await lockIssues(tx, ids);
    return { locked, deciding: new Map(), held: locked.map((row) => row.id) };
  }
  const pairs = [...(await decidingIssues(tx, ids)).values()];
  await lockDecisionPairs(tx, pairs);
  const locked = await lockIssues(tx, ids, await pairIssueIds(tx, pairs));
  const deciding = await decidingIssues(tx, ids);
  const lockedPairs = new Set(pairs.map(pairKey));
  if ([...deciding.values()].some((issue) => !lockedPairs.has(pairKey(issue)))) {
    throw new DecisionPairsChanged();
  }
  return { locked, deciding, held: locked.map((row) => row.id) };
}

/**
 * rbac-audit.md §8, record one `issue.status_changed` per issue whose status changed (a
 * mirrored duplicate its own, `mirrored: true`), in the transition's transaction.
 */
export interface TransitionAudit {
  recorder: AuditRecorder;
  context: AuditActorContext;
  bulk: boolean;
  /** The accepted AI triage suggestion (llm.md §7), or null. */
  suggestionId: string | null;
  /** The OAuth client of an MCP call (Phase 6N, ruling R8); absent for other callers. */
  mcpClientId?: string | null;
}

export interface TransitionOptions {
  lockTimeoutMs?: number;
  /** A requested issue's own changelog comment (instead of `comment`); its mirrored duplicates get the same one. */
  comments?: ReadonlyMap<string, string>;
  /**
   * Absent: nothing is recorded (the status import records one summary event itself, and the
   * events of the decisions in `TransitionResult.decisions`).
   */
  audit?: TransitionAudit;
  /**
   * The VEX justification of a false positive that writes the project's vulnerability decision
   * (vuln plan 2b, D9); ignored for every other issue and status.
   */
  reason?: VexJustification | null;
  /** `import`: the SonarQube status import, whose decisions need no reason (D9). Default `issue`. */
  source?: 'issue' | 'import';
  /**
   * Called inside the transaction with the number of other issues the vulnerability decisions
   * changed (the requested issues are the caller's to charge). It throws to refuse, which rolls
   * the whole transition back: one decision must not change many issues for one request's cost.
   * A transaction run again ({@link withConflictRetry}) charges only the excess over the earlier
   * attempts ({@link chargeAcrossAttempts}).
   */
  chargeMirrored?: (count: number) => void;
  /** Where a transaction run again after a conflict is logged (debug, with its SQLSTATE). */
  logger?: Pick<FastifyBaseLogger, 'debug'>;
}

/**
 * `charge` across the attempts of one transition: each attempt reports its whole count, and only
 * the excess over what earlier attempts charged is charged. The limiter lives in memory, so a
 * charge does not roll back with a deadlocked attempt, and a retry must not charge it twice. A
 * charge that throws (refuses) charged nothing.
 */
export function chargeAcrossAttempts(
  charge: ((count: number) => void) | undefined,
): ((count: number) => void) | undefined {
  if (charge === undefined) return undefined;
  let charged = 0;
  return (count) => {
    if (count <= charged) return;
    charge(count - charged);
    charged = count;
  };
}

/** The requested issues, split by what the user's roles allow on each one's project. */
interface IssueAccess {
  /** Issues the user may triage (`issue.triage`), with their organisation. */
  allowed: Map<string, string>;
  /** Issues the user may read but not triage (`project.read` only). */
  forbidden: Set<string>;
}

/**
 * rbac-audit.md §5: one query reads each requested issue with the user's organisation role and
 * project grant, and the policy decides per issue. Issues the user cannot read are in neither set,
 * so they fail as `NOT_FOUND`, exactly like one that does not exist.
 */
async function issueAccess(
  executor: Executor,
  user: UserRow,
  ids: readonly string[],
): Promise<IssueAccess> {
  const result: IssueAccess = { allowed: new Map(), forbidden: new Set() };
  if (ids.length === 0) return result;
  const visible = await executor.execute<{
    id: string;
    organization_id: string;
    organization_role: OrganizationRole | null;
    project_role: ProjectRole | null;
  }>(sql`
    SELECT i.id, p.organization_id, m.role AS organization_role, pm.role AS project_role
      FROM issues i
      JOIN projects p ON p.id = i.project_id
      LEFT JOIN memberships m ON m.organization_id = p.organization_id AND m.user_id = ${user.id}
      LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = ${user.id}
     WHERE i.id IN ${uuidList(ids)}`);
  for (const r of visible.rows) {
    const granted = projectPermissions(
      projectFacts(user, {
        organizationRole: r.organization_role,
        projectRole: r.project_role,
      }),
    );
    if (granted.has('issue.triage')) result.allowed.set(r.id, r.organization_id);
    else if (granted.has('project.read')) result.forbidden.add(r.id);
  }
  return result;
}

/**
 * Sets `to` on every requested issue the user can see, and mirrors it onto their duplicates
 * (data-model.md §5.3), in one transaction:
 *
 * 1. Permissions (one query, rbac-audit.md §5): an issue the user cannot read fails as
 *    `NOT_FOUND`, exactly like one that does not exist; one it can read but not triage (a viewer)
 *    fails as `FORBIDDEN`. Only the issues it may triage are locked and changed.
 * 2. The requested issues and their duplicates are locked `FOR NO KEY UPDATE` in one statement,
 *    in id order, together with every Trivy issue of the vulnerability decision pairs they may
 *    write, after those pairs' advisory locks ({@link lockForTransition}); the decisions of step 5
 *    then change only rows held here. Each transition is validated against the status read under
 *    that lock. Two
 *    concurrent transitions of one issue therefore serialise, and the second is judged against
 *    the first one's result (the lost-update guard). The same holds against ingestion in both
 *    directions: a transition waiting on a row ingestion closed or reopened sees the status
 *    ingestion committed, and ingestion's own guard (`status = from_status`) skips a row a
 *    transition changed after ingestion planned it. Ingestion also takes all of its issue row
 *    locks up front in one id-ordered pass (tracking/writes.ts `lockPlannedRows`), so the two
 *    never wait on each other in a cycle: one simply waits for the other to commit. A row an
 *    ingestion holds makes this wait up to `lockTimeoutMs`, then fail with SQLSTATE 55P03 (503
 *    `CONCURRENCY_CONFLICT` with `Retry-After`); nothing is written and a retry is safe. A
 *    transaction that finds a decision pair only once it holds the issues
 *    ({@link DecisionPairsChanged}), or that a deadlock aborts, runs again from the start, up to
 *    three times ({@link withConflictRetry}); then it fails the same way.
 * 3. A duplicate follows its primary only when the same transition is valid from its own status
 *    (ruling I3); otherwise it keeps its status.
 * 4. Every change that took effect writes one `issue_changes` row (user, old, new, comment): the
 *    comment is `options.comments`' entry of the requested issue (a duplicate: of its primary),
 *    else `comment`.
 * 5. (vuln plan 2b, D4): a Trivy issue with a package name on `main` or a tracked branch shares
 *    its pair's vulnerability decision. A false positive of one needs a reason
 *    (`REASON_REQUIRED` otherwise, checked before anything of it is written; a duplicate that
 *    would need one keeps its status). Once every issue has its own status, `open`,
 *    `false_positive` and `wont_fix` write the decision once per pair and scope among the
 *    changed issues: the row of the issue's branch when it has one (ruling R5), else the
 *    project's. It leaves alone the requested issues this request changed, and mirrors those it
 *    could not change (ruling R4). `resolved` writes none.
 * 6. (scm.md §7): the branches of the issues that changed, the decisions' included, get a
 *    re-evaluation of their latest analysis's gate, enqueued once in the same transaction (at
 *    most one waiting per branch), before any audit event is recorded.
 */
export async function transitionIssues(
  access: AccessContext & { db: Db },
  principal: UserPrincipal,
  requested: readonly string[],
  to: UserStatus,
  comment: string | null,
  options: TransitionOptions = {},
): Promise<TransitionResult> {
  const user = principal.user;
  const chargeMirrored = chargeAcrossAttempts(options.chargeMirrored);
  return withConflictRetry(
    () =>
      access.db.transaction(async (tx) => {
        await setLockTimeout(tx, options.lockTimeoutMs ?? TRANSITION_LOCK_TIMEOUT_MS);
        return transitionIssuesIn(tx, user, requested, to, comment, {
          comments: options.comments,
          audit: options.audit,
          reason: options.reason,
          source: options.source,
          chargeMirrored,
        });
      }),
    {
      onRetry: (code, attempt) =>
        options.logger?.debug(
          { component: 'issues', code, attempt },
          'an issue transition conflicted with another transaction; running it again',
        ),
    },
  );
}

/** What a requested issue is checked against (step 3 of {@link transitionIssues}). */
interface TransitionCheck {
  to: UserStatus;
  access: IssueAccess;
  byId: ReadonlyMap<string, LockedIssue>;
  /** A false positive that writes a vulnerability decision without the reason it needs. */
  reasonMissing: (id: string) => boolean;
}

/**
 * A requested issue's refusal, or its locked row when it may change. An issue already changed
 * (as the duplicate of an earlier one) is not refused for its status or a missing reason.
 */
function checkRequested(
  id: string,
  check: TransitionCheck,
  changes: ReadonlyMap<string, IssueStatus>,
): { row: LockedIssue } | { failure: TransitionFailure } {
  if (check.access.forbidden.has(id)) return { failure: { id, code: 'FORBIDDEN' } };
  const row = check.byId.get(id);
  if (!row || !check.access.allowed.has(id)) return { failure: { id, code: 'NOT_FOUND' } };
  if (!changes.has(id) && !transitionAllowed(row.status, check.to)) {
    return { failure: { id, code: 'INVALID_TRANSITION', from: row.status } };
  }
  if (!changes.has(id) && check.reasonMissing(id)) {
    return { failure: { id, code: 'REASON_REQUIRED' } };
  }
  return { row };
}

/**
 * The status changes of a transition, in request order: each allowed requested issue, then its
 * duplicates that may take the transition too, with its comment. Refusals go to `failed`.
 */
function selectChanges(
  ids: readonly string[],
  check: TransitionCheck,
  duplicatesOf: ReadonlyMap<string, LockedIssue[]>,
  commentFor: (id: string) => string | null,
  comment: string | null,
): {
  changes: Map<string, IssueStatus>;
  commentOf: Map<string, string | null>;
  result: TransitionResult;
} {
  const changes = new Map<string, IssueStatus>();
  const commentOf = new Map<string, string | null>();
  const result: TransitionResult = { succeeded: [], failed: [], decisions: [], reevaluate: [] };
  for (const id of ids) {
    const checked = checkRequested(id, check, changes);
    if ('failure' in checked) {
      result.failed.push(checked.failure);
      continue;
    }
    changes.set(id, checked.row.status);
    commentOf.set(id, commentFor(id));
    result.succeeded.push(id);
    for (const duplicate of duplicatesOf.get(id) ?? []) {
      if (
        !changes.has(duplicate.id) &&
        transitionAllowed(duplicate.status, check.to) &&
        !check.reasonMissing(duplicate.id)
      ) {
        changes.set(duplicate.id, duplicate.status);
        commentOf.set(duplicate.id, commentOf.get(id) ?? comment);
      }
    }
  }
  return { changes, commentOf, result };
}

/** What {@link transitionIssuesIn} takes besides the options of {@link transitionIssues}. */
export type TransitionInOptions = Pick<
  TransitionOptions,
  'comments' | 'reason' | 'source' | 'chargeMirrored'
> & {
  /**
   * The caller's {@link lockForTransition} of every issue its transitions change, taken before
   * the first (the status import's two statuses, D2-2): the issues are read again, no pair is.
   */
  locked?: Pick<TransitionLocks, 'deciding' | 'held'>;
} & (
    | { audit?: TransitionAudit; deferReevaluation?: false }
    | {
        audit?: never;
        /**
         * Queue no gate re-evaluation: `TransitionResult.reevaluate` names the issues, and the
         * caller queues them once for all of its transitions (the status import, D2-4), so the
         * branch locks of one batch are taken in one order. Never with `audit`, whose events
         * would precede them.
         */
        deferReevaluation: true;
      }
  );

/**
 * The locks of a transition whose caller took them all before (`first`, {@link lockForTransition}
 * of a superset of `ids`). The held rows of `ids` and their duplicates are read again for the
 * statuses an earlier transition of the transaction set, without a lock (ruling P8: they are
 * held already). Only held rows count: an issue linked as a duplicate since is neither read nor
 * locked, as if linked after the transaction. No pair is read or locked: a pair locked now would
 * follow the issue locks (D2-2).
 */
async function lockedBefore(
  tx: Executor,
  ids: readonly string[],
  first: Pick<TransitionLocks, 'deciding' | 'held'>,
): Promise<TransitionLocks> {
  const locked =
    ids.length === 0
      ? []
      : (
          await tx.execute<LockedIssue>(sql`
            SELECT id, status, duplicate_of_issue_id FROM issues
             WHERE (id IN ${uuidList(ids)} OR duplicate_of_issue_id IN ${uuidList(ids)})
               AND id IN ${uuidList(first.held)}
             ORDER BY id`)
        ).rows;
  return { locked, deciding: first.deciding, held: first.held };
}

/**
 * {@link transitionIssues} inside the caller's transaction, whose lock timeout the caller has set
 * ({@link setLockTimeout}). import-sonarqube.md §11.2 applies both of its statuses in one
 * transaction this way, with `locked`.
 */
export async function transitionIssuesIn(
  tx: Tx,
  user: UserRow,
  requested: readonly string[],
  to: UserStatus,
  comment: string | null,
  options: TransitionInOptions = {},
): Promise<TransitionResult> {
  const { comments } = options;
  const ids = [...new Set(requested)];
  const access = await issueAccess(tx, user, ids);
  const allowed = [...access.allowed.keys()];
  const { locked, deciding, held } = options.locked
    ? await lockedBefore(tx, allowed, options.locked)
    : await lockForTransition(tx, allowed, to !== 'resolved');
  const byId = new Map(locked.map((r) => [r.id, r]));
  const reasonMissing = (id: string) =>
    to === 'false_positive' && options.source !== 'import' && !options.reason && deciding.has(id);
  const duplicatesOf = new Map<string, LockedIssue[]>();
  for (const row of locked) {
    if (row.duplicate_of_issue_id === null) continue;
    const list = duplicatesOf.get(row.duplicate_of_issue_id) ?? [];
    list.push(row);
    duplicatesOf.set(row.duplicate_of_issue_id, list);
  }

  const { changes, commentOf, result } = selectChanges(
    ids,
    { to, access, byId, reasonMissing },
    duplicatesOf,
    (id) => comments?.get(id) ?? comment,
    comment,
  );

  const rows = [...changes].map(([id, from]) => ({ id, from_status: from }));
  const applied = await writeStatus(tx, rows, to, user.id);
  const log = applied
    .sort((a, b) => {
      if (a.id === b.id) return 0;
      return a.id < b.id ? -1 : 1;
    })
    .map((a) => ({
      id: uuidv7(),
      issue_id: a.id,
      old_value: a.old_value,
      comment: commentOf.get(a.id) ?? comment,
    }));
  await writeStatusLog(tx, log, user.id, to);
  if (to !== 'resolved') {
    const changed = new Set(log.map((change) => change.issue_id));
    result.decisions = await writeDecisionsOf(tx, log, deciding, {
      status: to,
      reason: to === 'false_positive' ? (options.reason ?? null) : null,
      userId: user.id,
      source: options.source ?? 'issue',
      // Ruling R4 (amended): a requested issue that could not change is mirrored like any other.
      skipIssueIds: ids.filter((id) => changed.has(id)),
      heldIssueIds: held,
    });
  }
  const mirrored = result.decisions.reduce((sum, d) => sum + d.result.appliedIssueIds.length, 0);
  if (mirrored > 0) options.chargeMirrored?.(mirrored);
  result.reevaluate = [
    ...applied.map((a) => a.id),
    ...result.decisions.flatMap((d) => d.result.appliedIssueIds),
  ];
  if (!options.deferReevaluation) await enqueueReevaluations(tx, result.reevaluate);
  if (options.audit) {
    await recordStatusChanges(tx, options.audit, log, to, result.succeeded);
    for (const { input, result: written } of result.decisions) {
      await recordDecision(tx, options.audit, input, written);
    }
  }
  return result;
}

/**
 * Step 5 of {@link transitionIssues}: one decision per pair and scope among the changed issues
 * that write one, in changelog order, with the comment of the first of them. The scope is the
 * issue's branch when that branch has a row of its own for the pair (ruling R5), else the
 * project. Ruling R4: written after every issue has its own status, so a second requested issue
 * of a pair never fails its status guard on the first's mirror.
 */
async function writeDecisionsOf(
  tx: Tx,
  log: readonly StatusLogRow[],
  deciding: ReadonlyMap<string, DecidingIssue>,
  shared: Pick<
    DecisionInput,
    'status' | 'reason' | 'userId' | 'source' | 'skipIssueIds' | 'heldIssueIds'
  >,
): Promise<WrittenDecision[]> {
  const changed = log.flatMap((change) => {
    const issue = deciding.get(change.issue_id);
    return issue ? [{ ...issue, comment: change.comment }] : [];
  });
  const ownRow = await branchDecisionKeys(tx, changed);
  const settings = await vulnerabilitySettingsOf(tx, [...new Set(changed.map((c) => c.projectId))]);
  const inputs = new Map<string, DecisionInput>();
  for (const issue of changed) {
    const atBranch = ownRow.has(
      JSON.stringify([issue.branchId, issue.packageName, issue.vulnerabilityId]),
    );
    const key = JSON.stringify([
      issue.projectId,
      issue.packageName,
      issue.vulnerabilityId,
      atBranch ? issue.branchId : null,
    ]);
    if (inputs.has(key)) continue;
    inputs.set(key, {
      ...shared,
      settings: settings.get(issue.projectId),
      projectId: issue.projectId,
      packageName: issue.packageName,
      vulnerabilityId: issue.vulnerabilityId,
      scope: atBranch ? { kind: 'branch', id: issue.branchId } : { kind: 'project' },
      comment: issue.comment,
    });
  }
  const written: WrittenDecision[] = [];
  for (const input of inputs.values()) {
    written.push({ input, result: await writeDecision(tx, input) });
  }
  return written;
}

/**
 * Sets `to` on the issue `issueId` as the system (6I-4: a person replied in Qualor's thread of an
 * AI finding, and the reply decided its status), in the caller's transaction. Nobody's permission
 * is checked and no user is named: `comment` says who replied. The issue is locked as every
 * transition locks it ({@link lockIssues}) and changes only from `open`: it is resolved now, by
 * nobody, with one `issue_changes` row of no user, the re-evaluation of its branch's gate queued
 * (which decorates its merge request again), and, with `audit`, one `issue.status_changed` by the
 * actor the caller gives (the system), in the details' shape a person's transition has. Duplicates
 * do not follow it: the AI findings it is for have none (tracking never dedupes them). Answers
 * whether it changed the issue.
 */
export async function transitionAsSystem(
  tx: Tx,
  issueId: string,
  to: 'wont_fix' | 'false_positive',
  comment: string,
  audit?: { recorder: AuditRecorder; context: AuditActorContext },
): Promise<boolean> {
  const locked = (await lockIssues(tx, [issueId])).find((row) => row.id === issueId);
  if (locked?.status !== 'open') return false;
  const applied = await writeStatus(tx, [{ id: issueId, from_status: 'open' }], to, null);
  if (applied.length === 0) return false;
  const log: StatusLogRow[] = [{ id: uuidv7(), issue_id: issueId, old_value: 'open', comment }];
  await writeStatusLog(tx, log, null, to);
  await enqueueReevaluations(tx, [issueId]);
  if (audit) {
    await recordStatusChanges(tx, { ...audit, bulk: false, suggestionId: null }, log, to, [
      issueId,
    ]);
  }
  return true;
}

/**
 * The `issue_changes` rows this transition wrote are the source of truth for what changed: one
 * event each, in the same order, so an issue the lost-update guard skipped has none. An issue that
 * was not itself requested (and succeeded) followed its primary: `mirrored`. The comment's text
 * stays in `issue_changes` (rbac-audit.md §8).
 */
async function recordStatusChanges(
  tx: Tx,
  audit: TransitionAudit,
  log: readonly StatusLogRow[],
  to: UserStatus,
  succeeded: readonly string[],
): Promise<void> {
  if (log.length === 0 || !audit.recorder.active()) return;
  const projectOf = new Map(
    (
      await tx.execute<{ id: string; project_id: string }>(sql`
        SELECT id, project_id FROM issues WHERE id IN ${uuidList(log.map((l) => l.issue_id))}`)
    ).rows.map((r) => [r.id, r.project_id]),
  );
  const refs = new Map<string, { project: AuditRef; organization: AuditRef | null }>();
  for (const projectId of new Set(projectOf.values())) {
    refs.set(projectId, await projectRefs(tx, projectId));
  }
  const requested = new Set(succeeded);
  const events: AuditEventInput[] = log.map((change) => {
    const projectId = projectOf.get(change.issue_id);
    const ref = projectId === undefined ? undefined : refs.get(projectId);
    return {
      action: 'issue.status_changed',
      organization: ref?.organization ?? null,
      project: ref?.project ?? null,
      target: { type: 'issue', id: change.issue_id, label: null },
      details: {
        from: change.old_value,
        to,
        bulk: audit.bulk,
        mirrored: !requested.has(change.issue_id),
        commented: change.comment !== null,
        suggestionId: audit.suggestionId,
        ...(audit.mcpClientId ? { mcpClientId: audit.mcpClientId } : {}),
      },
    };
  });
  await audit.recorder.record(tx, audit.context, events);
}

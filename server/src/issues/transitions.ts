import { sql } from 'drizzle-orm';
import type { AuditActorContext, AuditEventInput, AuditRecorder } from '../audit/recorder';
import { projectRefs, type AuditRef } from '../audit/refs';
import type { AccessContext } from '../auth/access';
import { projectFacts } from '../auth/facts';
import { projectPermissions } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import type { UserRow } from '../auth/sessions';
import { jsonChunks, uuidList } from '../db/bulk';
import type { Db, Executor, Tx } from '../db/client';
import { uuidv7 } from '../db/ids';
import type { OrganizationRole, ProjectRole } from '../db/schema';
import { enqueueReevaluations } from '../gates/reevaluate';
import type { IssueStatus } from '../tracking/plan';

/** data-model.md §6: the statuses a user may set; only the system sets `closed`. */
export const USER_STATUSES = ['open', 'resolved', 'wont_fix', 'false_positive'] as const;
export type UserStatus = (typeof USER_STATUSES)[number];

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
  await tx.execute(sql`SELECT set_config('lock_timeout', ${`${ms}ms`}, true)`);
}

export interface TransitionFailure {
  id: string;
  /**
   * NOT_FOUND: the issue does not exist or the caller cannot read it; FORBIDDEN: it can read it
   * but its role does not allow triage (rbac-audit.md §5, a viewer).
   */
  code: 'NOT_FOUND' | 'FORBIDDEN' | 'INVALID_TRANSITION';
  /** The status the issue has (INVALID_TRANSITION only). */
  from?: IssueStatus;
}

export interface TransitionResult {
  /** Requested ids whose status changed, in request order (mirrored duplicates not listed). */
  succeeded: string[];
  failed: TransitionFailure[];
}

export type LockedIssue = {
  id: string;
  status: IssueStatus;
  duplicate_of_issue_id: string | null;
};

/**
 * Locks `ids` and their duplicates `FOR NO KEY UPDATE` in one statement, in id order (step 2
 * below): the one lock order every transition and ingestion (tracking/writes.ts
 * `lockPlannedRows`) follows, so none of them wait on each other in a cycle. Taking a lock again
 * later in the same transaction is free, so a caller that runs several transitions in one
 * transaction locks all of their issues here first.
 */
export async function lockIssues(tx: Executor, ids: readonly string[]): Promise<LockedIssue[]> {
  if (ids.length === 0) return [];
  return (
    await tx.execute<LockedIssue>(sql`
      SELECT id, status, duplicate_of_issue_id FROM issues
       WHERE id IN ${uuidList(ids)}
          OR duplicate_of_issue_id IN ${uuidList(ids)}
       ORDER BY id
         FOR NO KEY UPDATE`)
  ).rows;
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
}

export interface TransitionOptions {
  lockTimeoutMs?: number;
  /** A requested issue's own changelog comment (instead of `comment`); its mirrored duplicates get the same one. */
  comments?: ReadonlyMap<string, string>;
  /** Absent: nothing is recorded (the status import records one summary event itself). */
  audit?: TransitionAudit;
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
 *    in id order, and each transition is validated against the status read under that lock. Two
 *    concurrent transitions of one issue therefore serialise, and the second is judged against
 *    the first one's result (the lost-update guard). The same holds against ingestion in both
 *    directions: a transition waiting on a row ingestion closed or reopened sees the status
 *    ingestion committed, and ingestion's own guard (`status = from_status`) skips a row a
 *    transition changed after ingestion planned it. Ingestion also takes all of its issue row
 *    locks up front in one id-ordered pass (tracking/writes.ts `lockPlannedRows`), so the two
 *    never wait on each other in a cycle: one simply waits for the other to commit. A row an
 *    ingestion holds makes this wait up to `lockTimeoutMs`, then fail with SQLSTATE 55P03 (503
 *    `CONCURRENCY_CONFLICT` with `Retry-After`); nothing is written and a retry is safe.
 * 3. A duplicate follows its primary only when the same transition is valid from its own status
 *    (ruling I3); otherwise it keeps its status.
 * 4. Every change that took effect writes one `issue_changes` row (user, old, new, comment): the
 *    comment is `options.comments`' entry of the requested issue (a duplicate: of its primary),
 *    else `comment`.
 * 5. (scm.md §7): the branches of the issues that changed get a re-evaluation of their
 *    latest analysis's gate, enqueued in the same transaction (at most one waiting per branch).
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
  return access.db.transaction(async (tx) => {
    await setLockTimeout(tx, options.lockTimeoutMs ?? TRANSITION_LOCK_TIMEOUT_MS);
    return transitionIssuesIn(tx, user, requested, to, comment, {
      comments: options.comments,
      audit: options.audit,
    });
  });
}

/**
 * {@link transitionIssues} inside the caller's transaction, whose lock timeout the caller has set
 * ({@link setLockTimeout}). import-sonarqube.md §11.2 applies both of its statuses in one
 * transaction this way.
 */
export async function transitionIssuesIn(
  tx: Tx,
  user: UserRow,
  requested: readonly string[],
  to: UserStatus,
  comment: string | null,
  options: Pick<TransitionOptions, 'comments' | 'audit'> = {},
): Promise<TransitionResult> {
  const { comments } = options;
  const ids = [...new Set(requested)];
  const { allowed, forbidden } = await issueAccess(tx, user, ids);
  const locked = await lockIssues(tx, [...allowed.keys()]);
  const byId = new Map(locked.map((r) => [r.id, r]));
  const duplicatesOf = new Map<string, LockedIssue[]>();
  for (const row of locked) {
    if (row.duplicate_of_issue_id === null) continue;
    const list = duplicatesOf.get(row.duplicate_of_issue_id) ?? [];
    list.push(row);
    duplicatesOf.set(row.duplicate_of_issue_id, list);
  }

  const changes = new Map<string, IssueStatus>();
  const commentOf = new Map<string, string | null>();
  const result: TransitionResult = { succeeded: [], failed: [] };
  for (const id of ids) {
    if (forbidden.has(id)) {
      result.failed.push({ id, code: 'FORBIDDEN' });
      continue;
    }
    const row = byId.get(id);
    if (!row || !allowed.has(id)) {
      result.failed.push({ id, code: 'NOT_FOUND' });
      continue;
    }
    if (!changes.has(id) && !transitionAllowed(row.status, to)) {
      result.failed.push({ id, code: 'INVALID_TRANSITION', from: row.status });
      continue;
    }
    changes.set(id, row.status);
    commentOf.set(id, comments?.get(id) ?? comment);
    result.succeeded.push(id);
    for (const duplicate of duplicatesOf.get(id) ?? []) {
      if (!changes.has(duplicate.id) && transitionAllowed(duplicate.status, to)) {
        changes.set(duplicate.id, duplicate.status);
        commentOf.set(duplicate.id, commentOf.get(id) ?? comment);
      }
    }
  }

  const rows = [...changes].map(([id, from]) => ({ id, from_status: from }));
  const resolving = to !== 'open';
  const applied: { id: string; old_value: string }[] = [];
  for (const chunk of jsonChunks(rows)) {
    const updated = await tx.execute<{ id: string; old_value: string }>(sql`
      UPDATE issues AS i SET status = ${to},
        resolved_at = ${resolving ? sql`now()` : sql`NULL`},
        resolved_by = ${resolving ? user.id : null}::uuid,
        updated_at = now()
      FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, from_status text)
      WHERE i.id = r.id AND i.status = r.from_status
      RETURNING i.id, r.from_status AS old_value`);
    applied.push(...updated.rows);
  }
  const log = applied
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((a) => ({
      id: uuidv7(),
      issue_id: a.id,
      old_value: a.old_value,
      comment: commentOf.get(a.id) ?? comment,
    }));
  for (const chunk of jsonChunks(log)) {
    await tx.execute(sql`
      INSERT INTO issue_changes (id, issue_id, user_id, field, old_value, new_value, comment)
      SELECT r.id, r.issue_id, ${user.id}, 'status', r.old_value, ${to}, r.comment
        FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, issue_id uuid, old_value text, comment text)`);
  }
  await enqueueReevaluations(
    tx,
    applied.map((a) => a.id),
  );
  if (options.audit) await recordStatusChanges(tx, options.audit, log, to, result.succeeded);
  return result;
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
  log: readonly { issue_id: string; old_value: string; comment: string | null }[],
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
      },
    };
  });
  await audit.recorder.record(tx, audit.context, events);
}

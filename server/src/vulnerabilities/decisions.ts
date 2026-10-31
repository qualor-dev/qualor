import { and, eq, isNull, or, sql, type SQL } from 'drizzle-orm';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import { uuidv7 } from '../db/ids';
import { vulnerabilityDecisions } from '../db/schema';
import { enqueueReevaluations } from '../gates/reevaluate';
import { writeStatus, writeStatusLog, type StatusLogRow } from '../issues/transitions';
import { isTrackedBranch, vulnerabilitySettings } from '../versions/settings';

/** The CycloneDX VEX justifications a "false positive" decision may name (spec §10). */
export const VEX_JUSTIFICATIONS = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
] as const;
export type VexJustification = (typeof VEX_JUSTIFICATIONS)[number];

export const DECISION_STATUSES = ['open', 'false_positive', 'wont_fix'] as const;
export type DecisionStatus = (typeof DECISION_STATUSES)[number];

export type TargetScope = { kind: 'branch' | 'version'; id: string };
export type DecisionScope = { kind: 'project' } | TargetScope;

export interface DecisionInput {
  projectId: string;
  packageName: string;
  vulnerabilityId: string;
  scope: DecisionScope;
  status: DecisionStatus;
  reason: VexJustification | null;
  comment: string | null;
  userId: string | null;
  source: 'tab' | 'issue' | 'import';
  /** A project-wide write only: the override of this target is removed in the same transaction. */
  replaceOverrideOf?: TargetScope;
  /** The issues the caller changes itself, so the decision leaves them alone. */
  skipIssueIds?: readonly string[];
  /**
   * Set by a transition, which already holds these issues locked (the pair's issues among them)
   * and queues the gate re-evaluations itself, once: the decision changes only these issues,
   * takes no new issue lock and queues nothing (the caller queues `appliedIssueIds`). Without it,
   * the decision locks the pair's issues itself, in one id-ordered statement, and queues them.
   */
  heldIssueIds?: readonly string[];
}

/** A (project, package, vulnerability) whose decisions one writer at a time changes. */
export interface DecisionPair {
  projectId: string;
  packageName: string;
  vulnerabilityId: string;
}

export type DecisionRow = typeof vulnerabilityDecisions.$inferSelect;

export interface DecisionResult {
  decision: DecisionRow;
  previous: DecisionRow | null;
  appliedIssueIds: string[];
  /** The target whose override `replaceOverrideOf` deleted; null when there was none. */
  overrideRemoved?: TargetScope | null;
}

/** Where the event of a decision is recorded (the caller's recorder and the acting person). */
export interface DecisionAudit {
  recorder: AuditRecorder;
  context: AuditActorContext;
  /** The OAuth client of an MCP call (Phase 6N, ruling R8), as `issue.status_changed` has it. */
  mcpClientId?: string | null;
}

type Candidate = {
  id: string;
  status: DecisionStatus;
  name: string;
  is_main: boolean;
  kind: string;
};

/**
 * Writes the decision of `input.scope` (one row per scope and pair) and applies it to the Trivy
 * issues of the pair (D4), in the caller's transaction:
 *
 * - On `main` and the tracked branches the issues mirror the decision: any of open, false
 *   positive and won't fix becomes its status.
 * - On every other branch and merge request a decision that is not Open changes only open
 *   issues, so local triage there stays local.
 * - `resolved` and `closed` issues never change. A project-wide write skips each branch that has
 *   a row of its own for the pair. A version decision touches no issue.
 *
 * Decisions ignore the monitoring switches (D5). Each changed issue gets its `issue_changes` row
 * and its branch's gate is evaluated again. With `audit`, one `vulnerability.decision_changed`
 * event is recorded.
 *
 * Locks, in this order: the pair ({@link lockDecisionPairs}, free when the caller holds it), the
 * decision row, then the pair's issues in one id-ordered `FOR NO KEY UPDATE` statement. A
 * transition passes `heldIssueIds` instead: it took the pair and every issue it may change before
 * it changed anything (issues/transitions.ts `lockForTransition`). An ingestion holds the pair's
 * lock shared from before it reads the decisions to its commit (tracking/stage.ts), so the
 * issues it creates are committed before this reads the pair's issues, or created with this
 * decision.
 */
export async function writeDecision(
  tx: Executor,
  input: DecisionInput,
  audit?: DecisionAudit,
): Promise<DecisionResult> {
  const { projectId, packageName, vulnerabilityId, scope } = input;
  await lockDecisionPairs(tx, [input]);
  if (input.replaceOverrideOf && scope.kind !== 'project') {
    throw new Error('replaceOverrideOf needs a project-wide decision');
  }
  let overrideRemoved: TargetScope | null = null;
  if (input.replaceOverrideOf) {
    const deleted = await tx
      .delete(vulnerabilityDecisions)
      .where(
        and(
          eq(vulnerabilityDecisions.projectId, projectId),
          eq(vulnerabilityDecisions.packageName, packageName),
          eq(vulnerabilityDecisions.vulnerabilityId, vulnerabilityId),
          input.replaceOverrideOf.kind === 'branch'
            ? eq(vulnerabilityDecisions.branchId, input.replaceOverrideOf.id)
            : eq(vulnerabilityDecisions.versionId, input.replaceOverrideOf.id),
        ),
      )
      .returning({ id: vulnerabilityDecisions.id });
    if (deleted.length > 0) overrideRemoved = input.replaceOverrideOf;
  }

  const previous = (await rowOfScope(tx, input)) ?? null;
  const values = {
    id: uuidv7(),
    projectId,
    packageName,
    vulnerabilityId,
    branchId: scope.kind === 'branch' ? scope.id : null,
    versionId: scope.kind === 'version' ? scope.id : null,
    status: input.status,
    reason: input.reason,
    comment: input.comment,
    decidedBy: input.userId,
    decidedAt: sql`now()`,
  };
  const set = {
    status: input.status,
    reason: input.reason,
    comment: input.comment,
    decidedBy: input.userId,
    decidedAt: sql`now()`,
  };
  const insert = tx.insert(vulnerabilityDecisions).values(values);
  const upsert =
    scope.kind === 'project'
      ? insert.onConflictDoUpdate({
          target: [
            vulnerabilityDecisions.projectId,
            vulnerabilityDecisions.packageName,
            vulnerabilityDecisions.vulnerabilityId,
          ],
          targetWhere: sql`branch_id IS NULL AND version_id IS NULL`,
          set,
        })
      : scope.kind === 'branch'
        ? insert.onConflictDoUpdate({
            target: [
              vulnerabilityDecisions.branchId,
              vulnerabilityDecisions.packageName,
              vulnerabilityDecisions.vulnerabilityId,
            ],
            targetWhere: sql`branch_id IS NOT NULL`,
            set,
          })
        : insert.onConflictDoUpdate({
            target: [
              vulnerabilityDecisions.versionId,
              vulnerabilityDecisions.packageName,
              vulnerabilityDecisions.vulnerabilityId,
            ],
            targetWhere: sql`version_id IS NOT NULL`,
            set,
          });
  const decision = first(await upsert.returning());

  const appliedIssueIds = scope.kind === 'version' ? [] : await applyToIssues(tx, input);
  if (!input.heldIssueIds) await enqueueReevaluations(tx, appliedIssueIds);

  const result = { decision, previous, appliedIssueIds, overrideRemoved };
  if (audit) await recordDecision(tx, audit, input, result);
  return result;
}

/**
 * The `vulnerability.decision_changed` event of a decision {@link writeDecision} wrote. A
 * transition records it itself, after it queued its gate re-evaluations, so no re-evaluation lock
 * is ever taken after the audit chain's. It names the override the write removed (final review
 * F8), and the MCP client of an agent's change.
 */
export async function recordDecision(
  tx: Executor,
  audit: DecisionAudit,
  input: DecisionInput,
  { decision, previous, appliedIssueIds, overrideRemoved }: DecisionResult,
): Promise<void> {
  if (!audit.recorder.active()) return;
  const { scope } = input;
  const refs = await projectRefs(tx, input.projectId);
  await audit.recorder.record(tx, audit.context, [
    {
      action: 'vulnerability.decision_changed',
      organization: refs.organization,
      project: refs.project,
      target: { type: 'vulnerability_decision', id: decision.id, label: null },
      details: {
        packageName: input.packageName,
        vulnerabilityId: input.vulnerabilityId,
        scope: scope.kind,
        targetId: scope.kind === 'project' ? null : scope.id,
        from: previous?.status ?? null,
        to: input.status,
        reason: input.reason,
        commented: input.comment !== null,
        appliedIssues: appliedIssueIds.length,
        source: input.source,
        ...(overrideRemoved && {
          overrideRemoved: true,
          removedScope: overrideRemoved.kind,
          removedTargetId: overrideRemoved.id,
        }),
        ...(audit.mcpClientId ? { mcpClientId: audit.mcpClientId } : {}),
      },
    },
  ]);
}

/**
 * The pair locks of one project are this many buckets: a transaction takes at most this many
 * locks per project, however many pairs a report names, so an ingestion of thousands of Trivy
 * findings never fills the server's shared lock table.
 */
export const PAIR_LOCK_BUCKETS = 1024;

/**
 * The bucket of a pair within its project: FNV-1a over its package name and vulnerability id,
 * then murmur3's finaliser, which carries every bit into the low ones the bucket keeps (FNV-1a's
 * lowest bit alone is a parity of the characters).
 */
export function pairBucket(pair: DecisionPair): number {
  const key = JSON.stringify([pair.packageName, pair.vulnerabilityId]);
  let hash = 0x811c9dc5;
  for (let i = 0; i < key.length; i += 1) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  hash ^= hash >>> 16;
  hash = Math.imul(hash, 0x85ebca6b);
  hash ^= hash >>> 13;
  hash = Math.imul(hash, 0xc2b2ae35);
  hash ^= hash >>> 16;
  return (hash >>> 0) % PAIR_LOCK_BUCKETS;
}

/**
 * Takes the advisory lock of each pair ({@link LOCKS.vulnerabilityDecision}) in one statement, in
 * ascending key order, so no two takers of overlapping pairs wait on each other in a cycle. The
 * second key is `hashtext(<project id>:<bucket>)` ({@link pairBucket}), so pairs of one bucket
 * share a lock.
 *
 * - `exclusive` (every writer of a decision): taken before any issue or decision row.
 * - `shared` (ingestion, tracking/stage.ts): taken before the decisions are read and before any
 *   issue is locked, so an ingestion and a writer of one pair run one after the other, and
 *   ingestions never wait on each other.
 *
 * Taking a lock again in the same transaction is free.
 */
export async function lockDecisionPairs(
  tx: Executor,
  pairs: readonly DecisionPair[],
  mode: 'exclusive' | 'shared' = 'exclusive',
): Promise<void> {
  if (pairs.length === 0) return;
  const buckets = new Map<string, { p: string; b: number }>();
  for (const pair of pairs) {
    const b = pairBucket(pair);
    buckets.set(`${pair.projectId}:${b}`, { p: pair.projectId, b });
  }
  const lock = sql.raw(
    mode === 'shared' ? 'pg_advisory_xact_lock_shared' : 'pg_advisory_xact_lock',
  );
  // The subquery (DISTINCT, ORDER BY) is never pulled up, so the locks follow its order.
  await tx.execute(sql`
    SELECT ${lock}(${LOCKS.vulnerabilityDecision}, s.key)
      FROM (SELECT DISTINCT hashtext(r.p || ':' || r.b::text) AS key
              FROM jsonb_to_recordset(${JSON.stringify([...buckets.values()])}::jsonb)
                AS r(p text, b integer)
             ORDER BY key) AS s`);
}

/**
 * Every Trivy issue of the pairs, whatever its branch and status: the issues a decision of one
 * may change, which a transition locks with its own before it changes anything.
 */
export async function pairIssueIds(
  db: Executor,
  pairs: readonly DecisionPair[],
): Promise<string[]> {
  if (pairs.length === 0) return [];
  const rows = await db.execute<{ id: string }>(sql`
    SELECT i.id
      FROM jsonb_to_recordset(${JSON.stringify(
        pairs.map((p) => ({
          project_id: p.projectId,
          package_name: p.packageName,
          vulnerability_id: p.vulnerabilityId,
        })),
      )}::jsonb) AS p(project_id uuid, package_name text, vulnerability_id text)
      JOIN issues i ON i.project_id = p.project_id AND i.package_name = p.package_name
      JOIN rules r ON r.id = i.rule_id
     WHERE r.engine_id = 'trivy' AND r.engine_rule_id = p.vulnerability_id`);
  return rows.rows.map((r) => r.id);
}

/**
 * Of the (branch, pair)s, those whose branch has a decision row of its own (ruling R5: a
 * transition there updates that row), as `JSON.stringify([branchId, packageName, vulnerabilityId])`.
 */
export async function branchDecisionKeys(
  db: Executor,
  at: readonly { branchId: string; packageName: string; vulnerabilityId: string }[],
): Promise<Set<string>> {
  if (at.length === 0) return new Set();
  const rows = await db.execute<{
    branch_id: string;
    package_name: string;
    vulnerability_id: string;
  }>(sql`
    SELECT d.branch_id, d.package_name, d.vulnerability_id
      FROM jsonb_to_recordset(${JSON.stringify(
        at.map((a) => ({
          branch_id: a.branchId,
          package_name: a.packageName,
          vulnerability_id: a.vulnerabilityId,
        })),
      )}::jsonb) AS p(branch_id uuid, package_name text, vulnerability_id text)
      JOIN vulnerability_decisions d ON d.branch_id = p.branch_id
       AND d.package_name = p.package_name AND d.vulnerability_id = p.vulnerability_id`);
  return new Set(
    rows.rows.map((r) => JSON.stringify([r.branch_id, r.package_name, r.vulnerability_id])),
  );
}

/** The row of the input's own scope and pair, locked, else undefined. */
async function rowOfScope(tx: Executor, input: DecisionInput): Promise<DecisionRow | undefined> {
  const { scope } = input;
  const [row] = await tx
    .select()
    .from(vulnerabilityDecisions)
    .where(
      and(
        eq(vulnerabilityDecisions.projectId, input.projectId),
        eq(vulnerabilityDecisions.packageName, input.packageName),
        eq(vulnerabilityDecisions.vulnerabilityId, input.vulnerabilityId),
        scope.kind === 'project'
          ? and(isNull(vulnerabilityDecisions.branchId), isNull(vulnerabilityDecisions.versionId))
          : scope.kind === 'branch'
            ? eq(vulnerabilityDecisions.branchId, scope.id)
            : eq(vulnerabilityDecisions.versionId, scope.id),
      ),
    )
    .for('update');
  return row;
}

/** D4: the status change of the decision on the Trivy issues of the pair. Answers the changed ids. */
async function applyToIssues(tx: Executor, input: DecisionInput): Promise<string[]> {
  const { projectId, packageName, vulnerabilityId, scope } = input;
  const candidates = await tx.execute<Candidate>(sql`
    SELECT i.id, i.status, b.name, b.is_main, b.kind
      FROM issues i
      JOIN rules r ON r.id = i.rule_id
      JOIN branches b ON b.id = i.branch_id
     WHERE i.project_id = ${projectId}
       AND r.engine_id = 'trivy' AND r.engine_rule_id = ${vulnerabilityId}
       AND i.package_name = ${packageName}
       AND i.status IN ('open', 'false_positive', 'wont_fix')
       ${input.skipIssueIds?.length ? sql`AND i.id NOT IN ${uuidList(input.skipIssueIds)}` : sql``}
       ${input.heldIssueIds ? sql`AND i.id IN ${uuidList(input.heldIssueIds)}` : sql``}
       ${scope.kind === 'branch' ? sql`AND b.id = ${scope.id}` : sql``}
       ${
         scope.kind === 'project'
           ? sql`AND NOT EXISTS (
               SELECT 1 FROM vulnerability_decisions d
                WHERE d.branch_id = b.id AND d.package_name = ${packageName}
                  AND d.vulnerability_id = ${vulnerabilityId})`
           : sql``
       }
     ORDER BY i.id
       FOR NO KEY UPDATE OF i`);
  if (candidates.rows.length === 0) return [];

  const settings = await vulnerabilitySettings(tx, projectId);
  const changing = candidates.rows.filter((row) => {
    if (row.status === input.status) return false;
    const mirrored = isTrackedBranch(settings, {
      name: row.name,
      isMain: row.is_main,
      kind: row.kind,
    });
    return mirrored || row.status === 'open';
  });
  if (changing.length === 0) return [];

  const applied = await writeStatus(
    tx,
    changing.map((row) => ({ id: row.id, from_status: row.status })),
    input.status,
    input.userId,
  );
  const log: StatusLogRow[] = applied.map((row) => ({
    id: uuidv7(),
    issue_id: row.id,
    old_value: row.old_value,
    comment: input.comment,
  }));
  await writeStatusLog(tx, log, input.userId, input.status);
  return applied.map((row) => row.id);
}

/**
 * The `LEFT JOIN LATERAL` that picks the decision in force for a row of `target_vulnerabilities`
 * (named `row`): the one of its own branch or version, else the project's.
 */
export function effectiveDecisionJoin(row: string, alias: string): SQL {
  const name = /^[a-z_][a-z0-9_]*$/;
  if (!name.test(row) || !name.test(alias)) throw new Error('effectiveDecisionJoin: bad name');
  return sql.raw(`LEFT JOIN LATERAL (
    SELECT d.* FROM vulnerability_decisions d
     WHERE d.project_id = ${row}.project_id
       AND d.package_name = ${row}.package_name
       AND d.vulnerability_id = ${row}.vulnerability_id
       AND (d.branch_id = ${row}.branch_id OR d.version_id = ${row}.version_id
            OR (d.branch_id IS NULL AND d.version_id IS NULL))
     ORDER BY (d.branch_id IS NULL AND d.version_id IS NULL)
     LIMIT 1) AS ${alias} ON true`);
}

/** The decision in force at a target (a branch or a version, or none for the project itself). */
export async function effectiveDecision(
  db: Executor,
  at: {
    projectId: string;
    branchId: string | null;
    versionId: string | null;
    packageName: string;
    vulnerabilityId: string;
  },
): Promise<DecisionRow | null> {
  const own = [
    at.branchId ? eq(vulnerabilityDecisions.branchId, at.branchId) : undefined,
    at.versionId ? eq(vulnerabilityDecisions.versionId, at.versionId) : undefined,
    and(isNull(vulnerabilityDecisions.branchId), isNull(vulnerabilityDecisions.versionId)),
  ];
  const [row] = await db
    .select()
    .from(vulnerabilityDecisions)
    .where(
      and(
        eq(vulnerabilityDecisions.projectId, at.projectId),
        eq(vulnerabilityDecisions.packageName, at.packageName),
        eq(vulnerabilityDecisions.vulnerabilityId, at.vulnerabilityId),
        or(...own),
      ),
    )
    .orderBy(sql`(branch_id IS NULL AND version_id IS NULL)`)
    .limit(1);
  return row ?? null;
}

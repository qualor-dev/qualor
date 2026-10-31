import { and, eq, isNull, or, sql, type SQL } from 'drizzle-orm';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import type { Executor } from '../db/client';
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
  /** The issue the caller changes itself, so the decision leaves it alone. */
  skipIssueId?: string;
}

export type DecisionRow = typeof vulnerabilityDecisions.$inferSelect;

/** Where the event of a decision is recorded (the caller's recorder and the acting person). */
export interface DecisionAudit {
  recorder: AuditRecorder;
  context: AuditActorContext;
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
 */
export async function writeDecision(
  tx: Executor,
  input: DecisionInput,
  audit?: DecisionAudit,
): Promise<{ decision: DecisionRow; previous: DecisionRow | null; appliedIssueIds: string[] }> {
  const { projectId, packageName, vulnerabilityId, scope } = input;
  if (input.replaceOverrideOf && scope.kind !== 'project') {
    throw new Error('replaceOverrideOf needs a project-wide decision');
  }
  if (input.replaceOverrideOf) {
    await tx
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
      );
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
  await enqueueReevaluations(tx, appliedIssueIds);

  if (audit?.recorder.active()) {
    const refs = await projectRefs(tx, projectId);
    await audit.recorder.record(tx, audit.context, [
      {
        action: 'vulnerability.decision_changed',
        organization: refs.organization,
        project: refs.project,
        target: { type: 'project', id: projectId, label: null },
        details: {
          packageName,
          vulnerabilityId,
          scope: scope.kind,
          targetId: scope.kind === 'project' ? null : scope.id,
          from: previous?.status ?? null,
          to: input.status,
          reason: input.reason,
          commented: input.comment !== null,
          appliedIssues: appliedIssueIds.length,
          source: input.source,
        },
      },
    ]);
  }
  return { decision, previous, appliedIssueIds };
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
       ${input.skipIssueId ? sql`AND i.id <> ${input.skipIssueId}` : sql``}
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
       FOR UPDATE OF i`);
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

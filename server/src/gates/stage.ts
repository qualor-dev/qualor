import {
  DEFAULT_SMALL_CHANGESET_LINES,
  evaluateGate,
  resolveMetricKey,
  type BranchKind,
  type Gate,
  type GateCondition,
} from '@qualor/shared';
import { eq, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Executor } from '../db/client';
import { analyses } from '../db/schema';
import type { IngestionStage } from '../ingest/process';
import { requireState } from '../ingest/state';
import type { ProjectRow } from '../projects/access';
import { instanceSetting } from '../settings';

/** gates.md §6 rule 3: "The threshold is instance-configurable, and 0 disables it." (ruling G6) */
export const SMALL_CHANGESET_SETTING = 'gate.smallChangesetLines';

/** Report warnings (from the CLI) that belong on the gate result, so the UI shows them there. */
export const GATE_WARNING_CODES: ReadonlySet<string> = new Set([
  'NEW_CODE_DEFINITION_FALLBACK',
  'NEW_CODE_BASELINE_MISSING',
  'BASELINE_ENDPOINT_UNAVAILABLE',
]);

/**
 * The project's gate (`projects.quality_gate_id`), else its organisation's default, with its
 * conditions; null when neither exists (gates.md §6 rule 1: the result is `none`).
 *
 * One statement, so one snapshot: the project's current `quality_gate_id` (re-read here, because
 * the `project` row was loaded before the ingestion transaction began and a gate deleted since
 * then has set it to NULL), the gate it names if that gate still exists in the project's
 * organisation, else the organisation's default, and that gate's conditions. A concurrent
 * delete, rename, condition change or set-default is either wholly visible or not at all, so the
 * result is always a gate that existed at one instant (never `none` because a default moved
 * mid-read). No row is locked: the read never waits on, or blocks, gate administration.
 * Conditions come ordered by metric key (unique per gate), so the result is deterministic.
 */
export async function effectiveGate(tx: Executor, project: ProjectRow): Promise<Gate | null> {
  const result = await tx.execute<{ id: string; name: string; conditions: GateCondition[] }>(sql`
    WITH target AS (SELECT quality_gate_id AS id FROM projects WHERE id = ${project.id})
    SELECT g.id, g.name,
           COALESCE(
             (SELECT json_agg(
                       json_build_object(
                         'metric', c.metric_key, 'operator', c.operator, 'threshold', c.threshold)
                       ORDER BY c.metric_key)
                FROM gate_conditions c
               WHERE c.gate_id = g.id),
             '[]'::json) AS conditions
      FROM quality_gates g
     WHERE g.organization_id = ${project.organizationId}
       AND (g.is_default OR g.id = (SELECT id FROM target))
     -- The project's own gate first; at most one default exists (quality_gates_one_default).
     ORDER BY (g.id = (SELECT id FROM target)) DESC NULLS LAST
     LIMIT 1`);
  const [gate] = result.rows;
  return gate ? { id: gate.id, name: gate.name, conditions: gate.conditions } : null;
}

/**
 * Server step 11: evaluates the quality gate with the pure `evaluateGate` of @qualor/shared on
 * the measures the measures stage computed, stores `gate_status`/`gate_result` on the analysis,
 * and leaves the result in `ctx.state.gate` — the hook for `analysis.completed` and
 * `gate.status_changed` webhooks (server step 13: a stage appended after this one, comparing it
 * with `ctx.previousAnalysis?.gateStatus`).
 */
export const gateStage: IngestionStage = {
  name: 'gate',
  async run(ctx) {
    const measures = requireState(ctx.state, 'measures');
    const gate = await effectiveGate(ctx.tx, ctx.project);
    // Each code once, in first-seen order: a report may repeat a warning.
    const warnings = [
      ...new Set(ctx.report.warnings.map((w) => w.code).filter((c) => GATE_WARNING_CODES.has(c))),
    ];
    // Ruling G5: a condition on a metric the catalog no longer has is skipped, not fatal (gates
    // are validated on write, so this only happens after a catalog change).
    let known: Gate | null = null;
    if (gate) {
      known = {
        ...gate,
        conditions: gate.conditions.filter((c) => resolveMetricKey(c.metric) !== undefined),
      };
      if (known.conditions.length < gate.conditions.length) {
        warnings.push('GATE_CONDITION_UNKNOWN_METRIC');
      }
    }
    const branchKind: BranchKind = ctx.branch.isMain
      ? 'main'
      : ctx.branch.kind === 'merge_request'
        ? 'merge_request'
        : 'branch';
    const result = evaluateGate(known, measures, {
      branchKind,
      baselineStatus: ctx.report.scm.baseline.status,
      smallChangesetLines: await instanceSetting(
        ctx.tx,
        SMALL_CHANGESET_SETTING,
        z.number().int().min(0),
        DEFAULT_SMALL_CHANGESET_LINES,
      ),
      warnings,
    });
    await ctx.tx
      .update(analyses)
      .set({ gateStatus: result.status, gateResult: result })
      .where(eq(analyses.id, ctx.analysisId));
    ctx.state.gate = result;
  },
};

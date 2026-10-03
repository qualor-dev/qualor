import type { IngestionContext, IngestionStage } from '../ingest/process';
import { requireState } from '../ingest/state';
import { newCodeClassifier } from '../newcode/lines';
import { planCarryOver, writeCarryOver } from './carry-over';
import { liveAfterWrites, planDedupe, writeDedupe } from './dedupe';
import {
  branchHasIssues,
  copyChangelogs,
  loadReferenceIssues,
  planInheritance,
  referenceBranchId,
} from './inherit';
import { planTracking, type InheritedIssue, type TrackingPlan } from './plan';
import { dbNow, loadCandidates, writePlan } from './writes';

export interface BuiltTracking {
  plan: TrackingPlan;
  inherited: ReadonlyMap<number, InheritedIssue> | undefined;
}

/** Loads the branch's candidates (and, on a first analysis, the reference issues) and plans. */
export async function buildTrackingPlan(ctx: IngestionContext): Promise<BuiltTracking> {
  const findings = requireState(ctx.state, 'findings');
  const now = await dbNow(ctx.tx);
  const candidates = await loadCandidates(ctx.tx, ctx.branch.id);
  // data-model.md §5.4: only the first analysis of a non-main branch or MR inherits: no
  // previous analysis and no issue on the branch yet (branchHasIssues says why both).
  let inherited: Map<number, InheritedIssue> | undefined;
  if (ctx.previousAnalysis === null && !(await branchHasIssues(ctx.tx, ctx.branch.id))) {
    const referenceId = await referenceBranchId(ctx.tx, ctx.branch);
    if (referenceId !== null) {
      const reference = await loadReferenceIssues(ctx.tx, referenceId);
      inherited = planInheritance(ctx.report, findings, reference, candidates);
    }
  }
  const plan = planTracking({
    report: ctx.report,
    findings,
    candidates,
    classifier: newCodeClassifier(ctx.report),
    now,
    inherited,
  });
  return { plan, inherited };
}

/** Writes a plan, copies inherited changelogs and recomputes cross-engine dedupe. */
export async function applyTrackingPlan(
  ctx: IngestionContext,
  { plan, inherited }: BuiltTracking,
): Promise<void> {
  const written = await writePlan(ctx.tx, plan, {
    projectId: ctx.project.id,
    branchId: ctx.branch.id,
    analysisId: ctx.analysisId,
  });
  await copyChangelogs(ctx.tx, plan.inserts);
  const live = await liveAfterWrites(ctx.tx, plan.live, written.blockedIds);
  const duplicates = planDedupe(live);
  await writeDedupe(ctx.tx, duplicates);
  // data-model.md §5.3 (plan 6B-1): a new qualor root takes a triaged duplicate's status, once.
  const carried = await writeCarryOver(
    ctx.tx,
    planCarryOver(live, duplicates, new Set(plan.inserts.map((i) => i.id))),
    ctx.analysisId,
  );
  ctx.logger.debug(
    {
      analysisId: ctx.analysisId,
      matched: plan.updates.length,
      created: plan.inserts.length,
      closed: plan.closes.length,
      inherited: inherited?.size ?? 0,
      duplicatesChanged: duplicates.length,
      carried,
    },
    'tracked issues',
  );
}

/**
 * Server step 8: issue tracking (data-model.md §5.2, §6), cross-engine dedupe (§5.3) and branch
 * and MR inheritance (§5.4). Runs after the rules stage, in the same transaction as everything
 * else of the analysis.
 */
export const trackingStage: IngestionStage = {
  name: 'tracking',
  async run(ctx) {
    await applyTrackingPlan(ctx, await buildTrackingPlan(ctx));
  },
};

import type { IngestionStage } from '../ingest/process';
import { isTrackedBranch, vulnerabilitySettings } from '../versions/settings';
import { readVulndbSettings } from '../vulndb/settings';
import { enqueueRecheck } from './recheck';

/**
 * Spec §7.3, "after an analysis, re-check that target at once": an analysis of a tracked branch
 * whose report carries a dependency inventory queues a re-check of its project, in the ingestion
 * transaction, so the job never runs before the inventory is committed. Nothing while the
 * instance or the project switch is off.
 *
 * The last stage: enqueueRecheck holds a global lock until the commit, so nothing runs after it.
 */
export const vulnerabilityRecheckStage: IngestionStage = {
  name: 'vulnerability-recheck',
  async run(ctx) {
    const { tx } = ctx;
    if (ctx.report.dependencies === undefined || ctx.branch.kind !== 'branch') return;
    if (!(await readVulndbSettings(tx)).enabled) return;
    const settings = await vulnerabilitySettings(tx, ctx.project.id);
    if (!settings.enabled || !isTrackedBranch(settings, ctx.branch)) return;
    await enqueueRecheck(tx, { projectIds: [ctx.project.id] });
  },
};

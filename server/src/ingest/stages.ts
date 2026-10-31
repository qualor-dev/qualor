import { gateStage } from '../gates/stage';
import { licensePolicyStage } from '../licenses/stage';
import { measuresStage } from '../measures/stage';
import { notificationStage } from '../notifications/stage';
import { reviewSnapshotStage } from '../review/stage';
import { rulesStage } from '../rules/stage';
import { scmStage } from '../scm/stage';
import { trackingStage } from '../tracking/stage';
import { versionLabelStage } from '../versions/stage';
import { vulnerabilityRecheckStage } from '../vulnerabilities/stage';
import { webhookStage } from '../webhooks/stage';
import type { IngestionStage } from './process';

/**
 * Order matters: each stage reads what earlier ones put in `ctx.state` (state.ts). The SCM stage
 * only enqueues a decoration job (scm.md §4.1). The licence policy stage adds its findings to the
 * rules stage's before tracking (6M §6). The review snapshot stage (6I-2) links a merge request's
 * snapshot to its newest analysis. The webhook stage is the last stage that may touch the
 * analysis (stages.test.ts): its payload is the analysis as ingestion stores it. Only stages that
 * write no analysis column come after it: the notification stage (mail E3), then the
 * vulnerability re-check request (0.15), last because it holds a global lock until the commit.
 */
export const DEFAULT_STAGES: readonly IngestionStage[] = [
  rulesStage,
  licensePolicyStage,
  trackingStage,
  measuresStage,
  versionLabelStage,
  gateStage,
  scmStage,
  reviewSnapshotStage,
  webhookStage,
  notificationStage,
  vulnerabilityRecheckStage,
];

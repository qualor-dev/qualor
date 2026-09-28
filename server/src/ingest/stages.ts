import { gateStage } from '../gates/stage';
import { measuresStage } from '../measures/stage';
import { rulesStage } from '../rules/stage';
import { scmStage } from '../scm/stage';
import { trackingStage } from '../tracking/stage';
import { webhookStage } from '../webhooks/stage';
import type { IngestionStage } from './process';

/**
 * Order matters: each stage reads what earlier ones put in `ctx.state` (state.ts). The SCM stage
 * only enqueues a decoration job (scm.md §4.1). The webhook stage stays last (stages.test.ts): its
 * payload is the analysis as ingestion stores it.
 */
export const DEFAULT_STAGES: readonly IngestionStage[] = [
  rulesStage,
  trackingStage,
  measuresStage,
  gateStage,
  scmStage,
  webhookStage,
];

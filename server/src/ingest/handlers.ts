import { z } from 'zod';
import type { UploadLimits } from '../config';
import type { Db } from '../db/client';
import type { JobHandlers } from '../queue/worker';
import { markFailed, processAnalysis, type IngestionStage, type ProcessLogger } from './process';
import { ANALYSIS_QUEUE } from './service';
import { DEFAULT_STAGES } from './stages';

const analysisPayload = z.object({ analysisId: z.uuid() });

export interface JobDeps {
  db: Db;
  upload: UploadLimits;
  stages?: readonly IngestionStage[] | undefined;
  logger?: ProcessLogger | undefined;
}

export function jobHandlers(deps: JobDeps): JobHandlers {
  const stages = deps.stages ?? DEFAULT_STAGES;
  return {
    [ANALYSIS_QUEUE]: async (job) => {
      // Ruling S13 #4: a payload that doesn't even parse can never succeed on retry — it is not a
      // transient failure, so complete the job (rather than throwing, which would retry it into
      // 'dead' after burning every attempt for nothing) and just warn about it.
      const parsed = analysisPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn(
          { jobId: job.id, queue: job.queue, issues: parsed.error.issues },
          'malformed analysis job payload; completing without retry',
        );
        return;
      }
      const { analysisId } = parsed.data;
      try {
        await processAnalysis(
          { db: deps.db, upload: deps.upload, stages, logger: deps.logger },
          analysisId,
        );
      } catch (err) {
        // Last attempt: leave a terminal state the CLI can see; rethrow so the job is buried as dead.
        if (job.attempts >= job.maxAttempts) {
          await markFailed(deps.db, analysisId, {
            code: 'PROCESSING_ERROR',
            message: 'The server failed to process this analysis',
          });
        }
        throw err;
      }
    },
  };
}

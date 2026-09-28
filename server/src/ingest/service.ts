import type { Db } from '../db/client';
import { first } from '../db/rows';
import { analyses, analysisReports } from '../db/schema';
import { enqueue } from '../queue/queue';

export const ANALYSIS_QUEUE = 'analysis';

/** Ruling R3: the branch is unknown until the job parses the report, so jobs serialise per project. */
export function analysisConcurrencyKey(projectId: string): string {
  return `analysis:project:${projectId}`;
}

/** Stores the analysis, its raw report and its job in one transaction. */
export async function createQueuedAnalysis(
  db: Db,
  input: { projectId: string; uploadedByTokenId: string | null; body: Buffer },
): Promise<string> {
  return db.transaction(async (tx) => {
    const { id } = first(
      await tx
        .insert(analyses)
        .values({
          projectId: input.projectId,
          uploadedByTokenId: input.uploadedByTokenId,
          status: 'queued',
        })
        .returning({ id: analyses.id }),
    );
    await tx
      .insert(analysisReports)
      .values({ analysisId: id, body: input.body, sizeBytes: input.body.length });
    await enqueue(tx, {
      queue: ANALYSIS_QUEUE,
      payload: { analysisId: id },
      concurrencyKey: analysisConcurrencyKey(input.projectId),
    });
    return id;
  });
}

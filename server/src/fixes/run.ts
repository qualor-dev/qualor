import { z } from 'zod';
import type { Limits } from '../limits';
import type { JobHandlers, WorkerLogger } from '../queue/worker';
import { MAX_DECORATION_ATTEMPTS } from '../scm/queue';
import type { ScmRuntime } from '../scm/runtime';
import { runFixClose, runFixCommit } from './commit';
import { FIX_QUEUE, FIX_SYNC_INTERVAL_SECONDS, fixPassWanted, scheduleFixSync } from './jobs';
import type { FixScmDeps } from './repository';
import { runFixSyncPass } from './sync';

/** What the `fixes` queue's jobs need (R17: they run on the SCM worker, with its runtime). */
export interface FixJobDeps extends FixScmDeps {
  /** The SCM worker's: the organisations' slots, GitHub's tokens and pacing. */
  runtime: ScmRuntime;
  /** `QUALOR_PUBLIC_URL`: the MR body's link to the project's Vulnerabilities tab; none without it. */
  publicUrl: string | null;
  /** Read for each run (the automatic mode's exploited rule needs `vuln.priority`). */
  limits: () => Pick<Limits, 'vulnerabilities'>;
  logger?: WorkerLogger;
}

const fixJob = z.object({
  kind: z.enum(['commit', 'close']),
  fixId: z.uuid(),
  generation: z.number().int().min(1),
  /** Ruling F10: attempts made before this job's, 0 for the first; 6 in all, as the AI post. */
  attempt: z
    .number()
    .int()
    .min(0)
    .max(MAX_DECORATION_ATTEMPTS - 1),
});
const syncJob = z.object({ kind: z.literal('sync'), organizationId: z.uuid() });
const fixJobPayload = z.union([fixJob, syncJob]);

/**
 * spec §6.7, R18: one pass of the organisation, then (as the Jira pass) the next one 15 minutes
 * out, from `finally` so a pass that throws keeps its schedule too, while the organisation still
 * has a project with fixes switched on or an active fix; otherwise it gets none until a project
 * is switched on.
 */
async function runFixSync(deps: FixJobDeps, organizationId: string): Promise<void> {
  try {
    await runFixSyncPass(deps, organizationId);
  } finally {
    if (await fixPassWanted(deps.db, organizationId)) {
      await scheduleFixSync(deps.db, organizationId, FIX_SYNC_INTERVAL_SECONDS);
    }
  }
}

/**
 * The `fixes` queue's handler (R17), run by the SCM worker: `commit` writes a fix's branch and its
 * MR, `close` closes a cancelled fix's MR and deletes its branch, `sync` is the organisation's pass
 * ({@link runFixSync}). A malformed payload is logged and the job completed.
 */
export function fixHandlers(deps: FixJobDeps): JobHandlers {
  return {
    [FIX_QUEUE]: async (job) => {
      const parsed = fixJobPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed fix job payload; completing');
        return;
      }
      const payload = parsed.data;
      if (payload.kind === 'sync') await runFixSync(deps, payload.organizationId);
      else if (payload.kind === 'commit') await runFixCommit(deps, payload);
      else await runFixClose(deps, payload);
    },
  };
}

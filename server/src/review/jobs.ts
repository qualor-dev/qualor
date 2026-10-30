import { eq, sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import type { Db, Executor } from '../db/client';
import { reviewSnapshots } from '../db/schema';
import { enqueue } from '../queue/queue';
import type { JobHandlers } from '../queue/worker';
import { purgeInactiveSnapshots, purgeProjectSnapshots } from './lifecycle';
import { REVIEW_SNAPSHOT_QUEUE, unpackSnapshot, type SnapshotLimits } from './snapshot-store';

type Logger = Pick<FastifyBaseLogger, 'info' | 'warn'>;

const unpackPayload = z.object({
  snapshotId: z.uuid(),
  /** How often the unpack waited already for its analysis to be ingested (6I-3). */
  deferrals: z.number().int().min(0).optional(),
});

/** The purge of the snapshots of projects without AI review (6I-3, R17): one organisation's, or all. */
const purgePayload = z.object({ purgeOrganizationId: z.uuid().nullable() });

/** The purge of one remapped project's older snapshots (R41). */
const remapPayload = z.object({
  purgeProjectId: z.uuid(),
  createdBefore: z.iso.datetime({ offset: true }),
});

/** The purges run one at a time; each looks at the settings as they are when it runs. */
const PURGE_KEY = 'review-snapshot:purge';

/**
 * Queues the purge of the snapshots of the projects of `organizationId` (null: of every
 * organisation) that AI review no longer covers. Called by the routes that write the settings,
 * inside their transaction: the job exists exactly when the write does, and runs after it, never
 * in it.
 */
export async function queueSnapshotPurge(
  tx: Executor,
  organizationId: string | null,
): Promise<void> {
  await enqueue(tx, {
    queue: REVIEW_SNAPSHOT_QUEUE,
    payload: { purgeOrganizationId: organizationId } satisfies z.infer<typeof purgePayload>,
    concurrencyKey: PURGE_KEY,
  });
}

/**
 * Queues the deletion of the snapshots of `projectId` made before this transaction's `now()`: the
 * project was mapped to another repository or connection, and AI review must not read the old
 * one's code. The cutoff is `now()` of this transaction, which is its start, not its commit: a
 * snapshot created after the transaction began stays, even one of the old mapping. That is
 * conservative.
 */
export async function queueRemapPurge(tx: Executor, projectId: string): Promise<void> {
  const { rows } = await tx.execute<{ now: Date | string }>(sql`SELECT now() AS now`);
  const now = rows[0]?.now;
  if (now === undefined) throw new Error('SELECT now() answered nothing');
  await enqueue(tx, {
    queue: REVIEW_SNAPSHOT_QUEUE,
    payload: {
      purgeProjectId: projectId,
      createdBefore: new Date(now).toISOString(),
    } satisfies z.infer<typeof remapPayload>,
    concurrencyKey: PURGE_KEY,
  });
}

/**
 * R41, for a change of a project's mapping (`PATCH /projects/:id`, the repository-setup run):
 * mapped to another repository or connection, or mapped again after an unmap whose purge has not
 * run yet (it would find the project active and keep the old copies), the copies of the old
 * mapping go ({@link queueRemapPurge}). A first mapping has copies to drop only after such an
 * unmap; one without any snapshot queues nothing.
 */
export async function queueRemapPurgeIfCopies(
  tx: Executor,
  before: { id: string; scmConnectionId: string | null; scmProjectRef: string | null },
  after: { scmConnectionId: string | null; scmProjectRef: string | null },
): Promise<void> {
  if (
    after.scmConnectionId === null ||
    (after.scmConnectionId === before.scmConnectionId &&
      after.scmProjectRef === before.scmProjectRef)
  ) {
    return;
  }
  const holdsCopies =
    before.scmConnectionId !== null ||
    (
      await tx
        .select({ id: reviewSnapshots.id })
        .from(reviewSnapshots)
        .where(eq(reviewSnapshots.projectId, before.id))
        .limit(1)
    ).length > 0;
  if (holdsCopies) await queueRemapPurge(tx, before.id);
}

/**
 * The queue that unpacks the uploaded review snapshots (6I-2) and purges those of the projects
 * AI review no longer covers (6I-3); main.ts runs it on the analysis worker. Unpacking never
 * throws for what the scanner sent: a snapshot it refuses is `rejected`, with the reason logged (it
 * never holds the snapshot's content). One whose analysis is not ingested yet waits: another job
 * comes later, and this one completes (it spends no try).
 */
export function reviewSnapshotHandlers(deps: {
  db: Db;
  logger: Logger;
  limits: SnapshotLimits;
}): JobHandlers {
  return {
    [REVIEW_SNAPSHOT_QUEUE]: async (job) => {
      const remap = remapPayload.safeParse(job.payload);
      if (remap.success) {
        const projectId = remap.data.purgeProjectId;
        const deleted = await purgeProjectSnapshots(
          deps.db,
          projectId,
          new Date(remap.data.createdBefore),
        );
        if (deleted > 0) {
          deps.logger.info({ projectId, deleted }, 'review snapshots of a remapped project purged');
        }
        return;
      }
      const purge = purgePayload.safeParse(job.payload);
      if (purge.success) {
        const organizationId = purge.data.purgeOrganizationId;
        const deleted = await purgeInactiveSnapshots(deps.db, organizationId);
        if (deleted > 0) {
          deps.logger.info(
            { organizationId, deleted },
            'review snapshots of projects without AI review purged',
          );
        }
        return;
      }
      // A payload that does not parse never will: complete the job instead of retrying it.
      const parsed = unpackPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger.warn(
          { jobId: job.id, queue: job.queue },
          'malformed review snapshot job payload; completing without retry',
        );
        return;
      }
      const { snapshotId, deferrals = 0 } = parsed.data;
      const outcome = await unpackSnapshot(deps.db, snapshotId, deps.limits, { deferrals });
      if (outcome === 'deferred') {
        deps.logger.info(
          { snapshotId, deferrals: deferrals + 1 },
          'review snapshot waits for its analysis to be ingested',
        );
      } else if (outcome === 'rejected') {
        const [row] = await deps.db
          .select({ error: reviewSnapshots.error })
          .from(reviewSnapshots)
          .where(eq(reviewSnapshots.id, snapshotId));
        deps.logger.warn({ snapshotId, error: row?.error ?? null }, 'review snapshot rejected');
      } else if (outcome === 'ready') {
        deps.logger.info({ snapshotId }, 'review snapshot unpacked');
      } else {
        deps.logger.info({ snapshotId }, 'review snapshot no longer stored; nothing to unpack');
      }
    },
  };
}

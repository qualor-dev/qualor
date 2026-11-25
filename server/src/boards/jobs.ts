import { sql } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { enqueue, enqueueMany } from '../queue/queue';
import {
  after,
  lockSchedule,
  pullPassForward,
  queuedJob,
  queuePass,
  type PassSchedule,
} from '../queue/schedule';

/*
 * Azure DevOps design §7.8, plan Ruling 6: the Jira job schedule (jira/jobs.ts) for Azure Boards,
 * with a pass per Azure DevOps connection rather than per organisation: an organisation may have
 * several connections, and each mapping and link names its own.
 */

/** The queue of both kinds of Boards job, on a worker of its own. */
export const BOARDS_QUEUE = 'boards';

export type BoardsJobPayload = { kind: 'create' | 'sync'; connectionId: string };

/** Design §7.8: a pass runs every 15 minutes per connection. */
export const BOARDS_SYNC_INTERVAL_SECONDS = 900;

/**
 * Jira's ruling R1: the two kinds do not share a concurrency key, so a create is never held up to
 * 15 minutes behind the waiting pass.
 */
export const boardsCreateKey = (connectionId: string): string => `boards-create:${connectionId}`;
export const boardsSyncKey = (connectionId: string): string => `boards-sync:${connectionId}`;

/**
 * Asks for a create run of the connection `delaySeconds` from now, unless one is queued; true when
 * this call queued it. A queued one is held back to `delaySeconds` from now when it is due sooner
 * (a 429's `Retry-After` holds for every run). Under `LOCKS.boardsSchedule`, with a queued job's
 * row locked until the caller's transaction commits: a link request calls it inside the
 * transaction that inserted its pending rows, so the worker never claims the job before the rows
 * it is about are committed.
 */
export async function enqueueBoardsCreate(
  db: Executor,
  connectionId: string,
  delaySeconds = 0,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await lockSchedule(tx, LOCKS.boardsSchedule);
    const queued = await queuedJob(tx, BOARDS_QUEUE, boardsCreateKey(connectionId));
    if (queued !== null) {
      if (delaySeconds > 0) {
        await tx.execute(sql`
          UPDATE jobs SET run_at = ${after(delaySeconds)}, updated_at = now()
           WHERE id = ${queued} AND run_at < ${after(delaySeconds)}`);
      }
      return false;
    }
    const payload: BoardsJobPayload = { kind: 'create', connectionId };
    await enqueue(tx, {
      queue: BOARDS_QUEUE,
      concurrencyKey: boardsCreateKey(connectionId),
      payload,
      runAt: after(delaySeconds),
    });
    return true;
  });
}

const syncPass = (connectionId: string): PassSchedule => ({
  lock: LOCKS.boardsSchedule,
  queue: BOARDS_QUEUE,
  key: boardsSyncKey(connectionId),
  payload: { kind: 'sync', connectionId } satisfies BoardsJobPayload,
});

/**
 * Queues the connection's next pass `delaySeconds` from now unless one is queued (a running pass
 * does not count, so it reschedules itself from its own `finally`); true when this call queued it.
 */
export async function scheduleBoardsSync(
  db: Executor,
  connectionId: string,
  delaySeconds: number,
): Promise<boolean> {
  return queuePass(db, syncPass(connectionId), delaySeconds);
}

/**
 * Moves the connection's waiting pass to now, or queues one (behind a running pass, which the
 * concurrency key holds back until it ends) when none waits.
 */
export async function syncBoardsNow(db: Executor, connectionId: string): Promise<void> {
  await pullPassForward(db, syncPass(connectionId));
}

/**
 * The Azure DevOps connections a pass runs for: those with a Boards mapping or a link that is not
 * dismissed (links keep syncing after their mapping is removed).
 */
const WANTED = sql`
  SELECT c.id FROM scm_connections c
   WHERE c.provider = 'azure'
     AND (EXISTS (SELECT 1 FROM project_boards_settings s WHERE s.connection_id = c.id)
          OR EXISTS (SELECT 1 FROM boards_links l
                      WHERE l.connection_id = c.id AND l.state <> 'dismissed'))`;

/** Whether the connection still wants its pass: its pass reschedules itself only while it does. */
export async function boardsPassWanted(db: Executor, connectionId: string): Promise<boolean> {
  const found = await db.execute<{ wanted: boolean }>(sql`
    SELECT EXISTS (SELECT 1 FROM (${WANTED}) w WHERE w.id = ${connectionId}) AS wanted`);
  return found.rows[0]?.wanted === true;
}

/**
 * Boot and reaping: one pass at now for each connection that wants one and has none queued or
 * running, so a restart or a lost lease never leaves a connection without its pass. The schedule
 * lock makes replicas that boot together queue one each; returns how many it queued.
 */
export async function ensureBoardsSyncScheduled(db: Db): Promise<number> {
  return db.transaction(async (tx) => {
    await lockSchedule(tx, LOCKS.boardsSchedule);
    const missing = await tx.execute<{ id: string }>(sql`
      SELECT w.id FROM (${WANTED}) w
       WHERE NOT EXISTS (
         SELECT 1 FROM jobs j
          WHERE j.queue = ${BOARDS_QUEUE} AND j.status IN ('queued', 'running')
            AND j.concurrency_key = 'boards-sync:' || w.id::text)`);
    const ids = await enqueueMany(
      tx,
      missing.rows.map((r) => ({
        queue: BOARDS_QUEUE,
        concurrencyKey: boardsSyncKey(r.id),
        payload: { kind: 'sync', connectionId: r.id } satisfies BoardsJobPayload,
      })),
    );
    return ids.length;
  });
}

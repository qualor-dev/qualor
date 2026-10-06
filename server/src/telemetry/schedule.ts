import { sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { uuidv7 } from '../db/ids';
import { LOCKS } from '../db/locks';
import { VERSION } from '../index';
import type { Edition } from '../license/edition';
import type { JobHandlers } from '../queue/worker';
import { collectTelemetry } from './collect';
import { installationId } from './installation-id';
import { sendTelemetry } from './send';

export const TELEMETRY_QUEUE = 'telemetry';
export const TELEMETRY_INTERVAL_SECONDS = 24 * 60 * 60;
export const TELEMETRY_BOOT_DELAY_SECONDS = 60;

export interface TelemetryDeps {
  db: Db;
  edition: Pick<Edition, 'edition'>;
  url: string;
  database: 'embedded' | 'external';
  logger?: { debug: (obj: object, msg: string) => void } | undefined;
}

export function telemetryBootMessage(enabled: boolean): string {
  return enabled
    ? 'Telemetry: enabled — anonymous usage statistics are sent daily to qualor.dev; set QUALOR_TELEMETRY=false to turn off (see /docs/telemetry)'
    : 'Telemetry: disabled';
}

/** Inserts one run `delaySeconds` from now unless one is queued (`alsoRunning`: or running). */
async function schedule(db: Db, delaySeconds: number, alsoRunning: boolean, replaceQueued: boolean): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.telemetry})`);
    if (replaceQueued) {
      await tx.execute(sql`DELETE FROM jobs WHERE queue = ${TELEMETRY_QUEUE} AND status = 'queued'`);
    }
    const statuses = alsoRunning ? sql`('queued', 'running')` : sql`('queued')`;
    const existing = await tx.execute(sql`
      SELECT 1 FROM jobs WHERE queue = ${TELEMETRY_QUEUE} AND status IN ${statuses} LIMIT 1`);
    if (existing.rows.length > 0) return false;
    await tx.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, run_at)
      VALUES (${uuidv7()}, ${TELEMETRY_QUEUE}, ${TELEMETRY_QUEUE}, '{}'::jsonb,
              now() + make_interval(secs => ${delaySeconds}))`);
    return true;
  });
}

/**
 * telemetry.md: a start sends about a minute later, whatever was queued for tomorrow; several
 * replicas booting together leave one run.
 */
export async function scheduleTelemetryAtBoot(db: Db): Promise<void> {
  await schedule(db, TELEMETRY_BOOT_DELAY_SECONDS, true, true);
}

/** After every reap: a run lost with its worker is replaced, a day later. */
export function ensureTelemetryScheduled(db: Db): Promise<boolean> {
  return schedule(db, TELEMETRY_INTERVAL_SECONDS, true, false);
}

/** QUALOR_TELEMETRY=false: a run queued by an earlier, enabled start never happens. */
export async function cancelTelemetry(db: Db): Promise<number> {
  const result = await db.execute(sql`DELETE FROM jobs WHERE queue = ${TELEMETRY_QUEUE} AND status = 'queued'`);
  return result.rowCount ?? 0;
}

export function telemetryHandlers(deps: TelemetryDeps): JobHandlers {
  return {
    [TELEMETRY_QUEUE]: async () => {
      try {
        const payload = await collectTelemetry({
          db: deps.db,
          edition: deps.edition,
          installationId: await installationId(deps.db),
          database: deps.database,
        });
        const outcome = await sendTelemetry(deps.url, payload, { userAgent: `qualor-server/${VERSION}` });
        if (!outcome.ok) deps.logger?.debug({ component: 'telemetry', reason: outcome.reason }, 'telemetry not sent');
      } catch (err) {
        // Never retried and never loud: a failure here must not touch the rest of the server.
        deps.logger?.debug(
          { component: 'telemetry', errorClass: err instanceof Error ? err.constructor.name : typeof err },
          'telemetry not sent',
        );
      }
      await schedule(deps.db, TELEMETRY_INTERVAL_SECONDS, false, false);
    },
  };
}

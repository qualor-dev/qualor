import { sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { uuidv7 } from '../db/ids';
import { LOCKS } from '../db/locks';
import { VERSION } from '../index';
import type { Edition } from '../license/edition';
import type { JobHandlers } from '../queue/worker';
import { priorityUrl, type PriorityDataset, type VulndbSource } from '../vulndb/settings';
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
  smtpConfigured: boolean;
  logger?: { debug: (obj: object, msg: string) => void } | undefined;
}

/** Where the vulnerability database comes from while its instance switch is on; null: off. */
export type VulndbBootSource = 'official' | 'mirror' | 'upload' | null;

/** With `vuln.priority`: the host the KEV and the EPSS file are each fetched from. */
export interface PriorityBootHosts {
  kev: string;
  epss: string;
}

const MIRROR_SETTING = 'the mirror set in Settings → Vulnerability database';

/** The host of each priority URL: the mirror's when it names one, else the official one. */
export function priorityBootHosts(source: VulndbSource): PriorityBootHosts {
  const hostOf = (dataset: PriorityDataset): string => {
    try {
      return new URL(priorityUrl(source, dataset)).host;
    } catch {
      return MIRROR_SETTING;
    }
  };
  return { kev: hostOf('kev'), epss: hostOf('epss') };
}

/**
 * The boot line. While the vulnerability database switch is on, it also names the download: the
 * server calls the official registry or the admin's mirror (an upload needs no network). With
 * `vuln.priority` (`priority` set), it names the KEV and EPSS hosts too, each on its own.
 */
export function telemetryBootMessage(
  enabled: boolean,
  vulndbSource: VulndbBootSource = null,
  priority: PriorityBootHosts | null = null,
): string {
  const telemetry = enabled
    ? 'Telemetry: enabled — anonymous usage statistics are sent daily to qualor.dev and Docker Hub is checked daily for a new version; set QUALOR_TELEMETRY=false to turn off (see /docs/telemetry)'
    : 'Telemetry: disabled';
  if (vulndbSource === null || vulndbSource === 'upload') return telemetry;
  const from = vulndbSource === 'official' ? 'ghcr.io' : MIRROR_SETTING;
  const also =
    priority === null ? '' : `, CISA KEV from ${priority.kev} and FIRST EPSS from ${priority.epss}`;
  return `${telemetry}. The Trivy vulnerability database is downloaded from ${from}${also} while Vulnerability monitoring is on (see /docs/vulnerability-database)`;
}

/** Inserts one run `delaySeconds` from now unless one is queued (`alsoRunning`: or running). */
async function schedule(
  db: Db,
  delaySeconds: number,
  alsoRunning: boolean,
  replaceQueued: boolean,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.telemetry})`);
    if (replaceQueued) {
      await tx.execute(
        sql`DELETE FROM jobs WHERE queue = ${TELEMETRY_QUEUE} AND status = 'queued'`,
      );
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
  const result = await db.execute(
    sql`DELETE FROM jobs WHERE queue = ${TELEMETRY_QUEUE} AND status = 'queued'`,
  );
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
          smtpConfigured: deps.smtpConfigured,
          logger: deps.logger,
        });
        const outcome = await sendTelemetry(deps.url, payload, {
          userAgent: `qualor-server/${VERSION}`,
        });
        if (!outcome.ok)
          deps.logger?.debug(
            { component: 'telemetry', reason: outcome.reason },
            'telemetry not sent',
          );
      } catch (err) {
        // Never retried and never loud: a failure here must not touch the rest of the server.
        deps.logger?.debug(
          {
            component: 'telemetry',
            errorClass: err instanceof Error ? err.constructor.name : typeof err,
          },
          'telemetry not sent',
        );
      }
      try {
        await schedule(deps.db, TELEMETRY_INTERVAL_SECONDS, false, false);
      } catch (err) {
        // Not retried: afterReap's ensureTelemetryScheduled re-creates the run.
        deps.logger?.debug(
          {
            component: 'telemetry',
            errorClass: err instanceof Error ? err.constructor.name : typeof err,
          },
          'telemetry next run not scheduled',
        );
      }
    },
  };
}

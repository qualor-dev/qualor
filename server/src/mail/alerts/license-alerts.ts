import { sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import type { Db } from '../../db/client';
import { uuidv7 } from '../../db/ids';
import { LOCKS } from '../../db/locks';
import { instanceSettings } from '../../db/schema';
import type { Edition } from '../../license/edition';
import { licensePlan } from '../../license/plan';
import { DAY_MS, graceEndsAt, type LicenseState } from '../../license/state';
import type { JobHandlers } from '../../queue/worker';
import { instanceSetting } from '../../settings';
import { queueMailToAdmins, type MailDeps } from '../outbox';
import { mailConfigured, readMailSettings } from '../settings';
import {
  LICENSE_ALERT_VARIANTS,
  renderLicenseExpiry,
  type LicenseAlertVariant,
} from '../templates/license-expiry';

export const LICENSE_ALERT_QUEUE = 'mail.license-check';
/** `{ licenseKey: '<kid>:<expires>', sent: Bucket[] }`: which alerts the current key had. */
export const LICENSE_ALERT_STATE_KEY = 'mail.license-alerts';
export const LICENSE_ALERT_INTERVAL_SECONDS = 24 * 60 * 60;
export const LICENSE_ALERT_BOOT_DELAY_SECONDS = 120;

export type LicenseAlertBucket = LicenseAlertVariant;

const stateSchema = z.strictObject({
  licenseKey: z.string().max(200),
  sent: z.array(z.enum(LICENSE_ALERT_VARIANTS)).max(LICENSE_ALERT_VARIANTS.length),
});
type AlertState = z.infer<typeof stateSchema>;

/**
 * E1 spec: `30d` when 7 < days ≤ 30, `7d` when 1 < days ≤ 7, `1d` when 0 < days ≤ 1, `grace`,
 * `expired`; none otherwise (no licence, an invalid one, or more than 30 days left).
 */
export function licenseAlertBucket(state: LicenseState, now: Date): LicenseAlertBucket | null {
  if (state.state === 'grace') return 'grace';
  if (state.state === 'expired') return 'expired';
  if (state.state !== 'active' || state.license === null) return null;
  const days = (Date.parse(state.license.expires) - now.getTime()) / DAY_MS;
  if (days > 30 || days <= 0) return null;
  if (days > 7) return '30d';
  if (days > 1) return '7d';
  return '1d';
}

export interface LicenseAlertDeps extends MailDeps {
  db: Db;
  edition: Pick<Edition, 'state' | 'now'>;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
}

/**
 * One daily check: when the alert is on and email is configured, the current bucket is queued to
 * every instance administrator once per licence key (a new key starts again; a missed earlier
 * bucket is never sent late). Under LOCKS.licenseAlerts, so two replicas never both send it.
 */
export async function checkLicenseAlerts(
  deps: LicenseAlertDeps,
): Promise<LicenseAlertBucket | null> {
  const state = deps.edition.state();
  const now = deps.edition.now();
  const bucket = licenseAlertBucket(state, now);
  const license = state.license;
  if (bucket === null || license === null || state.kid === null) return null;
  const kid = state.kid;
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.licenseAlerts})`);
    if (!(await readMailSettings(tx)).alerts.licenseExpiry) return null;
    if (!(await mailConfigured(tx, deps.config))) return null;
    const licenseKey = `${kid}:${license.expires}`;
    const stored = await instanceSetting<AlertState>(tx, LICENSE_ALERT_STATE_KEY, stateSchema, {
      licenseKey,
      sent: [],
    });
    const sent = stored.licenseKey === licenseKey ? stored.sent : [];
    if (sent.includes(bucket)) return null;
    const results = await queueMailToAdmins(tx, deps, {
      kind: 'license.expiry',
      render: () =>
        renderLicenseExpiry({
          variant: bucket,
          licensee: license.customer,
          plan: licensePlan(license.features),
          expires: new Date(license.expires),
          graceEndsAt: state.graceEndsAt ?? graceEndsAt(license),
          now,
          publicUrl: deps.config.publicUrl,
        }),
    });
    // Recorded only once something was queued: with email off, or no administrator address yet,
    // the bucket stays unsent so a later run (after configuring) still sends it.
    if (!results.some((r) => r.status === 'queued')) return null;
    const value: AlertState = { licenseKey, sent: [...sent, bucket] };
    await tx
      .insert(instanceSettings)
      .values({ key: LICENSE_ALERT_STATE_KEY, value })
      .onConflictDoUpdate({ target: instanceSettings.key, set: { value, updatedAt: sql`now()` } });
    return bucket;
  });
}

/** Inserts one run `delaySeconds` from now unless one is queued (`alsoRunning`: or running). */
async function schedule(
  db: Db,
  delaySeconds: number,
  alsoRunning: boolean,
  replaceQueued: boolean,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.licenseAlerts})`);
    if (replaceQueued) {
      await tx.execute(
        sql`DELETE FROM jobs WHERE queue = ${LICENSE_ALERT_QUEUE} AND status = 'queued'`,
      );
    }
    const statuses = alsoRunning ? sql`('queued', 'running')` : sql`('queued')`;
    const existing = await tx.execute(sql`
      SELECT 1 FROM jobs WHERE queue = ${LICENSE_ALERT_QUEUE} AND status IN ${statuses} LIMIT 1`);
    if (existing.rows.length > 0) return false;
    await tx.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, run_at)
      VALUES (${uuidv7()}, ${LICENSE_ALERT_QUEUE}, ${LICENSE_ALERT_QUEUE}, '{}'::jsonb,
              now() + make_interval(secs => ${delaySeconds}))`);
    return true;
  });
}

/** E1 spec: the first check 2 minutes after a start, whatever was queued; one run across replicas. */
export async function scheduleLicenseAlertAtBoot(db: Db): Promise<void> {
  await schedule(db, LICENSE_ALERT_BOOT_DELAY_SECONDS, true, true);
}

/** After every reap: a run lost with its worker is replaced, a day later. */
export function ensureLicenseAlertScheduled(db: Db): Promise<boolean> {
  return schedule(db, LICENSE_ALERT_INTERVAL_SECONDS, true, false);
}

/** On the analysis worker (main.ts): check, then schedule the next run a day later. */
export function licenseAlertHandlers(deps: LicenseAlertDeps): JobHandlers {
  return {
    [LICENSE_ALERT_QUEUE]: async () => {
      try {
        const bucket = await checkLicenseAlerts(deps);
        if (bucket !== null) {
          deps.logger?.info({ component: 'licence', bucket }, 'licence expiry alert queued');
        }
      } catch (err) {
        // Not retried: tomorrow's run checks again (missed buckets are not sent late anyway).
        deps.logger?.warn(
          {
            component: 'licence',
            errorClass: err instanceof Error ? err.constructor.name : typeof err,
          },
          'licence expiry check failed',
        );
      }
      await schedule(deps.db, LICENSE_ALERT_INTERVAL_SECONDS, false, false);
    },
  };
}

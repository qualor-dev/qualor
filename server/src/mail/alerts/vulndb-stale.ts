import { sql } from 'drizzle-orm';
import type { Db } from '../../db/client';
import { LOCKS } from '../../db/locks';
import { isDatasetStale, readVulndbState, updateVulndbStateLocked } from '../../vulndb/state';
import { currentDataset } from '../../vulndb/store';
import { queueMailToAdmins, type MailDeps } from '../outbox';
import { renderVulndbStale } from '../templates/vulndb-stale';

export interface VulndbStaleDeps extends MailDeps {
  db: Db;
  now: () => Date;
}

/**
 * 0.15: when the current dataset is stale, every instance administrator with an address gets one
 * email per dataset (`staleNotifiedDigest` records the digest). A fresh dataset clears the record,
 * so the next stale one mails again. Not gated by a licence. Under LOCKS.vulndbState, so two
 * replicas never both send it. True when a mail was queued.
 */
export async function notifyIfVulndbStale(deps: VulndbStaleDeps): Promise<boolean> {
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbState})`);
    const state = await readVulndbState(tx);
    const current = await currentDataset(tx, state);
    if (current === null) return false;
    const stale = isDatasetStale(current, deps.now());
    if (!stale) {
      if (state.staleNotifiedDigest !== null) {
        await updateVulndbStateLocked(tx, (s) => ({ ...s, staleNotifiedDigest: null }));
      }
      return false;
    }
    if (state.staleNotifiedDigest === current.digest) return false;
    const results = await queueMailToAdmins(tx, deps, {
      kind: 'vulndb.stale',
      render: () =>
        renderVulndbStale({
          dataDate: current.builtAt,
          lastError: state.lastError,
          publicUrl: deps.config.publicUrl,
        }),
    });
    // Recorded only once something was queued: with email off, or no administrator address yet,
    // a later run (after configuring) still sends it.
    if (!results.some((r) => r.status === 'queued')) return false;
    await updateVulndbStateLocked(tx, (s) => ({ ...s, staleNotifiedDigest: current.digest }));
    return true;
  });
}

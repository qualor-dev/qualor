import { and, eq, inArray, ne, notExists, or, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Db, Executor } from '../db/client';
import { jobs, organizations } from '../db/schema';
import { dropOrganizationLicensePolicy } from '../licenses/settings';
import { dropOrganizationLlmSettings } from '../llm/settings';
import { enqueue } from '../queue/queue';
import type { JobHandlers, WorkerLogger } from '../queue/worker';

/**
 * 0.16 issue #37: the queue of organisation deletes. main.ts runs it on the main worker, where the
 * SCM connection delete's snapshot purge runs too.
 */
export const ORGANIZATION_DELETE_QUEUE = 'organization-delete';

/** What every delete job's concurrency key starts with; the organisation's id follows. */
const KEY_PREFIX = `${ORGANIZATION_DELETE_QUEUE}:`;

/**
 * The delete job's concurrency key: one delete of an organisation runs at a time, and while a job
 * with this key is queued or running the organisation is "deleting" ({@link deletingOrganizations}).
 * UUIDs compare in lower case, as the database returns them.
 */
export function organizationDeleteKey(organizationId: string): string {
  return `${KEY_PREFIX}${organizationId.toLowerCase()}`;
}

const payloadSchema = z.object({ organizationId: z.uuid() });

/**
 * Queues the delete of the organisation, with the default attempts. Called inside the
 * transaction that records the request, so the job exists exactly when the request does.
 */
export async function queueOrganizationDelete(tx: Executor, organizationId: string): Promise<void> {
  await enqueue(tx, {
    queue: ORGANIZATION_DELETE_QUEUE,
    payload: { organizationId } satisfies z.infer<typeof payloadSchema>,
    concurrencyKey: organizationDeleteKey(organizationId),
  });
}

/**
 * The organisations of `ids` that are being deleted: those whose key has a `queued` or `running`
 * job, read in one query. A `succeeded`, `failed` or `dead` job does not count: a delete that died
 * leaves its organisation usable, and the delete can be asked for again.
 */
export async function deletingOrganizations(
  db: Executor,
  ids: readonly string[],
): Promise<Set<string>> {
  const deleting = new Set<string>();
  if (ids.length === 0) return deleting;
  const byKey = new Map(ids.map((id) => [organizationDeleteKey(id), id]));
  const keys = [...byKey.keys()];
  // One arm per status: each arm matches the partial indexes of its status (`status = 'queued'`,
  // `status = 'running'`), so the query never reads the whole table; `IN (...)` would not.
  const rows = await db
    .selectDistinct({ key: jobs.concurrencyKey })
    .from(jobs)
    .where(
      or(
        and(eq(jobs.status, 'queued'), inArray(jobs.concurrencyKey, keys)),
        and(eq(jobs.status, 'running'), inArray(jobs.concurrencyKey, keys)),
      ),
    );
  for (const { key } of rows) {
    const id = key === null ? undefined : byKey.get(key);
    if (id !== undefined) deleting.add(id);
  }
  return deleting;
}

/**
 * Whether an organisation other than `organizationId` exists that is not being deleted, as
 * {@link deletingOrganizations} reads it, in one query: `DELETE /organizations/:id` keeps one
 * (409 LAST_ORGANIZATION). The key is built in SQL from the id as the database spells it, in
 * lower case, so it equals {@link organizationDeleteKey}.
 */
export async function anotherOrganizationRemains(
  db: Executor,
  organizationId: string,
): Promise<boolean> {
  const key = sql`${KEY_PREFIX}::text || ${organizations.id}::text`;
  const [row] = await db
    .select({ id: organizations.id })
    .from(organizations)
    .where(
      and(
        ne(organizations.id, organizationId),
        notExists(
          db
            .select({ one: sql`1` })
            .from(jobs)
            .where(
              // One arm per status, for the partial indexes of each, as deletingOrganizations.
              or(
                and(eq(jobs.status, 'queued'), eq(jobs.concurrencyKey, key)),
                and(eq(jobs.status, 'running'), eq(jobs.concurrencyKey, key)),
              ),
            ),
        ),
      ),
    )
    .limit(1);
  return row !== undefined;
}

/**
 * Deletes the organisation in one transaction: its row, locked first, and through the ON DELETE
 * CASCADE of every foreign key to it everything it holds (projects and their data, connections,
 * gates, profiles, webhooks, memberships). Its entries in the `instance_settings` rows
 * `licensePolicy` and `llm` are dropped in the same transaction. Audit events have no foreign key
 * and stay. `'gone'` when the organisation no longer exists: nothing to do.
 *
 * Everything after the lock uses the id the database returned (ruling C1): `organizationId` may be
 * an upper-case spelling, which the settings' JSON keys would not match.
 */
export async function deleteOrganization(
  db: Db,
  organizationId: string,
): Promise<'deleted' | 'gone'> {
  return db.transaction(async (tx): Promise<'deleted' | 'gone'> => {
    const [row] = await tx
      .select({ id: organizations.id })
      .from(organizations)
      .where(eq(organizations.id, organizationId))
      .for('update');
    if (!row) return 'gone';
    await dropOrganizationLicensePolicy(tx, row.id);
    await dropOrganizationLlmSettings(tx, row.id);
    await tx.delete(organizations).where(eq(organizations.id, row.id));
    return 'deleted';
  });
}

/**
 * The queue that deletes organisations. An organisation that is gone already completes the job
 * quietly; a payload that does not parse never will, so it is logged and the job completed
 * instead of retried. Any other failure is retried by the queue.
 */
export function organizationDeleteHandlers(deps: { db: Db; logger: WorkerLogger }): JobHandlers {
  return {
    [ORGANIZATION_DELETE_QUEUE]: async (job) => {
      const parsed = payloadSchema.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger.warn(
          { jobId: job.id, queue: job.queue },
          'malformed organization delete job payload; completing without retry',
        );
        return;
      }
      const { organizationId } = parsed.data;
      const outcome = await deleteOrganization(deps.db, organizationId);
      deps.logger.info(
        { organizationId },
        outcome === 'deleted'
          ? 'organization deleted'
          : 'organization no longer exists; nothing to delete',
      );
    },
  };
}

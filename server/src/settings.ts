import { eq, sql } from 'drizzle-orm';
import type { z } from 'zod';
import type { Executor } from './db/client';
import { instanceSettings } from './db/schema';

/**
 * An `instance_settings` value, or `fallback` when the row is missing or does not match `schema`
 * (an operator's typo must never break ingestion or housekeeping).
 */
export async function instanceSetting<T>(
  db: Executor,
  key: string,
  schema: z.ZodType<T>,
  fallback: T,
): Promise<T> {
  const [row] = await db
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, key));
  if (!row) return fallback;
  const parsed = schema.safeParse(row.value);
  return parsed.success ? parsed.data : fallback;
}

/**
 * Removes the organisation's entry from the `organizations` object of the `key` row, in one
 * UPDATE that leaves every other entry and member exactly as stored, a newer version's included.
 * A missing row, a row whose `organizations` is not an object and a row without the entry are
 * left as they are. The caller holds the row's write lock.
 */
export async function dropOrganizationEntry(
  tx: Executor,
  key: string,
  organizationId: string,
): Promise<void> {
  await tx.execute(sql`
    UPDATE instance_settings
       SET value = value #- ARRAY['organizations', ${organizationId}::text], updated_at = now()
     WHERE key = ${key}
       AND jsonb_typeof(value -> 'organizations') = 'object'
       AND (value -> 'organizations') ? ${organizationId}::text`);
}

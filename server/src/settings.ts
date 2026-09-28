import { eq } from 'drizzle-orm';
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

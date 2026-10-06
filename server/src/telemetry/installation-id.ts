import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import type { Executor } from '../db/client';
import { instanceSettings } from '../db/schema';
import { instanceSetting } from '../settings';

/** The `instance_settings` row holding this installation's telemetry id (telemetry.md). */
export const TELEMETRY_SETTING_KEY = 'telemetry';

const storedSchema = z.object({ installationId: z.uuid() });

/**
 * telemetry.md: a random id, created on first use and kept. It is not derived from the licence,
 * an organisation or the host, so it says nothing about who runs the server.
 */
export async function installationId(db: Executor): Promise<string> {
  const read = () => instanceSetting(db, TELEMETRY_SETTING_KEY, storedSchema, null);
  const stored = await read();
  if (stored) return stored.installationId;
  const value = { installationId: randomUUID() };
  // A replica that created it first wins.
  await db.insert(instanceSettings).values({ key: TELEMETRY_SETTING_KEY, value }).onConflictDoNothing();
  const again = await read();
  if (again) return again.installationId;
  // The row exists but is malformed: replace it.
  await db
    .update(instanceSettings)
    .set({ value })
    .where(eq(instanceSettings.key, TELEMETRY_SETTING_KEY));
  return value.installationId;
}

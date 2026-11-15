import { sql } from 'drizzle-orm';
import type { AuditLog } from '../src/audit/recorder';
import type { TestContext } from './app';

/** A recorder's logger for tests that do not look at its lines (rbac-audit.md §10.2.1). */
export const QUIET_AUDIT_LOG: AuditLog = Object.freeze({ error: () => undefined });

/** Runs `action` while every insert into audit_events fails, as a recorder that throws. */
export async function whileAuditFails<T>(ctx: TestContext, action: () => Promise<T>): Promise<T> {
  await ctx.db.execute(sql`
    CREATE FUNCTION refuse_audit() RETURNS trigger LANGUAGE plpgsql
      AS $$ BEGIN RAISE EXCEPTION 'audit refused'; END $$`);
  await ctx.db.execute(sql`
    CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION refuse_audit()`);
  try {
    return await action();
  } finally {
    await ctx.db.execute(sql`DROP TRIGGER refuse_audit ON audit_events`);
    await ctx.db.execute(sql`DROP FUNCTION refuse_audit()`);
  }
}

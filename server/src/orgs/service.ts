import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import type { Db } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgErrorCode } from '../db/errors';
import { first } from '../db/rows';
import { memberships, organizations } from '../db/schema';
import { conflict } from '../http/problem';
import { ensureBuiltins } from './builtins';

export type OrganizationRow = typeof organizations.$inferSelect;

/**
 * data-model.md §4.1: there is no limit on the number of organisations (enterprise.md §1.3). The
 * unique index on `key` decides between two creators of the same key: one wins, the other gets
 * 409 ORG_KEY_TAKEN.
 */
export async function createOrganization(
  db: Db,
  input: { key: string; name: string; creatorId: string },
  audit?: { recorder: AuditRecorder; context: AuditActorContext },
): Promise<OrganizationRow> {
  return db.transaction(async (tx) => {
    let org: OrganizationRow;
    try {
      org = first(
        await tx.insert(organizations).values({ key: input.key, name: input.name }).returning(),
      );
    } catch (err) {
      if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) {
        throw conflict('ORG_KEY_TAKEN', 'That organization key is already taken');
      }
      throw err;
    }
    await tx
      .insert(memberships)
      .values({ organizationId: org.id, userId: input.creatorId, role: 'admin' });
    await ensureBuiltins(tx, org.id);
    await audit?.recorder.record(tx, audit.context, [
      {
        action: 'organization.created',
        organization: { id: org.id, key: org.key },
        target: { type: 'organization', id: org.id, label: org.name },
        details: { key: org.key, name: org.name },
      },
    ]);
    return org;
  });
}

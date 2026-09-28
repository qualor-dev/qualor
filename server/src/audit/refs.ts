import { eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { organizations, projects } from '../db/schema';

export interface AuditRef {
  id: string;
  key: string;
}

/**
 * The organisation's id and key, for an event's `organization` (names are copied, §7.3). A caller
 * that deletes the object reads its refs first; the empty key exists only so a race never throws
 * inside a transaction that already changed the data.
 */
export async function organizationRef(db: Executor, id: string): Promise<AuditRef> {
  const [row] = await db
    .select({ id: organizations.id, key: organizations.key })
    .from(organizations)
    .where(eq(organizations.id, id));
  return row ?? { id, key: '' };
}

/**
 * The project's id and key and its organisation's, for an event's `project` and `organization`
 * (null only in the race above: an organisation id must be a uuid).
 */
export async function projectRefs(
  db: Executor,
  id: string,
): Promise<{ project: AuditRef; organization: AuditRef | null }> {
  const [row] = await db
    .select({
      id: projects.id,
      key: projects.key,
      orgId: organizations.id,
      orgKey: organizations.key,
    })
    .from(projects)
    .innerJoin(organizations, eq(organizations.id, projects.organizationId))
    .where(eq(projects.id, id));
  return row
    ? { project: { id: row.id, key: row.key }, organization: { id: row.orgId, key: row.orgKey } }
    : { project: { id, key: '' }, organization: null };
}

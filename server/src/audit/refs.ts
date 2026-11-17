import { eq } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { Executor } from '../db/client';
import { organizations, projects } from '../db/schema';
import type { AuditAction, AuditDetails } from './catalogue';
import { actorOf, type AuditEventInput, type AuditRecorder } from './recorder';

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

/**
 * rbac-audit.md §8: one event about `project` (its target, with the project's and the
 * organisation's refs), by the request's actor, in the change's transaction `tx`. Nothing while
 * the recorder is not active.
 */
export async function recordProjectEvent<A extends AuditAction>(
  recorder: AuditRecorder,
  tx: Executor,
  request: FastifyRequest,
  project: { id: string; name: string },
  action: A,
  details: AuditDetails<A>,
): Promise<void> {
  if (!recorder.active()) return;
  const refs = await projectRefs(tx, project.id);
  const event = {
    action,
    organization: refs.organization,
    project: refs.project,
    target: { type: 'project', id: project.id, label: project.name },
    details,
  } as AuditEventInput;
  await recorder.record(tx, actorOf(request), [event]);
}

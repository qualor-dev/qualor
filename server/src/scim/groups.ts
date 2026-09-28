import { and, asc, count, eq, inArray, isNotNull, ne, sql, type SQL } from 'drizzle-orm';
import { isStorableText } from '../audit/canonical';
import { SYSTEM_ACTOR } from '../audit/recorder';
import type { Executor } from '../db/client';
import { identities, scimGroupMembers, scimGroups, users, type ScimGroupRow } from '../db/schema';
import { ScimError } from './errors';
import { applyGroupPatch } from './patch';
import {
  groupResource,
  listResponse,
  project,
  showsMembers,
  type ListResponse,
  type ScimGroupResource,
} from './representation';
import {
  CONTROL,
  inTransaction,
  isRecord,
  lockPeople,
  lockSyncTargets,
  member,
  scimDetails,
  syncIdentity,
  UUID,
  type ScimCaller,
  type ScimListQuery,
} from './users';

/** spec §12.7: members of one group. */
export const MAX_GROUP_MEMBERS = 10_000;
const MAX_TEXT = 255;
/** Rows per insert or `IN` list: well under PostgreSQL's 65 535 parameters. */
const CHUNK = 1_000;

const notFoundGroup = () => new ScimError(404, null, 'Group not found');
const uniqueness = (detail: string) => new ScimError(409, 'uniqueness', detail);
const invalidValue = (detail: string) => new ScimError(400, 'invalidValue', detail);
const tooManyMembers = () =>
  new ScimError(400, 'tooMany', `A group has at most ${MAX_GROUP_MEMBERS} members`);

interface GroupInput {
  displayName: string;
  externalId: string | null;
  members: string[];
}

interface Person {
  identityId: string;
  userId: string;
  username: string;
}

function chunks<T>(list: readonly T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += CHUNK) out.push(list.slice(i, i + CHUNK));
  return out;
}

function text(v: unknown, what: string): string {
  if (typeof v !== 'string' || !isStorableText(v) || CONTROL.test(v)) {
    throw invalidValue(`${what} must be text without control characters`);
  }
  if ([...v].length > MAX_TEXT) throw invalidValue(`${what} is longer than ${MAX_TEXT} characters`);
  return v;
}

/** A whole Group resource (POST, PUT): absent optional attributes are cleared (RFC 7644 §3.5.1). */
function groupFromResource(body: unknown): GroupInput {
  if (!isRecord(body)) throw new ScimError(400, 'invalidSyntax', 'The body must be a Group');
  const displayName = member(body, 'displayName');
  if (typeof displayName !== 'string' || displayName === '') {
    throw invalidValue('displayName is required');
  }
  const ext = member(body, 'externalId');
  const list = member(body, 'members');
  if (list !== undefined && list !== null && !Array.isArray(list)) {
    throw invalidValue('members must be a list of { value }');
  }
  const entries: unknown[] = Array.isArray(list) ? list : [];
  if (entries.length > MAX_GROUP_MEMBERS) throw tooManyMembers();
  return {
    displayName: text(displayName, 'displayName'),
    externalId: ext === undefined || ext === null || ext === '' ? null : text(ext, 'externalId'),
    members: entries.map((entry) => {
      const value = isRecord(entry) ? member(entry, 'value') : undefined;
      if (typeof value !== 'string' || value === '') {
        throw invalidValue('A member must be an object with a value');
      }
      return text(value, 'A member value');
    }),
  };
}

/**
 * The given ids that are SCIM Users of this connection, with their users. Anything else (another
 * connection's user, an unknown or malformed id) is left out, and counted by the caller.
 */
async function resolveMembers(
  tx: Executor,
  caller: ScimCaller,
  ids: Iterable<string>,
): Promise<Map<string, Person>> {
  const valid = [...new Set(ids)].filter((id) => UUID.test(id)).map((id) => id.toLowerCase());
  const found = new Map<string, Person>();
  for (const part of chunks([...new Set(valid)])) {
    const rows = await tx
      .select({ identityId: identities.id, userId: users.id, username: users.username })
      .from(identities)
      .innerJoin(users, eq(users.id, identities.userId))
      .where(
        and(
          eq(identities.connectionId, caller.connectionId),
          isNotNull(identities.scimUserName),
          inArray(identities.id, part),
        ),
      )
      // KEY SHARE: a user deleted concurrently is waited for, then left out (counted unknown),
      // never a foreign-key violation on the member row inserted below.
      .for('key share', { of: identities });
    for (const r of rows) found.set(r.identityId, r);
  }
  return found;
}

/** The distinct ids among `ids` that `resolved` does not hold (compared as UUIDs, any case). */
function unknownCount(ids: Iterable<string>, resolved: Map<string, Person>): number {
  const distinct = new Set([...ids].map((id) => (UUID.test(id) ? id.toLowerCase() : id)));
  return [...distinct].filter((id) => !resolved.has(id)).length;
}

async function people(tx: Executor, identityIds: readonly string[]): Promise<Person[]> {
  const out: Person[] = [];
  for (const part of chunks(identityIds)) {
    out.push(
      ...(await tx
        .select({ identityId: identities.id, userId: users.id, username: users.username })
        .from(identities)
        .innerJoin(users, eq(users.id, identities.userId))
        .where(inArray(identities.id, part))),
    );
  }
  return out;
}

async function memberIds(tx: Executor, groupId: string): Promise<Set<string>> {
  const rows = await tx
    .select({ identityId: scimGroupMembers.identityId })
    .from(scimGroupMembers)
    .where(eq(scimGroupMembers.groupId, groupId));
  return new Set(rows.map((r) => r.identityId));
}

/** Members of the groups, for the representation: `display` is the user's display name. */
async function membersOf(
  tx: Executor,
  groupIds: readonly string[],
): Promise<Map<string, { value: string; display: string | null }[]>> {
  const out = new Map<string, { value: string; display: string | null }[]>(
    groupIds.map((id) => [id, []]),
  );
  if (groupIds.length === 0) return out;
  const rows = await tx
    .select({
      groupId: scimGroupMembers.groupId,
      value: identities.id,
      displayName: users.displayName,
      userName: identities.scimUserName,
    })
    .from(scimGroupMembers)
    .innerJoin(identities, eq(identities.id, scimGroupMembers.identityId))
    .innerJoin(users, eq(users.id, identities.userId))
    .where(inArray(scimGroupMembers.groupId, [...groupIds]))
    .orderBy(asc(scimGroupMembers.createdAt), asc(identities.id));
  for (const r of rows) {
    out.get(r.groupId)?.push({ value: r.value, display: r.displayName ?? r.userName });
  }
  return out;
}

async function loadGroup(
  tx: Executor,
  caller: ScimCaller,
  id: string,
  forUpdate: boolean,
): Promise<ScimGroupRow> {
  if (!UUID.test(id)) throw notFoundGroup();
  const query = tx
    .select()
    .from(scimGroups)
    .where(and(eq(scimGroups.connectionId, caller.connectionId), eq(scimGroups.id, id)));
  const [row] = forUpdate ? await query.for('update') : await query;
  if (!row) throw notFoundGroup();
  return row;
}

async function assertNamesFree(
  tx: Executor,
  caller: ScimCaller,
  input: { displayName: string; externalId: string | null },
  except: string | null,
): Promise<void> {
  const others = except === null ? undefined : ne(scimGroups.id, except);
  const [byName] = await tx
    .select({ id: scimGroups.id })
    .from(scimGroups)
    .where(
      and(
        eq(scimGroups.connectionId, caller.connectionId),
        sql`lower(${scimGroups.displayName}) = lower(${input.displayName})`,
        others,
      ),
    );
  if (byName) throw uniqueness('displayName is already in use on this connection');
  if (input.externalId === null) return;
  const [byExternal] = await tx
    .select({ id: scimGroups.id })
    .from(scimGroups)
    .where(
      and(
        eq(scimGroups.connectionId, caller.connectionId),
        eq(scimGroups.externalId, input.externalId),
        others,
      ),
    );
  if (byExternal) throw uniqueness('externalId is already in use on this connection');
}

async function addMembers(tx: Executor, groupId: string, ids: readonly string[]): Promise<void> {
  for (const part of chunks(ids)) {
    await tx
      .insert(scimGroupMembers)
      .values(part.map((identityId) => ({ groupId, identityId })))
      .onConflictDoNothing();
  }
}

async function removeMembers(tx: Executor, groupId: string, ids: readonly string[]): Promise<void> {
  for (const part of chunks(ids)) {
    await tx
      .delete(scimGroupMembers)
      .where(
        and(eq(scimGroupMembers.groupId, groupId), inArray(scimGroupMembers.identityId, part)),
      );
  }
}

/**
 * spec §9.1: group sync for each person whose groups (or whose groups' values) changed. Called
 * after the request's member-row writes: every person's LOCKS.scimSync, sorted, all before the
 * first sync (so a concurrent change of another group of theirs waits, and its own sync then reads
 * this request's committed rows), then the organisations and projects their syncs may lock.
 */
async function syncPeople(tx: Executor, caller: ScimCaller, ids: Iterable<string>): Promise<void> {
  if (caller.connection.parsed.config.groupSource !== 'scim') return;
  const sorted = [...new Set(ids)].sort();
  if (sorted.length === 0) return;
  await lockPeople(tx, sorted);
  const persons = await people(tx, sorted);
  await lockSyncTargets(
    tx,
    caller,
    persons.map((p) => p.userId),
  );
  for (const person of persons) await syncIdentity(tx, caller, person);
}

async function resourceOf(
  tx: Executor,
  caller: ScimCaller,
  group: ScimGroupRow,
): Promise<ScimGroupResource> {
  const members = (await membersOf(tx, [group.id])).get(group.id) ?? [];
  return groupResource(group, members, caller.baseUrl);
}

// ─── Reading ────────────────────────────────────────────────────────────────

function filterWhere(filter: ScimListQuery['filter']): SQL | undefined | 'none' {
  if (filter === null) return undefined;
  switch (filter.attribute) {
    case 'displayName':
      return sql`lower(${scimGroups.displayName}) = lower(${filter.value})`;
    case 'externalId':
      return eq(scimGroups.externalId, filter.value);
    case 'id':
      return UUID.test(filter.value) ? eq(scimGroups.id, filter.value) : 'none';
    default:
      return 'none';
  }
}

/** `GET /Groups` (spec §12.5); `excludedAttributes=members` leaves the members unread. */
export async function listGroups(
  caller: ScimCaller,
  q: ScimListQuery,
): Promise<ListResponse<Partial<ScimGroupResource>>> {
  const db = caller.tx ?? caller.deps.db;
  const extra = filterWhere(q.filter);
  if (extra === 'none') return listResponse([], 0, q.startIndex);
  const where = and(eq(scimGroups.connectionId, caller.connectionId), extra);
  const [total] = await db.select({ n: count() }).from(scimGroups).where(where);
  const n = total?.n ?? 0;
  if (q.count === 0 || n === 0) return listResponse([], n, q.startIndex);
  const rows = await db
    .select()
    .from(scimGroups)
    .where(where)
    .orderBy(asc(scimGroups.createdAt), asc(scimGroups.id))
    .offset(q.startIndex - 1)
    .limit(q.count);
  const excluded = q.excludedAttributes ?? [];
  const members = showsMembers(q.attributes, excluded)
    ? await membersOf(
        db,
        rows.map((r) => r.id),
      )
    : null;
  return listResponse(
    rows.map((r) =>
      project(groupResource(r, members?.get(r.id) ?? null, caller.baseUrl), q.attributes, excluded),
    ),
    n,
    q.startIndex,
  );
}

/** `GET /Groups/{id}`, honouring `attributes=` and `excludedAttributes=members`. */
export async function getGroup(
  caller: ScimCaller,
  id: string,
  q: Pick<ScimListQuery, 'attributes' | 'excludedAttributes'> = { attributes: null },
): Promise<Partial<ScimGroupResource>> {
  const db = caller.tx ?? caller.deps.db;
  const group = await loadGroup(db, caller, id, false);
  const excluded = q.excludedAttributes ?? [];
  const members = showsMembers(q.attributes, excluded)
    ? ((await membersOf(db, [group.id])).get(group.id) ?? [])
    : null;
  return project(groupResource(group, members, caller.baseUrl), q.attributes, excluded);
}

// ─── Writing ────────────────────────────────────────────────────────────────

/**
 * `POST /Groups` (spec §12.7, 201): `displayName` unique ignoring case and `externalId` unique on
 * the connection (409). Members that are not Users of this connection are ignored and counted.
 */
export async function createGroup(caller: ScimCaller, body: unknown): Promise<ScimGroupResource> {
  const input = groupFromResource(body);
  return inTransaction(caller, async (tx) => {
    await assertNamesFree(tx, caller, input, null);
    const [group] = await tx
      .insert(scimGroups)
      .values({
        connectionId: caller.connectionId,
        displayName: input.displayName,
        externalId: input.externalId,
      })
      .returning();
    if (!group) throw new Error('scim group insert returned nothing');
    const resolved = await resolveMembers(tx, caller, input.members);
    const ids = [...resolved.keys()];
    await addMembers(tx, group.id, ids);
    await syncPeople(tx, caller, ids);
    await caller.deps.audit.record(tx, SYSTEM_ACTOR, [
      {
        action: 'scim.group_created',
        target: { type: 'scim_group', id: group.id, label: group.displayName },
        details: {
          ...scimDetails(caller),
          displayName: group.displayName,
          members: ids.length,
          unknownMembers: unknownCount(input.members, resolved),
        },
      },
    ]);
    return resourceOf(tx, caller, group);
  });
}

/**
 * Applies a new name and member set to a locked group: the writes, group sync for every person
 * whose groups changed (all members after a rename, since the mapped value may change), and
 * `scim.group_updated` when anything changed.
 */
async function writeGroup(
  tx: Executor,
  caller: ScimCaller,
  group: ScimGroupRow,
  change: {
    displayName: string;
    externalId: string | null;
    add: string[];
    remove: string[];
    unknownMembers: number;
    after: Set<string>;
  },
): Promise<ScimGroupResource> {
  if (change.after.size > MAX_GROUP_MEMBERS) throw tooManyMembers();
  const renamed =
    change.displayName !== group.displayName || change.externalId !== group.externalId;
  if (renamed) await assertNamesFree(tx, caller, change, group.id);
  let next = group;
  if (renamed || change.add.length > 0 || change.remove.length > 0) {
    const [row] = await tx
      .update(scimGroups)
      .set({ displayName: change.displayName, externalId: change.externalId })
      .where(eq(scimGroups.id, group.id))
      .returning();
    if (row) next = row;
  }
  await addMembers(tx, group.id, change.add);
  await removeMembers(tx, group.id, change.remove);
  await syncPeople(
    tx,
    caller,
    renamed ? [...change.after, ...change.remove] : [...change.add, ...change.remove],
  );
  if (renamed || change.add.length > 0 || change.remove.length > 0) {
    await caller.deps.audit.record(tx, SYSTEM_ACTOR, [
      {
        action: 'scim.group_updated',
        target: { type: 'scim_group', id: next.id, label: next.displayName },
        details: {
          ...scimDetails(caller),
          displayName: next.displayName,
          membersAdded: change.add.length,
          membersRemoved: change.remove.length,
          unknownMembers: change.unknownMembers,
          renamed,
        },
      },
    ]);
  }
  return resourceOf(tx, caller, next);
}

/** `PUT /Groups/{id}`: the body replaces the name, `externalId` and the whole member list. */
export async function replaceGroup(
  caller: ScimCaller,
  id: string,
  body: unknown,
): Promise<ScimGroupResource> {
  const input = groupFromResource(body);
  return inTransaction(caller, async (tx) => {
    const group = await loadGroup(tx, caller, id, true);
    const current = await memberIds(tx, group.id);
    const resolved = await resolveMembers(tx, caller, input.members);
    const after = new Set(resolved.keys());
    return writeGroup(tx, caller, group, {
      displayName: input.displayName,
      externalId: input.externalId,
      add: [...after].filter((m) => !current.has(m)),
      remove: [...current].filter((m) => !after.has(m)),
      unknownMembers: unknownCount(input.members, resolved),
      after,
    });
  });
}

/**
 * `PATCH /Groups/{id}` (spec §12.7): `add`/`remove` of members (Entra's `members[value eq "…"]`
 * too), `replace` of `displayName`, `externalId` or the whole member list; at most 1 000 member
 * changes (400 `tooMany`, the PATCH engine's bound).
 */
export async function patchGroup(
  caller: ScimCaller,
  id: string,
  body: unknown,
): Promise<ScimGroupResource> {
  const patch = applyGroupPatch(body);
  return inTransaction(caller, async (tx) => {
    const group = await loadGroup(tx, caller, id, true);
    const current = await memberIds(tx, group.id);
    let after: Set<string>;
    let unknownMembers: number;
    if (patch.replaceMembers !== null) {
      const resolved = await resolveMembers(tx, caller, patch.replaceMembers);
      after = new Set(resolved.keys());
      unknownMembers = unknownCount(patch.replaceMembers, resolved);
    } else {
      const adding = await resolveMembers(tx, caller, patch.add);
      const removing = await resolveMembers(tx, caller, patch.remove);
      after = new Set(current);
      for (const m of adding.keys()) after.add(m);
      for (const m of removing.keys()) after.delete(m);
      unknownMembers = unknownCount(patch.add, adding) + unknownCount(patch.remove, removing);
    }
    return writeGroup(tx, caller, group, {
      displayName:
        patch.displayName === undefined
          ? group.displayName
          : text(patch.displayName, 'displayName'),
      externalId:
        patch.externalId === undefined
          ? group.externalId
          : patch.externalId === null
            ? null
            : text(patch.externalId, 'externalId'),
      add: [...after].filter((m) => !current.has(m)),
      remove: [...current].filter((m) => !after.has(m)),
      unknownMembers,
      after,
    });
  });
}

/** `DELETE /Groups/{id}` (204): the group and its memberships go, and its members are synced. */
export async function deleteGroup(caller: ScimCaller, id: string): Promise<void> {
  await inTransaction(caller, async (tx) => {
    const group = await loadGroup(tx, caller, id, true);
    const former = [...(await memberIds(tx, group.id))];
    await tx.delete(scimGroups).where(eq(scimGroups.id, group.id));
    await syncPeople(tx, caller, former);
    await caller.deps.audit.record(tx, SYSTEM_ACTOR, [
      {
        action: 'scim.group_deleted',
        target: { type: 'scim_group', id: group.id, label: group.displayName },
        details: { ...scimDetails(caller), displayName: group.displayName, members: former.length },
      },
    ]);
  });
}

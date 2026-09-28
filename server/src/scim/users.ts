import { and, asc, count, eq, inArray, isNotNull, isNull, ne, sql, type SQL } from 'drizzle-orm';
import type { AuditEventInput } from '../audit/recorder';
import { SYSTEM_ACTOR } from '../audit/recorder';
import { deleteUserSessions } from '../auth/sessions';
import type { Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgConstraint, pgErrorCode } from '../db/errors';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import {
  apiTokens,
  identities,
  memberships,
  organizations,
  projectMemberships,
  scimGroupMembers,
  scimGroups,
  sessions,
  ssoGroupMappings,
  users,
  type IdentityRow,
  type ScimName,
} from '../db/schema';
import { ProblemError } from '../http/problem';
import type { LoadedConnection } from '../sso/connections';
import { MAX_GROUP_VALUES, syncGroupMemberships } from '../sso/groups';
import { assertBreakGlassKept } from '../sso/sign-in-policy';
import { deriveUsername, withSuffix } from '../sso/username';
import { ScimError } from './errors';
import type { ScimFilter } from './filter';
import type { ScimDeps } from './handle';
import { applyUserPatch, PATCH_OP_SCHEMA, type UserState } from './patch';
import {
  listResponse,
  project,
  userResource,
  type ListResponse,
  type ScimUserResource,
} from './representation';

/** Who is calling: the token, its connection, and (optionally) the transaction to run in. */
export interface ScimCaller {
  deps: ScimDeps;
  tx?: Executor;
  tokenId: string;
  connectionId: string;
  connection: LoadedConnection;
  baseUrl: string;
}

export interface ScimListQuery {
  filter: ScimFilter;
  startIndex: number;
  count: number;
  attributes: string[] | null;
  excludedAttributes?: string[];
}

/** spec §8.4: `-2` … `-20`. */
const MAX_SUFFIX = 20;
const DISPLAY_NAME_MAX = 255;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** No control character (U+0000–U+001F, U+007F–U+009F). */
export const CONTROL = /\p{Cc}/u;
/** spec §12.4, the detail of a refused email. */
export const EMAIL_IN_USE =
  "The email belongs to an existing Qualor account; enable linking by verified email on the connection, or change that account's email";

type UserRow = typeof users.$inferSelect;

// ─── Shared with groups.ts ──────────────────────────────────────────────────

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A member by name, ignoring case (RFC 7643 §2.1). */
export function member(record: Record<string, unknown>, name: string): unknown {
  const lower = name.toLowerCase();
  for (const key of Object.keys(record)) {
    if (key.toLowerCase() === lower) return record[key];
  }
  return undefined;
}

/** spec §12.8: every SCIM event names its token and connection. */
export const scimDetails = (caller: ScimCaller) => ({
  scimTokenId: caller.tokenId,
  connectionId: caller.connectionId,
});

const UNIQUE_DETAILS: Record<string, string> = {
  identities_connection_scim_user_name_key: 'userName is already in use on this connection',
  identities_connection_scim_external_id_key: 'externalId is already in use on this connection',
  identities_connection_user_key: 'That Qualor account already has a SCIM user on this connection',
  users_email_unique: EMAIL_IN_USE,
  scim_groups_display_name_key: 'displayName is already in use on this connection',
  scim_groups_external_id_key: 'externalId is already in use on this connection',
};

/**
 * Runs `fn` in the caller's transaction, or in a new one. A unique violation (a concurrent
 * request took the value between the check and the write) is a 409 `uniqueness`, never a 500.
 */
export async function inTransaction<T>(
  caller: ScimCaller,
  fn: (tx: Executor) => Promise<T>,
): Promise<T> {
  try {
    return caller.tx ? await fn(caller.tx) : await caller.deps.db.transaction(fn);
  } catch (err) {
    if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) {
      const detail = UNIQUE_DETAILS[pgConstraint(err) ?? ''];
      if (detail) throw new ScimError(409, 'uniqueness', detail);
    }
    throw err;
  }
}

const uniqueness = (detail: string) => new ScimError(409, 'uniqueness', detail);
const notFoundUser = () => new ScimError(404, null, 'User not found');

/**
 * LOCKS.scimSync for each person, sorted: one sync of a person at a time, so a sync reads the
 * person's SCIM groups only after every concurrent change of them committed. Lock order everywhere:
 * row locks on groups and identities, then these, then organisations (row locks), then projects
 * (LOCKS.projectGrants); LOCKS.instanceAdmins, when taken, comes first of all.
 */
export async function lockPeople(tx: Executor, identityIds: Iterable<string>): Promise<void> {
  for (const id of [...new Set(identityIds)].sort()) {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.scimSync}, hashtext(${id}))`);
  }
}

/**
 * Before a request syncs several people: every organisation and project their syncs may lock
 * (the connection's mappings, and the memberships it manages for them), in sync's own order
 * (organisations sorted, then projects sorted). Each sync then only re-takes locks it holds, so two
 * requests syncing different people never lock the same organisations in opposite orders.
 */
export async function lockSyncTargets(
  tx: Executor,
  caller: ScimCaller,
  userIds: readonly string[],
): Promise<void> {
  if (caller.connection.parsed.config.groupSource !== 'scim' || userIds.length === 0) return;
  const mapped = await tx
    .select({
      organizationId: ssoGroupMappings.organizationId,
      projectId: ssoGroupMappings.projectId,
    })
    .from(ssoGroupMappings)
    .where(eq(ssoGroupMappings.connectionId, caller.connectionId));
  const orgs = new Set(mapped.map((m) => m.organizationId));
  const projectIds = new Set(mapped.flatMap((m) => (m.projectId === null ? [] : [m.projectId])));
  for (const part of chunk(userIds)) {
    const managed = await tx
      .select({ organizationId: memberships.organizationId })
      .from(memberships)
      .where(
        and(
          eq(memberships.managedByConnectionId, caller.connectionId),
          inArray(memberships.userId, part),
        ),
      );
    for (const m of managed) orgs.add(m.organizationId);
    const managedProjects = await tx
      .select({ projectId: projectMemberships.projectId })
      .from(projectMemberships)
      .where(
        and(
          eq(projectMemberships.managedByConnectionId, caller.connectionId),
          inArray(projectMemberships.userId, part),
        ),
      );
    for (const m of managedProjects) projectIds.add(m.projectId);
  }
  for (const id of [...orgs].sort()) {
    await tx
      .select({ id: organizations.id })
      .from(organizations)
      .where(eq(organizations.id, id))
      .for('no key update');
  }
  for (const id of [...projectIds].sort()) {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.projectGrants}, hashtext(${id}))`);
  }
}

const CHUNK = 1_000;
function chunk<T>(list: readonly T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += CHUNK) out.push(list.slice(i, i + CHUNK));
  return out;
}

/**
 * spec §9.1, §9.2 (ruling: a group's `externalId`, else its `displayName`): when the connection's
 * `groupSource` is `scim`, turns the identity's SCIM groups into memberships (§9.3). Sync owns only
 * the rows it manages (SS5). The person's groups are read under their LOCKS.scimSync (re-entrant:
 * a caller syncing several people has taken them all already, sorted).
 */
export async function syncIdentity(
  tx: Executor,
  caller: ScimCaller,
  person: { identityId: string; userId: string; username: string },
): Promise<void> {
  if (caller.connection.parsed.config.groupSource !== 'scim') return;
  await lockPeople(tx, [person.identityId]);
  const rows = await tx
    .select({ externalId: scimGroups.externalId, displayName: scimGroups.displayName })
    .from(scimGroupMembers)
    .innerJoin(scimGroups, eq(scimGroups.id, scimGroupMembers.groupId))
    .where(
      and(
        eq(scimGroupMembers.identityId, person.identityId),
        eq(scimGroups.connectionId, caller.connectionId),
      ),
    );
  if (rows.length > MAX_GROUP_VALUES) {
    throw new ScimError(
      400,
      'tooMany',
      `A user can be in at most ${MAX_GROUP_VALUES} groups of a connection`,
    );
  }
  const { audit, log } = caller.deps;
  await syncGroupMemberships(tx, {
    connectionId: caller.connectionId,
    userId: person.userId,
    username: person.username,
    groups: rows.map((r) => r.externalId ?? r.displayName),
    audit,
    log,
  });
}

/**
 * One writer of instance-admin state at a time (PATCH /users takes the same lock first). Every
 * SCIM user write takes it before any row lock, so the order is the same everywhere.
 */
async function lockInstanceAdmins(tx: Executor): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.instanceAdmins})`);
}

// ─── Reading ────────────────────────────────────────────────────────────────

/** The SCIM Users of this connection: identities with a SCIM record (spec §12.3). */
const ofConnection = (caller: ScimCaller) =>
  and(eq(identities.connectionId, caller.connectionId), isNotNull(identities.scimUserName));

/**
 * The lock a write takes on the rows. `write` (PUT, PATCH) is FOR NO KEY UPDATE on the identity
 * and the user: it never blocks the KEY SHARE a concurrent group write takes (a member row's
 * foreign key, a sync's membership insert), which could otherwise wait on this request while this
 * request waits on its LOCKS.scimSync. `delete` is FOR UPDATE on the identity only (it is deleted).
 */
type RowLock = 'none' | 'write' | 'delete';

async function loadUser(
  tx: Executor,
  caller: ScimCaller,
  id: string,
  lock: RowLock,
): Promise<{ identity: IdentityRow; user: UserRow }> {
  if (!UUID.test(id)) throw notFoundUser();
  const query = tx
    .select({ identity: identities, user: users })
    .from(identities)
    .innerJoin(users, eq(users.id, identities.userId))
    .where(and(ofConnection(caller), eq(identities.id, id)));
  const [row] =
    lock === 'write'
      ? await query.for('no key update')
      : lock === 'delete'
        ? await query.for('update', { of: identities })
        : await query;
  if (!row) throw notFoundUser();
  return row;
}

function filterWhere(filter: ScimFilter): SQL | undefined | 'none' {
  if (filter === null) return undefined;
  switch (filter.attribute) {
    case 'userName':
      return sql`${identities.scimUserName} = ${filter.value}::citext`;
    case 'externalId':
      return eq(identities.scimExternalId, filter.value);
    case 'emails.value':
      return sql`${users.email} = ${filter.value}::citext`;
    case 'id':
      // A malformed id matches nothing (never a 400 or a cast error).
      return UUID.test(filter.value) ? eq(identities.id, filter.value) : 'none';
    default:
      return 'none';
  }
}

/** `GET /Users` (spec §12.5): one `eq` filter, paged by creation time, then id. */
export async function listUsers(
  caller: ScimCaller,
  q: ScimListQuery,
): Promise<ListResponse<Partial<ScimUserResource>>> {
  const db = caller.tx ?? caller.deps.db;
  const extra = filterWhere(q.filter);
  if (extra === 'none') return listResponse([], 0, q.startIndex);
  const where = and(ofConnection(caller), extra);
  const [total] = await db
    .select({ n: count() })
    .from(identities)
    .innerJoin(users, eq(users.id, identities.userId))
    .where(where);
  const n = total?.n ?? 0;
  if (q.count === 0 || n === 0) return listResponse([], n, q.startIndex);
  const rows = await db
    .select({ identity: identities, user: users })
    .from(identities)
    .innerJoin(users, eq(users.id, identities.userId))
    .where(where)
    .orderBy(asc(identities.createdAt), asc(identities.id))
    .offset(q.startIndex - 1)
    .limit(q.count);
  return listResponse(
    rows.map((r) =>
      project(userResource(r.identity, r.user, caller.baseUrl), q.attributes, q.excludedAttributes),
    ),
    n,
    q.startIndex,
  );
}

/** `GET /Users/{id}`: another connection's user, or a malformed id, is 404. */
export async function getUser(
  caller: ScimCaller,
  id: string,
  q: Pick<ScimListQuery, 'attributes' | 'excludedAttributes'> = { attributes: null },
): Promise<Partial<ScimUserResource>> {
  const { identity, user } = await loadUser(caller.tx ?? caller.deps.db, caller, id, 'none');
  return project(userResource(identity, user, caller.baseUrl), q.attributes, q.excludedAttributes);
}

// ─── The state ──────────────────────────────────────────────────────────────

const EMPTY: UserState = {
  userName: '',
  externalId: null,
  displayName: null,
  name: {},
  email: null,
  active: true,
};

/**
 * A whole User resource (POST, PUT) as a state: its members applied as a pathless replace onto an
 * empty state, so the PATCH engine's rules hold (unknown and extension attributes ignored, Entra's
 * string booleans read, absent optional attributes cleared, `active` absent = true).
 */
function stateFromResource(body: unknown): UserState {
  if (!isRecord(body)) throw new ScimError(400, 'invalidSyntax', 'The body must be a User');
  const userName = member(body, 'userName');
  if (typeof userName !== 'string' || userName === '') {
    throw new ScimError(400, 'invalidValue', 'userName is required');
  }
  return applyUserPatch(EMPTY, {
    schemas: [PATCH_OP_SCHEMA],
    Operations: [{ op: 'replace', value: body }],
  });
}

/** The rules the PATCH engine leaves to the store: `userName` without control characters. */
function checkState(state: UserState): void {
  if (state.userName === '') throw new ScimError(400, 'invalidValue', 'userName is required');
  if (CONTROL.test(state.userName)) {
    throw new ScimError(400, 'invalidValue', 'userName cannot hold control characters');
  }
}

function stateOf(identity: IdentityRow, user: UserRow): UserState {
  return {
    userName: identity.scimUserName ?? '',
    externalId: identity.scimExternalId,
    displayName: user.displayName,
    name: { ...identity.scimName },
    email: user.email,
    active: user.active,
  };
}

/** spec §12.4: `displayName`, else `name.formatted`, else given and family names joined. */
function storedDisplayName(state: UserState): string | null {
  const joined = [state.name.givenName, state.name.familyName]
    .filter((p): p is string => typeof p === 'string' && p !== '')
    .join(' ');
  const value = state.displayName ?? state.name.formatted ?? (joined === '' ? null : joined);
  if (value === null || value === '') return null;
  return [...value].slice(0, DISPLAY_NAME_MAX).join('');
}

const sameName = (a: ScimName, b: ScimName) =>
  a.givenName === b.givenName && a.familyName === b.familyName && a.formatted === b.formatted;

const lower = (v: string | null) => v?.toLowerCase() ?? null;

async function userNameTaken(
  tx: Executor,
  caller: ScimCaller,
  userName: string,
  except: string | null,
): Promise<boolean> {
  const [row] = await tx
    .select({ id: identities.id })
    .from(identities)
    .where(
      and(
        eq(identities.connectionId, caller.connectionId),
        sql`${identities.scimUserName} = ${userName}::citext`,
        except === null ? undefined : ne(identities.id, except),
      ),
    );
  return row !== undefined;
}

async function externalIdTaken(
  tx: Executor,
  caller: ScimCaller,
  externalId: string,
  except: string | null,
): Promise<boolean> {
  const [row] = await tx
    .select({ id: identities.id })
    .from(identities)
    .where(
      and(
        eq(identities.connectionId, caller.connectionId),
        eq(identities.scimExternalId, externalId),
        except === null ? undefined : ne(identities.id, except),
      ),
    );
  return row !== undefined;
}

async function emailOwner(tx: Executor, email: string): Promise<UserRow | undefined> {
  const [row] = await tx
    .select()
    .from(users)
    .where(sql`${users.email} = ${email}::citext`);
  return row;
}

/**
 * spec §12.6, deactivating (or deleting) the last active instance admin, or the last
 * usable break-glass admin while the stored policy is `break_glass_only` (§10.3), is 400
 * `mutability`. Under LOCKS.instanceAdmins, which the caller already holds.
 */
async function assertMayDeactivate(tx: Executor, user: UserRow): Promise<void> {
  if (user.isInstanceAdmin && user.active) {
    const [other] = await tx
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.isInstanceAdmin, true), eq(users.active, true), ne(users.id, user.id)))
      .limit(1);
    if (!other) {
      throw new ScimError(
        400,
        'mutability',
        'The last active instance administrator cannot be deactivated',
      );
    }
  }
  try {
    await assertBreakGlassKept(tx, { userId: user.id, active: false });
  } catch (err) {
    if (err instanceof ProblemError && err.code === 'LAST_BREAK_GLASS_ADMIN') {
      throw new ScimError(
        400,
        'mutability',
        'The last break-glass administrator cannot be deactivated while password sign-in is limited',
      );
    }
    throw err;
  }
}

/**
 * spec §12.6: every session of the user ends and every personal token is revoked (`revoked_at`
 * set, so a reactivation does not bring them back). The counts, for the audit event.
 */
async function endAccess(
  tx: Executor,
  userId: string,
): Promise<{ sessionsEnded: number; tokensRevoked: number }> {
  const [live] = await tx.select({ n: count() }).from(sessions).where(eq(sessions.userId, userId));
  await deleteUserSessions(tx, userId);
  const revoked = await tx
    .update(apiTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(
        eq(apiTokens.userId, userId),
        eq(apiTokens.kind, 'personal'),
        isNull(apiTokens.revokedAt),
      ),
    )
    .returning({ id: apiTokens.id });
  return { sessionsEnded: live?.n ?? 0, tokensRevoked: revoked.length };
}

const userTarget = (user: UserRow) => ({
  type: 'user' as const,
  id: user.id,
  label: user.username,
});

/**
 * Writes `after` over `before` (PUT and PATCH, spec §12.4–§12.6), in `tx` under the instance-admin
 * lock: uniqueness (409), the deactivation rules (400 `mutability`), then the identity's SCIM
 * record and the user's profile. A deactivation ends sessions and revokes personal tokens; a
 * reactivation syncs groups. Never changes `is_instance_admin`.
 */
async function applyUserState(
  tx: Executor,
  caller: ScimCaller,
  identity: IdentityRow,
  user: UserRow,
  before: UserState,
  after: UserState,
): Promise<{ identity: IdentityRow; user: UserRow }> {
  checkState(after);
  const deactivate = before.active && !after.active;
  const reactivate = !before.active && after.active;
  if (deactivate) await assertMayDeactivate(tx, user);
  if (
    lower(after.userName) !== lower(before.userName) &&
    (await userNameTaken(tx, caller, after.userName, identity.id))
  ) {
    throw uniqueness('userName is already in use on this connection');
  }
  if (
    after.externalId !== null &&
    after.externalId !== before.externalId &&
    (await externalIdTaken(tx, caller, after.externalId, identity.id))
  ) {
    throw uniqueness('externalId is already in use on this connection');
  }
  if (after.email !== null && lower(after.email) !== lower(before.email)) {
    const owner = await emailOwner(tx, after.email);
    if (owner && owner.id !== user.id)
      throw uniqueness('The email belongs to another Qualor account');
  }

  let nextIdentity = identity;
  if (
    after.userName !== before.userName ||
    after.externalId !== before.externalId ||
    !sameName(after.name, before.name)
  ) {
    nextIdentity = first(
      await tx
        .update(identities)
        .set({
          scimUserName: after.userName,
          scimExternalId: after.externalId,
          scimName: after.name,
        })
        .where(eq(identities.id, identity.id))
        .returning(),
    );
  }
  const displayName =
    after.displayName === before.displayName && sameName(after.name, before.name)
      ? user.displayName
      : storedDisplayName(after);
  let nextUser = user;
  if (
    displayName !== user.displayName ||
    after.email !== user.email ||
    after.active !== user.active
  ) {
    nextUser = first(
      await tx
        .update(users)
        .set({ displayName, email: after.email, active: after.active })
        .where(eq(users.id, user.id))
        .returning(),
    );
  }

  const events: AuditEventInput[] = [];
  const changes = [
    { field: 'userName' as const, from: identity.scimUserName, to: nextIdentity.scimUserName },
    { field: 'displayName' as const, from: user.displayName, to: nextUser.displayName },
    { field: 'email' as const, from: user.email, to: nextUser.email },
    {
      field: 'externalId' as const,
      from: identity.scimExternalId,
      to: nextIdentity.scimExternalId,
    },
  ].filter((c) => c.from !== c.to);
  if (changes.length > 0) {
    events.push({
      action: 'scim.user_updated',
      target: userTarget(nextUser),
      details: { ...scimDetails(caller), changes },
    });
  }
  if (deactivate) {
    const counts = await endAccess(tx, user.id);
    events.push({
      action: 'scim.user_deactivated',
      target: userTarget(nextUser),
      details: { ...scimDetails(caller), ...counts },
    });
  }
  if (reactivate) {
    events.push({
      action: 'scim.user_reactivated',
      target: userTarget(nextUser),
      details: scimDetails(caller),
    });
  }
  // rbac-audit.md §10.2.1: a deactivation alone goes through a malformed anchor; with other
  // changes the recorder refuses, and the request is a 409.
  if (events.length > 0) {
    await caller.deps.audit.recordOrSkipWhenAnchorMalformed(tx, SYSTEM_ACTOR, events);
  }
  if (reactivate) {
    await syncIdentity(tx, caller, {
      identityId: identity.id,
      userId: user.id,
      username: nextUser.username,
    });
  }
  return { identity: nextIdentity, user: nextUser };
}

// ─── Writing ────────────────────────────────────────────────────────────────

/**
 * `POST /Users` (spec §12.4, 201). A `userName` or `externalId` already on the connection is 409.
 * An email that belongs to a user links to that user only with `linkByEmail` on, the user active,
 * not an instance admin and without an identity here; otherwise 409 with EMAIL_IN_USE. Else a new
 * user as JIT makes one (no password), and the identity with its SCIM record and no subject.
 */
export async function createUser(caller: ScimCaller, body: unknown): Promise<ScimUserResource> {
  const state = stateFromResource(body);
  checkState(state);
  return inTransaction(caller, async (tx) => {
    await lockInstanceAdmins(tx);
    if (await userNameTaken(tx, caller, state.userName, null)) {
      throw uniqueness('userName is already in use on this connection');
    }
    if (state.externalId !== null && (await externalIdTaken(tx, caller, state.externalId, null))) {
      throw uniqueness('externalId is already in use on this connection');
    }
    let user: UserRow | undefined;
    let linkedExisting = false;
    if (state.email !== null) {
      const owner = await emailOwner(tx, state.email);
      if (owner) {
        const [here] = await tx
          .select({ id: identities.id })
          .from(identities)
          .where(
            and(eq(identities.connectionId, caller.connectionId), eq(identities.userId, owner.id)),
          );
        const may =
          caller.connection.parsed.config.linkByEmail &&
          owner.active &&
          !owner.isInstanceAdmin &&
          here === undefined;
        if (!may) throw uniqueness(EMAIL_IN_USE);
        user = owner;
        linkedExisting = true;
      }
    }
    if (!user) {
      // spec §12.4: the username from userName's local part, as JIT derives it (§8.4).
      const local = state.userName.split('@', 1)[0] ?? '';
      const base = deriveUsername({ username: local, email: state.email });
      for (let n = 1; n <= MAX_SUFFIX && !user; n += 1) {
        [user] = await tx
          .insert(users)
          .values({
            username: n === 1 ? base : withSuffix(base, n),
            email: state.email,
            displayName: storedDisplayName(state),
            passwordHash: null,
            passwordChangeRequired: false,
            isInstanceAdmin: false,
            active: state.active,
          })
          // Any unique conflict: the name (the next suffix) or the email (taken meanwhile).
          .onConflictDoNothing()
          .returning();
        if (!user && state.email !== null && (await emailOwner(tx, state.email))) {
          throw uniqueness(EMAIL_IN_USE);
        }
      }
      if (!user) throw uniqueness('No free Qualor username could be derived from userName');
    }
    const identity = first(
      await tx
        .insert(identities)
        .values({
          connectionId: caller.connectionId,
          userId: user.id,
          subject: null,
          linkedBy: 'scim',
          scimUserName: state.userName,
          scimExternalId: state.externalId,
          scimName: state.name,
        })
        .returning(),
    );
    await caller.deps.audit.record(tx, SYSTEM_ACTOR, [
      {
        action: 'scim.user_created',
        target: userTarget(user),
        details: { ...scimDetails(caller), linkedExisting },
      },
    ]);
    let result = { identity, user };
    if (linkedExisting) {
      // The linked account's profile now follows the IdP, audited like any SCIM change.
      result = await applyUserState(tx, caller, identity, user, stateOf(identity, user), state);
    }
    await syncIdentity(tx, caller, {
      identityId: identity.id,
      userId: user.id,
      username: user.username,
    });
    return userResource(result.identity, result.user, caller.baseUrl);
  });
}

/** `PUT /Users/{id}`: the body replaces the stored attributes (absent optional ones cleared). */
export async function replaceUser(
  caller: ScimCaller,
  id: string,
  body: unknown,
): Promise<ScimUserResource> {
  const after = stateFromResource(body);
  return inTransaction(caller, async (tx) => {
    await lockInstanceAdmins(tx);
    const { identity, user } = await loadUser(tx, caller, id, 'write');
    await lockPeople(tx, [identity.id]);
    const next = await applyUserState(tx, caller, identity, user, stateOf(identity, user), after);
    return userResource(next.identity, next.user, caller.baseUrl);
  });
}

/** `PATCH /Users/{id}` (spec §12.6): the operations in order, all or nothing. */
export async function patchUser(
  caller: ScimCaller,
  id: string,
  body: unknown,
): Promise<ScimUserResource> {
  return inTransaction(caller, async (tx) => {
    await lockInstanceAdmins(tx);
    const { identity, user } = await loadUser(tx, caller, id, 'write');
    await lockPeople(tx, [identity.id]);
    const before = stateOf(identity, user);
    const after = applyUserPatch(before, body);
    const next = await applyUserState(tx, caller, identity, user, before, after);
    return userResource(next.identity, next.user, caller.baseUrl);
  });
}

/**
 * `DELETE /Users/{id}` (spec §12.6, 204): deactivates (the same refusals), removes the
 * identity from the connection's SCIM groups (syncing with what remains), deletes the identity
 * and records `scim.user_deleted`. The user row stays.
 */
export async function deleteUser(caller: ScimCaller, id: string): Promise<void> {
  await inTransaction(caller, async (tx) => {
    await lockInstanceAdmins(tx);
    const { identity, user } = await loadUser(tx, caller, id, 'delete');
    if (user.active) {
      await assertMayDeactivate(tx, user);
      await tx.update(users).set({ active: false }).where(eq(users.id, user.id));
    }
    const counts = await endAccess(tx, user.id);
    await tx.delete(scimGroupMembers).where(eq(scimGroupMembers.identityId, identity.id));
    // LOCKS.scimSync after the member rows went (syncIdentity takes it), as a group write does: a
    // group write holding one of those rows never waits on this request's person lock.
    await syncIdentity(tx, caller, {
      identityId: identity.id,
      userId: user.id,
      username: user.username,
    });
    await tx.delete(identities).where(eq(identities.id, identity.id));
    await caller.deps.audit.recordOrSkipWhenAnchorMalformed(tx, SYSTEM_ACTOR, [
      {
        action: 'scim.user_deleted',
        target: userTarget(user),
        details: { ...scimDetails(caller), ...counts },
      },
    ]);
  });
}

import { and, asc, count, eq, inArray, isNull, ne, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import type { UserRow } from '../auth/sessions';
import type { Db, Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgErrorCode } from '../db/errors';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import {
  identities,
  scimGroupMembers,
  ssoConnections,
  users,
  type IdentityLinkMethod,
  type IdentityRow,
  type SsoProtocol,
} from '../db/schema';
import { conflict, notFound } from '../http/problem';
import type { Edition } from '../license/edition';
import { parseStoredConfig, type ConnectionConfig } from './connection-config';
import { inEffectConnectionIds } from './connections';
import { syncGroupMemberships } from './groups';
import { mayUsePassword, readSignInSettings } from './sign-in-policy';
import { deriveUsername, withSuffix } from './username';

/** What a validated OIDC or SAML sign-in says about the person (read from the verified token). */
export interface SignInClaims {
  subject: string;
  username: string | null;
  email: string | null;
  /** OIDC: `email_verified === true`; SAML: the connection's `emailVerified` (spec §8.3). */
  emailVerified: boolean;
  displayName: string | null;
  groups: string[];
  /** SAML: the assertion's NameID (the SCIM match's fallback, spec §8.2); absent for OIDC. */
  nameId?: string | null;
}

export type ResolveResult =
  | { ok: true; user: UserRow; identity: IdentityRow; created: boolean }
  | {
      ok: false;
      reason: 'no_account' | 'inactive_user' | 'email_in_use' | 'username_unavailable';
      userId: string | null;
    };

export type LinkResult =
  { ok: true; identity: IdentityRow } | { ok: false; reason: 'identity_in_use' | 'already_linked' };

/** spec §8.4: `-2` … `-20`. */
const MAX_SUFFIX = 20;
const DISPLAY_NAME_MAX = 255;
const EMAIL = z.email().max(320);
// eslint-disable-next-line no-control-regex -- removing control characters is the point
const CONTROL = /[\x00-\x1f\x7f-\x9f]/g;

/** Control characters removed, at most `max` code points, trimmed; empty becomes null. */
function clean(text: string | null, max: number): string | null {
  if (text === null) return null;
  const kept = [...text.replace(CONTROL, '')].slice(0, max).join('').trim();
  return kept.length > 0 ? kept : null;
}

/**
 * spec §8.3: the email only when the IdP verified it (for SAML, only when the connection says its
 * IdP does, whatever the caller passed) and it is a plausible address; otherwise null, never stored.
 */
function verifiedEmail(claims: SignInClaims, config: ConnectionConfig): string | null {
  if (!claims.emailVerified || claims.email === null) return null;
  if (config.protocol === 'saml' && !config.config.emailVerified) return null;
  const email = claims.email.trim();
  return EMAIL.safeParse(email).success ? email : null;
}

const EMAIL_NAME_ID = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

/**
 * §8.2 step 2's key, the value compared with a SCIM record's `userName`, or null for no match. OIDC:
 * the username claim, else the email only when the IdP verified it; SAML: the username attribute,
 * else the NameID, never the email attribute. An email never matches unverified, whatever it is
 * called: a username claim or attribute that is the email one counts only when the email is
 * verified (OIDC: `email_verified`; SAML: the connection's `emailVerified`), and so does a NameID of
 * the emailAddress format. An unverified email could be anyone's (A I-1).
 */
function scimMatchKey(claims: SignInClaims, config: ConnectionConfig): string | null {
  const names = config.config.claims;
  const usernameIsEmail = names.username !== null && names.username === names.email;
  if (config.protocol === 'oidc') {
    const verified = claims.emailVerified;
    const username = usernameIsEmail && !verified ? null : claims.username;
    return username ?? (verified ? claims.email : null);
  }
  const verified = config.config.emailVerified;
  const username = usernameIsEmail && !verified ? null : claims.username;
  if (username !== null) return username;
  if (config.config.nameIdFormat === EMAIL_NAME_ID && !verified) return null;
  return claims.nameId ?? null;
}

/** One IdP subject at a time (LOCKS.ssoSubject): resolution and linking never race each other. */
async function lockSubject(tx: Executor, connectionId: string, subject: string): Promise<void> {
  await tx.execute(
    sql`SELECT pg_advisory_xact_lock(${LOCKS.ssoSubject}, hashtext(${`${connectionId}:${subject}`}))`,
  );
}

async function emailTaken(tx: Executor, email: string): Promise<boolean> {
  const [taken] = await tx
    .select({ id: users.id })
    .from(users)
    .where(sql`${users.email} = ${email}::citext`);
  return taken !== undefined;
}

async function knownIdentity(
  tx: Executor,
  connectionId: string,
  subject: string,
): Promise<{ identity: IdentityRow; user: UserRow } | undefined> {
  const [row] = await tx
    .select({ identity: identities, user: users })
    .from(identities)
    .innerJoin(users, eq(users.id, identities.userId))
    .where(and(eq(identities.connectionId, connectionId), eq(identities.subject, subject)));
  return row;
}

const userTarget = (user: UserRow) => ({
  type: 'user' as const,
  id: user.id,
  label: user.username,
});

/**
 * sso-scim.md §8.2 for `intent: "sign_in"`, in order: the known identity, a SCIM record of this
 * connection, a verified email (`linkByEmail`), JIT (`jit`), else `no_account`. Never by username.
 * Runs in the caller's transaction, after the browser binding matched (SS4). Records
 * `sso.identity_linked` or `sso.user_provisioned`; logs nothing (claims may hold personal data).
 */
export async function resolveAccount(
  tx: Executor,
  input: {
    connectionId: string;
    config: ConnectionConfig;
    claims: SignInClaims;
    audit: AuditRecorder;
    actor: AuditActorContext;
  },
): Promise<ResolveResult> {
  const { connectionId, claims } = input;
  const settings = input.config.config;
  const email = verifiedEmail(claims, input.config);
  // Two first sign-ins of one subject: the second waits here, then finds the first's identity.
  await lockSubject(tx, connectionId, claims.subject);

  // 1. Known identity.
  let row = await knownIdentity(tx, connectionId, claims.subject);
  let created = false;

  // 2. A SCIM record of this connection without a subject, by its userName: the same IdP made it.
  if (!row) {
    const match = scimMatchKey(claims, input.config);
    if (match) {
      const [scim] = await tx
        .select({ identity: identities, user: users })
        .from(identities)
        .innerJoin(users, eq(users.id, identities.userId))
        .where(
          and(
            eq(identities.connectionId, connectionId),
            isNull(identities.subject),
            sql`${identities.scimUserName} = ${match}::citext`,
          ),
        );
      // An instance admin's record is never matched (§8.3's rule): an admin links with Link.
      if (scim?.user.isInstanceAdmin) {
        return { ok: false, reason: 'no_account', userId: null };
      }
      if (scim && !scim.user.active) {
        // Refused before anything is written: a deactivated record keeps no subject.
        return { ok: false, reason: 'inactive_user', userId: scim.user.id };
      }
      if (scim) {
        // `subject IS NULL` again: a concurrent sign-in of another subject may have taken it.
        const [identity] = await tx
          .update(identities)
          .set({ subject: claims.subject, linkedBy: 'scim_match' })
          .where(and(eq(identities.id, scim.identity.id), isNull(identities.subject)))
          .returning();
        if (identity) {
          row = { identity, user: scim.user };
          await input.audit.record(tx, input.actor, [
            {
              action: 'sso.identity_linked',
              target: userTarget(scim.user),
              details: { connectionId, method: 'scim_match' },
            },
          ]);
        }
      }
    }
  }

  // 3. Verified email (§8.3): the one active, non-instance-admin user with it, not yet linked here.
  if (!row && settings.linkByEmail && email) {
    const [target] = await tx
      .select()
      .from(users)
      .where(and(sql`${users.email} = ${email}::citext`, eq(users.active, true)));
    if (target && !target.isInstanceAdmin) {
      const [identity] = await tx
        .insert(identities)
        .values({
          connectionId,
          userId: target.id,
          subject: claims.subject,
          linkedBy: 'verified_email',
        })
        // The user already has an identity on this connection (or got one meanwhile): no link.
        .onConflictDoNothing()
        .returning();
      if (identity) {
        row = { identity, user: target };
        await input.audit.record(tx, input.actor, [
          {
            action: 'sso.identity_linked',
            target: userTarget(target),
            details: { connectionId, method: 'verified_email' },
          },
        ]);
      }
    }
  }

  // 4. JIT (§8.4): a new user, never an existing one of the same name.
  if (!row && settings.jit) {
    if (email && (await emailTaken(tx, email))) {
      return { ok: false, reason: 'email_in_use', userId: null };
    }
    const base = deriveUsername({ username: claims.username, email: claims.email });
    let user: UserRow | undefined;
    for (let n = 1; n <= MAX_SUFFIX && !user; n += 1) {
      [user] = await tx
        .insert(users)
        .values({
          username: n === 1 ? base : withSuffix(base, n),
          email,
          displayName: clean(claims.displayName, DISPLAY_NAME_MAX),
          passwordHash: null,
          passwordChangeRequired: false,
          isInstanceAdmin: false,
          active: true,
        })
        // Any unique conflict: the name (try the next suffix) or the email (taken meanwhile).
        .onConflictDoNothing()
        .returning();
      if (!user && email && (await emailTaken(tx, email))) {
        return { ok: false, reason: 'email_in_use', userId: null };
      }
    }
    if (!user) return { ok: false, reason: 'username_unavailable', userId: null };
    const identity = first(
      await tx
        .insert(identities)
        .values({ connectionId, userId: user.id, subject: claims.subject, linkedBy: 'jit' })
        .returning(),
    );
    await input.audit.record(tx, input.actor, [
      {
        action: 'sso.user_provisioned',
        target: userTarget(user),
        details: { connectionId, emailSet: email !== null },
      },
    ]);
    row = { identity, user };
    created = true;
  }

  if (!row) return { ok: false, reason: 'no_account', userId: null };
  if (!row.user.active) return { ok: false, reason: 'inactive_user', userId: row.user.id };

  // The identity's row before the user's, the order SCIM's writes and unlinking lock them in (a
  // new or matched identity is already locked by its own write): never a deadlock with them.
  await tx
    .select({ id: identities.id })
    .from(identities)
    .where(eq(identities.id, row.identity.id))
    .for('no key update');

  // The profile: the display name from the claim; a verified email nobody else has. Not an audited
  // `user.updated`: the IdP changed them, and the chain would fill with every rename there.
  let user = row.user;
  const displayName = clean(claims.displayName, DISPLAY_NAME_MAX);
  if (!created && displayName && displayName !== user.displayName) {
    user = first(
      await tx.update(users).set({ displayName }).where(eq(users.id, user.id)).returning(),
    );
  }
  if (
    !created &&
    email &&
    email.toLowerCase() !== (user.email ?? '').toLowerCase() &&
    !(await emailTaken(tx, email))
  ) {
    user = await setEmail(tx, user, email);
  }
  // `last_sign_in_at` is set with the session (issueSsoSession, §7.5), not here.
  return { ok: true, user, identity: row.identity, created };
}

/** The email, in a savepoint: another user taking it meanwhile leaves the old one (§8.2). */
async function setEmail(tx: Executor, user: UserRow, email: string): Promise<UserRow> {
  try {
    return await tx.transaction(async (sp) =>
      first(await sp.update(users).set({ email }).where(eq(users.id, user.id)).returning()),
    );
  } catch (err) {
    if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) return user;
    throw err;
  }
}

/**
 * spec §8.2 for `intent: "link"`: a signed-in user adds an identity on a connection. The subject
 * must not belong to another user (`identity_in_use`; the same user's link is `ok`), and the user
 * must have no identity on the connection (`already_linked`). Records `sso.identity_linked`.
 */
export async function linkIdentity(
  tx: Executor,
  input: {
    connectionId: string;
    userId: string;
    subject: string;
    audit: AuditRecorder;
    actor: AuditActorContext;
  },
): Promise<LinkResult> {
  const { connectionId, userId, subject } = input;
  await lockSubject(tx, connectionId, subject);
  // Twice at most: a conflicting insert of a concurrent link is committed, and seen, the second time.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const [bySubject] = await tx
      .select()
      .from(identities)
      .where(and(eq(identities.connectionId, connectionId), eq(identities.subject, subject)));
    if (bySubject) {
      return bySubject.userId === userId
        ? { ok: true, identity: bySubject }
        : { ok: false, reason: 'identity_in_use' };
    }
    const [byUser] = await tx
      .select({ id: identities.id })
      .from(identities)
      .where(and(eq(identities.connectionId, connectionId), eq(identities.userId, userId)));
    if (byUser) return { ok: false, reason: 'already_linked' };
    const [identity] = await tx
      .insert(identities)
      .values({ connectionId, userId, subject, linkedBy: 'user' })
      .onConflictDoNothing()
      .returning();
    if (identity) {
      const [user] = await tx
        .select({ id: users.id, username: users.username })
        .from(users)
        .where(eq(users.id, userId));
      await input.audit.record(tx, input.actor, [
        {
          action: 'sso.identity_linked',
          target: { type: 'user', id: userId, label: user?.username ?? null },
          details: { connectionId, method: 'user' },
        },
      ]);
      return { ok: true, identity };
    }
  }
  throw new Error('linkIdentity: the identity conflicted but neither row was found');
}

// ─── A user's identities (spec §17.1, §17.2) ────────────────────────────────

/** What the API shows of an identity: never the subject or the SCIM attributes. */
export interface IdentityView {
  id: string;
  connectionId: string;
  connectionName: string;
  protocol: SsoProtocol;
  linkedBy: IdentityLinkMethod;
  /** The identity carries a SCIM record: the IdP provisions it. */
  scim: boolean;
  createdAt: string;
  lastSignInAt: string | null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The user's identities, by connection name; 404 for an unknown user. */
export async function userIdentities(db: Executor, userId: string): Promise<IdentityView[]> {
  if (!UUID.test(userId)) throw notFound('User');
  const [user] = await db.select({ id: users.id }).from(users).where(eq(users.id, userId));
  if (!user) throw notFound('User');
  const rows = await db
    .select({ identity: identities, name: ssoConnections.name, protocol: ssoConnections.protocol })
    .from(identities)
    .innerJoin(ssoConnections, eq(ssoConnections.id, identities.connectionId))
    .where(eq(identities.userId, userId))
    .orderBy(asc(sql`lower(${ssoConnections.name})`), asc(identities.id));
  return rows.map(({ identity, name, protocol }) => ({
    id: identity.id,
    connectionId: identity.connectionId,
    connectionName: name,
    protocol,
    linkedBy: identity.linkedBy,
    scim: identity.scimUserName !== null,
    createdAt: identity.createdAt.toISOString(),
    lastSignInAt: identity.lastSignInAt?.toISOString() ?? null,
  }));
}

/**
 * spec §17.2: removes one identity of a user (the user themself, or an instance admin with
 * `byAdmin`). 404 unless the identity is the user's; 409 `SCIM_MANAGED_IDENTITY` for the user's
 * own unlink of an identity with a SCIM record; 409 `LAST_SIGN_IN_METHOD` when nothing else would
 * sign the user in: no password the policy lets them use (`mayUsePassword`, without the emergency
 * variable) and no other identity on a connection in effect (§4.4; nobody is locked out). With
 * the connection's `groupSource: scim`, the identity leaves its SCIM groups and the memberships
 * sync gave it are synced with what remains (§9.3, as SCIM's `DELETE /Users` does); the identity's
 * other rows go by cascade. Access-removing (rbac-audit.md §10.2.1): `sso.identity_unlinked` is
 * skipped, not the unlink, while the audit anchor is malformed.
 */
export async function unlinkIdentity(
  deps: {
    db: Db;
    audit: AuditRecorder;
    edition: Pick<Edition, 'isFeatureActive' | 'limits'>;
    log: { warn(obj: object, msg: string): void };
  },
  actor: AuditActorContext,
  userId: string,
  identityId: string,
  byAdmin: boolean,
): Promise<void> {
  if (!UUID.test(userId) || !UUID.test(identityId)) throw notFound('Identity');
  await deps.db.transaction(async (tx) => {
    // The identity first, then the user (the order SCIM's writes lock them in); the user's row
    // lock makes two unlinks of one user's identities see each other.
    const [identity] = await tx
      .select()
      .from(identities)
      .where(and(eq(identities.id, identityId), eq(identities.userId, userId)))
      .for('update');
    if (!identity) throw notFound('Identity');
    // The IdP provisions this identity (SCIM): only an instance admin may remove it; the person's
    // own unlink would be undone, or fight, the next SCIM change.
    if (!byAdmin && identity.scimUserName !== null) {
      throw conflict(
        'SCIM_MANAGED_IDENTITY',
        'Your identity provider manages this account link; ask an administrator to remove it',
      );
    }
    const [user] = await tx
      .select({
        id: users.id,
        username: users.username,
        active: users.active,
        isInstanceAdmin: users.isInstanceAdmin,
        hasPassword: sql<boolean>`${users.passwordHash} IS NOT NULL`,
      })
      .from(users)
      .where(eq(users.id, userId))
      .for('no key update');
    if (!user) throw notFound('Identity');
    // A password counts only while the policy lets it sign in (SS6), without the emergency
    // variable, which is meant to be removed again; another identity only on one in effect.
    const passwordUsable =
      user.hasPassword &&
      mayUsePassword(user, await readSignInSettings(tx), {
        sso: deps.edition.isFeatureActive('sso'),
        forced: false,
      }).allowed;
    // spec §4.4: only a connection in effect signs anyone in (without sso.multi, the oldest
    // enabled one), so only an identity on one counts.
    const inEffect = [...(await inEffectConnectionIds(tx, deps.edition))];
    const [others = { n: 0 }] =
      inEffect.length === 0
        ? []
        : await tx
            .select({ n: count() })
            .from(identities)
            .where(
              and(
                eq(identities.userId, userId),
                ne(identities.id, identityId),
                inArray(identities.connectionId, inEffect),
              ),
            );
    if (!passwordUsable && others.n === 0) {
      throw conflict(
        'LAST_SIGN_IN_METHOD',
        'This is the last way this user can sign in: set a password first',
      );
    }
    const [connection] = await tx
      .select({ protocol: ssoConnections.protocol, config: ssoConnections.config })
      .from(ssoConnections)
      .where(eq(ssoConnections.id, identity.connectionId));
    const parsed = connection ? parseStoredConfig(connection.protocol, connection.config) : null;
    if (parsed?.config.groupSource === 'scim') {
      await tx.delete(scimGroupMembers).where(eq(scimGroupMembers.identityId, identity.id));
      // The person's sync lock after the member rows went, as SCIM's DELETE /Users takes it.
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(${LOCKS.scimSync}, hashtext(${identity.id}))`,
      );
      await syncGroupMemberships(tx, {
        connectionId: identity.connectionId,
        userId: user.id,
        username: user.username,
        groups: [],
        audit: deps.audit,
        log: deps.log,
      });
    }
    await tx.delete(identities).where(eq(identities.id, identity.id));
    await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actor, [
      {
        action: 'sso.identity_unlinked',
        target: { type: 'user', id: user.id, label: user.username },
        details: { connectionId: identity.connectionId, byAdmin },
      },
    ]);
  });
}

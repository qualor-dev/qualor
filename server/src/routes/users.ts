import {
  and,
  asc,
  count,
  eq,
  gt,
  ilike,
  inArray,
  isNull,
  notExists,
  sql,
  type SQL,
} from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { USER_CHANGE_FIELDS } from '../audit/catalogue';
import { actorOf, type AuditEventInput } from '../audit/recorder';
import {
  accessOf,
  requireInstanceAdmin,
  requireMembersManager,
  requireOrganizationAccess,
  requireUser,
} from '../auth/access';
import {
  deleteAccountTokens,
  INVITATION_TTL_MINUTES,
  invitationsOf,
  issueAccountToken,
  type IssuedAccountToken,
} from '../auth/account-tokens';
import { hashPassword, newPasswordField } from '../auth/password';
import { deleteUserSessions, type UserRow } from '../auth/sessions';
import type { Executor, Tx } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgConstraint, pgErrorCode } from '../db/errors';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import { apiTokens, identities, memberships, projectMemberships, users } from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, type FieldError, forbidden, notFound, validationFailed } from '../http/problem';
import {
  idParams,
  NO_SSO,
  noContent,
  text,
  userDto,
  type UserDto,
  userSchema,
  type UserSsoSummary,
} from '../http/schemas';
import { likeLiteral, prefixPattern } from '../issues/query';
import {
  accountLink,
  accountMailState,
  INVITE_PATH,
  queuePasswordChangedNotice,
} from '../mail/account';
import { mailDeps, queueMail } from '../mail/outbox';
import { renderInvitationMail } from '../mail/templates/account-invitation';
import { instanceHost } from '../mail/templates/text';
import { USERNAME_PATTERN } from '../patterns';
import { projectForUser } from '../projects/access';
import {
  assertBreakGlassKept,
  effectivePasswordPolicy,
  readSignInSettings,
  type SignInLog,
} from '../sso/sign-in-policy';

const createUserBody = z.strictObject({
  username: z.string().regex(USERNAME_PATTERN),
  /** Required unless `invite`; with `invite` the user chooses it through the emailed link. */
  password: newPasswordField.optional(),
  displayName: text(255).optional(),
  email: z.email().max(320).optional(),
  isInstanceAdmin: z.boolean().default(false),
  /** Mail E2 A8: send an invitation email instead of setting an initial password. */
  invite: z.boolean().default(false),
});
const patchUserBody = z
  .strictObject({
    /** 0.16 issue #37: a new username; another user's name, ignoring case, is USERNAME_TAKEN. */
    username: z.string().regex(USERNAME_PATTERN).optional(),
    displayName: text(255).nullable().optional(),
    email: z.email().max(320).nullable().optional(),
    isInstanceAdmin: z.boolean().optional(),
    active: z.boolean().optional(),
    password: newPasswordField.optional(),
  })
  .refine((body) => Object.keys(body).length > 0, { message: 'At least one field is required' });

/**
 * sso-scim.md §16.2: each user's SSO identities (how many, and whether SCIM made one), for a page
 * of users in one grouped query; a user without identities gets NO_SSO.
 */
export async function userSsoSummaries(
  db: Executor,
  userIds: readonly string[],
): Promise<(userId: string) => UserSsoSummary> {
  const rows =
    userIds.length === 0
      ? []
      : await db
          .select({
            userId: identities.userId,
            identities: sql<number>`count(*)::int`,
            scim: sql<boolean>`bool_or(${identities.scimUserName} IS NOT NULL)`,
          })
          .from(identities)
          .where(inArray(identities.userId, [...userIds]))
          .groupBy(identities.userId);
  const byUser = new Map(rows.map((r) => [r.userId, { identities: r.identities, scim: r.scim }]));
  return (userId) => byUser.get(userId) ?? NO_SSO;
}

/** One user's SSO identities (userSsoSummaries for a single answer). */
export async function userSsoSummary(db: Executor, userId: string): Promise<UserSsoSummary> {
  return (await userSsoSummaries(db, [userId]))(userId);
}

function uniqueConflict(err: unknown) {
  if (pgErrorCode(err) !== PG_UNIQUE_VIOLATION) return null;
  return pgConstraint(err) === 'users_email_unique'
    ? conflict('EMAIL_TAKEN', 'That email address is already in use')
    : conflict('USERNAME_TAKEN', 'That username is already taken');
}

/**
 * 0.16 issue #37 (Claude): while QUALOR_DEMO_USER is set, a rename from or to the demo name,
 * ignoring case, is refused. Demo mode finds its account by name, so either rename would move
 * the read-only guard to another user.
 */
function assertDemoNameKept(demoUser: string | null, from: string, to: string): void {
  if (demoUser === null) return;
  const demo = demoUser.toLowerCase();
  if (from.toLowerCase() === demo || to.toLowerCase() === demo) {
    throw conflict(
      'DEMO_USER',
      'While the demo is on, the demo account keeps its username and no other user can take it',
    );
  }
}

type PatchUserBody = z.infer<typeof patchUserBody>;

/**
 * Re-reads the caller fresh, under the lock: their principal was resolved before the transaction
 * started and may since have been demoted (or deactivated) by a concurrent request that got here
 * first.
 */
async function assertCallerStillAdmin(tx: Tx, callerId: string): Promise<void> {
  const [caller] = await tx
    .select({ isInstanceAdmin: users.isInstanceAdmin, active: users.active })
    .from(users)
    .where(eq(users.id, callerId));
  if (!caller?.isInstanceAdmin || !caller.active) {
    throw forbidden('FORBIDDEN', 'Instance administrators only');
  }
}

async function loadExistingUser(tx: Tx, id: string) {
  const [existing] = await tx
    .select({
      username: users.username,
      displayName: users.displayName,
      email: users.email,
      active: users.active,
      isInstanceAdmin: users.isInstanceAdmin,
      hasPassword: sql<boolean>`${users.passwordHash} IS NOT NULL`,
    })
    .from(users)
    .where(eq(users.id, id));
  if (!existing) throw notFound('User');
  return existing;
}
type ExistingUser = Awaited<ReturnType<typeof loadExistingUser>>;

/**
 * The columns a PATCH sets. A username sent unchanged is no rename (letter case counts: it is the
 * stored spelling). It still goes into the set: a PATCH of only that name would otherwise make an
 * empty SET, which drizzle refuses (a 500); the UPDATE then sets the same value and the audit
 * diff lists nothing.
 */
function buildUserChanges(
  body: PatchUserBody,
  passwordHash: string | undefined,
  existing: ExistingUser,
  demoUser: string | null,
): Partial<typeof users.$inferInsert> {
  const changes: Partial<typeof users.$inferInsert> = {};
  if (body.username !== undefined) {
    if (body.username !== existing.username) {
      assertDemoNameKept(demoUser, existing.username, body.username);
    }
    changes.username = body.username;
  }
  if (body.displayName !== undefined) changes.displayName = body.displayName;
  if (body.email !== undefined) changes.email = body.email;
  if (body.isInstanceAdmin !== undefined) changes.isInstanceAdmin = body.isInstanceAdmin;
  if (body.active !== undefined) changes.active = body.active;
  if (passwordHash !== undefined) {
    changes.passwordHash = passwordHash;
    changes.passwordChangeRequired = true;
  }
  return changes;
}

/** The last active administrator, and the last usable break-glass one, must remain. */
async function assertAdminsRemain(tx: Tx, id: string, body: PatchUserBody): Promise<void> {
  const [admins] = await tx
    .select({ n: count() })
    .from(users)
    .where(and(eq(users.isInstanceAdmin, true), eq(users.active, true)));
  if ((admins?.n ?? 0) === 0) {
    throw conflict('LAST_ADMIN', 'At least one active instance administrator must remain');
  }
  // sso-scim.md §10.3: nor the last usable break-glass admin while the stored policy limits
  // password sign-in (whatever the licence or QUALOR_FORCE_PASSWORD_SIGN_IN say right now).
  await assertBreakGlassKept(tx, {
    userId: id,
    active: body.active,
    isInstanceAdmin: body.isInstanceAdmin,
  });
}

/** Sessions, pending mail links, personal tokens and the password notice a PATCH voids or queues. */
async function revokeCredentialsAfterUpdate(
  tx: Tx,
  config: RouteDeps['config'],
  input: {
    id: string;
    body: PatchUserBody;
    passwordHash: string | undefined;
    existing: ExistingUser;
    user: UserRow;
  },
): Promise<void> {
  const { id, body, passwordHash, existing, user } = input;
  if (body.active === false || passwordHash !== undefined) {
    await deleteUserSessions(tx, id);
  }
  // Mail E2: a set password, a deactivation or a new address (letter case aside) voids every
  // pending link (invitation, reset): those went to the address the account had before.
  if (
    body.active === false ||
    passwordHash !== undefined ||
    existing.email?.toLowerCase() !== user.email?.toLowerCase()
  ) {
    await deleteAccountTokens(tx, id);
  }
  if (passwordHash === undefined) return;
  // A reset password must also invalidate any personal access tokens minted under the old
  // one: otherwise a live token silently outlives the credential that was just rotated.
  await tx
    .update(apiTokens)
    .set({ revokedAt: new Date() })
    .where(
      and(eq(apiTokens.userId, id), eq(apiTokens.kind, 'personal'), isNull(apiTokens.revokedAt)),
    );
  // A7: an account that had a password hears that an administrator replaced it, at the
  // address it had before this change (the new one only when it had none).
  if (existing.hasPassword) {
    await queuePasswordChangedNotice(tx, mailDeps(config), {
      user: { ...user, email: existing.email ?? user.email },
      variant: 'admin',
      ip: null,
    });
  }
}

/**
 * rbac-audit.md §8: only the fields whose value changed; a password only as a flag.
 * rbac-audit.md §10.2.1: a deactivation or demotion alone is never blocked by a malformed audit
 * anchor; the recorder decides from the changes.
 */
function userUpdatedEvents(input: {
  existing: ExistingUser;
  user: UserRow;
  passwordHash: string | undefined;
}): AuditEventInput[] {
  const { existing, user, passwordHash } = input;
  const fieldChanges = USER_CHANGE_FIELDS.filter((field) => existing[field] !== user[field]).map(
    (field) => ({ field, from: existing[field], to: user[field] }),
  );
  if (fieldChanges.length === 0 && passwordHash === undefined) return [];
  return [
    {
      action: 'user.updated',
      target: { type: 'user', id: user.id, label: user.username },
      details: { changes: fieldChanges, passwordReset: passwordHash !== undefined },
    },
  ];
}

/** A user with their SSO summary and invitation, for one answer. */
export async function singleUserDto(db: Executor, user: UserRow): Promise<UserDto> {
  return userDto(
    user,
    await userSsoSummary(db, user.id),
    (await invitationsOf(db, [user.id]))(user.id),
  );
}

const MAIL_NOT_CONFIGURED = () =>
  conflict(
    'MAIL_NOT_CONFIGURED',
    'Email is not configured: set up an SMTP server in Settings → Email',
  );

/**
 * A8: invitations need mail and QUALOR_PUBLIC_URL (409s, in that order), and password sign-in
 * open to everyone: under break-glass-only, new users sign in with single sign-on. Returns the
 * public URL the link starts with.
 */
async function invitationBase(deps: RouteDeps, log: SignInLog): Promise<string> {
  const mail = await accountMailState(deps.db, deps.config);
  if (!mail.ready) {
    throw mail.missing === 'mail'
      ? MAIL_NOT_CONFIGURED()
      : conflict(
          'PUBLIC_URL_REQUIRED',
          'Invitations need QUALOR_PUBLIC_URL for the link in the email',
        );
  }
  const stored = await readSignInSettings(deps.db, log);
  const facts = {
    sso: deps.edition.isFeatureActive('sso'),
    forced: deps.config.forcePasswordSignIn,
  };
  if (effectivePasswordPolicy(stored, facts) === 'break_glass_only') {
    throw conflict(
      'PASSWORD_SIGN_IN_DISABLED',
      'Password sign-in is limited to break-glass administrators: new users sign in with single sign-on',
    );
  }
  return mail.publicUrl;
}

/** A new invitation link (replacing an earlier one) and its email, in the caller's transaction. */
async function sendInvitation(
  tx: Executor,
  deps: RouteDeps,
  input: { user: UserRow; email: string; inviter: UserRow; publicUrl: string },
): Promise<IssuedAccountToken> {
  const issued = await issueAccountToken(tx, {
    userId: input.user.id,
    kind: 'invitation',
    createdBy: input.inviter.id,
    ttlMinutes: INVITATION_TTL_MINUTES,
  });
  const queued = await queueMail(tx, mailDeps(deps.config), {
    kind: 'account.invitation',
    to: { address: input.email, userId: input.user.id },
    render: () =>
      renderInvitationMail({
        inviter: input.inviter.displayName ?? input.inviter.username,
        username: input.user.username,
        email: input.email,
        host: instanceHost(deps.config.publicUrl),
        url: accountLink(input.publicUrl, INVITE_PATH, issued.token),
        expiresAt: issued.expiresAt,
      }),
  });
  // Mail turned off after the check (or an address queueMail refuses): refuse, and the
  // transaction takes the link back.
  if (queued.status === 'skipped') throw MAIL_NOT_CONFIGURED();
  return issued;
}

/** A8: invitable is active, without a password, with an email and no SSO identity. */
function invitationNotApplicable() {
  return conflict(
    'INVITATION_NOT_APPLICABLE',
    'Only an active user without a password, with an email address and without single sign-on can be invited',
  );
}

/** The rate-limit key of the user-name routes: the user (authentication has run), else the address. */
function perCaller(request: FastifyRequest): string {
  return request.principal && request.principal.kind !== 'project'
    ? `user:${request.principal.user.id}`
    : request.ip;
}

/**
 * The user pickers' match (GET /users/search, GET /organizations/{id}/members?q): the username
 * starts with `q`, or a word of the display name does. A word starts the name or follows a space
 * (one or more) or a hyphen ("smi" finds "Alice Smith", "luc" finds "Jean-Luc"), never inside a
 * word. Case-insensitive; `%`, `_` and `\` in `q` are literal.
 */
export function userNameMatches(q: string): SQL {
  const word = likeLiteral(q);
  const alternatives = [
    ilike(users.username, prefixPattern(q)),
    ilike(users.displayName, `${word}%`),
    ilike(users.displayName, `% ${word}%`),
    ilike(users.displayName, `%-${word}%`),
  ];
  const anyOf = sql.join(alternatives, sql` or `);
  return sql`(${anyOf})`;
}

/** GET /users/search: at most 64 characters of q (a username's length) and 10 suggestions. */
const SEARCH_MAX = 64;
const SEARCH_LIMIT = 10;
const userSuggestionSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  displayName: z.string().nullable(),
});

export const userRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/users',
    {
      schema: {
        tags: ['users'],
        summary: 'List users',
        querystring: z.strictObject({
          ...pageQuery,
          /** sso-scim.md §11: `no-password` lists the users without a password (SSO-only). */
          signIn: z.enum(['no-password']).optional(),
        }),
        response: { 200: pageSchema(userSchema) },
      },
    },
    async (request) => {
      requireInstanceAdmin(request);
      const after = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select()
        .from(users)
        .where(
          and(
            after ? gt(users.id, after) : undefined,
            request.query.signIn === 'no-password' ? isNull(users.passwordHash) : undefined,
          ),
        )
        .orderBy(asc(users.id))
        .limit(request.query.limit + 1);
      const page = toPage(rows, request.query.limit);
      const ids = page.items.map((u) => u.id);
      const sso = await userSsoSummaries(deps.db, ids);
      const invitation = await invitationsOf(deps.db, ids);
      return {
        items: page.items.map((u) => userDto(u, sso(u.id), invitation(u.id))),
        nextCursor: page.nextCursor,
      };
    },
  );

  app.get(
    '/users/lookup',
    {
      config: {
        // api.md §3: 30 a minute per caller. Authentication (an app-level onRequest hook) has run
        // by now, so the key is the user, and one address cannot exhaust another user's budget.
        rateLimit: { max: 30, timeWindow: 60_000, keyGenerator: perCaller },
        openapi: { problems: [403, 404, 429] },
      },
      schema: {
        tags: ['users'],
        summary:
          'Find an active user by exact name, ignoring case (org admins, to add a member); only id, username and display name',
        querystring: z.strictObject({ username: text(64) }),
        response: {
          200: z.object({ id: z.uuid(), username: z.string(), displayName: z.string().nullable() }),
        },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'admin');
      await requireMembersManager(accessOf(deps), principal);
      // the name only, never the email, the admin flag or the active status, so the
      // lookup tells an org admin no more than who to add.
      const [user] = await deps.db
        .select({ id: users.id, username: users.username, displayName: users.displayName })
        .from(users)
        .where(and(eq(users.username, request.query.username), eq(users.active, true)));
      if (!user) throw notFound('User');
      return user;
    },
  );

  app.get(
    '/users/search',
    {
      config: {
        // api.md §3: the user picker asks as the person types (debounced), so it has its own
        // budget, 60 a minute per caller; the exact lookup keeps its 30. In memory: each server
        // process (replica) counts on its own, as the login throttle (auth/throttle.ts).
        rateLimit: { max: 60, timeWindow: 60_000, keyGenerator: perCaller },
        openapi: { problems: [403, 404, 429] },
      },
      schema: {
        tags: ['users'],
        summary:
          'Suggest active users whose username starts with q, or a word of whose display name does, ignoring case (org admins, to add a member or a project role); only id, username and display name',
        querystring: z.strictObject({
          q: text(SEARCH_MAX).meta({
            description:
              'The start of a username, or of a word of a display name (words split at spaces and hyphens), ignoring case; trimmed, then at least 2 characters (1 for an instance admin), at most 64 UTF-16 units; % and _ match themselves',
          }),
          limit: z.coerce
            .number()
            .int()
            .min(1)
            .max(SEARCH_LIMIT)
            .default(SEARCH_LIMIT)
            .meta({ description: '1 to 10 users; 10 by default' }),
          excludeOrganization: z.uuid().optional().meta({
            description:
              'Leave out the members of this organisation; the caller must be allowed to manage its members',
          }),
          excludeProject: z.uuid().optional().meta({
            description:
              "Leave out the users with a role granted on this project; the caller must be allowed to manage its grants (org.members.manage on the project's organisation)",
          }),
        }),
        response: { 200: z.object({ users: z.array(userSuggestionSchema) }) },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'admin');
      const access = accessOf(deps);
      await requireMembersManager(access, principal);
      const { limit, excludeOrganization, excludeProject } = request.query;
      // spaces around the name are not part of it: " a" is one character, not two.
      const q = request.query.q.trim();
      const min = principal.user.isInstanceAdmin ? 1 : 2;
      // characters as a person counts them (code points), not UTF-16 units.
      if ([...q].length < min) {
        throw validationFailed([{ path: 'query.q', message: `Type at least ${min} characters` }]);
      }
      if (excludeOrganization !== undefined) {
        await requireOrganizationAccess(
          access,
          principal,
          excludeOrganization,
          'org.members.manage',
        );
      }
      if (excludeProject !== undefined) {
        // as PUT /projects/{id}/members/{userId}: 404 for a project the caller cannot see, 403
        // when it may not manage the members of the project's organisation.
        const project = await projectForUser(access, principal, excludeProject, 'project.read');
        await requireOrganizationAccess(
          access,
          principal,
          project.organizationId,
          'org.members.manage',
        );
      }
      // the name only, never the email or the admin flag, as the lookup (the same audience).
      const found = await deps.db
        .select({ id: users.id, username: users.username, displayName: users.displayName })
        .from(users)
        .where(
          and(
            eq(users.active, true),
            userNameMatches(q),
            excludeOrganization === undefined
              ? undefined
              : notExists(
                  deps.db
                    .select({ one: sql`1` })
                    .from(memberships)
                    .where(
                      and(
                        eq(memberships.organizationId, excludeOrganization),
                        eq(memberships.userId, users.id),
                      ),
                    ),
                ),
            excludeProject === undefined
              ? undefined
              : notExists(
                  deps.db
                    .select({ one: sql`1` })
                    .from(projectMemberships)
                    .where(
                      and(
                        eq(projectMemberships.projectId, excludeProject),
                        eq(projectMemberships.userId, users.id),
                      ),
                    ),
                ),
          ),
        )
        .orderBy(asc(users.username))
        .limit(limit);
      return { users: found };
    },
  );

  app.post(
    '/users',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            409: 'USERNAME_TAKEN; EMAIL_TAKEN; with invite: MAIL_NOT_CONFIGURED, PUBLIC_URL_REQUIRED, PASSWORD_SIGN_IN_DISABLED',
          },
        },
      },
      schema: {
        tags: ['users'],
        summary:
          'Create a user: with an initial password (changed at first sign-in), or invited by email',
        body: createUserBody,
        response: { 201: userSchema },
      },
    },
    async (request, reply) => {
      const principal = requireInstanceAdmin(request);
      const body = request.body;
      let publicUrl: string | null = null;
      if (body.invite) {
        const errors: FieldError[] = [];
        if (body.password !== undefined) {
          errors.push({
            path: 'body.password',
            message: 'Leave the password out when you send an invitation',
          });
        }
        if (body.email === undefined) {
          errors.push({ path: 'body.email', message: 'An invitation needs an email address' });
        }
        if (errors.length > 0) throw validationFailed(errors);
        publicUrl = await invitationBase(deps, request.log);
      } else if (body.password === undefined) {
        throw validationFailed([{ path: 'body.password', message: 'Required' }]);
      }
      const passwordHash = body.password === undefined ? null : await hashPassword(body.password);
      try {
        const { user, invitation } = await deps.db.transaction(async (tx) => {
          const created = first(
            await tx
              .insert(users)
              .values({
                username: body.username,
                passwordHash,
                displayName: body.displayName ?? null,
                email: body.email ?? null,
                isInstanceAdmin: body.isInstanceAdmin,
                // An invited user has no password to change; they choose their own.
                passwordChangeRequired: !body.invite,
              })
              .returning(),
          );
          const target = { type: 'user' as const, id: created.id, label: created.username };
          const sent =
            publicUrl !== null && created.email !== null
              ? await sendInvitation(tx, deps, {
                  user: created,
                  email: created.email,
                  inviter: principal.user,
                  publicUrl,
                })
              : null;
          const events: AuditEventInput[] = [
            {
              action: 'user.created',
              target,
              details: {
                instanceAdmin: created.isInstanceAdmin,
                passwordChangeRequired: created.passwordChangeRequired,
                invited: body.invite,
              },
            },
          ];
          if (sent) events.push({ action: 'user.invited', target, details: { resend: false } });
          await deps.audit.record(tx, actorOf(request), events);
          return { user: created, invitation: sent };
        });
        return reply
          .code(201)
          .send(userDto(user, NO_SSO, invitation ? { expiresAt: invitation.expiresAt } : null));
      } catch (err) {
        throw uniqueConflict(err) ?? err;
      }
    },
  );

  app.patch(
    '/users/:id',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: {
            409: 'LAST_ADMIN (the last active instance administrator cannot be deactivated or demoted); LAST_BREAK_GLASS_ADMIN (while password sign-in is limited to break-glass administrators, the last usable one cannot be deactivated or demoted); USERNAME_TAKEN; EMAIL_TAKEN; DEMO_USER (while QUALOR_DEMO_USER is set, the demo account keeps its username and no user takes it, ignoring case)',
          },
        },
      },
      schema: {
        tags: ['users'],
        summary: 'Update a user',
        params: idParams,
        body: patchUserBody,
        response: { 200: userSchema },
      },
    },
    async (request) => {
      const principal = requireInstanceAdmin(request);
      const { id } = request.params;
      const body = request.body;
      // Hash before opening the transaction: argon2 is CPU-bound, not DB-bound, and shouldn't
      // hold the advisory lock (or a pooled connection) for the duration.
      const passwordHash =
        body.password !== undefined ? await hashPassword(body.password) : undefined;
      const updated = await deps.db.transaction(async (tx) => {
        // Serialises admin changes so two concurrent demotions cannot both pass the count check.
        await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.instanceAdmins})`);
        await assertCallerStillAdmin(tx, principal.user.id);
        const existing = await loadExistingUser(tx, id);
        const changes = buildUserChanges(body, passwordHash, existing, deps.config.demoUser);
        let user: UserRow;
        try {
          user = first(await tx.update(users).set(changes).where(eq(users.id, id)).returning());
        } catch (err) {
          throw uniqueConflict(err) ?? err;
        }
        await assertAdminsRemain(tx, id, body);
        await revokeCredentialsAfterUpdate(tx, deps.config, {
          id,
          body,
          passwordHash,
          existing,
          user,
        });
        const events = userUpdatedEvents({ existing, user, passwordHash });
        if (events.length > 0) {
          await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), events);
        }
        return user;
      });
      return singleUserDto(deps.db, updated);
    },
  );

  app.post(
    '/users/:id/invitation',
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: 60_000,
          keyGenerator: (request) =>
            request.principal && request.principal.kind !== 'project'
              ? `user:${request.principal.user.id}`
              : request.ip,
        },
        openapi: {
          problems: [409, 429],
          problemDescriptions: {
            409: 'INVITATION_NOT_APPLICABLE (only an active user without a password, with an email address and without single sign-on); MAIL_NOT_CONFIGURED; PUBLIC_URL_REQUIRED; PASSWORD_SIGN_IN_DISABLED',
          },
        },
      },
      schema: {
        tags: ['users'],
        summary: 'Send a new invitation email; the earlier link stops working',
        params: idParams,
        response: { 200: userSchema },
      },
    },
    async (request) => {
      const principal = requireInstanceAdmin(request);
      const { id } = request.params;
      const [existing] = await deps.db.select({ id: users.id }).from(users).where(eq(users.id, id));
      if (!existing) throw notFound('User');
      const publicUrl = await invitationBase(deps, request.log);
      const { user, issued } = await deps.db.transaction(async (tx) => {
        const [locked] = await tx.select().from(users).where(eq(users.id, id)).for('update');
        if (!locked) throw notFound('User');
        const sso = await userSsoSummary(tx, locked.id);
        const email = locked.email;
        if (
          !locked.active ||
          locked.passwordHash !== null ||
          email === null ||
          sso.identities > 0
        ) {
          throw invitationNotApplicable();
        }
        const sent = await sendInvitation(tx, deps, {
          user: locked,
          email,
          inviter: principal.user,
          publicUrl,
        });
        await deps.audit.record(tx, actorOf(request), [
          {
            action: 'user.invited',
            target: { type: 'user', id: locked.id, label: locked.username },
            details: { resend: true },
          },
        ]);
        return { user: locked, issued: sent };
      });
      // NO_SSO: the route refused any user with an identity.
      return userDto(user, NO_SSO, { expiresAt: issued.expiresAt });
    },
  );

  app.delete(
    '/users/:id/invitation',
    {
      schema: {
        tags: ['users'],
        summary: 'Revoke a pending invitation; its link stops working',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      requireInstanceAdmin(request);
      const { id } = request.params;
      await deps.db.transaction(async (tx) => {
        const [user] = await tx
          .select({ id: users.id, username: users.username })
          .from(users)
          .where(eq(users.id, id));
        if (!user) throw notFound('User');
        if ((await deleteAccountTokens(tx, id, 'invitation')) === 0) throw notFound('Invitation');
        await deps.audit.record(tx, actorOf(request), [
          {
            action: 'user.invitation_revoked',
            target: { type: 'user', id: user.id, label: user.username },
            details: {},
          },
        ]);
      });
      return reply.code(204).send();
    },
  );
};

import { and, asc, count, eq, gt, inArray, isNull, sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { USER_CHANGE_FIELDS } from '../audit/catalogue';
import { actorOf } from '../audit/recorder';
import { accessOf, requireInstanceAdmin, requireMembersManager, requireUser } from '../auth/access';
import { hashPassword, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '../auth/password';
import { deleteUserSessions, type UserRow } from '../auth/sessions';
import type { Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgConstraint, pgErrorCode } from '../db/errors';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import { apiTokens, identities, users } from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, forbidden, notFound } from '../http/problem';
import { idParams, NO_SSO, text, userDto, userSchema, type UserSsoSummary } from '../http/schemas';
import { USERNAME_PATTERN } from '../patterns';
import { assertBreakGlassKept } from '../sso/sign-in-policy';

const password = z.string().min(PASSWORD_MIN_LENGTH).max(PASSWORD_MAX_LENGTH);
const createUserBody = z.strictObject({
  username: z.string().regex(USERNAME_PATTERN),
  password,
  displayName: text(255).optional(),
  email: z.email().max(320).optional(),
  isInstanceAdmin: z.boolean().default(false),
});
const patchUserBody = z
  .strictObject({
    displayName: text(255).nullable().optional(),
    email: z.email().max(320).nullable().optional(),
    isInstanceAdmin: z.boolean().optional(),
    active: z.boolean().optional(),
    password: password.optional(),
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
      const sso = await userSsoSummaries(
        deps.db,
        page.items.map((u) => u.id),
      );
      return { items: page.items.map((u) => userDto(u, sso(u.id))), nextCursor: page.nextCursor };
    },
  );

  app.get(
    '/users/lookup',
    {
      config: {
        // api.md §3: 30 a minute per caller. Authentication (an app-level onRequest hook) has run
        // by now, so the key is the user, and one address cannot exhaust another user's budget.
        rateLimit: {
          max: 30,
          timeWindow: 60_000,
          keyGenerator: (request) =>
            request.principal && request.principal.kind !== 'project'
              ? `user:${request.principal.user.id}`
              : request.ip,
        },
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

  app.post(
    '/users',
    {
      config: { openapi: { problems: [409] } },
      schema: {
        tags: ['users'],
        summary: 'Create a user (must change the password at first login)',
        body: createUserBody,
        response: { 201: userSchema },
      },
    },
    async (request, reply) => {
      requireInstanceAdmin(request);
      const body = request.body;
      const passwordHash = await hashPassword(body.password);
      try {
        const user = await deps.db.transaction(async (tx) => {
          const created = first(
            await tx
              .insert(users)
              .values({
                username: body.username,
                passwordHash,
                displayName: body.displayName ?? null,
                email: body.email ?? null,
                isInstanceAdmin: body.isInstanceAdmin,
                passwordChangeRequired: true,
              })
              .returning(),
          );
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'user.created',
              target: { type: 'user', id: created.id, label: created.username },
              details: {
                instanceAdmin: created.isInstanceAdmin,
                passwordChangeRequired: created.passwordChangeRequired,
              },
            },
          ]);
          return created;
        });
        return reply.code(201).send(userDto(user, NO_SSO));
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
            409: 'LAST_ADMIN (the last active instance administrator cannot be deactivated or demoted); LAST_BREAK_GLASS_ADMIN (while password sign-in is limited to break-glass administrators, the last usable one cannot be deactivated or demoted)',
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
        // Re-read the caller fresh, under the lock: their principal was resolved before this
        // transaction started and may since have been demoted (or deactivated) by a concurrent
        // request that got here first.
        const [caller] = await tx
          .select({ isInstanceAdmin: users.isInstanceAdmin, active: users.active })
          .from(users)
          .where(eq(users.id, principal.user.id));
        if (!caller?.isInstanceAdmin || !caller.active) {
          throw forbidden('FORBIDDEN', 'Instance administrators only');
        }
        const [existing] = await tx
          .select({
            displayName: users.displayName,
            email: users.email,
            active: users.active,
            isInstanceAdmin: users.isInstanceAdmin,
          })
          .from(users)
          .where(eq(users.id, id));
        if (!existing) throw notFound('User');
        const changes: Partial<typeof users.$inferInsert> = {};
        if (body.displayName !== undefined) changes.displayName = body.displayName;
        if (body.email !== undefined) changes.email = body.email;
        if (body.isInstanceAdmin !== undefined) changes.isInstanceAdmin = body.isInstanceAdmin;
        if (body.active !== undefined) changes.active = body.active;
        if (passwordHash !== undefined) {
          changes.passwordHash = passwordHash;
          changes.passwordChangeRequired = true;
        }
        let user: UserRow;
        try {
          user = first(await tx.update(users).set(changes).where(eq(users.id, id)).returning());
        } catch (err) {
          throw uniqueConflict(err) ?? err;
        }
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
        if (body.active === false || passwordHash !== undefined) await deleteUserSessions(tx, id);
        if (passwordHash !== undefined) {
          // A reset password must also invalidate any personal access tokens minted under the old
          // one: otherwise a live token silently outlives the credential that was just rotated.
          await tx
            .update(apiTokens)
            .set({ revokedAt: new Date() })
            .where(
              and(
                eq(apiTokens.userId, id),
                eq(apiTokens.kind, 'personal'),
                isNull(apiTokens.revokedAt),
              ),
            );
        }
        // rbac-audit.md §8: only the fields whose value changed; a password only as a flag.
        const fieldChanges = USER_CHANGE_FIELDS.filter(
          (field) => existing[field] !== user[field],
        ).map((field) => ({ field, from: existing[field], to: user[field] }));
        if (fieldChanges.length > 0 || passwordHash !== undefined) {
          // rbac-audit.md §10.2.1: a deactivation or demotion alone is never blocked by a
          // malformed audit anchor; the recorder decides from the changes.
          await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
            {
              action: 'user.updated',
              target: { type: 'user', id: user.id, label: user.username },
              details: { changes: fieldChanges, passwordReset: passwordHash !== undefined },
            },
          ]);
        }
        return user;
      });
      return userDto(updated, await userSsoSummary(deps.db, updated.id));
    },
  );
};

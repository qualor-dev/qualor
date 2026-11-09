import { and, asc, eq, sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { accessOf, requireUser } from '../auth/access';
import { visibleProjectsCondition } from '../auth/facts';
import type { UserRow } from '../auth/sessions';
import type { Executor } from '../db/client';
import {
  memberships,
  notificationPreferences,
  projects,
  projectWatches,
  WATCH_BRANCHES,
} from '../db/schema';
import { ProblemError } from '../http/problem';
import { idParams, noContent } from '../http/schemas';
import { mailConfigured } from '../mail/settings';
import { publicLink } from '../mail/templates/text';
import {
  MAX_TOKEN_LENGTH,
  verifyUnsubscribeToken,
  verifyVulnerabilityUnsubscribeToken,
} from '../notifications/unsubscribe';
import { projectForUser } from '../projects/access';

const branches = z.enum(WATCH_BRANCHES);
const events = z.strictObject({
  gateFailed: z.boolean(),
  gateRecovered: z.boolean(),
  analysisFailed: z.boolean(),
});
const emailFields = {
  /** The caller has an address, the server has SMTP, and the caller's notification email is on. */
  emailReady: z.boolean(),
  /** Why not (the UI's hint), in this order; null when ready. */
  emailBlocker: z.enum(['no_address', 'not_configured', 'preference_off']).nullable(),
};
const watchResponse = z.discriminatedUnion('watching', [
  z.object({ watching: z.literal(false), ...emailFields }),
  z.object({ watching: z.literal(true), branches, events, ...emailFields }),
]);
const preferencesSchema = z.object({ email: z.boolean(), orgWebhookFailures: z.boolean() });
const notificationsResponse = z.object({
  preferences: preferencesSchema,
  /** The caller administers an organisation (the failing-webhook switch applies). */
  isOrgAdmin: z.boolean(),
  emailAddress: z.string().nullable(),
  mailConfigured: z.boolean(),
  /** The caller's watches of projects it can still see, by project name. */
  watches: z.array(
    z.object({
      project: z.object({ id: z.uuid(), key: z.string(), name: z.string() }),
      branches,
      events,
    }),
  ),
});
/**
 * Fastify decodes the query before validation, so this sees the token itself. The bound only
 * caps the work: `verifyUnsubscribeToken` answers anything over MAX_TOKEN_LENGTH with
 * TOKEN_INVALID, and this cap turns only a far longer `t` into a 422.
 */
const tokenQuery = z.strictObject({ t: z.string().max(MAX_TOKEN_LENGTH * 2) });

type WatchRow = typeof projectWatches.$inferSelect;
type Preferences = z.infer<typeof preferencesSchema>;

function eventsOf(row: WatchRow): z.infer<typeof events> {
  return {
    gateFailed: row.gateFailed,
    gateRecovered: row.gateRecovered,
    analysisFailed: row.analysisFailed,
  };
}

/** A missing row is the defaults (mail E3 N6). */
async function preferencesOf(db: Executor, userId: string): Promise<Preferences> {
  const [row] = await db
    .select()
    .from(notificationPreferences)
    .where(eq(notificationPreferences.userId, userId));
  return { email: row?.email ?? true, orgWebhookFailures: row?.orgWebhookFailures ?? true };
}

/** Why no notification mail reaches the user, checked in this order; null when it does. */
async function emailBlocker(
  deps: RouteDeps,
  user: UserRow,
): Promise<'no_address' | 'not_configured' | 'preference_off' | null> {
  if (user.email === null) return 'no_address';
  if (!(await mailConfigured(deps.db, deps.config))) return 'not_configured';
  if (!(await preferencesOf(deps.db, user.id)).email) return 'preference_off';
  return null;
}

async function emailState(deps: RouteDeps, user: UserRow) {
  const blocker = await emailBlocker(deps, user);
  return { emailReady: blocker === null, emailBlocker: blocker };
}

async function watchState(
  deps: RouteDeps,
  user: UserRow,
  projectId: string,
): Promise<z.infer<typeof watchResponse>> {
  const [row] = await deps.db
    .select()
    .from(projectWatches)
    .where(and(eq(projectWatches.userId, user.id), eq(projectWatches.projectId, projectId)));
  const email = await emailState(deps, user);
  return row
    ? { watching: true, branches: row.branches, events: eventsOf(row), ...email }
    : { watching: false, ...email };
}

/**
 * mail E3: watching a project and the caller's notification settings. Personal preferences, like
 * a token's last use: no audit record (audit/routes.ts UNAUDITED_MUTATIONS).
 */
export const notificationRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  app.get(
    '/projects/:id/watch',
    {
      schema: {
        tags: ['notifications'],
        summary: 'Whether the caller watches a project, and whether email would reach them',
        params: idParams,
        response: { 200: watchResponse },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.read',
      );
      return watchState(deps, principal.user, project.id);
    },
  );

  app.put(
    '/projects/:id/watch',
    {
      schema: {
        tags: ['notifications'],
        summary: 'Watch a project, or change what the caller watches',
        description:
          'Emails when the quality gate fails or passes again and when an analysis fails, on the main branch (`main`) or on every branch and merge request (`all`).',
        params: idParams,
        body: z.strictObject({ branches, events }),
        response: { 200: watchResponse },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.read',
      );
      const { branches: scope, events: chosen } = request.body;
      const values = {
        branches: scope,
        gateFailed: chosen.gateFailed,
        gateRecovered: chosen.gateRecovered,
        analysisFailed: chosen.analysisFailed,
      };
      await deps.db
        .insert(projectWatches)
        .values({ userId: principal.user.id, projectId: project.id, ...values })
        .onConflictDoUpdate({
          target: [projectWatches.userId, projectWatches.projectId],
          set: { ...values, updatedAt: sql`now()` },
        });
      return watchState(deps, principal.user, project.id);
    },
  );

  app.delete(
    '/projects/:id/watch',
    {
      schema: {
        tags: ['notifications'],
        summary: 'Stop watching a project',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request, 'write');
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.read',
      );
      await deps.db
        .delete(projectWatches)
        .where(
          and(
            eq(projectWatches.userId, principal.user.id),
            eq(projectWatches.projectId, project.id),
          ),
        );
      return reply.code(204).send();
    },
  );

  app.get(
    '/me/notifications',
    {
      schema: {
        tags: ['notifications'],
        summary: "The caller's notification settings and watched projects",
        response: { 200: notificationsResponse },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const user = principal.user;
      const rows = await deps.db
        .select({
          watch: projectWatches,
          project: { id: projects.id, key: projects.key, name: projects.name },
        })
        .from(projectWatches)
        .innerJoin(projects, eq(projects.id, projectWatches.projectId))
        .where(
          and(eq(projectWatches.userId, user.id), visibleProjectsCondition(accessOf(deps), user)),
        )
        .orderBy(asc(projects.name), asc(projects.id));
      const [administers] = await deps.db
        .select({ organizationId: memberships.organizationId })
        .from(memberships)
        .where(and(eq(memberships.userId, user.id), eq(memberships.role, 'admin')))
        .limit(1);
      return {
        preferences: await preferencesOf(deps.db, user.id),
        isOrgAdmin: administers !== undefined,
        emailAddress: user.email,
        mailConfigured: await mailConfigured(deps.db, deps.config),
        watches: rows.map((r) => ({
          project: r.project,
          branches: r.watch.branches,
          events: eventsOf(r.watch),
        })),
      };
    },
  );

  app.put(
    '/me/notifications',
    {
      schema: {
        tags: ['notifications'],
        summary: "Change the caller's notification switches",
        body: z.strictObject({
          email: z.boolean().optional(),
          orgWebhookFailures: z.boolean().optional(),
        }),
        response: { 200: z.object({ preferences: preferencesSchema }) },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      const { email, orgWebhookFailures } = request.body;
      const set = {
        ...(email === undefined ? {} : { email }),
        ...(orgWebhookFailures === undefined ? {} : { orgWebhookFailures }),
      };
      await deps.db
        .insert(notificationPreferences)
        .values({ userId: principal.user.id, ...set })
        .onConflictDoUpdate({
          target: notificationPreferences.userId,
          set: { ...set, updatedAt: sql`now()` },
        });
      return { preferences: await preferencesOf(deps.db, principal.user.id) };
    },
  );
};

/**
 * mail E3 N5: the one-click stop (RFC 8058). Its own plugin, so the body parsers it needs stay in
 * this encapsulation context. Mail clients POST `List-Unsubscribe=One-Click` as a form
 * (urlencoded or multipart, RFC 8058 §3.1); the UI's page posts without a body. The body says
 * nothing either way: only the token counts. The request log never shows the token
 * (http/logger.ts drops the query of these URLs).
 */
export const unsubscribeRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  // JSON too: `{}`, an empty JSON body and a broken one are all ignored, never a 400 of their own.
  app.removeAllContentTypeParsers();
  for (const type of [
    'application/x-www-form-urlencoded',
    'multipart/form-data',
    'application/json',
  ]) {
    app.addContentTypeParser(
      type,
      { parseAs: 'string', bodyLimit: 1024 },
      (_request, _body, done) => done(null, {}),
    );
  }

  app.post(
    '/notifications/unsubscribe',
    {
      config: {
        public: true,
        rateLimit: { max: 30, timeWindow: 60_000 },
        openapi: {
          problems: [400, 429],
          problemDescriptions: { 400: 'TOKEN_INVALID (the link is not one this server made)' },
        },
      },
      schema: {
        tags: ['notifications'],
        summary: 'Stop watching the project of an email link (one click, no sign-in)',
        description:
          'The token of the link in a notification email (`t`). Deletes that watch; idempotent. Any body (RFC 8058 `List-Unsubscribe=One-Click`, urlencoded or multipart, or none) is ignored. A GET only redirects to the page that asks first: link scanners must not unsubscribe people.',
        security: [],
        querystring: tokenQuery,
        response: { 200: z.object({ project: z.object({ name: z.string() }).nullable() }) },
      },
    },
    async (request) => {
      const parsed = verifyUnsubscribeToken(deps.config.secretKey, request.query.t);
      if (!parsed) {
        throw new ProblemError(400, 'TOKEN_INVALID', 'This unsubscribe link is not valid');
      }
      await deps.db
        .delete(projectWatches)
        .where(
          and(
            eq(projectWatches.userId, parsed.userId),
            eq(projectWatches.projectId, parsed.projectId),
          ),
        );
      const [project] = await deps.db
        .select({ name: projects.name })
        .from(projects)
        .where(eq(projects.id, parsed.projectId));
      return { project: project ?? null };
    },
  );

  app.get(
    '/notifications/unsubscribe',
    {
      config: {
        public: true,
        rateLimit: { max: 30, timeWindow: 60_000 },
        openapi: { problems: [429] },
      },
      schema: {
        tags: ['notifications'],
        summary: 'Open the stop-watching page of an email link (changes nothing)',
        description:
          'Redirects to the UI page `/unsubscribe#t=…`, which asks before it stops anything: link scanners must not unsubscribe people. The token is not checked here.',
        security: [],
        querystring: tokenQuery,
        response: { 303: z.undefined().describe('To /unsubscribe#t=<token> (Location)') },
      },
    },
    async (request, reply) => {
      const path = `/unsubscribe#t=${encodeURIComponent(request.query.t)}`;
      return reply
        .code(303)
        .header('location', publicLink(deps.config.publicUrl, path) ?? path)
        .send();
    },
  );

  app.post(
    '/notifications/unsubscribe/vulnerabilities',
    {
      config: {
        public: true,
        rateLimit: { max: 30, timeWindow: 60_000 },
        openapi: {
          problems: [400, 429],
          problemDescriptions: { 400: 'TOKEN_INVALID (the link is not one this server made)' },
        },
      },
      schema: {
        tags: ['notifications'],
        summary: 'Stop the vulnerability emails of an email link (one click, no sign-in)',
        description:
          'The token of the link in a vulnerability email (`t`). Turns "New vulnerabilities in tracked versions" off on every watch of that user and keeps the watches; idempotent. Any body (RFC 8058 `List-Unsubscribe=One-Click`, urlencoded or multipart, or none) is ignored. A GET only redirects to the page that asks first: link scanners must not unsubscribe people.',
        security: [],
        querystring: tokenQuery,
        response: { 200: z.object({}) },
      },
    },
    async (request) => {
      const parsed = verifyVulnerabilityUnsubscribeToken(deps.config.secretKey, request.query.t);
      if (!parsed) {
        throw new ProblemError(400, 'TOKEN_INVALID', 'This unsubscribe link is not valid');
      }
      await deps.db
        .update(projectWatches)
        .set({ newVulnerabilities: false, updatedAt: sql`now()` })
        .where(
          and(
            eq(projectWatches.userId, parsed.userId),
            eq(projectWatches.newVulnerabilities, true),
          ),
        );
      return {};
    },
  );

  app.get(
    '/notifications/unsubscribe/vulnerabilities',
    {
      config: {
        public: true,
        rateLimit: { max: 30, timeWindow: 60_000 },
        openapi: { problems: [429] },
      },
      schema: {
        tags: ['notifications'],
        summary: 'Open the stop page of a vulnerability email link (changes nothing)',
        description:
          'Redirects to the UI page `/unsubscribe/vulnerabilities#t=…`, which asks before it stops anything: link scanners must not unsubscribe people. The token is not checked here.',
        security: [],
        querystring: tokenQuery,
        response: {
          303: z.undefined().describe('To /unsubscribe/vulnerabilities#t=<token> (Location)'),
        },
      },
    },
    async (request, reply) => {
      const path = `/unsubscribe/vulnerabilities#t=${encodeURIComponent(request.query.t)}`;
      return reply
        .code(303)
        .header('location', publicLink(deps.config.publicUrl, path) ?? path)
        .send();
    },
  );
};

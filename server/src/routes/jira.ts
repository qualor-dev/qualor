import { count, eq, sql } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import {
  JIRA_CONNECTION_CHANGED_FIELDS,
  urlOrigin,
  type AuditAction,
  type AuditDetails,
} from '../audit/catalogue';
import { actorOf, type AuditEventInput } from '../audit/recorder';
import { organizationRef } from '../audit/refs';
import { accessOf, requireOrganizationAccess, requireUser } from '../auth/access';
import { decryptSecret, encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import {
  jiraConnections,
  jiraLinks,
  organizations,
  projectJiraSettings,
  type JiraDeployment,
} from '../db/schema';
import { conflict, notFound, validationFailed, type FieldError } from '../http/problem';
import { idParams, iso, noContent, noNul, timestamp } from '../http/schemas';
import {
  connectionOf,
  JIRA_TOKEN_AAD,
  JIRA_TOKEN_PATTERN,
  testJiraConnection,
  type JiraConnectionRow,
} from '../jira/connection';
import { scheduleJiraSync, syncJiraNow } from '../jira/jobs';
import {
  BACKGROUND_PROBLEM_CODES,
  JIRA_PROBLEM_CODES,
  setConnectionProblem,
} from '../jira/problems';
import { jiraApiUrlProblem, jiraSiteUrlProblem, normalJiraUrl } from '../jira/url';

const LINK_STATES = ['pending', 'created', 'failed', 'missing', 'dismissed'] as const;

export const jiraProblemSchema = z.object({
  code: z.enum(BACKGROUND_PROBLEM_CODES),
  /** One of the fixed texts of `JIRA_PROBLEM_TEXT`; never Jira's own words. */
  message: z.string(),
  at: timestamp,
});

export const jiraConnectionSchema = z.object({
  id: z.uuid(),
  organizationId: z.uuid(),
  deployment: z.enum(['cloud', 'data_center']),
  siteUrl: z.string(),
  apiUrl: z.string().nullable(),
  email: z.string().nullable(),
  tokenSet: z.boolean(),
  /** False when `token_enc` no longer decrypts (QUALOR_SECRET_KEY changed): save the token again. */
  tokenReadable: z.boolean(),
  /** The last failure that concerns the whole connection, set by a job; null when there is none. */
  problem: jiraProblemSchema.nullable(),
  /** Projects mapped to a Jira project through this connection. */
  mappedProjects: z.number().int(),
  /** Links by state, for the confirm steps of the settings page. */
  links: z.object({
    pending: z.number().int(),
    created: z.number().int(),
    failed: z.number().int(),
    missing: z.number().int(),
    dismissed: z.number().int(),
  }),
  createdAt: timestamp,
  updatedAt: timestamp,
});
type JiraConnectionDto = z.infer<typeof jiraConnectionSchema>;

const jiraConnectionAnswerSchema = z.object({
  connection: jiraConnectionSchema.nullable(),
  /** Whether the server has `QUALOR_PUBLIC_URL`; without it, Jira issues carry no Qualor links. */
  publicUrlSet: z.boolean(),
});

export const jiraTestSchema = z.object({
  ok: z.boolean(),
  user: z.object({ displayName: z.string() }).nullable(),
  projectsVisible: z.number().int().nullable(),
  problem: z.object({ code: z.enum(JIRA_PROBLEM_CODES), message: z.string() }).nullable(),
});

const TOKEN_TEXT = 'Use 1-1024 printable ASCII characters without spaces';

const putBody = z.strictObject({
  deployment: z.enum(['cloud', 'data_center']),
  siteUrl: noNul(z.string().min(1).max(2_048)),
  apiUrl: noNul(z.string().max(2_048)).nullable().optional().meta({
    description:
      'Jira Cloud only: https://api.atlassian.com/ex/jira/<cloud id>, which a scoped API token needs',
  }),
  email: z.email().max(254).nullable().optional().meta({
    description: 'Jira Cloud only, required there: the Atlassian account of the token',
  }),
  token: z.string().regex(JIRA_TOKEN_PATTERN, { message: TOKEN_TEXT }).optional().meta({
    description:
      'Write-only. Required on create and with a changed deployment, siteUrl or apiUrl; kept when omitted',
  }),
});

/** The stored form of the address and the Cloud-only fields, or the 422 with every problem. */
function checkedConnection(
  body: z.infer<typeof putBody>,
  internalHosts: ReadonlySet<string>,
): { deployment: JiraDeployment; siteUrl: string; apiUrl: string | null; email: string | null } {
  const { deployment } = body;
  const errors: FieldError[] = [];
  const siteProblem = jiraSiteUrlProblem(body.siteUrl, deployment, internalHosts);
  if (siteProblem !== null) errors.push({ path: 'body.siteUrl', message: siteProblem });
  const apiUrl = body.apiUrl ?? null;
  const email = body.email ?? null;
  if (deployment === 'cloud') {
    if (email === null) {
      errors.push({ path: 'body.email', message: 'A Jira Cloud connection needs the email' });
    }
    const apiProblem = apiUrl === null ? null : jiraApiUrlProblem(apiUrl);
    if (apiProblem !== null) errors.push({ path: 'body.apiUrl', message: apiProblem });
  } else {
    const wrong = 'Not a field of a Data Center connection';
    if (email !== null) errors.push({ path: 'body.email', message: wrong });
    if (apiUrl !== null) errors.push({ path: 'body.apiUrl', message: wrong });
  }
  if (errors.length > 0) throw validationFailed(errors);
  return {
    deployment,
    siteUrl: normalJiraUrl(body.siteUrl),
    apiUrl: apiUrl === null ? null : normalJiraUrl(apiUrl),
    email,
  };
}

/**
 * spec §6.1, §6.8: the organisation's Jira connection (org admins, `org.jira.manage`). The token
 * is write-only: no response, log line, audit entry or error text holds it, nor the email.
 */
export const jiraRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  const key = encryptionKey(deps.config.secretKey);
  const jiraDeps = {
    secretKey: deps.config.secretKey,
    internalHosts: deps.config.jiraInternalHosts,
  };
  /** rbac-audit.md §8: one event about `connection` in the change's transaction `tx`. */
  const audit = async <A extends AuditAction>(
    tx: Executor,
    request: FastifyRequest,
    connection: JiraConnectionRow,
    action: A,
    details: AuditDetails<A>,
  ): Promise<void> => {
    if (!deps.audit.active()) return;
    const event = {
      action,
      organization: await organizationRef(tx, connection.organizationId),
      target: { type: 'jira_connection', id: connection.id, label: connection.siteUrl },
      details,
    } as AuditEventInput;
    await deps.audit.record(tx, actorOf(request), [event]);
  };

  const linkCounts = async (db: Executor, connectionId: string) => {
    const rows = await db
      .select({ state: jiraLinks.state, n: count() })
      .from(jiraLinks)
      .where(eq(jiraLinks.connectionId, connectionId))
      .groupBy(jiraLinks.state);
    const counts = Object.fromEntries(LINK_STATES.map((s) => [s, 0])) as Record<
      (typeof LINK_STATES)[number],
      number
    >;
    for (const r of rows) counts[r.state] = r.n;
    return counts;
  };
  const dto = async (db: Executor, row: JiraConnectionRow): Promise<JiraConnectionDto> => {
    const [mapped] = await db
      .select({ n: count() })
      .from(projectJiraSettings)
      .where(eq(projectJiraSettings.connectionId, row.id));
    return {
      id: row.id,
      organizationId: row.organizationId,
      deployment: row.deployment,
      siteUrl: row.siteUrl,
      apiUrl: row.apiUrl,
      email: row.email,
      tokenSet: true,
      tokenReadable: decryptSecret(key, row.tokenEnc, JIRA_TOKEN_AAD) !== null,
      problem: row.problem
        ? {
            code: row.problem.code as (typeof BACKGROUND_PROBLEM_CODES)[number],
            message: row.problem.message,
            at: new Date(row.problem.at).toISOString(),
          }
        : null,
      mappedProjects: mapped?.n ?? 0,
      links: await linkCounts(db, row.id),
      createdAt: iso(row.createdAt),
      updatedAt: iso(row.updatedAt),
    };
  };

  app.get(
    '/organizations/:id/jira',
    {
      schema: {
        tags: ['jira'],
        summary:
          "The organisation's Jira connection or null (org admins): never the token; `publicUrlSet` tells whether Jira issues can carry Qualor links",
        params: idParams,
        response: { 200: jiraConnectionAnswerSchema },
      },
    },
    async (request) => {
      const organizationId = request.params.id;
      await requireOrganizationAccess(
        accessOf(deps),
        requireUser(request),
        organizationId,
        'org.jira.manage',
      );
      const row = await connectionOf(deps.db, organizationId);
      return {
        connection: row === null ? null : await dto(deps.db, row),
        publicUrlSet: deps.config.publicUrl !== null,
      };
    },
  );

  app.put(
    '/organizations/:id/jira',
    {
      schema: {
        tags: ['jira'],
        summary:
          "Create or replace the organisation's Jira connection (org admins). The token is required on create and with a new address (deployment, siteUrl or apiUrl), which also removes the project mappings and the links of the old one; a token or email alone keeps everything. Nothing is sent to Jira: use the test route",
        params: idParams,
        body: putBody,
        response: { 200: jiraConnectionSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const organizationId = request.params.id;
      const body = request.body;
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.jira.manage');
      const next = checkedConnection(body, deps.config.jiraInternalHosts);
      const tokenEnc =
        body.token === undefined ? undefined : encryptSecret(key, body.token, JIRA_TOKEN_AAD);
      const written = await deps.db.transaction(async (tx) => {
        // Two requests at once make one connection: the organisation first, then the row.
        await tx
          .select({ id: organizations.id })
          .from(organizations)
          .where(eq(organizations.id, organizationId))
          .for('no key update');
        const [row] = await tx
          .select()
          .from(jiraConnections)
          .where(eq(jiraConnections.organizationId, organizationId))
          .for('update');
        if (!row) {
          if (tokenEnc === undefined) {
            throw validationFailed([
              { path: 'body.token', message: 'The token is required to connect Jira' },
            ]);
          }
          const created = first(
            await tx
              .insert(jiraConnections)
              .values({ organizationId, ...next, tokenEnc })
              .returning(),
          );
          // The schedule lock before the audit chain's, as every Jira path takes them.
          await scheduleJiraSync(tx, organizationId, 0);
          await audit(tx, request, created, 'jira_connection.created', {
            deployment: created.deployment,
            siteOrigin: urlOrigin(created.siteUrl),
          });
          return created;
        }
        // spec §6.1: a stored token only ever serves the address it was saved for; a new address
        // is a new connection, whose mappings and links belong to the old site.
        const moves =
          next.deployment !== row.deployment ||
          next.siteUrl !== row.siteUrl ||
          next.apiUrl !== row.apiUrl;
        if (moves && tokenEnc === undefined) {
          throw validationFailed([
            {
              path: 'body.token',
              message: 'Changing the address needs the token again, in the same request',
            },
          ]);
        }
        const changed = JIRA_CONNECTION_CHANGED_FIELDS.filter((field) =>
          field === 'token' ? tokenEnc !== undefined : next[field] !== row[field],
        );
        if (changed.length === 0) return row;
        if (moves) {
          await tx.delete(projectJiraSettings).where(eq(projectJiraSettings.connectionId, row.id));
          await tx.delete(jiraLinks).where(eq(jiraLinks.connectionId, row.id));
        }
        const updated = first(
          await tx
            .update(jiraConnections)
            .set({
              ...next,
              ...(tokenEnc === undefined ? {} : { tokenEnc }),
              updatedAt: sql`now()`,
            })
            .where(eq(jiraConnections.id, row.id))
            .returning(),
        );
        // R5: a new token, email or address may be what the background problem was about; the
        // waiting pass runs now, so a bad new one shows within seconds.
        await setConnectionProblem(tx, row.id, null);
        await syncJiraNow(tx, organizationId);
        await audit(tx, request, updated, 'jira_connection.updated', { changed });
        return updated;
      });
      const [fresh] = await deps.db
        .select()
        .from(jiraConnections)
        .where(eq(jiraConnections.id, written.id));
      return dto(deps.db, fresh ?? written);
    },
  );

  app.delete(
    '/organizations/:id/jira',
    {
      schema: {
        tags: ['jira'],
        summary:
          "Remove the organisation's Jira connection with its project mappings and links (org admins); the Jira issues stay. 404 without a connection",
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const organizationId = request.params.id;
      await requireOrganizationAccess(
        accessOf(deps),
        requireUser(request),
        organizationId,
        'org.jira.manage',
      );
      await deps.db.transaction(async (tx) => {
        const [row] = await tx
          .select()
          .from(jiraConnections)
          .where(eq(jiraConnections.organizationId, organizationId))
          .for('update');
        if (!row) throw notFound('Jira connection');
        const [links] = await tx
          .select({ n: count() })
          .from(jiraLinks)
          .where(eq(jiraLinks.connectionId, row.id));
        await tx.delete(jiraConnections).where(eq(jiraConnections.id, row.id));
        await audit(tx, request, row, 'jira_connection.deleted', {
          deployment: row.deployment,
          siteOrigin: urlOrigin(row.siteUrl),
          links: links?.n ?? 0,
        });
      });
      return reply.code(204).send();
    },
  );

  app.post(
    '/organizations/:id/jira/test',
    {
      config: {
        openapi: {
          problems: [409],
          problemDescriptions: { 409: 'JIRA_NOT_CONNECTED: the organisation has no connection' },
        },
      },
      schema: {
        tags: ['jira'],
        summary:
          "Check the stored connection (org admins): `GET /myself`, then the projects the account sees. Answers 200 with `problem` (a fixed text and its code) when it fails; a passing test clears the connection's background problem. Not audited",
        params: idParams,
        response: { 200: jiraTestSchema },
      },
    },
    async (request) => {
      const organizationId = request.params.id;
      await requireOrganizationAccess(
        accessOf(deps),
        requireUser(request),
        organizationId,
        'org.jira.manage',
      );
      const row = await connectionOf(deps.db, organizationId);
      if (!row) throw conflict('JIRA_NOT_CONNECTED', 'The organisation has no Jira connection');
      const result = await testJiraConnection(row, jiraDeps);
      if (result.ok && row.problem !== null) await setConnectionProblem(deps.db, row.id, null);
      return result;
    },
  );
};

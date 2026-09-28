import { and, asc, count, eq, gt, isNull } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import {
  SCM_CONNECTION_CHANGED_FIELDS,
  type AuditAction,
  type AuditDetails,
} from '../audit/catalogue';
import { actorOf, type AuditEventInput } from '../audit/recorder';
import { organizationRef } from '../audit/refs';
import {
  type AccessContext,
  accessOf,
  requireOrganizationAccess,
  requirePermission,
  requireUser,
} from '../auth/access';
import { grantInOrganization, memberOf, organizationFacts } from '../auth/facts';
import { organizationPermissions } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import { memberships, organizations, scmConnections } from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import {
  conflict,
  notFound,
  ProblemError,
  validationFailed,
  type FieldError,
} from '../http/problem';
import { idParams, iso, noContent, noNul, timestamp } from '../http/schemas';
import { SCM_PROJECT_REF_PATTERN } from '../patterns';
import {
  forgetForeignMergeRequestUrls,
  MAX_SCM_CONNECTIONS_PER_ORGANIZATION,
  SCM_TOKEN_AAD,
  SCM_TOKEN_PATTERN,
  TEST_PROBLEM_CODES,
  testConnection,
  type ScmConnectionRow,
} from '../scm/connections';
import {
  GITHUB_APP_ID,
  isGitHubAppId,
  MAX_PRIVATE_KEY_BYTES,
  parseAppPrivateKey,
  PRIVATE_KEY_PROBLEM_TEXT,
  WEBHOOK_SECRET_PATTERN,
} from '../scm/github/app-auth';
import { githubWebhookUrl, testGitHubConnection } from '../scm/github/connections';
import {
  decryptPrivateKey,
  decryptWebhookSecret,
  encryptPrivateKey,
  encryptWebhookSecret,
} from '../scm/github/credentials';
import { GITHUB_REPO_PATTERN, githubBaseUrlProblem } from '../scm/github/url';
import { normalBaseUrl, scmBaseUrlProblem } from '../scm/url';

const githubSchema = z.object({
  appId: z.string(),
  /** False when `token_enc` no longer decrypts to an RSA key (QUALOR_SECRET_KEY changed). */
  keyReadable: z.boolean(),
  webhookSecretSet: z.boolean(),
  webhookSecretReadable: z.boolean(),
  /** Null without `QUALOR_PUBLIC_URL` or without a webhook secret (github.md §2.2). */
  webhookUrl: z.string().nullable(),
});

const connectionSchema = z.object({
  id: z.uuid(),
  organizationId: z.uuid(),
  provider: z.enum(['gitlab', 'github']),
  baseUrl: z.string(),
  createdAt: timestamp,
  /** The GitHub App (github.md §2.2); null for GitLab. Never the key or the secret. */
  github: githubSchema.nullable(),
});

const testResultSchema = z.object({
  ok: z.boolean(),
  user: z.object({ username: z.string() }).nullable(),
  project: z.object({ id: z.number().int(), pathWithNamespace: z.string() }).nullable(),
  problem: z.object({ code: z.enum(TEST_PROBLEM_CODES), message: z.string() }).nullable(),
});

function connectionDto(
  row: ScmConnectionRow,
  key: Buffer,
  publicUrl: string | null,
): z.infer<typeof connectionSchema> {
  const secretSet = row.webhookSecretEnc !== null;
  return {
    id: row.id,
    organizationId: row.organizationId,
    provider: row.provider,
    baseUrl: row.baseUrl,
    createdAt: iso(row.createdAt),
    github:
      row.provider === 'github'
        ? {
            appId: row.appId ?? '',
            keyReadable: decryptPrivateKey(key, row.tokenEnc) !== null,
            webhookSecretSet: secretSet,
            webhookSecretReadable:
              secretSet && decryptWebhookSecret(key, row.webhookSecretEnc) !== null,
            webhookUrl: secretSet ? githubWebhookUrl(publicUrl, row.id) : null,
          }
        : null,
  };
}

const baseUrl = noNul(z.string().min(1).max(2_048));
/**
 * The GitLab access token (scm.md §2.1): the `api` scope and the Developer role, preferably a
 * project access token of the mapped GitLab project (it reaches nothing else), else a group access
 * token or a bot user's personal token, never a human's. Stored encrypted (AAD
 * `scm_connections.token_enc`), never echoed or logged; the pattern keeps it header-safe.
 */
const token = z.string().regex(SCM_TOKEN_PATTERN, {
  message: 'Use 1-1024 printable ASCII characters without spaces',
});
/** github.md §2.2: the App id GitHub shows, a positive integer without leading zeros. */
const APP_ID_TEXT = 'Use the App id GitHub shows (a positive integer)';
const appId = z
  .string()
  .regex(GITHUB_APP_ID, { message: APP_ID_TEXT, abort: true })
  .refine(isGitHubAppId, { message: APP_ID_TEXT });
/**
 * github.md §2.2: the App's private key PEM (PKCS#1 or PKCS#8, RSA ≥ 2 048 bits, unencrypted),
 * checked in the handler. Stored encrypted as its PKCS#8 export, never echoed or logged.
 */
const privateKey = noNul(z.string().min(1).max(MAX_PRIVATE_KEY_BYTES));
/** github.md §2.2: optional; the same value as in the App's webhook settings. */
const webhookSecret = z.string().regex(WEBHOOK_SECRET_PATTERN, {
  message: 'Use 16-256 printable ASCII characters without spaces',
});
/** A field of the other provider: refused with its own path. */
const notAField = (provider: string) =>
  z
    .never({ message: `Not a field of a ${provider} connection` })
    .meta({ description: `Not a field of a ${provider} connection: sending it is a 422` })
    .optional();

const PROJECT_REF_TEXT = {
  gitlab: 'Use the GitLab project id or its full path (group/project)',
  github: 'Use the GitHub repository as owner/repo',
} as const;
/**
 * A project reference of either provider: a GitLab project id or path (scm.md §2.2), or a GitHub
 * `owner/repo` (github.md §2.3). Where the connection is known, it is checked against its own
 * provider's pattern ({@link projectRefProblem}).
 */
export const scmProjectRef = z
  .string()
  .max(255)
  .regex(new RegExp(`${SCM_PROJECT_REF_PATTERN.source}|${GITHUB_REPO_PATTERN.source}`), {
    message: 'Use the GitLab project id or its full path (group/project), or GitHub owner/repo',
  });

/** Why `ref` is not a project reference of `provider`, or null. */
export function projectRefProblem(provider: 'gitlab' | 'github', ref: string): string | null {
  const pattern = provider === 'github' ? GITHUB_REPO_PATTERN : SCM_PROJECT_REF_PATTERN;
  return pattern.test(ref) ? null : PROJECT_REF_TEXT[provider];
}

/** The canonical PKCS#8 PEM of an App private key, or a 422 on `body.privateKey`. */
function checkedPrivateKey(raw: string): string {
  const parsed = parseAppPrivateKey(raw);
  if ('problem' in parsed) {
    throw validationFailed([
      { path: 'body.privateKey', message: PRIVATE_KEY_PROBLEM_TEXT[parsed.problem] },
    ]);
  }
  return parsed.pkcs8;
}

/**
 * The connection named in the path. Every route is 🛡 (scm.md §2.1), like webhooks: a missing
 * connection and one of an organisation the caller does not belong to are the same 404; a member
 * who is not an admin gets 403.
 */
async function connectionFor(
  access: AccessContext,
  principal: UserPrincipal,
  id: string,
): Promise<ScmConnectionRow> {
  const [row] = await access.db
    .select({
      connection: scmConnections,
      organizationRole: memberships.role,
      hasProjectGrant: grantInOrganization(principal.user, scmConnections.organizationId),
    })
    .from(scmConnections)
    .leftJoin(memberships, memberOf(principal.user, scmConnections.organizationId))
    .where(eq(scmConnections.id, id));
  if (!row) throw notFound('SCM connection');
  const permissions = organizationPermissions(organizationFacts(principal.user, row));
  requirePermission(principal, permissions, 'org.scm.manage', 'org.read', 'SCM connection');
  return row.connection;
}

export const scmConnectionRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const key = encryptionKey(deps.config.secretKey);
  const publicUrl = deps.config.publicUrl;
  const dto = (row: ScmConnectionRow) => connectionDto(row, key, publicUrl);
  /**
   * rbac-audit.md §8, §9: one event about `connection` in the change's transaction `tx`. Its
   * base URL is recorded in full (it holds no credentials); never a token, key or secret.
   */
  const audit = async <A extends AuditAction>(
    tx: Executor,
    request: FastifyRequest,
    connection: ScmConnectionRow,
    action: A,
    details: AuditDetails<A>,
  ): Promise<void> => {
    if (!deps.audit.active()) return;
    const event = {
      action,
      organization: await organizationRef(tx, connection.organizationId),
      target: { type: 'scm_connection', id: connection.id, label: connection.baseUrl },
      details,
    } as AuditEventInput;
    await deps.audit.record(tx, actorOf(request), [event]);
  };
  const scmDeps = {
    secretKey: deps.config.secretKey,
    internalHosts: deps.config.scmInternalHosts,
  };
  const checkedBaseUrl = (raw: string, provider: 'gitlab' | 'github'): string => {
    const problem = scmBaseUrlProblem(raw, deps.config.scmInternalHosts);
    if (problem) throw validationFailed([{ path: 'body.baseUrl', message: problem }]);
    const url = normalBaseUrl(raw);
    const githubProblem = provider === 'github' ? githubBaseUrlProblem(url) : null;
    if (githubProblem) throw validationFailed([{ path: 'body.baseUrl', message: githubProblem }]);
    return url;
  };

  app.get(
    '/scm-connections',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['scm'],
        summary:
          'SCM connections of an organisation (org admins); never the token, the private key or the webhook secret',
        querystring: z.strictObject({ ...pageQuery, organizationId: z.uuid() }),
        response: { 200: pageSchema(connectionSchema) },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const { organizationId, limit, cursor } = request.query;
      await requireOrganizationAccess(accessOf(deps), principal, organizationId, 'org.scm.manage');
      const after = decodeCursor(cursor);
      const rows = await deps.db
        .select()
        .from(scmConnections)
        .where(
          and(
            eq(scmConnections.organizationId, organizationId),
            after ? gt(scmConnections.id, after) : undefined,
          ),
        )
        .orderBy(asc(scmConnections.id))
        .limit(limit + 1);
      const page = toPage(rows, limit);
      return { items: page.items.map(dto), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/scm-connections',
    {
      config: { openapi: { problems: [404, 409] } },
      schema: {
        tags: ['scm'],
        summary:
          'Connect an organisation to GitLab (token) or GitHub App (App id, private key, webhook secret)',
        body: z.discriminatedUnion('provider', [
          z.strictObject({
            organizationId: z.uuid(),
            provider: z.literal('gitlab'),
            baseUrl,
            token,
            appId: notAField('GitLab'),
            privateKey: notAField('GitLab'),
            webhookSecret: notAField('GitLab'),
          }),
          z.strictObject({
            organizationId: z.uuid(),
            provider: z.literal('github'),
            baseUrl,
            appId,
            privateKey,
            webhookSecret: webhookSecret.optional(),
            token: notAField('GitHub'),
          }),
        ]),
        response: { 201: connectionSchema },
      },
    },
    async (request, reply) => {
      const principal = requireUser(request);
      const body = request.body;
      await requireOrganizationAccess(
        accessOf(deps),
        principal,
        body.organizationId,
        'org.scm.manage',
      );
      const url = checkedBaseUrl(body.baseUrl, body.provider);
      // The CHECK of migration 0003 backs these rules; the API refuses first, with field errors.
      const values: typeof scmConnections.$inferInsert =
        body.provider === 'github'
          ? {
              organizationId: body.organizationId,
              provider: 'github',
              baseUrl: url,
              appId: body.appId,
              tokenEnc: encryptPrivateKey(key, checkedPrivateKey(body.privateKey)),
              webhookSecretEnc:
                body.webhookSecret === undefined
                  ? null
                  : encryptWebhookSecret(key, body.webhookSecret),
            }
          : {
              organizationId: body.organizationId,
              provider: 'gitlab',
              baseUrl: url,
              tokenEnc: encryptSecret(key, body.token, SCM_TOKEN_AAD),
            };
      const created = await deps.db.transaction(async (tx) => {
        // Serialises concurrent creations for the organisation, so the bound below holds.
        await tx
          .select({ id: organizations.id })
          .from(organizations)
          .where(eq(organizations.id, body.organizationId))
          .for('no key update');
        const [existing] = await tx
          .select({ n: count() })
          .from(scmConnections)
          .where(eq(scmConnections.organizationId, body.organizationId));
        if ((existing?.n ?? 0) >= MAX_SCM_CONNECTIONS_PER_ORGANIZATION) {
          throw conflict(
            'SCM_CONNECTION_LIMIT_REACHED',
            `An organisation has at most ${MAX_SCM_CONNECTIONS_PER_ORGANIZATION} SCM connections`,
          );
        }
        const row = first(await tx.insert(scmConnections).values(values).returning());
        await audit(tx, request, row, 'scm_connection.created', {
          provider: row.provider,
          baseUrl: row.baseUrl,
        });
        return row;
      });
      return reply.code(201).send(dto(created));
    },
  );

  app.patch(
    '/scm-connections/:id',
    {
      config: {
        openapi: {
          problems: [503],
          problemDescriptions: {
            503: 'The connection changed while the request was handled (CONCURRENCY_CONFLICT); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['scm'],
        summary:
          'Change an SCM connection: GitLab (token) or GitHub App (App id, private key, webhook secret); each field on its own, a new base URL with the credentials again',
        params: idParams,
        body: z
          .strictObject({
            baseUrl: baseUrl.optional(),
            token: token.optional(),
            appId: appId.optional(),
            privateKey: privateKey.optional(),
            webhookSecret: webhookSecret.nullable().optional(),
          })
          .refine((b) => Object.keys(b).length > 0, { message: 'At least one field is required' }),
        response: { 200: connectionSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const row = await connectionFor(accessOf(deps), principal, request.params.id);
      const body = request.body;
      const github = row.provider === 'github';
      const foreign = github
        ? (['token'] as const)
        : (['appId', 'privateKey', 'webhookSecret'] as const);
      const wrong = foreign.filter((f) => body[f] !== undefined);
      if (wrong.length > 0) {
        throw validationFailed(
          wrong.map((f) => ({
            path: `body.${f}`,
            message: `Not a field of a ${github ? 'GitHub' : 'GitLab'} connection`,
          })),
        );
      }
      // scm.md §2.1, github.md §2.2: stored credentials only ever serve the address they were
      // saved for. A new origin or path needs them in the same request, so no admin can redirect a
      // token or a key they were never shown (one an instance admin set up, say) to a host of
      // their choosing.
      const credential = github ? ('privateKey' as const) : ('token' as const);
      const bringsCredential = body[credential] !== undefined;
      const needsCredential: FieldError = github
        ? {
            path: 'body.privateKey',
            message: 'Changing the address needs the private key again, in the same request',
          }
        : {
            path: 'body.token',
            message: 'Changing the base URL needs the token again, in the same request',
          };
      const changes: Partial<typeof scmConnections.$inferInsert> = {};
      let moves = false;
      if (body.baseUrl !== undefined) {
        const next = checkedBaseUrl(body.baseUrl, row.provider);
        moves = next !== row.baseUrl;
        if (moves) {
          const missing: FieldError[] = [];
          if (!bringsCredential) missing.push(needsCredential);
          if (github && row.webhookSecretEnc !== null && body.webhookSecret === undefined) {
            missing.push({
              path: 'body.webhookSecret',
              message:
                'Changing the address needs the webhook secret again, or null to drop it, in the same request',
            });
          }
          if (missing.length > 0) throw validationFailed(missing);
        }
        changes.baseUrl = next;
      }
      if (body.token !== undefined)
        changes.tokenEnc = encryptSecret(key, body.token, SCM_TOKEN_AAD);
      if (body.appId !== undefined) changes.appId = body.appId;
      if (body.privateKey !== undefined) {
        changes.tokenEnc = encryptPrivateKey(key, checkedPrivateKey(body.privateKey));
      }
      if (body.webhookSecret !== undefined) {
        changes.webhookSecretEnc =
          body.webhookSecret === null ? null : encryptWebhookSecret(key, body.webhookSecret);
      }
      const updated = await deps.db.transaction(async (tx) => {
        // The checks above hold only for the row they read: the write is conditional on the
        // stored address, so an address changed by a concurrent request (with its own
        // credentials) is never paired with this request's, or kept with this request's address.
        // A move that keeps the webhook secret untouched also needs it to be still unset.
        const [written] = await tx
          .update(scmConnections)
          .set(changes)
          .where(
            and(
              eq(scmConnections.id, row.id),
              eq(scmConnections.baseUrl, row.baseUrl),
              moves && github && body.webhookSecret === undefined
                ? isNull(scmConnections.webhookSecretEnc)
                : undefined,
            ),
          )
          .returning();
        if (!written) {
          const [now] = await tx
            .select({ id: scmConnections.id })
            .from(scmConnections)
            .where(eq(scmConnections.id, row.id));
          if (!now) throw notFound('SCM connection');
          // The stored address is no longer the one this request named: a change of address.
          // A GitHub change without the key (the App id or the secret alone) did not ask for a
          // move, so it is told the address changed, not that a move needs the key.
          if (!bringsCredential && github) {
            throw new ProblemError(
              503,
              'CONCURRENCY_CONFLICT',
              "The connection's address changed while this request was handled; reload it and check the address before trying again",
              { headers: { 'retry-after': '1' } },
            );
          }
          if (!bringsCredential) throw validationFailed([needsCredential]);
          throw new ProblemError(
            503,
            'CONCURRENCY_CONFLICT',
            'The connection changed while this request was handled; reload it and try again',
            { headers: { 'retry-after': '1' } },
          );
        }
        if (written.baseUrl !== row.baseUrl) {
          await forgetForeignMergeRequestUrls(tx, { connectionId: written.id });
        }
        // Names only (rbac-audit.md §8): a credential sent is a change, its value never recorded.
        const changed = SCM_CONNECTION_CHANGED_FIELDS.filter((field) => {
          if (field === 'baseUrl') return written.baseUrl !== row.baseUrl;
          if (field === 'appId') return written.appId !== row.appId;
          if (field === 'webhookSecret') {
            return (
              body.webhookSecret !== undefined &&
              (body.webhookSecret !== null || row.webhookSecretEnc !== null)
            );
          }
          return body[field] !== undefined;
        });
        if (changed.length > 0) {
          await audit(tx, request, written, 'scm_connection.updated', { changed });
        }
        return written;
      });
      return dto(updated);
    },
  );

  app.delete(
    '/scm-connections/:id',
    {
      schema: {
        tags: ['scm'],
        summary: 'Delete an SCM connection; its projects stop being decorated',
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const row = await connectionFor(accessOf(deps), requireUser(request), request.params.id);
      await deps.db.transaction(async (tx) => {
        const [deleted] = await tx
          .delete(scmConnections)
          .where(eq(scmConnections.id, row.id))
          .returning();
        if (deleted) {
          await audit(tx, request, deleted, 'scm_connection.deleted', {
            provider: deleted.provider,
            baseUrl: deleted.baseUrl,
          });
        }
      });
      return reply.code(204).send();
    },
  );

  app.post(
    '/scm-connections/:id/test',
    {
      schema: {
        tags: ['scm'],
        summary:
          'Check the connection (and a GitLab project or GitHub owner/repo) with the stored credentials',
        params: idParams,
        body: z.strictObject({ projectRef: scmProjectRef.optional() }),
        response: { 200: testResultSchema },
      },
    },
    async (request) => {
      const row = await connectionFor(accessOf(deps), requireUser(request), request.params.id);
      const ref = request.body.projectRef ?? null;
      const problem = ref === null ? null : projectRefProblem(row.provider, ref);
      if (problem) throw validationFailed([{ path: 'body.projectRef', message: problem }]);
      return row.provider === 'github'
        ? testGitHubConnection(row, scmDeps, ref)
        : testConnection(row, scmDeps, ref);
    },
  );
};

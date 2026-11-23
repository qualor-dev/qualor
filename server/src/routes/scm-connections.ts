import { assertNever, SCM_PROVIDERS, type ScmProvider } from '@qualor/shared';
import { and, asc, count, eq, gt, isNotNull, isNull, sql, type AnyColumn } from 'drizzle-orm';
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
import { memberships, organizations, projects, scmConnections } from '../db/schema';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import {
  conflict,
  notFound,
  ProblemError,
  validationFailed,
  type FieldError,
} from '../http/problem';
import { idParams, iso, noContent, noNul, timestamp } from '../http/schemas';
import { queueSnapshotPurge } from '../review/jobs';
import { AZURE_AUTH_KINDS } from '../scm/azure/auth-kinds';
import { MAX_AZURE_CERTIFICATE_BYTES } from '../scm/azure/certificate';
import {
  azureCreate,
  azureCredentialField,
  azureMoveNeeds,
  azurePatch,
  azureClientFor,
  azureViewOf,
  mappedAzureProjects,
  testAzureConnection,
} from '../scm/azure/connections';
import { generateHookPassword, subscribeProjects } from '../scm/azure/hooks';
import { AZURE_REPOSITORY_ID, azureBaseUrlProblem, azureWebhookUrl } from '../scm/azure/url';
import { ScmError } from '../scm/provider';
import {
  forgetForeignMergeRequestUrls,
  MAX_SCM_CONNECTIONS_PER_ORGANIZATION,
  MISSING_ACCESS,
  SCM_TOKEN_AAD,
  SCM_TOKEN_PATTERN,
  scmDepsOf,
  TEST_PROBLEM_CODES,
  testConnection,
  type ScmConnectionRow,
} from '../scm/connections';
import { notAFieldText, PROVIDER, type ConnectionPatch } from '../scm/providers';
import {
  GITHUB_APP_ID,
  isGitHubAppId,
  MAX_PRIVATE_KEY_BYTES,
  parseAppPrivateKey,
  PRIVATE_KEY_PROBLEM_TEXT,
  WEBHOOK_SECRET_PATTERN,
} from '../scm/github/app-auth';
import {
  githubWebhookUrl,
  gitlabWebhookUrl,
  testGitHubConnection,
} from '../scm/github/connections';
import {
  decryptPrivateKey,
  decryptWebhookSecret,
  encryptPrivateKey,
  encryptWebhookSecret,
} from '../scm/github/credentials';
import { CI_SETUP_MISSING, createCiSetupStatus, type CiSetupStatus } from '../scm/ci-setup-status';
import { githubBaseUrlProblem } from '../scm/github/url';
import { clearScmProblem } from '../scm/problems';
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

const gitlabSchema = z.object({
  webhookSecretSet: z.boolean(),
  /** False when `webhook_secret_enc` no longer decrypts (QUALOR_SECRET_KEY changed). */
  webhookSecretReadable: z.boolean(),
  /** Null without `QUALOR_PUBLIC_URL` or without a webhook secret. */
  webhookUrl: z.string().nullable(),
  /** Whether Qualor may open CI-setup merge requests in this connection's repositories. */
  ciSetupAllowed: z.boolean(),
});

const azureSchema = z.object({
  /** From the host alone: dev.azure.com and *.visualstudio.com are Services. */
  deployment: z.enum(['services', 'server']),
  auth: z.enum(AZURE_AUTH_KINDS),
  /** A service principal's directory (tenant) and application (client) ids; null for a PAT. */
  tenantId: z.string().nullable(),
  clientId: z.string().nullable(),
  /** False when the stored credential no longer decrypts (QUALOR_SECRET_KEY changed) or parses. */
  credentialReadable: z.boolean(),
  /** The certificate kind's: SHA-1 thumbprint (upper-case hex, as Entra shows it) and expiry. */
  certificate: z.object({ thumbprint: z.string(), notAfter: timestamp }).nullable(),
  /** Whether the connection has a webhook password (the service hooks' Basic password). */
  webhookSecretSet: z.boolean(),
  /** Where Azure DevOps delivers the hooks; null without `QUALOR_PUBLIC_URL` or without a password. */
  webhookUrl: z.string().nullable(),
});

const HOOK_OUTCOMES = ['created', 'replaced', 'unchanged', 'refused'] as const;

const ciSetupSchema = z.object({
  available: z.boolean(),
  reason: z.enum(['not_allowed', 'missing_permissions', 'no_public_url']).nullable().meta({
    description:
      'Why CI setup is not available, the first that applies: `no_public_url` (the server has no QUALOR_PUBLIC_URL), `not_allowed` (GitLab: the connection does not allow it) or `missing_permissions` (GitHub: no installation grants Contents, Workflows and Secrets, read and write, or they could not be read).',
  }),
  missing: z.array(z.enum(CI_SETUP_MISSING)).meta({
    description:
      'GitHub: the permissions the best installation of the App lacks (the first that grants the most of the three). Empty for GitLab, and when they could not be read.',
  }),
});

const connectionSchema = z.object({
  id: z.uuid(),
  organizationId: z.uuid(),
  provider: z.enum(SCM_PROVIDERS),
  baseUrl: z.string(),
  createdAt: timestamp,
  /** The GitHub App (github.md §2.2); null for GitLab. Never the key or the secret. */
  github: githubSchema.nullable(),
  /** What GitLab's webhook needs (6I-4); null for GitHub. Never the secret. */
  gitlab: gitlabSchema.nullable(),
  /** The Azure DevOps side (design §7.1); null for GitLab and GitHub. Never the credential. */
  azure: azureSchema.nullable(),
  /** Whether Qualor can open CI-setup pull or merge requests through this connection. */
  ciSetup: ciSetupSchema,
  /** Whether Qualor may open fix merge or pull requests in this connection's repositories. */
  fixMrsAllowed: z.boolean(),
  /** The credential or permission failure of the last decoration (Azure DevOps); null when none. */
  problem: z.object({ code: z.enum(TEST_PROBLEM_CODES), at: timestamp }).nullable(),
});

const testResultSchema = z.object({
  ok: z.boolean(),
  user: z.object({ username: z.string() }).nullable(),
  project: z
    .object({
      /** GitLab's and GitHub's numeric id; Azure DevOps' repository id (a GUID). */
      id: z.union([z.number().int(), z.string()]),
      /** Azure DevOps: `<project>/<repository>`. */
      pathWithNamespace: z.string(),
      /** GitLab: the token's access level in the project (40 = Maintainer); null if unknown. */
      accessLevel: z.number().int().nullable(),
    })
    .nullable(),
  problem: z.object({ code: z.enum(TEST_PROBLEM_CODES), message: z.string() }).nullable(),
  missingAccess: z.array(z.enum(MISSING_ACCESS)).nullable().meta({
    description:
      "GitHub, with a repository: what the App's installation lacks of the access Qualor uses beyond what every job needs (Checks and Pull requests, read and write, whose lack fails the test), in this order: `contents_write` (Qualor's conversations are not resolved or reopened), `issues_read` (GitHub sends no Issue comment event), `event_check_run` (the Re-run button does nothing), `event_issue_comment` and `event_pull_request_review_comment` (commands and replies are answered at the next analysis). `[]` when nothing is missing; the test passes either way. Null for GitLab, without a repository, and when the test failed.",
  }),
  visible: z
    .object({ repositories: z.number().int(), projects: z.number().int() })
    .nullable()
    .meta({
      description:
        'Azure DevOps: the repositories the identity sees, and the projects that hold them. Null for GitLab and GitHub, and when the test failed.',
    }),
  hooks: z
    .array(
      z.object({
        projectId: z.string(),
        state: z.enum(['enabled', 'onProbation', 'disabled', 'missing']),
      }),
    )
    .nullable()
    .meta({
      description:
        "Azure DevOps: the state of Qualor's service hook subscriptions in each Azure project that holds a mapped repository (`missing`: Qualor does not have both of its subscriptions there; `disabled`: Azure DevOps or a person switched one off). Null for GitLab and GitHub, and when the test failed or the subscriptions could not be read.",
    }),
});

const hookSecretSchema = z.object({
  url: z.string().nullable().meta({
    description: 'The address Azure DevOps delivers to; null without QUALOR_PUBLIC_URL.',
  }),
  user: z.literal('qualor'),
  password: z.string().meta({
    description:
      'The new webhook password. Shown only in this answer; Qualor cannot show it again.',
  }),
});

const hooksSchema = z.object({
  projects: z.array(
    z.object({
      projectId: z.string(),
      comment: z.enum(HOOK_OUTCOMES),
      updated: z.enum(HOOK_OUTCOMES),
    }),
  ),
});

/** The hooks could not be written: Azure DevOps' fixed text, never its own words. */
function hooksUnavailable(detail: string): ProblemError {
  return new ProblemError(
    502,
    'SCM_UNAVAILABLE',
    'Azure DevOps service hooks could not be written',
    {
      detail,
    },
  );
}

function connectionDto(
  row: ScmConnectionRow,
  key: Buffer,
  publicUrl: string | null,
  ciSetup: CiSetupStatus,
): z.infer<typeof connectionSchema> {
  const secretSet = row.webhookSecretEnc !== null;
  const secretReadable = secretSet && decryptWebhookSecret(key, row.webhookSecretEnc) !== null;
  let github: z.infer<typeof githubSchema> | null = null;
  let gitlab: z.infer<typeof gitlabSchema> | null = null;
  let azure: z.infer<typeof azureSchema> | null = null;
  switch (row.provider) {
    case 'github':
      github = {
        appId: row.appId ?? '',
        keyReadable: decryptPrivateKey(key, row.tokenEnc) !== null,
        webhookSecretSet: secretSet,
        webhookSecretReadable: secretReadable,
        webhookUrl: secretSet ? githubWebhookUrl(publicUrl, row.id) : null,
      };
      break;
    case 'gitlab':
      gitlab = {
        webhookSecretSet: secretSet,
        webhookSecretReadable: secretReadable,
        webhookUrl: secretSet ? gitlabWebhookUrl(publicUrl, row.id) : null,
        ciSetupAllowed: row.ciSetupAllowed,
      };
      break;
    case 'azure': {
      const view = azureViewOf(row, key);
      azure = {
        ...view,
        webhookSecretSet: secretSet,
        webhookUrl: secretSet && publicUrl !== null ? azureWebhookUrl(publicUrl, row.id) : null,
        certificate: view.certificate && {
          ...view.certificate,
          notAfter: iso(view.certificate.notAfter),
        },
      };
      break;
    }
    default:
      return assertNever(row.provider, 'provider');
  }
  return {
    id: row.id,
    organizationId: row.organizationId,
    provider: row.provider,
    baseUrl: row.baseUrl,
    createdAt: iso(row.createdAt),
    github,
    gitlab,
    azure,
    ciSetup,
    fixMrsAllowed: row.fixMrsAllowed,
    problem: row.problem && { code: row.problem.code, at: row.problem.at },
  };
}

const baseUrl = noNul(z.string().min(1).max(2_048));
/**
 * The GitLab access token (scm.md §2.1): the `api` scope and the Maintainer role (a Developer
 * cannot set a commit status on a protected branch), preferably a
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
/**
 * github.md §2.2: optional; the same value as in the App's webhook settings. On a GitLab
 * connection (6I-4) the same rules: the secret token of the project's webhook.
 */
const webhookSecret = z.string().regex(WEBHOOK_SECRET_PATTERN, {
  message: 'Use 16-256 printable ASCII characters without spaces',
});
/** A field of another provider: refused with its own path. */
const notAField = (provider: ScmProvider) =>
  z
    .never({ message: notAFieldText(provider) })
    .meta({ description: `${notAFieldText(provider)}: sending it is a 422` })
    .optional();
/** Azure DevOps (design §7.1): a service principal's tenant or client id, a GUID in any case. */
const azureId = (name: string) =>
  z.string().regex(AZURE_REPOSITORY_ID, { message: `Use the ${name}, a GUID` });
/**
 * Azure DevOps: the certificate of a service principal and its private key (RSA ≥ 2 048 bits,
 * unencrypted), one PEM text, checked in the handler. Stored encrypted as sent, never echoed or
 * logged.
 */
const certificate = noNul(z.string().min(1).max(MAX_AZURE_CERTIFICATE_BYTES));

/**
 * A project reference: a GitLab project id or path (scm.md §2.2), a GitHub `owner/repo`
 * (github.md §2.3) or an Azure DevOps repository id (design §7.2), checked against the mapped
 * connection's provider (`PROVIDER[provider].projectRefProblem`).
 */
export const scmProjectRef = z.string().min(1).max(255);

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
 * How a PATCH that lost a race on the stored row is told: `address`, the address changed whatever
 * it names, unless it brings the credential (GitHub); `unnamed-address`, so only when it names no
 * address and brings no credential, else that a move needs the credential (GitLab); `connection`,
 * the connection changed (Azure DevOps, where the kind or the ids may have changed instead).
 */
const LOST_RACE: Record<ScmProvider, 'address' | 'unnamed-address' | 'connection'> = {
  github: 'address',
  gitlab: 'unnamed-address',
  azure: 'connection',
};
/** The shape of an address beyond the common rules (scm/url.ts), or null. */
const ADDRESS_SHAPE_PROBLEM: Record<ScmProvider, (normalised: string) => string | null> = {
  gitlab: () => null,
  github: githubBaseUrlProblem,
  azure: azureBaseUrlProblem,
};

/** A 422 for each sent field the connection's provider does not have. */
function checkProviderFields(body: ConnectionPatch, provider: ScmProvider): void {
  const wrong = PROVIDER[provider].foreignFields.filter((f) => body[f] !== undefined);
  if (wrong.length > 0) {
    throw validationFailed(
      wrong.map((f) => ({ path: `body.${f}`, message: notAFieldText(provider) })),
    );
  }
}

/**
 * The credential field a move of the address must bring again (on Azure DevOps that of the kind
 * the connection is or becomes), and the 422 without it.
 */
function moveCredential(
  row: ScmConnectionRow,
  body: ConnectionPatch,
): { field: 'privateKey' | 'token' | 'certificate'; needed: FieldError } {
  switch (row.provider) {
    case 'github':
      return {
        field: 'privateKey',
        needed: {
          path: 'body.privateKey',
          message: 'Changing the address needs the private key again, in the same request',
        },
      };
    case 'gitlab':
      return {
        field: 'token',
        needed: {
          path: 'body.token',
          message: 'Changing the base URL needs the token again, in the same request',
        },
      };
    case 'azure': {
      // The CHECK of migration 0034 sets the kind of every Azure DevOps row.
      const kind = body.azureAuth ?? row.azureAuth ?? 'pat';
      return { field: azureCredentialField(kind), needed: azureMoveNeeds(kind) };
    }
    default:
      return assertNever(row.provider, 'provider');
  }
}

/**
 * The provider's own checks of a PATCH whose address becomes `baseUrl`, and the columns they
 * set: Azure DevOps' kind and ids (azure/connections.ts); nothing for GitLab and GitHub.
 */
function providerChanges(
  row: ScmConnectionRow,
  body: ConnectionPatch,
  baseUrl: string,
  moves: boolean,
): { columns: Partial<typeof scmConnections.$inferInsert> } | { problems: FieldError[] } {
  switch (row.provider) {
    case 'github':
    case 'gitlab':
      return { columns: {} };
    case 'azure':
      return azurePatch(row, body, baseUrl, moves);
    default:
      return assertNever(row.provider, 'provider');
  }
}

/** `column` holds `value`, NULL included. */
const holds = (column: AnyColumn, value: string | null) =>
  value === null ? isNull(column) : eq(column, value);

/**
 * What a move of the address lacks: the credential (`missingCredential`, when it was not sent)
 * and, while a webhook secret is stored, the secret again or null.
 */
function moveProblems(
  body: ConnectionPatch,
  row: ScmConnectionRow,
  missingCredential: FieldError | null,
): FieldError[] {
  const missing: FieldError[] = [];
  if (missingCredential !== null) missing.push(missingCredential);
  if (row.webhookSecretEnc !== null && body.webhookSecret === undefined) {
    missing.push({
      path: 'body.webhookSecret',
      message:
        'Changing the address needs the webhook secret again, or null to drop it, in the same request',
    });
  }
  return missing;
}

/** Sets in `changes` the stored form of each sent field besides the base URL. */
function addFieldChanges(
  changes: Partial<typeof scmConnections.$inferInsert>,
  body: ConnectionPatch,
  key: Buffer,
): void {
  if (body.token !== undefined) changes.tokenEnc = encryptSecret(key, body.token, SCM_TOKEN_AAD);
  // Azure DevOps: the certificate with its key as sent, once azurePatch accepted it.
  if (body.certificate !== undefined) {
    changes.tokenEnc = encryptSecret(key, body.certificate, SCM_TOKEN_AAD);
  }
  if (body.appId !== undefined) changes.appId = body.appId;
  if (body.privateKey !== undefined) {
    changes.tokenEnc = encryptPrivateKey(key, checkedPrivateKey(body.privateKey));
  }
  if (body.ciSetupAllowed !== undefined) changes.ciSetupAllowed = body.ciSetupAllowed;
  if (body.fixMrsAllowed !== undefined) changes.fixMrsAllowed = body.fixMrsAllowed;
  if (body.webhookSecret !== undefined) {
    changes.webhookSecretEnc =
      body.webhookSecret === null ? null : encryptWebhookSecret(key, body.webhookSecret);
  }
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
  const scmDeps = scmDepsOf(deps.config);
  /** A passing test says the credential works again: the background problem it recorded is gone. */
  const clearedByPass = async <T extends { ok: boolean }>(result: T, id: string): Promise<T> => {
    if (result.ok) await clearScmProblem(deps.db, id);
    return result;
  };
  const ciSetupOf = createCiSetupStatus({
    deps: scmDeps,
    publicUrl,
    warn: (message, context) => app.log.warn(context, message),
  });
  const dto = async (row: ScmConnectionRow) =>
    connectionDto(row, key, publicUrl, await ciSetupOf(row));
  /** The repository ids the connection's projects are mapped to. */
  const mappedRefs = async (connectionId: string): Promise<string[]> =>
    (
      await deps.db
        .select({ ref: projects.scmProjectRef })
        .from(projects)
        .where(and(eq(projects.scmConnectionId, connectionId), isNotNull(projects.scmProjectRef)))
    ).flatMap((p) => (p.ref === null ? [] : [p.ref]));
  /** The Azure DevOps connection of the path; any other provider's is not found. */
  const azureConnectionFor = async (request: FastifyRequest<{ Params: { id: string } }>) => {
    const row = await connectionFor(accessOf(deps), requireUser(request), request.params.id);
    if (row.provider !== 'azure') throw notFound('Azure DevOps connection');
    return row;
  };
  /**
   * Stores a new webhook password for the Azure DevOps connection and returns it: the only time
   * it is seen. Azure DevOps does not hold it until the subscriptions are written again.
   */
  const storeNewHookPassword = async (tx: Executor, row: ScmConnectionRow): Promise<string> => {
    const password = generateHookPassword();
    await tx
      .update(scmConnections)
      .set({ webhookSecretEnc: encryptWebhookSecret(key, password) })
      .where(eq(scmConnections.id, row.id));
    return password;
  };
  const checkedBaseUrl = (raw: string, provider: ScmProvider): string => {
    const problem = scmBaseUrlProblem(raw, deps.config.scmInternalHosts);
    if (problem) throw validationFailed([{ path: 'body.baseUrl', message: problem }]);
    const url = normalBaseUrl(raw);
    const shape = ADDRESS_SHAPE_PROBLEM[provider](url);
    if (shape) throw validationFailed([{ path: 'body.baseUrl', message: shape }]);
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
      return { items: await Promise.all(page.items.map(dto)), nextCursor: page.nextCursor };
    },
  );

  app.post(
    '/scm-connections',
    {
      config: { openapi: { problems: [404, 409] } },
      schema: {
        tags: ['scm'],
        summary:
          'Connect an organisation to GitLab (token, optional webhook secret), GitHub App (App id, private key, webhook secret) or Azure DevOps (a service principal with a client secret or a certificate, or a PAT)',
        body: z.discriminatedUnion('provider', [
          z.strictObject({
            organizationId: z.uuid(),
            provider: z.literal('gitlab'),
            baseUrl,
            token,
            appId: notAField('gitlab'),
            privateKey: notAField('gitlab'),
            webhookSecret: webhookSecret.optional(),
            ciSetupAllowed: z.boolean().optional(),
            fixMrsAllowed: z.boolean().optional(),
          }),
          z.strictObject({
            organizationId: z.uuid(),
            provider: z.literal('github'),
            baseUrl,
            appId,
            privateKey,
            webhookSecret: webhookSecret.optional(),
            token: notAField('github'),
            ciSetupAllowed: notAField('github'),
            fixMrsAllowed: z.boolean().optional(),
          }),
          z.strictObject({
            organizationId: z.uuid(),
            provider: z.literal('azure'),
            baseUrl,
            azureAuth: z.enum(AZURE_AUTH_KINDS).meta({
              description:
                '`service_principal_secret` (`tenantId`, `clientId`, the client secret in `token`) and `service_principal_certificate` (`tenantId`, `clientId`, `certificate`) on Azure DevOps Services only; `pat` (`token`) on both',
            }),
            token: token.optional(),
            tenantId: azureId('directory (tenant) id').optional(),
            clientId: azureId('application (client) id').optional(),
            certificate: certificate.optional(),
            appId: notAField('azure'),
            privateKey: notAField('azure'),
            webhookSecret: notAField('azure'),
            ciSetupAllowed: notAField('azure'),
            fixMrsAllowed: notAField('azure'),
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
      // The CHECK of migrations 0003 and 0017 backs the App id rules (migration 0017 lets a GitLab
      // connection hold a webhook secret); the API refuses first, with field errors.
      const webhookSecretEnc =
        body.webhookSecret === undefined ? null : encryptWebhookSecret(key, body.webhookSecret);
      let values: typeof scmConnections.$inferInsert;
      switch (body.provider) {
        case 'github':
          values = {
            organizationId: body.organizationId,
            provider: 'github',
            baseUrl: url,
            appId: body.appId,
            tokenEnc: encryptPrivateKey(key, checkedPrivateKey(body.privateKey)),
            webhookSecretEnc,
            fixMrsAllowed: body.fixMrsAllowed ?? false,
          };
          break;
        case 'gitlab':
          values = {
            organizationId: body.organizationId,
            provider: 'gitlab',
            baseUrl: url,
            tokenEnc: encryptSecret(key, body.token, SCM_TOKEN_AAD),
            webhookSecretEnc,
            ciSetupAllowed: body.ciSetupAllowed ?? false,
            fixMrsAllowed: body.fixMrsAllowed ?? false,
          };
          break;
        case 'azure': {
          // The CHECKs of migration 0034 back the kind and id rules; the API refuses first.
          const azure = azureCreate(body, url);
          if ('problems' in azure) throw validationFailed(azure.problems);
          values = {
            organizationId: body.organizationId,
            provider: 'azure',
            baseUrl: url,
            ...azure.columns,
            tokenEnc: encryptSecret(key, azure.credential, SCM_TOKEN_AAD),
          };
          break;
        }
        default:
          return assertNever(body, 'provider');
      }
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
      return reply.code(201).send(await dto(created));
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
          'Change an SCM connection: GitLab (token, webhook secret), GitHub App (App id, private key, webhook secret) or Azure DevOps (authentication kind, ids, credential); each field on its own, a new base URL with the credentials again, a new Azure DevOps kind or id with its credential',
        params: idParams,
        body: z
          .strictObject({
            baseUrl: baseUrl.optional(),
            token: token.optional(),
            appId: appId.optional(),
            privateKey: privateKey.optional(),
            webhookSecret: webhookSecret.nullable().optional(),
            ciSetupAllowed: z.boolean().optional(),
            fixMrsAllowed: z.boolean().optional(),
            azureAuth: z.enum(AZURE_AUTH_KINDS).optional(),
            tenantId: azureId('directory (tenant) id').optional(),
            clientId: azureId('application (client) id').optional(),
            certificate: certificate.optional(),
          })
          .refine((b) => Object.keys(b).length > 0, { message: 'At least one field is required' }),
        response: { 200: connectionSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const row = await connectionFor(accessOf(deps), principal, request.params.id);
      const body = request.body;
      checkProviderFields(body, row.provider);
      // scm.md §2.1, github.md §2.2: stored credentials only ever serve the address they were
      // saved for. A new origin or path needs them in the same request, so no admin can redirect a
      // token or a key they were never shown (one an instance admin set up, say) to a host of
      // their choosing. On Azure DevOps the same holds for the kind and the ids (azurePatch).
      const { field: credential, needed: needsCredential } = moveCredential(row, body);
      const bringsCredential = body[credential] !== undefined;
      const changes: Partial<typeof scmConnections.$inferInsert> = {};
      let moves = false;
      let next = row.baseUrl;
      if (body.baseUrl !== undefined) {
        next = checkedBaseUrl(body.baseUrl, row.provider);
        moves = next !== row.baseUrl;
        changes.baseUrl = next;
      }
      const missing = moves
        ? moveProblems(body, row, bringsCredential ? null : needsCredential)
        : [];
      const own = providerChanges(row, body, next, moves);
      if ('problems' in own || missing.length > 0) {
        throw validationFailed([...missing, ...('problems' in own ? own.problems : [])]);
      }
      Object.assign(changes, own.columns);
      addFieldChanges(changes, body, key);
      const updated = await deps.db.transaction(async (tx) => {
        // The checks above hold only for the row they read: the write is conditional on the
        // stored address (and Azure DevOps kind and ids), so an address changed by a concurrent
        // request (with its own credentials) is never paired with this request's, or kept with
        // this request's address. A move that keeps the webhook secret untouched also needs it
        // to be still unset.
        const [written] = await tx
          .update(scmConnections)
          .set(changes)
          .where(
            and(
              eq(scmConnections.id, row.id),
              eq(scmConnections.baseUrl, row.baseUrl),
              holds(scmConnections.azureAuth, row.azureAuth),
              holds(scmConnections.azureTenantId, row.azureTenantId),
              holds(scmConnections.azureClientId, row.azureClientId),
              moves && body.webhookSecret === undefined
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
          // GitLab and GitHub: the stored address is no longer the one this request named, a
          // change of address. A change without the credential that names no address (the GitHub
          // App id or either provider's secret alone) did not ask for a move, so it is told the
          // address changed, not that a move needs the credential. A GitHub change is told so
          // whatever it names. Azure DevOps: the address, the kind or the ids changed.
          const lost = LOST_RACE[row.provider];
          if (
            lost !== 'connection' &&
            !bringsCredential &&
            (lost === 'address' || body.baseUrl === undefined)
          ) {
            throw new ProblemError(
              503,
              'CONCURRENCY_CONFLICT',
              "The connection's address changed while this request was handled; reload it and check the address before trying again",
              { headers: { 'retry-after': '1' } },
            );
          }
          if (lost !== 'connection' && !bringsCredential) {
            throw validationFailed([needsCredential]);
          }
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
          if (field === 'azureAuth') return written.azureAuth !== row.azureAuth;
          if (field === 'tenantId') return written.azureTenantId !== row.azureTenantId;
          if (field === 'clientId') return written.azureClientId !== row.azureClientId;
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
      return await dto(updated);
    },
  );

  app.post(
    '/scm-connections/:id/azure-hooks/secret',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['scm'],
        summary:
          "Azure DevOps: generate a new webhook password (the service hooks' Basic password) and show it once. The subscriptions keep the old one until `POST /scm-connections/{id}/azure-hooks` writes them again",
        params: idParams,
        response: { 200: hookSecretSchema },
      },
    },
    async (request) => {
      const row = await azureConnectionFor(request);
      const password = await deps.db.transaction(async (tx) => {
        const created = await storeNewHookPassword(tx, row);
        await audit(tx, request, row, 'scm_connection.updated', { changed: ['webhookSecret'] });
        return created;
      });
      return {
        url: publicUrl === null ? null : azureWebhookUrl(publicUrl, row.id),
        user: 'qualor' as const,
        password,
      };
    },
  );

  app.post(
    '/scm-connections/:id/azure-hooks',
    {
      config: { openapi: { problems: [404, 409] } },
      schema: {
        tags: ['scm'],
        summary:
          "Azure DevOps: create Qualor's two service hook subscriptions in each Azure project that holds a mapped repository, or rewrite them when their version, status or password differ. 409 `PUBLIC_URL_NOT_HTTPS` unless QUALOR_PUBLIC_URL is an https address",
        params: idParams,
        response: { 200: hooksSchema },
      },
    },
    async (request) => {
      const row = await azureConnectionFor(request);
      if (publicUrl === null || !publicUrl.startsWith('https://')) {
        throw conflict(
          'PUBLIC_URL_NOT_HTTPS',
          'Azure DevOps sends the hooks with a password only to an https address: set QUALOR_PUBLIC_URL to one',
        );
      }
      const made = azureClientFor(row, scmDeps);
      if ('problem' in made) throw hooksUnavailable(made.problem);
      let password = decryptWebhookSecret(key, row.webhookSecretEnc);
      let passwordKnownToAzure = row.webhookSecretEnc?.hooksPushed === true;
      if (password === null) {
        password = await deps.db.transaction(async (tx) => {
          const created = await storeNewHookPassword(tx, row);
          await audit(tx, request, row, 'scm_connection.updated', { changed: ['webhookSecret'] });
          return created;
        });
        passwordKnownToAzure = false;
      }
      let projectOutcomes;
      try {
        const refs = await mappedRefs(row.id);
        projectOutcomes = await subscribeProjects({
          client: made.client,
          url: azureWebhookUrl(publicUrl, row.id),
          password,
          passwordKnownToAzure,
          projectIds:
            refs.length === 0 ? [] : mappedAzureProjects(await made.client.repositories(), refs),
        });
      } catch (err) {
        if (err instanceof ScmError) throw hooksUnavailable(err.message);
        throw err;
      }
      const complete = projectOutcomes.every(
        (p) => p.comment !== 'refused' && p.updated !== 'refused',
      );
      await deps.db.transaction(async (tx) => {
        if (complete) {
          // Azure DevOps holds this password now. A new password has another envelope, so a
          // rotation that ran meanwhile keeps its own (unmarked) one.
          const [stored] = await tx
            .select({ value: scmConnections.webhookSecretEnc })
            .from(scmConnections)
            .where(eq(scmConnections.id, row.id));
          if (stored?.value && decryptWebhookSecret(key, stored.value) === password) {
            await tx
              .update(scmConnections)
              .set({ webhookSecretEnc: { ...stored.value, hooksPushed: true } })
              .where(
                and(
                  eq(scmConnections.id, row.id),
                  sql`${scmConnections.webhookSecretEnc}->>'ct' = ${stored.value.ct}`,
                ),
              );
          }
        }
        await audit(tx, request, row, 'scm_connection.hooks_updated', {
          projects: projectOutcomes.length,
        });
      });
      return { projects: projectOutcomes };
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
          // Its projects lose their mapping (ON DELETE SET NULL), and AI review needs a mapped
          // project: a job deletes the copies of their merge requests once this commits.
          await queueSnapshotPurge(tx, deleted.organizationId);
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
          'Check the connection (and a GitLab project, GitHub owner/repo or Azure DevOps repository id) with the stored credentials',
        params: idParams,
        body: z.strictObject({ projectRef: scmProjectRef.optional() }),
        response: { 200: testResultSchema },
      },
    },
    async (request) => {
      const row = await connectionFor(accessOf(deps), requireUser(request), request.params.id);
      const ref = request.body.projectRef ?? null;
      const problem = ref === null ? null : PROVIDER[row.provider].projectRefProblem(ref);
      if (problem) throw validationFailed([{ path: 'body.projectRef', message: problem }]);
      switch (row.provider) {
        case 'github':
          return { ...(await testGitHubConnection(row, scmDeps, ref)), hooks: null };
        case 'gitlab':
          return { ...(await testConnection(row, scmDeps, ref)), hooks: null };
        case 'azure': {
          const url = publicUrl === null ? null : azureWebhookUrl(publicUrl, row.id);
          const result = await testAzureConnection(row, scmDeps, ref, {
            repositoryRefs: await mappedRefs(row.id),
            url,
          });
          return { ...(await clearedByPass(result, row.id)), hooks: result.hooks ?? null };
        }
        default:
          return assertNever(row.provider, 'provider');
      }
    },
  );
};

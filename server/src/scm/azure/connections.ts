import { assertNever } from '@qualor/shared';
import { and, eq, isNotNull, sql } from 'drizzle-orm';
import { decryptSecret, encryptionKey } from '../../crypto/secrets';
import type { Executor } from '../../db/client';
import { projects, scmConnections } from '../../db/schema';
import type { FieldError } from '../../http/problem';
import {
  SCM_TOKEN_AAD,
  type ConnectionTest,
  type MissingAccess,
  type ScmConnectionRow,
  type ScmDeps,
  type TestProblemCode,
} from '../connections';
import { InstallationTokenCache } from '../github/app-auth';
import { ScmError, type ScmErrorReason } from '../provider';
import { isInternalHostAllowed, scmBaseUrlProblem } from '../url';
import type { AzureAuthKind } from './auth-kinds';
import { AZURE_CERTIFICATE_PROBLEM_TEXT, parseAzureCertificate } from './certificate';
import { AzureDevOpsClient, type AzureCredential } from './client';
import { ownSubscriptions, projectHookState } from './hooks';
import { azureRightsReadable } from './rights';
import {
  entraCacheKey,
  entraToken,
  entraTokenUrl,
  type EntraCredential,
  type EntraOptions,
} from './entra';
import {
  azureBaseUrlProblem,
  azureDeployment,
  azureIdentitiesBase,
  type AzureDeployment,
} from './url';

/**
 * Azure DevOps connections (design §7.1, §7.2): what the connection API checks and stores for
 * each authentication kind, the client of a stored connection, its test and its repositories.
 * Credentials are write-only: no text here, no return value and no error carries one.
 */

export const AZURE_CONNECTION_TEXT = {
  serverTakesPat: 'Azure DevOps Server takes a personal access token',
  unreadable:
    'The stored credential cannot be decrypted (QUALOR_SECRET_KEY changed?); set it again',
  certificateExpired: 'The stored certificate has expired; upload a new one',
} as const;

/** The fields of an Azure DevOps POST or PATCH that this module checks. */
export interface AzureFields {
  azureAuth?: AzureAuthKind;
  /** The PAT, or the client secret. */
  token?: string;
  tenantId?: string;
  clientId?: string;
  /** The certificate and its private key, one PEM text. */
  certificate?: string;
}

/** The Azure DevOps columns of a connection besides the credential. */
export type AzureColumns = Pick<
  typeof scmConnections.$inferInsert,
  'azureAuth' | 'azureTenantId' | 'azureClientId'
>;

interface KindRules {
  /** The body field that carries the credential. */
  credential: 'token' | 'certificate';
  /** The credential as the texts name it. */
  name: string;
  /** The 422 of a creation without it. */
  missing: string;
  /** A service principal: tenant and client ids, Services only. */
  principal: boolean;
}

const KIND: Record<AzureAuthKind, KindRules> = {
  pat: {
    credential: 'token',
    name: 'personal access token',
    missing: 'Add the personal access token',
    principal: false,
  },
  service_principal_secret: {
    credential: 'token',
    name: 'client secret',
    missing: 'Add the client secret',
    principal: true,
  },
  service_principal_certificate: {
    credential: 'certificate',
    name: 'certificate',
    missing: 'Add the certificate and its private key, as PEM',
    principal: true,
  },
};

const ID_NAME = { tenantId: 'directory (tenant) id', clientId: 'application (client) id' } as const;
const IDS = ['tenantId', 'clientId'] as const;

/** The body field that carries the credential of `kind`. */
export function azureCredentialField(kind: AzureAuthKind): 'token' | 'certificate' {
  return KIND[kind].credential;
}

/** The 422 of a move of the address without the credential of `kind`. */
export function azureMoveNeeds(kind: AzureAuthKind): FieldError {
  const { credential, name } = KIND[kind];
  return {
    path: `body.${credential}`,
    message: `Changing the address needs the ${name} again, in the same request`,
  };
}

/**
 * The 422s of `body` for a connection of `kind` at `baseUrl` (normalised): a service principal on
 * a Server (the deployment comes from the host alone), a field the kind does not take, the
 * credential or an id it needs that is absent (`needs`: the text, or null when not needed), and a
 * certificate {@link parseAzureCertificate} refuses.
 */
function problemsOf(
  kind: AzureAuthKind,
  body: AzureFields,
  baseUrl: string,
  needs: { credential: string | null; tenantId: string | null; clientId: string | null },
): FieldError[] {
  const rules = KIND[kind];
  const problems: FieldError[] = [];
  if (rules.principal && azureDeployment(baseUrl) === 'server') {
    problems.push({ path: 'body.azureAuth', message: AZURE_CONNECTION_TEXT.serverTakesPat });
  }
  const notOfKind = `Not a field of a connection with a ${rules.name}`;
  const other = rules.credential === 'token' ? 'certificate' : 'token';
  if (body[other] !== undefined) problems.push({ path: `body.${other}`, message: notOfKind });
  const credentialNeeded = needs.credential;
  if (body[rules.credential] === undefined && credentialNeeded !== null) {
    problems.push({ path: `body.${rules.credential}`, message: credentialNeeded });
  }
  for (const id of IDS) {
    const needed = needs[id];
    if (!rules.principal && body[id] !== undefined) {
      problems.push({ path: `body.${id}`, message: notOfKind });
    } else if (rules.principal && body[id] === undefined && needed !== null) {
      problems.push({ path: `body.${id}`, message: needed });
    }
  }
  if (rules.credential === 'certificate' && body.certificate !== undefined) {
    const parsed = parseAzureCertificate(body.certificate);
    if ('problem' in parsed) {
      problems.push({
        path: 'body.certificate',
        message: AZURE_CERTIFICATE_PROBLEM_TEXT[parsed.problem],
      });
    }
  }
  return problems;
}

/** A service principal's ids as stored (lower case), or null for a PAT. */
function idsOf(kind: AzureAuthKind, body: AzureFields): Omit<AzureColumns, 'azureAuth'> {
  if (!KIND[kind].principal) return { azureTenantId: null, azureClientId: null };
  return {
    azureTenantId: body.tenantId?.toLowerCase() ?? null,
    azureClientId: body.clientId?.toLowerCase() ?? null,
  };
}

/**
 * POST of an Azure DevOps connection at `baseUrl` (normalised, through the address rules): its
 * columns and the credential to encrypt into `token_enc` (the PAT, the client secret, or the
 * certificate with its key as sent), or the 422s.
 */
export function azureCreate(
  body: AzureFields & { azureAuth: AzureAuthKind },
  baseUrl: string,
): { columns: AzureColumns; credential: string } | { problems: FieldError[] } {
  const kind = body.azureAuth;
  const rules = KIND[kind];
  const problems = problemsOf(kind, body, baseUrl, {
    credential: rules.missing,
    tenantId: `Add the ${ID_NAME.tenantId}`,
    clientId: `Add the ${ID_NAME.clientId}`,
  });
  const credential = body[rules.credential];
  if (problems.length > 0 || credential === undefined) return { problems };
  return { columns: { azureAuth: kind, ...idsOf(kind, body) }, credential };
}

/**
 * PATCH of an Azure DevOps connection whose address becomes `baseUrl` (normalised; `moves` when it
 * is another one): the kind and id columns it changes, or the 422s. A stored credential serves
 * only the address, kind and ids it was saved with, so another kind needs its own credential and
 * ids, and another tenant or client the credential again, in the same request (a move needs it
 * too; the route asks for that, with {@link azureMoveNeeds}). A PAT keeps no ids.
 */
export function azurePatch(
  row: ScmConnectionRow,
  body: AzureFields,
  baseUrl: string,
  moves: boolean,
): { columns: Partial<AzureColumns> } | { problems: FieldError[] } {
  // The CHECK of migration 0034 sets the kind of every Azure DevOps row.
  const stored = row.azureAuth ?? 'pat';
  const kind = body.azureAuth ?? stored;
  const rules = KIND[kind];
  const kindChanges = kind !== stored;
  const storedIds = { tenantId: row.azureTenantId, clientId: row.azureClientId };
  const idsChange =
    rules.principal &&
    IDS.some((id) => {
      const sent = body[id];
      return sent !== undefined && sent.toLowerCase() !== storedIds[id];
    });
  // A move needs the credential as well; the route asks for it once (azureMoveNeeds).
  let credential: string | null = null;
  if (!moves && kindChanges) {
    credential = `Changing the authentication kind needs the ${rules.name}, in the same request`;
  } else if (!moves && idsChange) {
    credential = `Changing the tenant or client id needs the ${rules.name} again, in the same request`;
  }
  const idNeeded = (id: (typeof IDS)[number]) =>
    kindChanges
      ? `Changing the authentication kind needs the ${ID_NAME[id]}, in the same request`
      : null;
  const problems = problemsOf(kind, body, baseUrl, {
    credential,
    tenantId: idNeeded('tenantId'),
    clientId: idNeeded('clientId'),
  });
  if (problems.length > 0) return { problems };
  // Another kind sets its ids (none for a PAT); the same kind changes those sent.
  const ids = idsOf(kind, body);
  const columns: Partial<AzureColumns> = kindChanges ? { azureAuth: kind, ...ids } : {};
  if (body.tenantId !== undefined) columns.azureTenantId = ids.azureTenantId;
  if (body.clientId !== undefined) columns.azureClientId = ids.azureClientId;
  return { columns };
}

/** What a connection shows of its Azure DevOps side; never the credential. */
export interface AzureView {
  deployment: AzureDeployment;
  auth: AzureAuthKind;
  tenantId: string | null;
  clientId: string | null;
  /**
   * False when `token_enc` no longer decrypts (QUALOR_SECRET_KEY changed), or the certificate's PEM
   * no longer parses.
   */
  credentialReadable: boolean;
  /** The certificate kind's thumbprint (SHA-1, upper-case hex) and expiry; else null. */
  certificate: { thumbprint: string; notAfter: Date } | null;
}

/** Shown as stored: an expired certificate still has its thumbprint and its date. */
const ANY_DATE = () => Number.NEGATIVE_INFINITY;

export function azureViewOf(row: ScmConnectionRow, key: Buffer): AzureView {
  const auth = row.azureAuth ?? 'pat';
  const credential = decryptSecret(key, row.tokenEnc, SCM_TOKEN_AAD);
  let readable = credential !== null;
  let certificate: AzureView['certificate'] = null;
  if (KIND[auth].credential === 'certificate' && credential !== null) {
    const parsed = parseAzureCertificate(credential, ANY_DATE);
    readable = !('problem' in parsed);
    if (!('problem' in parsed)) {
      certificate = { thumbprint: parsed.thumbprintSha1, notAfter: parsed.notAfter };
    }
  }
  return {
    deployment: azureDeployment(row.baseUrl),
    auth,
    tenantId: row.azureTenantId,
    clientId: row.azureClientId,
    credentialReadable: readable,
    certificate,
  };
}

/** The bearer token of `entra`, from `tokens` while it holds, else from Entra (and kept). */
function bearer(
  connectionId: string,
  entra: EntraCredential,
  deps: ScmDeps,
  tokens: InstallationTokenCache,
): () => Promise<string> {
  const key = entraCacheKey(connectionId, entra);
  const origin = deps.azureTokenOrigin;
  // Ruling 1: only a test's fake Entra (on loopback) stands in for Microsoft's endpoint.
  const options: EntraOptions =
    origin === null
      ? {}
      : {
          tokenUrl: (tenantId) => entraTokenUrl(tenantId, origin),
          allowInternalHosts: true,
          // The tests' stall check shortens the wait (undefined keeps the default).
          timeoutMs: deps.azureClientOptions?.timeoutMs,
        };
  return async () => {
    const cached = tokens.get(key);
    if (cached !== null) return cached;
    let issued: { token: string; expiresAt: number };
    try {
      issued = await entraToken(entra, options);
    } catch (err) {
      throw entraFailure(err);
    }
    tokens.set(key, issued.token, issued.expiresAt);
    return issued.token;
  };
}

/** Fixed texts for a token request that failed in transport or on Microsoft's side. */
export const ENTRA_FAILURE_TEXT = {
  unreachable: 'Microsoft Entra could not be reached',
  timeout: 'Microsoft Entra did not answer in time',
  error: 'Microsoft Entra answered with an error',
} as const;

/**
 * An error of the Entra token request as one the test reports under a token_endpoint code, so a
 * blocked or failing Entra is never blamed on Azure DevOps. Entra's refusals already are
 * token_endpoint and stay; the rest get a code and a fixed text naming Microsoft Entra and the
 * class of the cause, never Entra's own words. The error's kind stays, so retries still tell
 * transient from final.
 */
function entraFailure(err: unknown): unknown {
  if (!(err instanceof ScmError) || err.reason === 'token_endpoint') return err;
  let reason: ScmErrorReason;
  let message: string;
  switch (err.reason) {
    case 'unresolved':
    case 'unreachable':
    case 'not_public':
      reason = 'token_endpoint_unreachable';
      message = ENTRA_FAILURE_TEXT.unreachable;
      break;
    case 'timeout':
      reason = 'token_endpoint_timeout';
      message = ENTRA_FAILURE_TEXT.timeout;
      break;
    default:
      reason = 'token_endpoint_error';
      message = ENTRA_FAILURE_TEXT.error;
  }
  return new ScmError(err.kind, message, {
    reason,
    status: err.status,
    retryAfterSeconds: err.retryAfterSeconds,
    request: err.request,
  });
}

/** The credential the client sends for `row`, or why there is none. */
function credentialOf(
  row: ScmConnectionRow,
  secret: string,
  deps: ScmDeps,
  tokens: InstallationTokenCache,
): { credential: AzureCredential } | { problem: string } {
  const kind = row.azureAuth ?? 'pat';
  if (kind === 'pat') return { credential: { kind: 'pat', pat: secret } };
  if (azureDeployment(row.baseUrl) === 'server') {
    return { problem: AZURE_CONNECTION_TEXT.serverTakesPat };
  }
  const { azureTenantId: tenantId, azureClientId: clientId } = row;
  if (tenantId === null || clientId === null) return { problem: AZURE_CONNECTION_TEXT.unreadable };
  let entra: EntraCredential;
  switch (kind) {
    case 'service_principal_secret':
      entra = { kind: 'secret', tenantId, clientId, secret };
      break;
    case 'service_principal_certificate': {
      const certificate = parseAzureCertificate(secret);
      if ('problem' in certificate) {
        return {
          problem:
            certificate.problem === 'expired'
              ? AZURE_CONNECTION_TEXT.certificateExpired
              : AZURE_CONNECTION_TEXT.unreadable,
        };
      }
      entra = { kind: 'certificate', tenantId, clientId, certificate };
      break;
    }
    default:
      return assertNever(kind, 'Azure DevOps authentication kind');
  }
  return { credential: { kind: 'bearer', token: bearer(row.id, entra, deps, tokens) } };
}

/**
 * Where the client sends requests: the stored address, or in tests (ruling 5) a Services
 * organisation's path on the fake's origin. The outbound rules check that target.
 */
function targetOf(baseUrl: string, deps: ScmDeps): string {
  const origin = deps.azureTestOrigin;
  if (origin === null || azureDeployment(baseUrl) !== 'services') return baseUrl;
  return `${origin}${new URL(baseUrl).pathname}`.replace(/\/+$/, '');
}

/** Tests only: the path the fake serves the identities host (`vssps.…`) under, on the test origin. */
export const AZURE_TEST_IDENTITIES_PREFIX = '/vssps';

/**
 * Where the client looks up identities: on Services the `vssps` host of the organisation
 * (`azureIdentitiesBase`), in tests (ruling 5) the fake's prefix on the test origin; a Server
 * collection answers them itself. The same address rules as the base's apply to that target.
 */
function identitiesTargetOf(baseUrl: string, deps: ScmDeps): string {
  const deployment = azureDeployment(baseUrl);
  const origin = deps.azureTestOrigin;
  if (origin !== null && deployment === 'services') {
    const path = new URL(baseUrl).pathname;
    return `${origin}${AZURE_TEST_IDENTITIES_PREFIX}${path}`.replace(/\/+$/, '');
  }
  return azureIdentitiesBase(baseUrl, deployment);
}

/**
 * A client for an Azure DevOps connection, or why there is none: a credential that no longer
 * decrypts or parses, an expired certificate, a service principal on a Server, or a base URL the
 * current `QUALOR_SCM_INTERNAL_HOSTS` or the Azure DevOps address rules no longer allow (checked
 * again before every client, so removing a host from the list stops requests to it at once). A
 * service principal's bearer tokens come from Microsoft Entra, kept in `runtime.azureTokens` when
 * a job passes it, else for this client alone.
 */
export function azureClientFor(
  row: ScmConnectionRow,
  deps: ScmDeps,
  runtime?: { azureTokens: InstallationTokenCache },
): { client: AzureDevOpsClient } | { problem: string } {
  const secret = decryptSecret(encryptionKey(deps.secretKey), row.tokenEnc, SCM_TOKEN_AAD);
  if (secret === null) return { problem: AZURE_CONNECTION_TEXT.unreadable };
  const identities = identitiesTargetOf(row.baseUrl, deps);
  // The identities host is held to the base's rules: the same address check, its own permission.
  const problem =
    scmBaseUrlProblem(row.baseUrl, deps.internalHosts) ??
    azureBaseUrlProblem(row.baseUrl) ??
    scmBaseUrlProblem(identities, deps.internalHosts);
  if (problem) return { problem };
  const found = credentialOf(
    row,
    secret,
    deps,
    runtime?.azureTokens ?? new InstallationTokenCache(),
  );
  if ('problem' in found) return found;
  const target = targetOf(row.baseUrl, deps);
  return {
    client: new AzureDevOpsClient(
      {
        baseUrl: target,
        credential: found.credential,
        allowInternalHosts: isInternalHostAllowed(new URL(target), deps.internalHosts),
        identities: {
          baseUrl: identities,
          allowInternalHosts: isInternalHostAllowed(new URL(identities), deps.internalHosts),
        },
      },
      deps.azureClientOptions,
    ),
  };
}

export function clientProblemCode(problem: string): TestProblemCode {
  if (problem === AZURE_CONNECTION_TEXT.unreadable) return 'undecryptable';
  if (problem === AZURE_CONNECTION_TEXT.certificateExpired) return 'token_endpoint';
  return 'url_not_allowed';
}

export function problemCode(err: ScmError): TestProblemCode {
  switch (err.reason) {
    case 'sign_in_required':
    case 'html_answer':
    case 'token_endpoint':
    case 'token_endpoint_unreachable':
    case 'token_endpoint_timeout':
    case 'token_endpoint_error':
    case 'permission_missing':
      return err.reason;
    default:
      break;
  }
  if (err.kind === 'auth') return 'token_refused';
  if (err.kind === 'not_found') return 'not_found';
  switch (err.reason) {
    case 'not_public':
    case 'unresolved':
    case 'timeout':
    case 'unreachable':
    case 'bad_answer':
      return err.reason;
    case 'budget':
    case 'invalid_input':
      return 'bad_answer';
    // Azure DevOps never raises not_installed (GitHub only); the switch stays exhaustive.
    case 'http':
    case 'stale':
    case 'other':
    case 'not_installed':
      return 'http_error';
  }
}

/** What the Test needs to report the hooks: the mapped repositories and Qualor's webhook address. */
export interface HookTestInput {
  /** The repository ids the connection's projects are mapped to. */
  repositoryRefs: readonly string[];
  /** Null without `QUALOR_PUBLIC_URL`: nothing can be Qualor's own, every project is `missing`. */
  url: string | null;
  /** Whether Azure DevOps holds the stored password (`hooksCurrent` of the DTO); false reads `stale`. */
  current: boolean;
}

/**
 * `POST /scm-connections/{id}/test` for Azure DevOps (design §7.1): who the credential is
 * (`connectionData`, its display name), the repositories it sees and the projects that hold them,
 * and with a repository id that repository as `<project>/<repository>`; the state of Qualor's hooks;
 * and whether the identity can read who may change findings (`missingAccess`). Fixed texts and
 * codes only, never Azure DevOps' or Entra's words.
 */
export async function testAzureConnection(
  row: ScmConnectionRow,
  deps: ScmDeps,
  projectRef: string | null,
  hookInput: HookTestInput = { repositoryRefs: [], url: null, current: false },
): Promise<ConnectionTest> {
  const failed = (code: TestProblemCode, message: string): ConnectionTest => ({
    ok: false,
    user: null,
    project: null,
    problem: { code, message },
    missingAccess: null,
    visible: null,
  });
  const found = azureClientFor(row, deps);
  if ('problem' in found) return failed(clientProblemCode(found.problem), found.problem);
  try {
    const identity = await found.client.connectionData();
    const repositories = await found.client.repositories();
    const repository = projectRef === null ? null : await found.client.repository(projectRef);
    const hooks = await hookStates(found.client, repositories, hookInput);
    const missingAccess = await rightsAccess(
      found.client,
      identity.id,
      repositories,
      hookInput.repositoryRefs,
    );
    return {
      ok: true,
      user: { username: identity.displayName },
      project:
        repository === null
          ? null
          : {
              id: repository.id,
              pathWithNamespace: `${repository.projectName}/${repository.name}`,
              accessLevel: null,
            },
      problem: null,
      missingAccess,
      visible: {
        repositories: repositories.length,
        projects: new Set(repositories.map((r) => r.projectId)).size,
      },
      hooks,
    };
  } catch (err) {
    if (err instanceof ScmError) return failed(problemCode(err), err.message);
    throw err;
  }
}

/**
 * What replies and commands need of the identity (`azureMayTriage`): to read identities on the
 * identities host and a repository's permissions. Asked once, of the identity itself and of the
 * first mapped repository it sees: `['read_permissions']` when it cannot, `[]` when it can; null
 * without such a repository, or when the answer said nothing either way (a timeout, a 5xx).
 */
async function rightsAccess(
  client: AzureDevOpsClient,
  identityId: string,
  repositories: readonly { id: string; projectId: string }[],
  refs: readonly string[],
): Promise<MissingAccess[] | null> {
  const wanted = new Set(refs.map((r) => r.toLowerCase()));
  const repository = repositories.find((r) => wanted.has(r.id.toLowerCase()));
  if (repository === undefined) return null;
  const readable = await azureRightsReadable(client, repository, identityId);
  if (readable === null) return null;
  return readable ? [] : ['read_permissions'];
}

/** The repository ids the connection's projects are mapped to. */
export async function mappedRepositoryRefs(db: Executor, connectionId: string): Promise<string[]> {
  const rows = await db
    .select({ ref: projects.scmProjectRef })
    .from(projects)
    .where(and(eq(projects.scmConnectionId, connectionId), isNotNull(projects.scmProjectRef)));
  return rows.flatMap((p) => (p.ref === null ? [] : [p.ref]));
}

/**
 * Marks the stored hook password as one Azure DevOps holds (`hooksPushed`): a complete subscribe
 * wrote it, or a delivery came with it. The write is conditional on the address and the password
 * still being those of `row`, so a move of the address (which clears the password) or a new
 * password meanwhile is never marked. Returns whether it wrote.
 */
export async function markHookPasswordHeld(
  db: Executor,
  row: Pick<ScmConnectionRow, 'id' | 'baseUrl' | 'webhookSecretEnc'>,
): Promise<boolean> {
  const stored = row.webhookSecretEnc;
  if (stored === null) return false;
  const written = await db
    .update(scmConnections)
    .set({ webhookSecretEnc: { ...stored, hooksPushed: true } })
    .where(
      and(
        eq(scmConnections.id, row.id),
        eq(scmConnections.baseUrl, row.baseUrl),
        sql`${scmConnections.webhookSecretEnc} ->> 'ct' = ${stored.ct}`,
      ),
    )
    .returning({ id: scmConnections.id });
  return written.length > 0;
}

/** The Azure project ids (lower case, sorted) of the mapped repositories the identity still sees. */
export function mappedAzureProjects(
  repositories: readonly { id: string; projectId: string }[],
  refs: readonly string[],
): string[] {
  const wanted = new Set(refs.map((r) => r.toLowerCase()));
  const projectIds = repositories
    .filter((r) => wanted.has(r.id.toLowerCase()))
    .map((r) => r.projectId.toLowerCase());
  return [...new Set(projectIds)].sort();
}

/** Qualor's hook state per mapped Azure project; null when the subscriptions cannot be read. */
async function hookStates(
  client: AzureDevOpsClient,
  repositories: readonly { id: string; projectId: string }[],
  input: HookTestInput,
): Promise<NonNullable<ConnectionTest['hooks']> | null> {
  const projectIds = mappedAzureProjects(repositories, input.repositoryRefs);
  if (projectIds.length === 0) return [];
  if (input.url === null) return projectIds.map((projectId) => ({ projectId, state: 'missing' }));
  try {
    const own = ownSubscriptions(await client.subscriptions(), input.url);
    return projectIds.map((projectId) => ({
      projectId,
      state: projectHookState(own, projectId, input.current),
    }));
  } catch (err) {
    if (err instanceof ScmError) return null;
    throw err;
  }
}

/** A repository of the listing (`GET /scm-connections/{id}/repositories`). */
export interface AzureListedRepository {
  /** The repository's id (lower case): what a project maps to. */
  ref: string;
  /** `<project>/<repository>`. */
  name: string;
  defaultBranch: string | null;
  /** A disabled repository. */
  archived: boolean;
}

/**
 * One page of the repositories the connection sees, `<project>/<repository>` in name order,
 * narrowed by `filter` (a part of that name, without case). Azure DevOps lists every repository of
 * the organisation or collection at once, so the filter and the pages are applied here.
 */
export async function listAzureRepositories(
  row: ScmConnectionRow,
  deps: ScmDeps,
  options: { page: number; perPage: number; filter: string },
): Promise<{ repositories: AzureListedRepository[]; hasMore: boolean }> {
  const made = azureClientFor(row, deps);
  if ('problem' in made) throw new ScmError('refused', made.problem, { reason: 'invalid_input' });
  const needle = options.filter.toLowerCase();
  const all = (await made.client.repositories())
    .map((r) => ({
      ref: r.id,
      name: `${r.projectName}/${r.name}`,
      defaultBranch: r.defaultBranch,
      archived: r.isDisabled,
    }))
    .filter((r) => r.name.toLowerCase().includes(needle))
    .sort(
      (a, b) =>
        a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }) || a.ref.localeCompare(b.ref),
    );
  const start = (options.page - 1) * options.perPage;
  return {
    repositories: all.slice(start, start + options.perPage),
    hasMore: all.length > start + options.perPage,
  };
}

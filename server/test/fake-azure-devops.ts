import {
  createHash,
  randomBytes,
  randomInt,
  randomUUID,
  verify,
  X509Certificate,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM } from './tls';

/**
 * A local fake of the Azure DevOps REST routes Qualor uses (Azure DevOps design §7.1, §7.9), with
 * a fake Microsoft Entra token endpoint (https, the test CA: call `trustTestCa()`), for tests:
 * nothing in `pnpm test` contacts Azure DevOps or Entra. One fake is one Services organisation
 * (`<url>` = `http://127.0.0.1:<port>/probe-org`) or one Server collection
 * (`…/DefaultCollection`), as the probe bench was.
 *
 * Recorded answers. The probe (sub-plan 0, `tools/azure/`) recorded real answers of Azure DevOps
 * Server 20.0 and of a Services organisation in `azure-shapes/<deployment>/` (status, content type
 * and body, or for a refusal the status, the headers and the body's first 200 characters; ids made
 * synthetic, ending `fa6e0000…`). The fake serves them with its own values laid over them:
 * - `GET _apis/connectionData` (`api-version=7.0-preview`): `1-connectiondata-pat` for the PAT, and
 *   on Services `1-connectiondata-secret` / `-certificate` for a token the fake Entra issued; the
 *   fake's id and display name (`patUser`, `principalUser`) over both users of the answer.
 * - A repository: the repository object of `9-event-pr-updated` (`resource.repository`, the same
 *   GitRepository a `GET _apis/git/repositories/{id}` answers), with the fake's id, name, project
 *   and URLs; `defaultBranch` (`refs/heads/<name>`, the form of `8-definition-get`) is left out for
 *   an empty repository, as Azure DevOps does. Its other fields are as recorded.
 * - An unknown repository: `10-not-found` (404 WrappedException, TF401019), with the id asked for.
 * - A wrong PAT, an unknown or expired bearer token (any bearer token on Server, which takes PATs
 *   only), and any other scheme: `10-wrong-pat` (401, no content type, empty body).
 * - A request without a credential: `10-no-credential`, which is a 302 to the sign-in page on
 *   Services and a 401 JSON (TF400813) on Server; its body is the recorded excerpt (the probe kept
 *   the first 200 characters), which nobody parses.
 *
 * Constructions, where nothing was recorded:
 * - The repositories list (`GET _apis/git/repositories`): the `{ count, value }` envelope of the
 *   recorded lists (`7-policy-types`) around the repository objects above. The probe listed no
 *   projects or repositories.
 * - TF401444 (an identity the organisation has not added, `identityAdded: false`; the probe could
 *   not make one): a 401 with the recorded wrong-PAT `www-authenticate`, the message URL-encoded in
 *   `x-tfs-serviceerror` (as the recorded Server 401 carries TF400813) and the WrappedException
 *   body of `10-not-found` with Microsoft's TF401444 text. It answers the service principal only.
 * - A 400 for a route asked at another api-version than Qualor's (the probe saw Server refuse
 *   connectionData at 7.0 with VssInvalidPreviewVersionException), and a 404 for any other route:
 *   the WrappedException body of `10-not-found` with the fake's own message.
 * - The token endpoint (`POST /{tenant}/oauth2/v2.0/token`): Microsoft's documented client
 *   credentials answer, and its documented error body (`error`, `error_description` with an
 *   AADSTS code) for a refusal: 400, or 401 `invalid_client` for a wrong secret or assertion. It
 *   checks the tenant, `client_id`, the scope, and either the secret or the client assertion: an
 *   RS256 JWT whose `x5t` is the registered certificate's SHA-1, signed by its key, with `aud` this
 *   endpoint, `iss` = `sub` = the client id, a `jti`, and `nbf`/`exp` around the fake's clock.
 */

export type FakeAzureDeployment = 'services' | 'server';

const SHAPES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'azure-shapes');
/** The organisation (Services) and the collection (Server) of the recordings. */
const BASE_PATH: Record<FakeAzureDeployment, string> = {
  services: '/probe-org',
  server: '/DefaultCollection',
};
/** What Entra requires; written out here, not imported, so the fake checks the client. */
const ENTRA_SCOPE = '499b84ac-1321-427f-aa17-267ca6975798/.default';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const TOKEN_SECONDS = 3599;
const CLOCK_SKEW_SECONDS = 300;
const JSON_7_0 = 'application/json; charset=utf-8; api-version=7.0';
const TF401444_TYPE =
  'Microsoft.TeamFoundation.Framework.Server.UnauthorizedRequestException, Microsoft.TeamFoundation.Framework.Server';

/** A recorded answer (`azure-shapes/<deployment>/<name>.json`). */
export function azureShape<T = Record<string, unknown>>(
  deployment: FakeAzureDeployment,
  name: string,
): T {
  return JSON.parse(readFileSync(path.join(SHAPES, deployment, `${name}.json`), 'utf8')) as T;
}

/** A recording: an answer with its JSON body, or a refusal with its headers and body excerpt. */
interface Recording {
  status: number;
  contentType: string | null;
  body?: unknown;
  wwwAuthenticate?: string | null;
  location?: string | null;
  tfsServiceError?: string | null;
  first200?: string;
}

/** A recording as an answer to inject: its status, headers and body as recorded. */
export function recordedAnswer(deployment: FakeAzureDeployment, name: string): InjectedAnswer {
  const shape = azureShape<Recording>(deployment, name);
  const headers: Record<string, string> = {};
  if (shape.contentType) headers['content-type'] = shape.contentType;
  if (shape.wwwAuthenticate) headers['www-authenticate'] = shape.wwwAuthenticate;
  if (shape.location) headers.location = shape.location;
  if (shape.tfsServiceError) headers['x-tfs-serviceerror'] = shape.tfsServiceError;
  const body = 'body' in shape ? JSON.stringify(shape.body) : (shape.first200 ?? '');
  return { status: shape.status, headers, body };
}

export interface FakeAzureIdentity {
  id: string;
  displayName: string;
}

/** The service principal the fake Entra knows: a client secret, a certificate (PEM), or both. */
export interface FakeAzurePrincipal {
  tenantId: string;
  clientId: string;
  secret?: string;
  certificatePem?: string;
}

export interface FakeAzureRepositoryInput {
  id?: string;
  name: string;
  /** Repositories with the same project name share one project (and its id). */
  projectName: string;
  /** Default `main`; null: an empty repository, which has none. */
  defaultBranch?: string | null;
  isDisabled?: boolean;
}

export interface FakeAzureRepository {
  id: string;
  name: string;
  projectId: string;
  projectName: string;
  defaultBranch: string | null;
  isDisabled: boolean;
}

export interface RecordedRequest {
  method: string;
  /** The path under the organisation or collection (`/_apis/…`), still percent-encoded. */
  path: string;
  query: string;
  headers: IncomingMessage['headers'];
  body: string;
}

export interface InjectedAnswer {
  status: number;
  headers?: Record<string, string>;
  /** A string is sent as it is; anything else as JSON. None: an empty body. */
  body?: unknown;
  /** Never answer (the client's deadline must fire). */
  hang?: boolean;
  /** Runs before the answer (a test's change in the middle of a job). */
  before?: () => Promise<void>;
  /** After `before`, answer as the fake normally would, with `headers` added (`status` ignored). */
  passThrough?: boolean;
}

interface Injection {
  method: string;
  path: RegExp;
  answers: InjectedAnswer[];
}

export interface FakeAzureDevOps {
  /** The base URL (no trailing slash), as a connection stores it. */
  readonly url: string;
  readonly deployment: FakeAzureDeployment;
  readonly pat: string;
  /** Who the PAT is (connectionData). */
  readonly patUser: FakeAzureIdentity;
  /** Who the service principal is, on a fake with one. */
  readonly principalUser: FakeAzureIdentity | null;
  /** The fake Entra's token endpoint for a tenant (`EntraOptions.tokenUrl`). */
  tokenUrl(tenantId: string): string;
  /** False: the organisation has not added the service principal (TF401444). Default true. */
  identityAdded: boolean;
  readonly repositories: readonly FakeAzureRepository[];
  addRepository(input: FakeAzureRepositoryInput): FakeAzureRepository;
  readonly requests: RecordedRequest[];
  /** The requests to the token endpoint (path from `/`). */
  readonly tokenRequests: RecordedRequest[];
  /** The next matching requests get these answers, in order, before the fake answers normally. */
  inject(method: string, path: RegExp, ...answers: InjectedAnswer[]): void;
  /** Forgets the recorded requests (not the state). */
  clearRequests(): void;
  close(): Promise<void>;
}

/**
 * Entra's refusals as Microsoft's error-code reference names them: status, `error`, AADSTS code
 * and text. Qualor reads none of it (any refusal is `token_endpoint`).
 */
const ENTRA_REFUSAL = {
  tenant: [400, 'invalid_request', 90002, 'Tenant not found.'],
  grant: [400, 'unsupported_grant_type', 70003, 'The app requested an unsupported grant type.'],
  client: [400, 'unauthorized_client', 700016, 'Application was not found in the directory.'],
  scope: [400, 'invalid_scope', 70011, "The value of the parameter 'scope' is not valid."],
  proof: [400, 'invalid_request', 7000218, "Neither 'client_assertion' nor 'client_secret' given."],
  wrongSecret: [401, 'invalid_client', 7000215, 'Invalid client secret provided.'],
  malformed: [401, 'invalid_client', 50027, 'JWT token is invalid or malformed.'],
  signature: [401, 'invalid_client', 700027, 'Client assertion failed signature validation.'],
  issuer: [401, 'invalid_client', 700021, "The assertion's issuer doesn't match 'client_id'."],
  lifetime: [401, 'invalid_client', 700024, 'Client assertion is not within its valid time range.'],
} as const;
type EntraRefusal = keyof typeof ENTRA_REFUSAL;

function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
) {
  const json = body !== undefined && typeof body !== 'string';
  res.writeHead(status, {
    ...(json ? { 'content-type': 'application/json; charset=utf-8' } : {}),
    ...headers,
  });
  res.end(json ? JSON.stringify(body) : ((body as string | undefined) ?? ''));
}

/** The request as `requests` keeps it, once its body is read. */
function recorded(req: IncomingMessage, prefix: string): Promise<RecordedRequest> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const [pathname = '/', query = ''] = (req.url ?? '/').split('?', 2) as [string, string?];
    const sub = pathname.startsWith(`${prefix}/`) ? pathname.slice(prefix.length) : pathname;
    const done = () =>
      resolve({
        method: req.method ?? '',
        path: sub,
        query,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', done);
    req.on('error', done);
  });
}

function listen(server: Server | HttpsServer): Promise<number> {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)),
  );
}

function closeServer(server: Server | HttpsServer): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
}

/** A credential that has the form of a classic PAT (52 base32 characters). */
function newPat(): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  return Array.from({ length: 52 }, () => alphabet[randomInt(alphabet.length)]).join('');
}

const decoded = (part: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(part, 'base64url').toString()) as Record<string, unknown>;

/** Why a client assertion is refused, or null. */
function assertionProblem(
  assertion: string,
  expected: {
    clientId: string;
    audience: string;
    certificate: X509Certificate | null;
    now: number;
  },
): EntraRefusal | null {
  const { certificate } = expected;
  const [header = '', claims = '', signature = '', ...rest] = assertion.split('.');
  let h: Record<string, unknown>;
  let c: Record<string, unknown>;
  try {
    h = decoded(header);
    c = decoded(claims);
  } catch {
    return 'malformed';
  }
  if (!certificate || rest.length > 0 || h.alg !== 'RS256') return 'signature';
  if (h.x5t !== createHash('sha1').update(certificate.raw).digest('base64url')) return 'signature';
  const signed = Buffer.from(`${header}.${claims}`);
  if (!verify('sha256', signed, certificate.publicKey, Buffer.from(signature, 'base64url'))) {
    return 'signature';
  }
  if (c.aud !== expected.audience || typeof c.jti !== 'string' || c.jti === '') return 'malformed';
  if (c.iss !== expected.clientId || c.sub !== expected.clientId) return 'issuer';
  const seconds = Math.floor(expected.now / 1000);
  if (typeof c.nbf !== 'number' || typeof c.exp !== 'number') return 'malformed';
  return c.nbf > seconds + CLOCK_SKEW_SECONDS || c.exp <= seconds ? 'lifetime' : null;
}

export async function createFakeAzureDevOps(options: {
  deployment: FakeAzureDeployment;
  pat?: string;
  principal?: FakeAzurePrincipal;
  identityAdded?: boolean;
  repositories?: FakeAzureRepositoryInput[];
  /** The fake Entra's clock (assertion lifetimes, token expiry). */
  now?: () => number;
}): Promise<FakeAzureDevOps> {
  const { deployment, principal } = options;
  if (principal && deployment === 'server') {
    throw new Error('fake Azure DevOps: Azure DevOps Server takes a personal access token only');
  }
  if (principal && !principal.secret && !principal.certificatePem) {
    throw new Error('fake Azure DevOps: the principal needs a secret or a certificate');
  }
  const certificatePem = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(
    principal?.certificatePem ?? '',
  )?.[0];
  const certificate = certificatePem ? new X509Certificate(certificatePem) : null;
  const now = options.now ?? Date.now;
  const pat = options.pat ?? newPat();
  const basePath = BASE_PATH[deployment];
  const patUser: FakeAzureIdentity =
    deployment === 'services'
      ? { id: 'c0ffee00-0000-4000-8000-000000000001', displayName: 'qualor-bot@example.com' }
      : { id: 'c0ffee00-0000-4000-8000-000000000002', displayName: 'Qualor Bot' };
  const principalUser: FakeAzureIdentity | null = principal
    ? { id: 'c0ffee00-0000-4000-8000-000000000003', displayName: 'Qualor Azure App' }
    : null;
  const requests: RecordedRequest[] = [];
  const tokenRequests: RecordedRequest[] = [];
  const injections: Injection[] = [];
  const repositories: FakeAzureRepository[] = [];
  const projectIds = new Map<string, string>();
  /** Issued bearer tokens: how the principal proved itself, and until when the token holds. */
  const tokens = new Map<string, { how: 'secret' | 'certificate'; expiresAt: number }>();
  let url = '';
  let tokenOrigin = '';

  const wrongPat = recordedAnswer(deployment, '10-wrong-pat');
  const noCredential = recordedAnswer(deployment, '10-no-credential');
  const notFound = azureShape<{ body: Record<string, unknown> }>(deployment, '10-not-found').body;
  type Event = { body: { resource: { repository: Record<string, unknown> } } };
  const { project: recordedProject, ...recordedRepository } = azureShape<Event>(
    deployment,
    '9-event-pr-updated',
  ).body.resource.repository;
  const listEnvelope = azureShape<{ body: Record<string, unknown> }>(deployment, '7-policy-types');

  const wrapped = (res: ServerResponse, status: number, message: string, typeKey: string) =>
    send(
      res,
      status,
      { ...notFound, message, typeName: typeKey, typeKey },
      { 'content-type': JSON_7_0 },
    );

  const identityAnswer = (res: ServerResponse, kind: 'pat' | 'secret' | 'certificate') => {
    type Users = {
      authenticatedUser: Record<string, unknown>;
      authorizedUser: Record<string, unknown>;
    };
    const shape = azureShape<{ contentType: string; body: Users }>(
      deployment,
      `1-connectiondata-${kind}`,
    );
    const who = kind === 'pat' ? patUser : principalUser!;
    const account = kind === 'pat' ? who.displayName : principal!.clientId;
    const overlay = (user: Record<string, unknown>) => ({
      ...user,
      id: who.id,
      providerDisplayName: who.displayName,
      ...('customDisplayName' in user ? { customDisplayName: who.displayName } : {}),
      properties: { Account: { $type: 'System.String', $value: account } },
    });
    const { authenticatedUser, authorizedUser } = shape.body;
    const body = {
      ...shape.body,
      authenticatedUser: overlay(authenticatedUser),
      authorizedUser: overlay(authorizedUser),
    };
    send(res, 200, body, { 'content-type': shape.contentType });
  };

  const repositoryJson = (r: FakeAzureRepository) => {
    const web = `${url}/${encodeURIComponent(r.projectName)}/_git/${encodeURIComponent(r.name)}`;
    return {
      ...recordedRepository,
      id: r.id,
      name: r.name,
      url: `${url}/${r.projectId}/_apis/git/repositories/${r.id}`,
      project: {
        ...(recordedProject as Record<string, unknown>),
        id: r.projectId,
        name: r.projectName,
        url: `${url}/_apis/projects/${r.projectId}`,
      },
      ...(r.defaultBranch === null ? {} : { defaultBranch: `refs/heads/${r.defaultBranch}` }),
      remoteUrl: web,
      webUrl: web,
      isDisabled: r.isDisabled,
    };
  };

  const tf401444 = (res: ServerResponse) => {
    const message = `TF401444: Please sign-in at least once as ${principal!.tenantId}\\${principal!.clientId} in a web browser to enable access to the service.`;
    const body = {
      ...notFound,
      message,
      typeName: TF401444_TYPE,
      typeKey: 'UnauthorizedRequestException',
    };
    send(res, 401, body, {
      ...wrongPat.headers,
      'content-type': 'application/json; charset=utf-8',
      'x-tfs-serviceerror': encodeURIComponent(message),
    });
  };

  /** Who the request is: the PAT's user, the service principal, nobody, or a refused credential. */
  const authenticate = (
    header: string | undefined,
  ): 'pat' | 'secret' | 'certificate' | 'none' | 'wrong' => {
    if (!header) return 'none';
    const [scheme = '', value = ''] = header.split(' ', 2);
    if (/^basic$/i.test(scheme)) {
      const text = Buffer.from(value, 'base64').toString('utf8');
      const colon = text.indexOf(':');
      return colon >= 0 && text.slice(colon + 1) === pat ? 'pat' : 'wrong';
    }
    const token =
      /^bearer$/i.test(scheme) && deployment === 'services' ? tokens.get(value) : undefined;
    return token && token.expiresAt > now() ? token.how : 'wrong';
  };

  const answer = (req: RecordedRequest, res: ServerResponse, inside: boolean): void => {
    if (!inside) {
      return wrapped(res, 404, 'fake Azure DevOps: no such collection', 'NotFound');
    }
    const who = authenticate(req.headers.authorization);
    if (who === 'none')
      return send(res, noCredential.status, noCredential.body, noCredential.headers);
    if (who === 'wrong') return send(res, wrongPat.status, wrongPat.body, wrongPat.headers);
    if (who !== 'pat' && !fake.identityAdded) return tf401444(res);
    const version = new URLSearchParams(req.query).get('api-version') ?? '';
    const one = /^\/_apis\/git\/repositories\/([^/]+)$/.exec(req.path);
    const route =
      req.method !== 'GET'
        ? null
        : req.path === '/_apis/connectionData'
          ? { wanted: /^7\.0-preview(\.1)?$/, name: 'connectionData' as const }
          : req.path === '/_apis/git/repositories'
            ? { wanted: /^7\.0$/, name: 'list' as const }
            : one
              ? { wanted: /^7\.0$/, name: 'repository' as const }
              : null;
    if (!route) return wrapped(res, 404, 'fake Azure DevOps: no such route', 'NotFound');
    if (!route.wanted.test(version)) {
      const text = `fake Azure DevOps: this route is not asked at api-version ${version}`;
      return wrapped(res, 400, text, 'VssInvalidPreviewVersionException');
    }
    if (route.name === 'connectionData') return identityAnswer(res, who);
    if (route.name === 'list') {
      const value = repositories.map(repositoryJson);
      return send(
        res,
        200,
        { ...listEnvelope.body, count: value.length, value },
        { 'content-type': JSON_7_0 },
      );
    }
    const id = decodeURIComponent(one![1]!);
    const repository = repositories.find((r) => r.id === id.toLowerCase());
    if (repository) return send(res, 200, repositoryJson(repository), { 'content-type': JSON_7_0 });
    const message = String(notFound.message).replace(
      /[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/i,
      id,
    );
    send(res, 404, { ...notFound, message }, { 'content-type': 'application/json; charset=utf-8' });
  };

  const handleApi = async (incoming: IncomingMessage, res: ServerResponse) => {
    const inside = (incoming.url ?? '').startsWith(`${basePath}/`);
    const req = await recorded(incoming, basePath);
    requests.push(req);
    const injected = injections.find(
      (i) => i.method === req.method && i.path.test(req.path) && i.answers.length > 0,
    );
    const given = injected?.answers.shift();
    if (!given) return answer(req, res, inside);
    await given.before?.();
    if (given.passThrough) {
      for (const [name, value] of Object.entries(given.headers ?? {})) res.setHeader(name, value);
      answer(req, res, inside);
    } else if (!given.hang) {
      send(res, given.status, given.body, given.headers);
    }
  };

  /** How the token request proves the principal, or why Entra refuses it. */
  const proofOf = (req: RecordedRequest): { how: 'secret' | 'certificate' } | EntraRefusal => {
    const tenant = /^\/([^/]+)\/oauth2\/v2\.0\/token$/.exec(req.path)?.[1];
    if (req.method !== 'POST' || !principal || tenant !== principal.tenantId) return 'tenant';
    const form = new URLSearchParams(req.body);
    if (form.get('grant_type') !== 'client_credentials') return 'grant';
    if (form.get('client_id') !== principal.clientId) return 'client';
    if (form.get('scope') !== ENTRA_SCOPE) return 'scope';
    const secret = form.get('client_secret');
    const assertion = form.get('client_assertion');
    if (secret !== null && assertion === null) {
      return principal.secret !== undefined && secret === principal.secret
        ? { how: 'secret' }
        : 'wrongSecret';
    }
    if (
      assertion === null ||
      secret !== null ||
      form.get('client_assertion_type') !== ASSERTION_TYPE
    ) {
      return 'proof';
    }
    const audience = `${tokenOrigin}${req.path}`;
    const problem = assertionProblem(assertion, {
      clientId: principal.clientId,
      audience,
      certificate,
      now: now(),
    });
    return problem ?? { how: 'certificate' };
  };

  const handleToken = async (incoming: IncomingMessage, res: ServerResponse) => {
    const req = await recorded(incoming, '');
    tokenRequests.push(req);
    const proof = proofOf(req);
    if (typeof proof === 'string') {
      const [status, error, code, text] = ENTRA_REFUSAL[proof];
      const at = new Date(now()).toISOString();
      return send(res, status, {
        error,
        error_description: `AADSTS${code}: ${text} Trace ID: ${randomUUID()} Correlation ID: ${randomUUID()} Timestamp: ${at}`,
        error_codes: [code],
        timestamp: at,
        trace_id: randomUUID(),
        correlation_id: randomUUID(),
        error_uri: `https://login.microsoftonline.com/error?code=${code}`,
      });
    }
    const token = `fake-entra-${randomBytes(24).toString('base64url')}`;
    tokens.set(token, { how: proof.how, expiresAt: now() + TOKEN_SECONDS * 1000 });
    send(res, 200, {
      token_type: 'Bearer',
      expires_in: TOKEN_SECONDS,
      ext_expires_in: TOKEN_SECONDS,
      access_token: token,
    });
  };

  const api = createServer((req, res) => void handleApi(req, res));
  url = `http://127.0.0.1:${await listen(api)}${basePath}`;
  const entra = principal
    ? createHttpsServer(
        { cert: TEST_SERVER_CERT_PEM, key: TEST_SERVER_KEY_PEM },
        (req, res) => void handleToken(req, res),
      )
    : null;
  if (entra) tokenOrigin = `https://127.0.0.1:${await listen(entra)}`;

  const fake: FakeAzureDevOps = {
    url,
    deployment,
    pat,
    patUser,
    principalUser,
    tokenUrl(tenantId) {
      if (!entra) throw new Error('fake Azure DevOps: no principal, so no token endpoint');
      return `${tokenOrigin}/${tenantId}/oauth2/v2.0/token`;
    },
    identityAdded: options.identityAdded ?? true,
    repositories,
    addRepository(input) {
      const projectId = projectIds.get(input.projectName) ?? randomUUID();
      projectIds.set(input.projectName, projectId);
      const repository: FakeAzureRepository = {
        id: (input.id ?? randomUUID()).toLowerCase(),
        name: input.name,
        projectId,
        projectName: input.projectName,
        defaultBranch: input.defaultBranch === undefined ? 'main' : input.defaultBranch,
        isDisabled: input.isDisabled ?? false,
      };
      repositories.push(repository);
      return repository;
    },
    requests,
    tokenRequests,
    inject(method, pathPattern, ...answers) {
      injections.push({ method, path: pathPattern, answers: [...answers] });
    },
    clearRequests() {
      requests.length = 0;
      tokenRequests.length = 0;
    },
    async close() {
      await closeServer(api);
      if (entra) await closeServer(entra);
    },
  };
  for (const input of options.repositories ?? []) fake.addRepository(input);
  return fake;
}

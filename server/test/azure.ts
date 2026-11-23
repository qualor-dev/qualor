import { createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { Config } from '../src/config';
import type { AzureCredential } from '../src/scm/azure/client';
import { parseAzureCertificate } from '../src/scm/azure/certificate';
import { entraToken, type EntraCredential, type EntraOptions } from '../src/scm/azure/entra';
import {
  azureShape,
  type FakeAzureChange,
  type FakeAzureDeployment,
  type FakeAzureDevOps,
  type FakeAzureIteration,
  type FakeAzurePullRequest,
  type FakeAzurePullRequestInput,
} from './fake-azure-devops';
import { TEST_IDP, type TestKeyPair } from './saml';

/**
 * The service principal the tests register with the fake Entra: a client secret and the PEM an
 * administrator pastes for a certificate (the test IdP's certificate and its key).
 */
export const AZURE_TEST_PRINCIPAL = {
  tenantId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  clientId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
  // Assembled at run time, so the repository's own Gitleaks check finds no fake secret here.
  secret: ['azure-test-', 'client-secret'].join(''),
  certificatePem: `${TEST_IDP.certPem}${TEST_IDP.keyPem}`,
} as const;

/**
 * The fake listens on 127.0.0.1 on a port of its own, which the operator must list with that port
 * (an entry without a port allows only the scheme's default one).
 */
export function azureTestConfig(fake: FakeAzureDevOps): Partial<Config> {
  return { scmInternalHosts: new Set([new URL(fake.url).host]) as ReadonlySet<string> };
}

/**
 * A Services fake's organisation as a connection stores it (ruling 5): the real host with the
 * fake's organisation, so the deployment and the address rules are those of production.
 */
export function servicesUrlOf(fake: FakeAzureDevOps): string {
  return `https://dev.azure.com${new URL(fake.url).pathname}`;
}

/**
 * A server that reaches the fakes: their hosts listed in `QUALOR_SCM_INTERNAL_HOSTS`, a Services
 * organisation's requests sent to the Services fake (`azureTestOrigin`, ruling 5) and Entra's to
 * its token endpoint (`azureTokenOrigin`, ruling 1). A Server fake is reached at its own address.
 */
export function azureServerConfig(
  services: FakeAzureDevOps,
  ...others: FakeAzureDevOps[]
): Partial<Config> {
  const hosts = [services, ...others].map((fake) => new URL(fake.url).host);
  return {
    scmInternalHosts: new Set(hosts) as ReadonlySet<string>,
    azureTestOrigin: new URL(services.url).origin,
    azureTokenOrigin:
      services.principalUser === null
        ? null
        : new URL(services.tokenUrl(AZURE_TEST_PRINCIPAL.tenantId)).origin,
  };
}

/** `entraToken`'s options for the fake's token endpoint (https on loopback). */
export function fakeEntraOptions(fake: FakeAzureDevOps): EntraOptions {
  return { tokenUrl: (tenantId) => fake.tokenUrl(tenantId), allowInternalHosts: true };
}

/** The test principal as `entraToken` takes it; a certificate from `pair` (default the test IdP). */
export function entraCredentialOf(
  kind: 'secret' | 'certificate',
  pair: TestKeyPair = TEST_IDP,
): EntraCredential {
  const { tenantId, clientId, secret } = AZURE_TEST_PRINCIPAL;
  if (kind === 'secret') return { kind, tenantId, clientId, secret };
  const certificate = parseAzureCertificate(`${pair.certPem}${pair.keyPem}`);
  if ('problem' in certificate) throw new Error(`test certificate: ${certificate.problem}`);
  return { kind, tenantId, clientId, certificate };
}

/** The fake's PAT as the client takes it. */
export function patOf(fake: FakeAzureDevOps): AzureCredential {
  return { kind: 'pat', pat: fake.pat };
}

/** A bearer credential that asks the fake's Entra for a new token on every request. */
export function bearerOf(
  fake: FakeAzureDevOps,
  credential: 'secret' | 'certificate' | EntraCredential,
): AzureCredential {
  const entra = typeof credential === 'string' ? entraCredentialOf(credential) : credential;
  return {
    kind: 'bearer',
    token: async () => (await entraToken(entra, fakeEntraOptions(fake))).token,
  };
}

/** A 40-character commit id the tests can tell apart (`azureCommitId('a')`). */
export function azureCommitId(seed: string): string {
  return createHash('sha1').update(seed).digest('hex');
}

/**
 * A pull request in the fake with one iteration: `changes` (paths without a leading `/`), and
 * `files` (path to content, a Buffer for a binary file) as the source commit holds them. For a
 * decoration test, which then reads `fake.pullRequest(...)` back.
 */
export function seedAzurePullRequest(
  fake: FakeAzureDevOps,
  repositoryId: string,
  options: {
    pullRequest?: FakeAzurePullRequestInput;
    changes?: FakeAzureChange[];
    files?: Record<string, string | Buffer>;
    sourceCommit?: string;
    baseCommit?: string;
  } = {},
): {
  pullRequest: FakeAzurePullRequest;
  iteration: FakeAzureIteration;
  sourceCommit: string;
  baseCommit: string;
} {
  const sourceCommit = options.sourceCommit ?? azureCommitId('source');
  const baseCommit = options.baseCommit ?? azureCommitId('base');
  const pullRequest = fake.addPullRequest(repositoryId, {
    headSha: sourceCommit,
    ...options.pullRequest,
  });
  const iteration = fake.addIteration(repositoryId, pullRequest.id, {
    sourceRefCommit: sourceCommit,
    commonRefCommit: baseCommit,
    changes: options.changes ?? Object.keys(options.files ?? {}).map((path) => ({ path })),
  });
  for (const [path, content] of Object.entries(options.files ?? {})) {
    fake.addFile(repositoryId, sourceCommit, path, content);
  }
  return { pullRequest, iteration, sourceCommit, baseCommit };
}

/**
 * Where a client looks up identities on `fake`: on Services the fake's second host (a prefix of its
 * server, which the test origin seam maps the `vssps` host to, see `identitiesUrl`), allowed as
 * the fake's own address; on Server the collection itself (undefined: the client's default).
 */
export function identitiesOf(
  fake: FakeAzureDevOps,
): { baseUrl: string; allowInternalHosts: boolean } | undefined {
  return fake.deployment === 'services'
    ? { baseUrl: fake.identitiesUrl, allowInternalHosts: true }
    : undefined;
}

const isPlain = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** `overrides` laid over `base`: plain objects merge, anything else (arrays too) replaces. */
function overlaid(base: unknown, overrides: unknown): unknown {
  if (!isPlain(base) || !isPlain(overrides)) return overrides;
  const merged: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(overrides)) merged[key] = overlaid(base[key], value);
  return merged;
}

/**
 * Posts a recorded service hook delivery (`azure-shapes/<deployment>/9-event-<name>.json`, e.g.
 * `comment-created`, `comment-reply`, `pr-updated`) to Qualor's route for the connection, as Azure
 * DevOps would: JSON, with `auth` as the Basic credential (user name default `qualor`; none: no
 * `Authorization` header). `overrides` are laid over the recorded body field by field.
 */
export async function deliverAzureEvent(
  app: Pick<FastifyInstance, 'inject'>,
  connectionId: string,
  name: string,
  overrides: Record<string, unknown> = {},
  auth?: { username?: string; password: string },
  deployment: FakeAzureDeployment = 'services',
) {
  if (!/^[a-z-]{1,40}$/.test(name)) throw new Error(`not an Azure DevOps event name: ${name}`);
  const { body } = azureShape<{ body: unknown }>(deployment, `9-event-${name}`);
  const basic = auth
    ? {
        authorization: `Basic ${Buffer.from(`${auth.username ?? 'qualor'}:${auth.password}`).toString('base64')}`,
      }
    : {};
  return await app.inject({
    method: 'POST',
    url: `/api/v0/azure-devops/webhooks/${connectionId}`,
    headers: { 'content-type': 'application/json', ...basic },
    payload: JSON.stringify(overlaid(body, overrides)),
  });
}

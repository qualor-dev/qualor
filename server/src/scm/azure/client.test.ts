import { inspect } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AZURE_TEST_PRINCIPAL, bearerOf, entraCredentialOf, patOf } from '../../../test/azure';
import {
  azureShape,
  createFakeAzureDevOps,
  recordedAnswer,
  type FakeAzureDevOps,
} from '../../../test/fake-azure-devops';
import { TEST_SP } from '../../../test/saml';
import { trustTestCa } from '../../../test/tls';
import { VERSION } from '../../index';
import { ScmError } from '../provider';
import {
  AZURE_SHAPES,
  AZURE_TEXT,
  AzureDevOpsClient,
  AzureError,
  MAX_AZURE_REQUESTS,
  MAX_AZURE_RESPONSE_BYTES,
  type AzureClientOptions,
  type AzureCredential,
} from './client';

const NOW = 1_800_000_000_000;
/** Text in an answer's body that must never reach an error. */
const MARKER = 'azure-body-marker-3d7a';
const REPOSITORY = /^\/_apis\/git\/repositories\/[^/]+$/;
const CONNECTION_DATA = /^\/_apis\/connectionData$/;
const TF401444 =
  'TF401444: Please sign-in at least once as tenant\\client in a web browser to enable access to the service.';

let services: FakeAzureDevOps;
let server: FakeAzureDevOps;
let untrust: () => void;

beforeAll(async () => {
  untrust = trustTestCa();
  services = await createFakeAzureDevOps({
    deployment: 'services',
    principal: AZURE_TEST_PRINCIPAL,
    repositories: [
      { name: 'api', projectName: 'Payments' },
      { name: 'web', projectName: 'Payments', defaultBranch: 'develop' },
      { name: 'empty', projectName: 'Platform', defaultBranch: null },
      { name: 'archive', projectName: 'Platform', isDisabled: true },
    ],
  });
  server = await createFakeAzureDevOps({
    deployment: 'server',
    repositories: [{ name: 'probe', projectName: 'probe-org' }],
  });
});

afterAll(async () => {
  await services.close();
  await server.close();
  untrust();
});

beforeEach(() => {
  services.clearRequests();
  server.clearRequests();
  services.identityAdded = true;
});

function clientOf(
  fake: FakeAzureDevOps,
  credential: AzureCredential = patOf(fake),
  options: AzureClientOptions = {},
): AzureDevOpsClient {
  return new AzureDevOpsClient(
    { baseUrl: fake.url, credential, allowInternalHosts: true },
    { timeoutMs: 2_000, ...options },
  );
}

async function failure(promise: Promise<unknown>): Promise<ScmError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof ScmError) return err;
    throw err;
  }
  throw new Error('no error');
}

/** Every way an error could be written down: none may carry a credential or the answer's body. */
function written(err: unknown): string {
  const e = err as Error;
  return [e.message, String(e), e.stack ?? '', JSON.stringify(e), inspect(e)].join('\n');
}

function expectNoLeak(err: unknown, fake: FakeAzureDevOps): void {
  const text = written(err);
  for (const leak of [fake.pat, Buffer.from(`:${fake.pat}`).toString('base64'), MARKER]) {
    expect(text).not.toContain(leak);
  }
  expect(text).not.toMatch(/Basic |Bearer /);
}

const apiVersion = (query: string) => new URLSearchParams(query).get('api-version');

describe('the recorded answers the fake serves parse with the client schemas', () => {
  it.each(['services', 'server'] as const)('%s', (deployment) => {
    const kinds = deployment === 'services' ? ['pat', 'secret', 'certificate'] : ['pat'];
    for (const kind of kinds) {
      const shape = azureShape<{ body: unknown }>(deployment, `1-connectiondata-${kind}`);
      expect(AZURE_SHAPES.connectionData.safeParse(shape.body).success, kind).toBe(true);
    }
    const event = azureShape<{ body: { resource: { repository: unknown } } }>(
      deployment,
      '9-event-pr-updated',
    );
    expect(AZURE_SHAPES.repository.safeParse(event.body.resource.repository).success).toBe(true);
  });
});

describe('requests (Azure DevOps design §7.1, §7.9)', () => {
  it('sends a PAT as Basic with an empty user name, asks for JSON and names Qualor', async () => {
    await clientOf(services).connectionData();
    const [request] = services.requests;
    expect(request?.headers.authorization).toBe(
      `Basic ${Buffer.from(`:${services.pat}`).toString('base64')}`,
    );
    expect(request?.headers.accept).toBe('application/json');
    expect(request?.headers['user-agent']).toBe(`Qualor/${VERSION}`);
  });

  it('asks token() for the bearer token of every request', async () => {
    const issued = bearerOf(services, 'secret');
    if (issued.kind !== 'bearer') throw new Error('bearer');
    const tokens: string[] = [];
    const credential: AzureCredential = {
      kind: 'bearer',
      token: async () => {
        const token = await issued.token();
        tokens.push(token);
        return token;
      },
    };
    const client = clientOf(services, credential);
    await client.connectionData();
    await client.repositories();
    expect(tokens).toHaveLength(2);
    expect(services.requests.map((r) => r.headers.authorization)).toEqual(
      tokens.map((token) => `Bearer ${token}`),
    );
  });

  it('asks connectionData at 7.0-preview and the Git routes at 7.0', async () => {
    const client = clientOf(services);
    await client.connectionData();
    await client.repositories();
    await client.repository(services.repositories[0]!.id);
    expect(services.requests.map((r) => [r.path, apiVersion(r.query)])).toEqual([
      ['/_apis/connectionData', '7.0-preview'],
      ['/_apis/git/repositories', '7.0'],
      [`/_apis/git/repositories/${services.repositories[0]!.id}`, '7.0'],
    ]);
  });

  it('counts its requests and never shows its credential', async () => {
    const client = clientOf(services);
    await client.connectionData();
    await client.repositories();
    expect(client.requestCount).toBe(2);
    expect(JSON.stringify(client)).not.toContain(services.pat);
    expect(inspect(client, { depth: 5 })).not.toContain(services.pat);
  });
});

describe('connectionData names the identity (probe item 1)', () => {
  it('of a PAT on Services and on Server', async () => {
    expect(await clientOf(services).connectionData()).toEqual(services.patUser);
    expect(await clientOf(server).connectionData()).toEqual(server.patUser);
  });

  it.each(['secret', 'certificate'] as const)('of a service principal with a %s', async (kind) => {
    const identity = await clientOf(services, bearerOf(services, kind)).connectionData();
    expect(identity).toEqual(services.principalUser);
    expect(identity).not.toEqual(services.patUser);
  });
});

describe('repositories', () => {
  it('lists every repository of the organisation with its project', async () => {
    const listed = await clientOf(services).repositories();
    expect(listed).toEqual(
      services.repositories.map((r) => ({
        id: r.id,
        name: r.name,
        projectId: r.projectId,
        projectName: r.projectName,
        webUrl: `${services.url}/${r.projectName}/_git/${r.name}`,
        defaultBranch: r.defaultBranch,
        isDisabled: r.isDisabled,
      })),
    );
    expect(listed.map((r) => r.defaultBranch)).toEqual(['main', 'develop', null, 'main']);
    expect(new Set(listed.map((r) => r.projectId)).size).toBe(2);
  });

  it('reads one repository by its id, in any case', async () => {
    const [probe] = server.repositories;
    const repository = await clientOf(server).repository(probe!.id.toUpperCase());
    expect(repository).toMatchObject({ id: probe!.id, name: 'probe', projectName: 'probe-org' });
  });

  it('refuses an id that is not a GUID without sending anything', async () => {
    const err = await failure(clientOf(server).repository('../_apis/projects'));
    expect(err).toMatchObject({ kind: 'refused', reason: 'invalid_input' });
    expect(server.requests).toHaveLength(0);
  });
});

describe('error mapping (Azure DevOps design §7.9, probe item 10)', () => {
  it('answers a transport failure as transient, with the outbound reason', async () => {
    services.inject('GET', CONNECTION_DATA, { status: 200, hang: true });
    const slow = await failure(clientOf(services, undefined, { timeoutMs: 200 }).connectionData());
    expect(slow).toMatchObject({ kind: 'transient', reason: 'timeout' });
    const unresolved = await failure(
      new AzureDevOpsClient(
        {
          baseUrl: 'https://ado.qualor.invalid/Default',
          credential: patOf(services),
          allowInternalHosts: false,
        },
        { resolve: async () => [] },
      ).connectionData(),
    );
    expect(unresolved).toMatchObject({ kind: 'transient', reason: 'unresolved' });
  });

  it('reads an answer over 8 MiB as a bad answer', async () => {
    services.inject('GET', CONNECTION_DATA, {
      status: 200,
      body: JSON.stringify({ padding: 'x'.repeat(MAX_AZURE_RESPONSE_BYTES) }),
    });
    const err = await failure(clientOf(services).connectionData());
    expect(err).toMatchObject({ kind: 'bad_answer', reason: 'bad_answer' });
  });

  it('refuses a loopback address that is not listed', async () => {
    const err = await failure(
      new AzureDevOpsClient({
        baseUrl: services.url,
        credential: patOf(services),
        allowInternalHosts: false,
      }).connectionData(),
    );
    expect(err).toMatchObject({ kind: 'refused', reason: 'not_public' });
    expect(services.requests).toHaveLength(0);
  });

  it("reads Services' recorded 302 to the sign-in page as a refused credential", async () => {
    services.inject('GET', CONNECTION_DATA, recordedAnswer('services', '10-no-credential'));
    const err = await failure(clientOf(services).connectionData());
    expect(err).toMatchObject({ kind: 'auth', reason: 'html_answer', status: 302 });
    expect(err.message).toBe('Azure DevOps answered with a sign-in page; check the credential');
    expect(err.message).toBe(AZURE_TEXT.signInPage);
    expect(services.requests).toHaveLength(1);
    expect(written(err)).not.toContain('_signin');
  });

  it.each([301, 304, 307, 308])(
    'reads any other %i as a refused credential too',
    async (status) => {
      services.inject('GET', CONNECTION_DATA, {
        status,
        headers: { location: `${services.url}/_apis/connectionData` },
        body: { [MARKER]: true },
      });
      const err = await failure(clientOf(services).connectionData());
      expect(err).toMatchObject({ kind: 'auth', reason: 'html_answer', status });
      expect(services.requests).toHaveLength(1);
    },
  );

  it.each([200, 203])('reads a %i HTML page as a refused credential', async (status) => {
    services.inject('GET', CONNECTION_DATA, {
      status,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      body: `<html><head><title>Sign in</title></head><body>${MARKER}</body></html>`,
    });
    const err = await failure(clientOf(services).connectionData());
    expect(err).toMatchObject({ kind: 'auth', reason: 'html_answer', status });
    expectNoLeak(err, services);
  });

  it.each([
    ['services', () => services],
    ['server', () => server],
  ] as const)('reads the recorded 401 of a wrong PAT on %s', async (_name, fakeOf) => {
    const fake = fakeOf();
    const err = await failure(
      clientOf(fake, { kind: 'pat', pat: 'wrong'.repeat(10) }).connectionData(),
    );
    expect(err).toMatchObject({ kind: 'auth', reason: 'http', status: 401 });
    expect(err.message).toBe('Azure DevOps refused the credential (HTTP 401)');
    expect(fake.requests).toHaveLength(1);
  });

  it("reads Server's recorded 401 without a credential (TF400813) as a refused credential", async () => {
    server.inject('GET', CONNECTION_DATA, recordedAnswer('server', '10-no-credential'));
    const err = await failure(clientOf(server).connectionData());
    expect(err).toMatchObject({ kind: 'auth', reason: 'http', status: 401 });
    expect(written(err)).not.toContain('TF400813');
  });

  it('reads TF401444 (an identity the organisation has not added) as sign-in required', async () => {
    services.identityAdded = false;
    const err = await failure(clientOf(services, bearerOf(services, 'secret')).connectionData());
    expect(err).toMatchObject({ kind: 'auth', reason: 'sign_in_required', status: 401 });
    expect(err.message).toBe(
      'The identity is not a member of this organization or has no access level',
    );
    expect(written(err)).not.toContain(AZURE_TEST_PRINCIPAL.clientId);
    // The PAT's user is a member: only the service principal is refused.
    expect(await clientOf(services).connectionData()).toEqual(services.patUser);
  });

  it('finds TF401444 in the x-tfs-serviceerror header or in the body alone', async () => {
    services.inject(
      'GET',
      CONNECTION_DATA,
      { status: 401, headers: { 'x-tfs-serviceerror': encodeURIComponent(TF401444) } },
      { status: 401, body: { message: TF401444 } },
    );
    for (let i = 0; i < 2; i++) {
      expect(await failure(clientOf(services).connectionData())).toMatchObject({
        kind: 'auth',
        reason: 'sign_in_required',
      });
    }
  });

  it('reads a 403 as a missing permission', async () => {
    services.inject('GET', REPOSITORY, { status: 403, body: { message: MARKER } });
    const err = await failure(clientOf(services).repository(services.repositories[0]!.id));
    expect(err).toMatchObject({ kind: 'auth', reason: 'permission_missing', status: 403 });
    expect(err.request).toBe('GET /_apis/git/repositories/{id}');
    expectNoLeak(err, services);
  });

  it("reads the recorded 404 as not found, keeping Azure DevOps' words for decisions only", async () => {
    const missing = 'a069a277-1d27-4cf4-8065-fa6e0000f174';
    const err = await failure(clientOf(server).repository(missing));
    expect(err).toBeInstanceOf(AzureError);
    expect(err).toMatchObject({ kind: 'not_found', status: 404 });
    const azure = err as AzureError;
    expect(azure.azureMessage).toMatch(/^TF401019: The Git repository with name or identifier/);
    expect(Object.keys(azure)).not.toContain('azureMessage');
    expect(Object.keys(azure)).not.toContain('providerMessage');
    expect(written(err)).not.toContain('TF401019');
  });

  it("cuts the credential out of Azure DevOps' words, should they ever echo it", async () => {
    const basic = Buffer.from(`:${services.pat}`).toString('base64');
    services.inject('GET', REPOSITORY, {
      status: 404,
      body: { message: `nothing for ${services.pat} (${basic})` },
    });
    const err = await failure(clientOf(services).repository(services.repositories[0]!.id));
    expect((err as AzureError).azureMessage).toBe('nothing for [credential] ([credential])');
  });

  it('reads a 429 as rate limited, with its Retry-After, and does not retry it', async () => {
    services.inject('GET', CONNECTION_DATA, { status: 429, headers: { 'retry-after': '7' } });
    const err = await failure(clientOf(services).connectionData());
    expect(err).toMatchObject({ kind: 'rate_limited', retryAfterSeconds: 7, status: 429 });
    expect(services.requests).toHaveLength(1);
  });

  it.each([
    [500, 'transient'],
    [503, 'transient'],
    [400, 'refused'],
    [409, 'refused'],
  ] as const)('reads a %i as %s', async (status, kind) => {
    services.inject('GET', CONNECTION_DATA, { status, body: { message: MARKER } });
    const err = await failure(clientOf(services).connectionData());
    expect(err).toMatchObject({ kind, reason: 'http', status });
    expect(err.message).toBe(`Azure DevOps answered HTTP ${status}`);
    expectNoLeak(err, services);
  });

  it('reads an answer that is not JSON, or not the expected shape, as a bad answer', async () => {
    services.inject(
      'GET',
      CONNECTION_DATA,
      { status: 200, body: `not json ${MARKER}` },
      { status: 200, body: { authenticatedUser: { id: 7 } } },
      { status: 200 },
    );
    for (let i = 0; i < 3; i++) {
      const err = await failure(clientOf(services).connectionData());
      expect(err).toMatchObject({ kind: 'bad_answer', reason: 'bad_answer', status: 200 });
      expect(err.request).toBe('GET /_apis/connectionData');
      expectNoLeak(err, services);
    }
  });

  it('reads a JSON answer that starts with a byte order mark (Server writes one)', async () => {
    const shape = azureShape<{ body: unknown }>('server', '1-connectiondata-pat');
    server.inject('GET', CONNECTION_DATA, {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: `${String.fromCharCode(0xfeff)}${JSON.stringify(shape.body)}`,
    });
    expect(await clientOf(server).connectionData()).toMatchObject({ displayName: 'Probe User' });
  });

  it('surfaces an Entra failure as entraToken throws it, before any Azure DevOps request', async () => {
    // A certificate the fake Entra does not know for this client: its assertion does not verify.
    const stranger = entraCredentialOf('certificate', TEST_SP);
    const err = await failure(clientOf(services, bearerOf(services, stranger)).connectionData());
    expect(err).toMatchObject({ kind: 'auth', reason: 'token_endpoint' });
    expect(err.request).toBe('POST /{tenant}/oauth2/v2.0/token');
    expect(services.requests).toHaveLength(0);
    const own = new ScmError('transient', 'Microsoft Entra could not be reached');
    const thrown = await failure(
      clientOf(services, { kind: 'bearer', token: () => Promise.reject(own) }).connectionData(),
    );
    expect(thrown).toBe(own);
    expect(thrown.request).toBeNull();
  });
});

describe('pacing (Azure DevOps design §7.4): a success may ask the next request to wait', () => {
  function paced(fake: FakeAzureDevOps) {
    const slept: number[] = [];
    const client = clientOf(fake, undefined, {
      now: () => NOW,
      sleep: (ms) => {
        slept.push(ms);
        return Promise.resolve();
      },
    });
    return { client, slept };
  }

  it.each([
    ['retry-after', '5', 5_000],
    ['x-ratelimit-delay', '0.25', 250],
    ['retry-after', '120', 30_000],
    ['x-ratelimit-delay', '45.5', 30_000],
  ])('%s: %s waits %i ms before the next request, once', async (header, value, ms) => {
    const { client, slept } = paced(services);
    services.inject('GET', CONNECTION_DATA, {
      status: 200,
      passThrough: true,
      headers: { [header]: value },
    });
    expect(await client.connectionData()).toEqual(services.patUser);
    expect(slept).toEqual([]);
    await client.repositories();
    expect(slept).toEqual([ms]);
    await client.repositories();
    expect(slept).toEqual([ms]);
    expect(services.requests).toHaveLength(3);
  });

  it('prefers Retry-After to X-RateLimit-Delay, and reads an HTTP date', async () => {
    const { client, slept } = paced(services);
    services.inject('GET', CONNECTION_DATA, {
      status: 200,
      passThrough: true,
      headers: { 'retry-after': new Date(NOW + 3_000).toUTCString(), 'x-ratelimit-delay': '9' },
    });
    await client.connectionData();
    await client.connectionData();
    expect(slept).toEqual([3_000]);
  });

  it('waits once, even when the delayed request fails', async () => {
    const { client, slept } = paced(services);
    services.inject(
      'GET',
      CONNECTION_DATA,
      { status: 200, passThrough: true, headers: { 'retry-after': '2' } },
      { status: 503 },
    );
    await client.connectionData();
    expect(await failure(client.connectionData())).toMatchObject({ kind: 'transient' });
    await client.connectionData();
    expect(slept).toEqual([2_000]);
  });
});

describe('the request budget (Azure DevOps design §7.4: 400 per job)', () => {
  it('sends no request past the budget', async () => {
    const client = clientOf(services, undefined, { maxRequests: 2 });
    await client.connectionData();
    await client.connectionData();
    const err = await failure(client.connectionData());
    expect(err).toMatchObject({ kind: 'budget', reason: 'budget' });
    expect(err.message).toBe('More than 2 Azure DevOps requests in one job');
    expect(services.requests).toHaveLength(2);
  });

  it('allows 400 by default', async () => {
    expect(MAX_AZURE_REQUESTS).toBe(400);
    const client = new AzureDevOpsClient(
      {
        baseUrl: 'https://ado.qualor.invalid/Default',
        credential: patOf(services),
        allowInternalHosts: false,
      },
      { resolve: async () => [] },
    );
    for (let i = 0; i < 400; i++) {
      expect(await failure(client.connectionData())).toMatchObject({ reason: 'unresolved' });
    }
    expect(await failure(client.connectionData())).toMatchObject({ kind: 'budget' });
    expect(client.requestCount).toBe(400);
  });
});

describe('the fake replays the recorded refusals (probe item 10)', () => {
  const noCredential = (fake: FakeAzureDevOps) =>
    fetch(`${fake.url}/_apis/projects?$top=1&api-version=7.0`, {
      headers: { accept: 'application/json' },
      redirect: 'manual',
    });

  it('Services: a 302 to the sign-in page', async () => {
    const recorded = azureShape<{ location: string }>('services', '10-no-credential');
    const res = await noCredential(services);
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(recorded.location);
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8');
  });

  it('Server: a 401 with a JSON body and TF400813 in x-tfs-serviceerror', async () => {
    const res = await noCredential(server);
    expect(res.status).toBe(401);
    expect(res.headers.get('content-type')).toBe('application/json');
    expect(decodeURIComponent(res.headers.get('x-tfs-serviceerror') ?? '')).toMatch(/^TF400813:/);
  });
});

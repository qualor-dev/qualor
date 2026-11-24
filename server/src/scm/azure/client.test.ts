import { inspect } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  AZURE_TEST_PRINCIPAL,
  azureCommitId,
  bearerOf,
  entraCredentialOf,
  identitiesOf,
  patOf,
  seedAzurePullRequest,
} from '../../../test/azure';
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
  type NewAzureSubscription,
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
  const identities = identitiesOf(fake);
  return new AzureDevOpsClient(
    {
      baseUrl: fake.url,
      credential,
      allowInternalHosts: true,
      ...(identities ? { identities } : {}),
    },
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

const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
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

describe('pull requests, threads and statuses (sub-plan 4)', () => {
  const repo = () => services.repositories[0]!;
  const lastRequest = () => services.requests.at(-1)!;
  const rest = (r: { path: string }) => r.path.replace(`/_apis/git/repositories/${repo().id}`, '');
  const bodyOf = (r: { body: string }) => JSON.parse(r.body) as unknown;
  const STATUS = {
    iterationId: 1,
    state: 'succeeded',
    description: 'Quality gate passed',
    targetUrl: 'https://qualor.example/p/1',
    genre: 'qualor',
    name: 'gate',
  } as const;

  const COMMIT_STATUS: Omit<typeof STATUS, 'iterationId'> = {
    state: STATUS.state,
    description: STATUS.description,
    targetUrl: STATUS.targetUrl,
    genre: STATUS.genre,
    name: STATUS.name,
  };

  it('reads a pull request: state, refs, head commit and web URL', async () => {
    const { pullRequest } = seedAzurePullRequest(services, repo().id, {
      pullRequest: { title: 'Fix it', isDraft: true },
    });
    const pr = await clientOf(services).pullRequest(repo().id, pullRequest.id);
    expect(pr).toEqual({
      id: pullRequest.id,
      status: 'active',
      isDraft: true,
      title: 'Fix it',
      sourceRefName: pullRequest.sourceRefName,
      targetRefName: 'refs/heads/main',
      headSha: pullRequest.headSha,
      webUrl: `${services.url}/Payments/_git/api/pullrequest/${pullRequest.id}`,
      mergeStatus: 'succeeded',
      repositoryId: repo().id,
      fork: false,
    });
    expect(rest(lastRequest())).toBe(`/pullrequests/${pullRequest.id}`);
    expect(apiVersion(lastRequest().query)).toBe('7.0');
    expect(lastRequest().method).toBe('GET');
  });

  it('reads a pull request without a merge yet: headSha null', async () => {
    const { pullRequest } = seedAzurePullRequest(services, repo().id, {
      pullRequest: { headSha: null, status: 'abandoned' },
    });
    expect(await clientOf(services).pullRequest(repo().id, pullRequest.id)).toMatchObject({
      status: 'abandoned',
      headSha: null,
    });
  });

  it('answers an unknown pull request as not found, and a bad repository id before sending', async () => {
    expect(await failure(clientOf(services).pullRequest(repo().id, 9999))).toMatchObject({
      kind: 'not_found',
    });
    services.clearRequests();
    expect(await failure(clientOf(services).pullRequest('../x', 1))).toMatchObject({
      reason: 'invalid_input',
    });
    expect(services.requests).toHaveLength(0);
  });

  it('lists the iterations with lower-case commit ids', async () => {
    const { pullRequest } = seedAzurePullRequest(services, repo().id);
    services.addIteration(repo().id, pullRequest.id, {
      sourceRefCommit: 'ABCDEF0123456789ABCDEF0123456789ABCDEF01',
      commonRefCommit: azureCommitId('c2'),
      targetRefCommit: azureCommitId('t2'),
    });
    const list = await clientOf(services).iterations(repo().id, pullRequest.id);
    expect(list.map((i) => i.id)).toEqual([1, 2]);
    expect(list[1]).toEqual({
      id: 2,
      sourceRefCommit: 'abcdef0123456789abcdef0123456789abcdef01',
      commonRefCommit: azureCommitId('c2'),
      targetRefCommit: azureCommitId('t2'),
    });
    expect(rest(lastRequest())).toBe(`/pullrequests/${pullRequest.id}/iterations`);
  });

  describe('iterationChanges', () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => ({ path: `f${i}.ts` }));

    it('lists changes without the leading slash, with renames', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id, {
        changes: [
          { path: 'src/a.ts', changeType: 'add' },
          {
            path: 'src/b.ts',
            originalPath: 'src/old.ts',
            changeType: 'rename',
            changeTrackingId: 7,
          },
        ],
      });
      const answer = await clientOf(services).iterationChanges(repo().id, pullRequest.id, 1);
      expect(answer).toEqual({
        complete: true,
        changes: [
          { path: 'src/a.ts', originalPath: null, changeType: 'add', changeTrackingId: 1 },
          {
            path: 'src/b.ts',
            originalPath: 'src/old.ts',
            changeType: 'rename',
            changeTrackingId: 7,
          },
        ],
      });
      expect(rest(lastRequest())).toBe(`/pullrequests/${pullRequest.id}/iterations/1/changes`);
      expect(new URLSearchParams(lastRequest().query).get('$top')).toBe('100');
      expect(new URLSearchParams(lastRequest().query).get('$skip')).toBe('0');
    });

    it('pages with $skip, 100 at a time', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id, { changes: many(250) });
      const answer = await clientOf(services).iterationChanges(repo().id, pullRequest.id, 1);
      expect(answer.complete).toBe(true);
      expect(answer.changes).toHaveLength(250);
      expect(services.requests.map((r) => new URLSearchParams(r.query).get('$skip'))).toEqual([
        '0',
        '100',
        '200',
      ]);
    });

    it('stops past maxPages and says it is incomplete', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id, { changes: many(250) });
      const answer = await clientOf(services).iterationChanges(repo().id, pullRequest.id, 1, 2);
      expect(answer.complete).toBe(false);
      expect(answer.changes).toHaveLength(200);
      expect(services.requests).toHaveLength(2);
    });

    it('is complete when the last allowed page is the last one', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id, { changes: many(150) });
      const answer = await clientOf(services).iterationChanges(repo().id, pullRequest.id, 1, 2);
      expect(answer.complete).toBe(true);
      expect(answer.changes).toHaveLength(150);
    });
  });

  describe('fileText', () => {
    it('reads the text of a file at a commit', async () => {
      const { sourceCommit } = seedAzurePullRequest(services, repo().id, {
        files: { 'src/a b.ts': 'const a = 1;\n' },
      });
      const answer = await clientOf(services).fileText(repo().id, 'src/a b.ts', sourceCommit);
      expect(answer).toEqual({ text: 'const a = 1;\n' });
      expect(rest(lastRequest())).toBe('/items');
      expect(Object.fromEntries(new URLSearchParams(lastRequest().query))).toEqual({
        path: '/src/a b.ts',
        'versionDescriptor.version': sourceCommit,
        'versionDescriptor.versionType': 'commit',
        includeContent: 'true',
        $format: 'json',
        'api-version': '7.0',
      });
    });

    it('skips a binary file, a file over the limit and a missing one, never throwing', async () => {
      const commit = azureCommitId('files');
      services.addFile(repo().id, commit, 'logo.png', Buffer.from([0x89, 0x50, 0, 0x47]));
      services.addFile(repo().id, commit, 'big.txt', 'a'.repeat(1024 * 1024 + 1));
      services.addFile(repo().id, commit, 'fits.txt', 'a'.repeat(1024 * 1024));
      const client = clientOf(services);
      expect(await client.fileText(repo().id, 'logo.png', commit)).toEqual({ skipped: 'binary' });
      expect(await client.fileText(repo().id, 'big.txt', commit)).toEqual({ skipped: 'too_large' });
      expect(await client.fileText(repo().id, 'gone.txt', commit)).toEqual({ skipped: 'missing' });
      expect(await client.fileText(repo().id, 'fits.txt', commit)).toHaveProperty('text');
      expect(await client.fileText(repo().id, 'fits.txt', commit, 10)).toEqual({
        skipped: 'too_large',
      });
    });

    it('skips a file over the 8 MiB an answer may have', async () => {
      const commit = azureCommitId('huge');
      services.addFile(repo().id, commit, 'huge.txt', 'a'.repeat(MAX_AZURE_RESPONSE_BYTES + 1));
      expect(await clientOf(services).fileText(repo().id, 'huge.txt', commit)).toEqual({
        skipped: 'too_large',
      });
    });

    it('still throws a failure that is no property of the file', async () => {
      services.inject('GET', /\/items$/, recordedAnswer('services', '10-wrong-pat'));
      const read = clientOf(services).fileText(repo().id, 'a.ts', azureCommitId('x'));
      expect(await failure(read)).toMatchObject({ kind: 'auth' });
    });
  });

  describe('threads', () => {
    it('lists threads, keeping system threads with a null status', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      services.addSystemThread(repo().id, pullRequest.id);
      services.addThread(repo().id, pullRequest.id, {
        status: 'fixed',
        filePath: 'src/a.ts',
        line: 12,
        comments: [
          { content: 'first', authorId: 'u-1' },
          { content: 'second', authorId: 'u-2' },
        ],
      });
      services.addThread(repo().id, pullRequest.id);
      const list = await clientOf(services).threads(repo().id, pullRequest.id);
      expect(list).toHaveLength(3);
      expect(list[0]).toMatchObject({
        status: null,
        filePath: null,
        rightLine: null,
        comments: [{ id: 1, content: 'Updated the source branch', commentType: 'system' }],
      });
      expect(list[1]).toEqual({
        id: list[1]!.id,
        status: 'fixed',
        filePath: 'src/a.ts',
        rightLine: 12,
        publishedDate: expect.stringMatching(ISO_DATE),
        comments: [
          {
            id: 1,
            authorId: 'u-1',
            authorName: 'u-1',
            content: 'first',
            commentType: 'text',
            parentCommentId: 0,
            publishedDate: expect.stringMatching(ISO_DATE),
            isDeleted: false,
          },
          {
            id: 2,
            authorId: 'u-2',
            authorName: 'u-2',
            content: 'second',
            commentType: 'text',
            parentCommentId: 0,
            publishedDate: expect.stringMatching(ISO_DATE),
            isDeleted: false,
          },
        ],
      });
      expect(list[2]).toMatchObject({ status: 'active', filePath: null, rightLine: null });
      expect(rest(lastRequest())).toBe(`/pullrequests/${pullRequest.id}/threads`);
    });

    it('creates a thread on a line: closed is 4, the whole line selected, no pullRequestThreadContext', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const created = await clientOf(services).createThread(repo().id, pullRequest.id, {
        content: 'Hello',
        status: 'closed',
        anchor: { filePath: 'src/a.ts', startLine: 5, endLine: 5, endLineLength: 9 },
      });
      expect(lastRequest().method).toBe('POST');
      expect(lastRequest().headers['content-type']).toBe('application/json');
      expect(apiVersion(lastRequest().query)).toBe('7.0');
      expect(rest(lastRequest())).toBe(`/pullrequests/${pullRequest.id}/threads`);
      expect(bodyOf(lastRequest())).toEqual({
        comments: [{ parentCommentId: 0, content: 'Hello', commentType: 1 }],
        status: 4,
        threadContext: {
          filePath: '/src/a.ts',
          rightFileStart: { line: 5, offset: 1 },
          rightFileEnd: { line: 5, offset: 10 },
        },
      });
      const stored = services.pullRequest(repo().id, pullRequest.id).threads[0]!;
      expect(created).toEqual({ id: stored.id, commentId: 1 });
      expect(stored).toMatchObject({ status: 'closed', filePath: 'src/a.ts', line: 5 });
    });

    it('creates an active thread on the pull request as a whole, without a context', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      await clientOf(services).createThread(repo().id, pullRequest.id, {
        content: 'Summary',
        status: 'active',
      });
      expect(bodyOf(lastRequest())).toEqual({
        comments: [{ parentCommentId: 0, content: 'Summary', commentType: 1 }],
        status: 1,
      });
    });

    it('sets a status with nothing but the status, and never sends properties', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id);
      const client = clientOf(services);
      await client.setThreadStatus(repo().id, pullRequest.id, thread.id, 'fixed');
      expect(lastRequest().method).toBe('PATCH');
      expect(rest(lastRequest())).toBe(`/pullrequests/${pullRequest.id}/threads/${thread.id}`);
      expect(bodyOf(lastRequest())).toEqual({ status: 2 });
      expect(thread.status).toBe('fixed');
      await client.setThreadStatus(repo().id, pullRequest.id, thread.id, 'active');
      expect(bodyOf(lastRequest())).toEqual({ status: 1 });
      expect(thread.status).toBe('active');
      const patches = services.requests.filter((r) => r.method === 'PATCH');
      expect(patches).toHaveLength(2);
      expect(patches.every((r) => !r.body.includes('properties'))).toBe(true);
    });

    it('adds a comment and edits one', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id);
      const client = clientOf(services);
      await client.addComment(repo().id, pullRequest.id, thread.id, 'Resolved');
      expect(lastRequest().method).toBe('POST');
      expect(rest(lastRequest())).toBe(
        `/pullrequests/${pullRequest.id}/threads/${thread.id}/comments`,
      );
      expect(bodyOf(lastRequest())).toEqual({
        content: 'Resolved',
        parentCommentId: 0,
        commentType: 1,
      });
      await client.editComment(repo().id, pullRequest.id, thread.id, 2, 'Resolved, again');
      expect(lastRequest().method).toBe('PATCH');
      expect(rest(lastRequest())).toBe(
        `/pullrequests/${pullRequest.id}/threads/${thread.id}/comments/2`,
      );
      expect(bodyOf(lastRequest())).toEqual({ content: 'Resolved, again' });
      expect(thread.comments.map((c) => c.content)).toEqual(['A comment', 'Resolved, again']);
    });

    it('answers a comment edit on a missing comment as not found', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id);
      const edit = clientOf(services).editComment(repo().id, pullRequest.id, thread.id, 9, 'x');
      expect(await failure(edit)).toMatchObject({ kind: 'not_found' });
    });
  });

  describe('statuses', () => {
    it('posts a status on an iteration and reads it back', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id, {
        pullRequest: { statusPolicy: true },
      });
      const client = clientOf(services);
      await client.postPullRequestStatus(repo().id, pullRequest.id, STATUS);
      expect(lastRequest().method).toBe('POST');
      expect(rest(lastRequest())).toBe(`/pullrequests/${pullRequest.id}/statuses`);
      expect(apiVersion(lastRequest().query)).toBe('7.0');
      expect(bodyOf(lastRequest())).toEqual({
        iterationId: 1,
        state: 'succeeded',
        description: 'Quality gate passed',
        targetUrl: 'https://qualor.example/p/1',
        context: { genre: 'qualor', name: 'gate' },
      });
      await client.postPullRequestStatus(repo().id, pullRequest.id, {
        ...STATUS,
        state: 'failed',
        targetUrl: null,
      });
      expect(bodyOf(lastRequest())).not.toHaveProperty('targetUrl');
      // Both are kept, each with its id: the higher one is the newer status.
      const listed = await client.iterationStatuses(repo().id, pullRequest.id, 1);
      expect(listed.map((s) => s.state).sort()).toEqual(['failed', 'succeeded']);
      const newest = listed.reduce((a, b) => (b.id > a.id ? b : a));
      expect(newest).toEqual({
        ...STATUS,
        id: newest.id,
        state: 'failed',
        targetUrl: null,
        authorId: services.patUser.id,
      });
      expect(listed.find((s) => s.id !== newest.id)?.id).toBeLessThan(newest.id);
      expect(rest(lastRequest())).toBe(`/pullrequests/${pullRequest.id}/iterations/1/statuses`);
    });

    it('lists only the statuses of the qualor genre', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const client = clientOf(services);
      await client.postPullRequestStatus(repo().id, pullRequest.id, STATUS);
      services.pullRequest(repo().id, pullRequest.id).iterations[0]!.statuses.push({
        iterationId: 1,
        state: 'succeeded',
        description: 'x',
        targetUrl: null,
        genre: 'other-tool',
        name: 'ci',
      });
      expect(await client.iterationStatuses(repo().id, pullRequest.id, 1)).toHaveLength(1);
    });

    it('reads the recorded listing of a pipeline-built pull request: a status of another genre without a state', async () => {
      // Probe item 19: Azure Pipelines' own status carries no `state` while it is notSet.
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      services.inject(
        'GET',
        /\/iterations\/1\/statuses$/,
        recordedAnswer('services', '19-iteration-statuses'),
      );
      expect(await clientOf(services).iterationStatuses(repo().id, pullRequest.id, 1)).toEqual([]);
    });

    it("reads a status of Qualor's genre without a state as notSet", async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      services.inject('GET', /\/iterations\/1\/statuses$/, {
        status: 200,
        body: { count: 1, value: [{ id: 4, context: { genre: 'qualor', name: 'gate' } }] },
      });
      const listed = await clientOf(services).iterationStatuses(repo().id, pullRequest.id, 1);
      expect(listed.map((s) => [s.id, s.state])).toEqual([[4, 'notSet']]);
    });

    it('reads who posted a status, and null when the answer names nobody', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      services.inject('GET', /\/iterations\/1\/statuses$/, {
        status: 200,
        body: {
          count: 2,
          value: [
            { id: 2, state: 'failed', context: { genre: 'qualor', name: 'gate' } },
            {
              id: 1,
              state: 'succeeded',
              context: { genre: 'qualor', name: 'gate' },
              createdBy: { id: 'a-pipeline', displayName: 'Build Service' },
            },
          ],
        },
      });
      const listed = await clientOf(services).iterationStatuses(repo().id, pullRequest.id, 1);
      expect(listed.map((s) => [s.id, s.authorId])).toEqual([
        [2, null],
        [1, 'a-pipeline'],
      ]);
    });

    it('reads the recorded 403 for a status without an iteration as permission_missing', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id, {
        pullRequest: { statusPolicy: true },
      });
      const post = clientOf(services).postPullRequestStatus(repo().id, pullRequest.id, {
        ...STATUS,
        iterationId: undefined,
      } as unknown as typeof STATUS);
      const err = await failure(post);
      expect(err).toMatchObject({ kind: 'auth', reason: 'permission_missing', status: 403 });
      expect(err.message).toBe(AZURE_TEXT.forbidden);
    });

    it('posts a commit status (201), which carries no iteration', async () => {
      const sha = azureCommitId('commit');
      const commitStatus = COMMIT_STATUS;
      await clientOf(services).postCommitStatus(repo().id, sha.toUpperCase(), commitStatus);
      expect(lastRequest().method).toBe('POST');
      expect(rest(lastRequest())).toBe(`/commits/${sha}/statuses`);
      expect(bodyOf(lastRequest())).toEqual({
        state: 'succeeded',
        description: 'Quality gate passed',
        targetUrl: 'https://qualor.example/p/1',
        context: { genre: 'qualor', name: 'gate' },
      });
      expect(services.commitStatuses.at(-1)).toMatchObject({ repositoryId: repo().id, sha });
      const bad = clientOf(services).postCommitStatus(repo().id, 'zz', commitStatus);
      expect(await failure(bad)).toMatchObject({ reason: 'invalid_input' });
    });
  });

  describe('the fake enforces the probe', () => {
    it('refuses a thread PATCH with properties (400) and a status without iterationId (403)', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id, {
        pullRequest: { statusPolicy: true },
      });
      const thread = services.addThread(repo().id, pullRequest.id);
      const url = `${services.url}/_apis/git/repositories/${repo().id}/pullrequests/${pullRequest.id}`;
      const headers = {
        authorization: `Basic ${Buffer.from(`:${services.pat}`).toString('base64')}`,
        'content-type': 'application/json',
      };
      const patch = await fetch(`${url}/threads/${thread.id}?api-version=7.0`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ status: 2, properties: { x: { $type: 'System.String' } } }),
      });
      expect(patch.status).toBe(400);
      expect(thread.status).toBe('active');
      const post = await fetch(`${url}/statuses?api-version=7.0`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ state: 'succeeded', context: { genre: 'qualor', name: 'gate' } }),
      });
      expect(post.status).toBe(403);
    });

    it('accepts a status without iterationId when the pull request has no status policy', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const url = `${services.url}/_apis/git/repositories/${repo().id}/pullrequests/${pullRequest.id}`;
      const post = await fetch(`${url}/statuses?api-version=7.0`, {
        method: 'POST',
        headers: {
          authorization: `Basic ${Buffer.from(`:${services.pat}`).toString('base64')}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ state: 'succeeded', context: { genre: 'qualor', name: 'gate' } }),
      });
      expect(post.status).toBe(200);
    });
  });

  describe('writes and the request budget', () => {
    it('counts every write against the same budget as reads', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id);
      const client = clientOf(services, undefined, { maxRequests: 3 });
      await client.pullRequest(repo().id, pullRequest.id);
      await client.createThread(repo().id, pullRequest.id, { content: 'a', status: 'active' });
      await client.addComment(repo().id, pullRequest.id, thread.id, 'b');
      expect(client.requestCount).toBe(3);
      const err = await failure(client.postPullRequestStatus(repo().id, pullRequest.id, STATUS));
      expect(err).toMatchObject({ kind: 'budget' });
      expect(services.requests).toHaveLength(3);
    });

    it('resolves a write whose answer has no body', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id);
      for (const status of [200, 201, 204]) {
        services.inject('PATCH', /\/threads\/\d+$/, { status });
        await expect(
          clientOf(services).setThreadStatus(repo().id, pullRequest.id, thread.id, 'fixed'),
        ).resolves.toBeUndefined();
      }
    });

    it('names a failed write by its method and route, without ids or query', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const err = await failure(
        clientOf(services).setThreadStatus(repo().id, pullRequest.id, 9999, 'fixed'),
      );
      expect(err).toMatchObject({ kind: 'not_found' });
      expect(err.request).toBe(
        `PATCH /_apis/git/repositories/{id}/pullrequests/${pullRequest.id}/threads/9999`,
      );
    });
  });
});

describe('replies, rights and service hooks (sub-plan 5, task 2)', () => {
  const repo = () => services.repositories[0]!;
  const lastRequest = () => services.requests.at(-1)!;
  const bodyOf = (r: { body: string }) => JSON.parse(r.body) as Record<string, unknown>;
  const PASSWORD = 'hook-password-8c1d-not-for-logs';
  const HOOK_URL = 'https://qualor.example/api/v0/azure-devops/webhooks/c1';
  const commentHook = (extra: Partial<NewAzureSubscription> = {}): NewAzureSubscription => ({
    eventType: 'ms.vss-code.git-pullrequest-comment-event',
    resourceVersion: '2.0',
    projectId: repo().projectId,
    repositoryId: repo().id,
    url: HOOK_URL,
    password: PASSWORD,
    ...extra,
  });

  describe('threads: a single thread, dates, parents, names, deleted and system comments', () => {
    it('reads one thread with the new comment fields', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id, {
        comments: [
          {
            content: 'root',
            authorId: services.patUser.id,
            publishedDate: '2026-11-23T10:00:00.5Z',
          },
          {
            content: 'reply',
            authorId: services.principalUser!.id,
            parentCommentId: 1,
            publishedDate: '2026-11-23T10:05:00.25Z',
          },
        ],
      });
      services.clearRequests();
      const got = await clientOf(services).thread(repo().id, pullRequest.id, thread.id);
      expect(lastRequest()).toMatchObject({
        method: 'GET',
        path: `/_apis/git/repositories/${repo().id}/pullrequests/${pullRequest.id}/threads/${thread.id}`,
      });
      expect(apiVersion(lastRequest().query)).toBe('7.0');
      expect(got.id).toBe(thread.id);
      expect(got.publishedDate).toBe('2026-11-23T10:00:00.5Z');
      expect(got.comments).toEqual([
        {
          id: 1,
          authorId: services.patUser.id,
          authorName: services.patUser.displayName,
          content: 'root',
          commentType: 'text',
          parentCommentId: 0,
          publishedDate: '2026-11-23T10:00:00.5Z',
          isDeleted: false,
        },
        {
          id: 2,
          authorId: services.principalUser!.id,
          authorName: services.principalUser!.displayName,
          content: 'reply',
          commentType: 'text',
          parentCommentId: 1,
          publishedDate: '2026-11-23T10:05:00.25Z',
          isDeleted: false,
        },
      ]);
    });

    it('parses a deleted comment without an author and a system comment', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id, {
        comments: [
          { content: 'root' },
          { content: 'gone', isDeleted: true, parentCommentId: 1 },
          { content: 'Updated the source branch', commentType: 'system' },
        ],
      });
      const raw = await fetch(
        `${services.url}/_apis/git/repositories/${repo().id}/pullrequests/${pullRequest.id}/threads/${thread.id}?api-version=7.0`,
        {
          headers: { authorization: `Basic ${Buffer.from(`:${services.pat}`).toString('base64')}` },
        },
      );
      const rawBody = (await raw.json()) as { comments: Record<string, unknown>[] };
      expect(rawBody.comments[1]).not.toHaveProperty('author');
      expect(rawBody.comments[1]?.isDeleted).toBe(true);
      const got = await clientOf(services).thread(repo().id, pullRequest.id, thread.id);
      expect(got.comments[1]).toMatchObject({
        id: 2,
        authorId: '',
        authorName: '',
        content: '',
        parentCommentId: 1,
        isDeleted: true,
      });
      expect(got.comments[2]).toMatchObject({ commentType: 'system', isDeleted: false });
    });

    it('answers an unknown thread as not found and refuses a bad repository id unsent', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const err = await failure(clientOf(services).thread(repo().id, pullRequest.id, 9999));
      expect(err).toMatchObject({ kind: 'not_found' });
      expect(err.request).toBe(
        `GET /_apis/git/repositories/{id}/pullrequests/${pullRequest.id}/threads/9999`,
      );
      services.clearRequests();
      await failure(clientOf(services).thread('../x', 1, 1));
      expect(services.requests).toHaveLength(0);
    });

    it('lists the dates and parents too', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      services.addThread(repo().id, pullRequest.id, {
        comments: [{ content: 'a' }, { content: 'b', parentCommentId: 1 }],
      });
      const [first] = await clientOf(services).threads(repo().id, pullRequest.id);
      expect(first?.publishedDate).toMatch(ISO_DATE);
      expect(first?.comments.map((c) => c.parentCommentId)).toEqual([0, 1]);
    });
  });

  describe('reply', () => {
    it('posts a comment under a parent and returns its id', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id);
      const id = await clientOf(services).reply(repo().id, pullRequest.id, thread.id, 1, 'Thanks');
      expect(id).toBe(2);
      expect(lastRequest().method).toBe('POST');
      expect(lastRequest().path).toBe(
        `/_apis/git/repositories/${repo().id}/pullrequests/${pullRequest.id}/threads/${thread.id}/comments`,
      );
      expect(apiVersion(lastRequest().query)).toBe('7.0');
      expect(bodyOf(lastRequest())).toEqual({
        content: 'Thanks',
        parentCommentId: 1,
        commentType: 1,
      });
      expect(thread.comments[1]).toMatchObject({ id: 2, parentCommentId: 1, content: 'Thanks' });
      const again = await clientOf(services).reply(repo().id, pullRequest.id, thread.id, 2, 'More');
      expect(again).toBe(3);
    });

    it('keeps addComment as it was (parent 0, no result)', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id);
      await expect(
        clientOf(services).addComment(repo().id, pullRequest.id, thread.id, 'note'),
      ).resolves.toBeUndefined();
      expect(bodyOf(lastRequest())).toEqual({
        content: 'note',
        parentCommentId: 0,
        commentType: 1,
      });
    });

    it('is a bad answer when Azure DevOps names no comment id', async () => {
      const { pullRequest } = seedAzurePullRequest(services, repo().id);
      const thread = services.addThread(repo().id, pullRequest.id);
      services.inject('POST', /\/comments$/, { status: 200, body: { content: 'x' } });
      const err = await failure(
        clientOf(services).reply(repo().id, pullRequest.id, thread.id, 1, 'x'),
      );
      expect(err).toMatchObject({ kind: 'bad_answer' });
    });
  });

  describe('identityDescriptor (identities host)', () => {
    it('asks the identities host for the id and returns the descriptor (PAT and service principal)', async () => {
      services.clearRequests();
      const viaPat = await clientOf(services).identityDescriptor(services.patUser.id);
      expect(viaPat).toBe(
        azureShape<{ body: { value: { descriptor: string }[] } }>(
          'services',
          '20-identities-pat-user',
        ).body.value[0]!.descriptor,
      );
      const request = services.requests.at(-1)!;
      expect(request).toMatchObject({ method: 'GET', path: '/vssps/_apis/identities' });
      expect(new URLSearchParams(request.query).get('identityIds')).toBe(services.patUser.id);
      expect(apiVersion(request.query)).toBe('7.0');
      expect(request.headers.authorization).toBe(
        `Basic ${Buffer.from(`:${services.pat}`).toString('base64')}`,
      );

      const viaToken = await clientOf(services, bearerOf(services, 'secret')).identityDescriptor(
        services.principalUser!.id,
      );
      expect(viaToken).toMatch(/^Microsoft\.VisualStudio\.Services\.Claims\.AadServicePrincipal;/);
      expect(services.requests.at(-1)!.headers.authorization).toMatch(/^Bearer fake-entra-/);
    });

    it('answers null for an id the organisation does not know', async () => {
      const unknown = '11111111-2222-4333-8444-555555555555';
      expect(await clientOf(services).identityDescriptor(unknown)).toBeNull();
    });

    it('is null when the answer holds an identity without a descriptor', async () => {
      services.inject('GET', /\/_apis\/identities$/, {
        status: 200,
        body: { count: 1, value: [{ id: services.patUser.id }] },
      });
      expect(await clientOf(services).identityDescriptor(services.patUser.id)).toBeNull();
    });

    it('refuses an id that is not a GUID without sending anything', async () => {
      services.clearRequests();
      const err = await failure(clientOf(services).identityDescriptor('1&x=2'));
      expect(err).toMatchObject({ kind: 'refused', reason: 'invalid_input' });
      expect(services.requests).toHaveLength(0);
    });

    it('on a Server collection is the collection itself', async () => {
      const user = server.addUser({ role: 'contributor' });
      server.clearRequests();
      const descriptor = await clientOf(server).identityDescriptor(user.id);
      expect(descriptor).toBe(user.descriptor);
      expect(server.requests.at(-1)?.path).toBe('/_apis/identities');
    });

    it('counts against the budget of the one client', async () => {
      const client = clientOf(services, undefined, { maxRequests: 1 });
      await client.identityDescriptor(services.patUser.id);
      expect(await failure(client.connectionData())).toMatchObject({ kind: 'budget' });
      expect(client.requestCount).toBe(1);
    });
  });

  describe('the identities host goes through the same outbound rules as the base', () => {
    it('derives vssps.dev.azure.com, resolves it itself and refuses a non-public address', async () => {
      const resolved: string[] = [];
      const client = new AzureDevOpsClient(
        {
          baseUrl: 'https://dev.azure.com/acme',
          credential: patOf(services),
          allowInternalHosts: true,
        },
        {
          resolve: async (host) => {
            resolved.push(host);
            return [{ address: '10.0.0.7', family: 4 }];
          },
        },
      );
      const err = await failure(client.identityDescriptor(services.patUser.id));
      // The base's own permission to use internal hosts does not carry over to its other host.
      expect(err).toMatchObject({ kind: 'refused', reason: 'not_public' });
      expect(resolved).toEqual(['vssps.dev.azure.com']);
    });

    it('derives <org>.vssps.visualstudio.com for a legacy organisation', async () => {
      const resolved: string[] = [];
      const client = new AzureDevOpsClient(
        {
          baseUrl: 'https://acme.visualstudio.com',
          credential: patOf(services),
          allowInternalHosts: false,
        },
        {
          resolve: async (host) => {
            resolved.push(host);
            return [];
          },
        },
      );
      const err = await failure(client.identityDescriptor(services.patUser.id));
      expect(err).toMatchObject({ kind: 'transient', reason: 'unresolved' });
      expect(resolved).toEqual(['acme.vssps.visualstudio.com']);
    });

    it('refuses a loopback identities host that is not allowed, before any request', async () => {
      services.clearRequests();
      const identities = identitiesOf(services)!;
      const client = new AzureDevOpsClient({
        baseUrl: services.url,
        credential: patOf(services),
        allowInternalHosts: true,
        identities: { ...identities, allowInternalHosts: false },
      });
      const err = await failure(client.identityDescriptor(services.patUser.id));
      expect(err).toMatchObject({ kind: 'refused', reason: 'not_public' });
      expect(services.requests).toHaveLength(0);
    });

    it('keeps the two hosts apart: identities on its own prefix, the rest on the base', async () => {
      services.clearRequests();
      await clientOf(services).identityDescriptor(services.patUser.id);
      await clientOf(services).connectionData();
      expect(services.requests.map((r) => r.path)).toEqual([
        '/vssps/_apis/identities',
        '/_apis/connectionData',
      ]);
    });
  });

  describe('contributeAllowed (bit 4 of extendedInfo.effectiveAllow)', () => {
    it.each([
      ['owner', true],
      ['contributor', true],
      ['reader', false],
    ] as const)('is %s -> %s', async (role, allowed) => {
      const user = services.addUser({ role });
      const client = clientOf(services);
      const descriptor = await client.identityDescriptor(user.id);
      expect(descriptor).toBe(user.descriptor);
      services.clearRequests();
      expect(await client.contributeAllowed(repo().projectId, repo().id, descriptor!)).toBe(
        allowed,
      );
      const request = lastRequest();
      expect(request.method).toBe('GET');
      expect(request.path).toBe('/_apis/accesscontrollists/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87');
      const query = new URLSearchParams(request.query);
      expect(query.get('token')).toBe(`repoV2/${repo().projectId}/${repo().id}`);
      expect(query.get('descriptors')).toBe(descriptor);
      expect(query.get('includeExtendedInfo')).toBe('true');
      expect(query.get('api-version')).toBe('7.0');
    });

    it('is false for an identity the ACL has no entry for, and for an answer without a list', async () => {
      const client = clientOf(services);
      expect(
        await client.contributeAllowed(
          repo().projectId,
          repo().id,
          'Microsoft.IdentityModel.Claims.ClaimsIdentity;t\\nobody@example.invalid',
        ),
      ).toBe(false);
      services.inject('GET', /accesscontrollists/, { status: 200, body: { count: 0, value: [] } });
      expect(await client.contributeAllowed(repo().projectId, repo().id, 'x;y')).toBe(false);
    });

    it('reads the recorded answers: PAT user and service principal allowed, reader not', async () => {
      type Acl = { body: { value: { acesDictionary: Record<string, unknown> }[] } };
      for (const name of ['20-acl-pat-user', '20-acl-service-principal']) {
        const [descriptor] = Object.keys(
          azureShape<Acl>('services', name).body.value[0]!.acesDictionary,
        );
        services.inject('GET', /accesscontrollists/, recordedAnswer('services', name));
        expect(
          await clientOf(services).contributeAllowed(repo().projectId, repo().id, descriptor!),
        ).toBe(true);
      }
      services.inject('GET', /accesscontrollists/, recordedAnswer('server', '16-acl-reader'));
      expect(
        await clientOf(services).contributeAllowed(
          repo().projectId,
          repo().id,
          'System.Security.Principal.WindowsIdentity;S-1-5-21-0-0-0-1005',
        ),
      ).toBe(false);
    });

    it('refuses ids that are not GUIDs unsent', async () => {
      services.clearRequests();
      const client = clientOf(services);
      await failure(client.contributeAllowed('x', repo().id, 'd'));
      await failure(client.contributeAllowed(repo().projectId, '../x', 'd'));
      expect(services.requests).toHaveLength(0);
    });
  });

  describe('service hooks', () => {
    it('lists the pull request event types with their versions, as recorded', async () => {
      for (const fake of [services, server]) {
        fake.clearRequests();
        const types = await clientOf(fake).hookEventTypes();
        const recorded = azureShape<{
          pullRequestEvents: { id: string; supportedResourceVersions: string[] }[];
        }>(fake.deployment, '9-event-types').pullRequestEvents;
        expect(types).toEqual(
          recorded.map((e) => ({ id: e.id, versions: e.supportedResourceVersions })),
        );
        expect(fake.requests.at(-1)).toMatchObject({
          method: 'GET',
          path: '/_apis/hooks/publishers/tfs/eventTypes',
        });
        expect(apiVersion(fake.requests.at(-1)!.query)).toBe('7.0');
        const byId = Object.fromEntries(types.map((t) => [t.id, t.versions]));
        expect(byId['ms.vss-code.git-pullrequest-comment-event']).toEqual([
          '2.0',
          '1.0',
          '1.0-preview.1',
        ]);
        expect(byId['git.pullrequest.updated']).toEqual(['1.0', '1.0-preview.1']);
      }
    });

    it('creates a subscription with the body of the recordings', async () => {
      const made = await clientOf(services).createSubscription(commentHook());
      expect(lastRequest().method).toBe('POST');
      expect(lastRequest().path).toBe('/_apis/hooks/subscriptions');
      expect(apiVersion(lastRequest().query)).toBe('7.0');
      expect(bodyOf(lastRequest())).toEqual({
        publisherId: 'tfs',
        eventType: 'ms.vss-code.git-pullrequest-comment-event',
        resourceVersion: '2.0',
        consumerId: 'webHooks',
        consumerActionId: 'httpRequest',
        publisherInputs: { projectId: repo().projectId, repository: repo().id },
        consumerInputs: {
          url: HOOK_URL,
          basicAuthUsername: 'qualor',
          basicAuthPassword: PASSWORD,
          resourceDetailsToSend: 'all',
          messagesToSend: 'none',
          detailedMessagesToSend: 'none',
        },
      });
      expect(made).toEqual({
        id: expect.stringMatching(/^[0-9a-f-]{36}$/),
        status: 'enabled',
        eventType: 'ms.vss-code.git-pullrequest-comment-event',
        resourceVersion: '2.0',
        projectId: repo().projectId,
        url: HOOK_URL,
      });
      expect(JSON.stringify(made)).not.toContain(PASSWORD);
      expect(services.subscriptions.find((s) => s.id === made.id)?.password).toBe(PASSWORD);
    });

    it('adds the branch filter when given', async () => {
      await clientOf(services).createSubscription(
        commentHook({
          eventType: 'git.pullrequest.updated',
          resourceVersion: '1.0',
          branch: 'refs/heads/main',
        }),
      );
      expect(bodyOf(lastRequest()).publisherInputs).toEqual({
        projectId: repo().projectId,
        repository: repo().id,
        branch: 'refs/heads/main',
      });
    });

    it('lists the subscriptions with the filters, and shows a status a test sets', async () => {
      const client = clientOf(services);
      const before = (await client.subscriptions()).length;
      const made = await client.createSubscription(commentHook({ url: `${HOOK_URL}-list` }));
      services.setSubscriptionStatus(made.id, 'onProbation');
      const listed = await client.subscriptions();
      expect(listed).toHaveLength(before + 1);
      expect(listed.find((s) => s.id === made.id)).toEqual({ ...made, status: 'onProbation' });
      const request = lastRequest();
      expect(request).toMatchObject({ method: 'GET', path: '/_apis/hooks/subscriptions' });
      const query = new URLSearchParams(request.query);
      expect(query.get('publisherId')).toBe('tfs');
      expect(query.get('consumerId')).toBe('webHooks');
      expect(query.get('consumerActionId')).toBe('httpRequest');
      expect(query.get('api-version')).toBe('7.0');
    });

    it('replaces a subscription with PUT, keeping the id', async () => {
      const client = clientOf(services);
      const made = await client.createSubscription(commentHook({ url: `${HOOK_URL}-put` }));
      services.setSubscriptionStatus(made.id, 'disabledBySystem');
      const replaced = await client.replaceSubscription(
        made.id,
        commentHook({ url: `${HOOK_URL}-put`, resourceVersion: '1.0' }),
      );
      expect(lastRequest().method).toBe('PUT');
      expect(lastRequest().path).toBe(`/_apis/hooks/subscriptions/${made.id}`);
      expect(apiVersion(lastRequest().query)).toBe('7.0');
      expect(bodyOf(lastRequest())).toMatchObject({
        eventType: 'ms.vss-code.git-pullrequest-comment-event',
        resourceVersion: '1.0',
        consumerInputs: { basicAuthPassword: PASSWORD },
      });
      expect(replaced).toEqual({ ...made, resourceVersion: '1.0', status: 'enabled' });
    });

    it('answers a PUT of an unknown subscription as not found and refuses a bad id unsent', async () => {
      const err = await failure(
        clientOf(services).replaceSubscription(
          '11111111-2222-4333-8444-555555555555',
          commentHook(),
        ),
      );
      expect(err).toMatchObject({ kind: 'not_found' });
      expect(err.request).toBe('PUT /_apis/hooks/subscriptions/{id}');
      services.clearRequests();
      await failure(clientOf(services).replaceSubscription('../x', commentHook()));
      expect(services.requests).toHaveLength(0);
    });

    it('is refused for a password over http, with the recorded 400 and no password in the error', async () => {
      const err = await failure(
        clientOf(services).createSubscription(commentHook({ url: 'http://qualor.example/hook' })),
      );
      expect(err).toMatchObject({ kind: 'refused', status: 400 });
      expect((err as AzureError).azureMessage).toMatch(/must be HTTPS when a basic authentication/);
      expect(written(err)).not.toContain(PASSWORD);
    });

    it('is refused for a resource version the event does not offer', async () => {
      const err = await failure(
        clientOf(services).createSubscription(
          commentHook({ eventType: 'git.pullrequest.updated', resourceVersion: '9.9' }),
        ),
      );
      expect(err).toMatchObject({ kind: 'refused', status: 400 });
    });

    it('a PUT counts against the budget, which stays 400 by default', async () => {
      const made = await clientOf(services).createSubscription(
        commentHook({ url: `${HOOK_URL}-budget` }),
      );
      services.clearRequests();
      const client = clientOf(services, undefined, { maxRequests: 2 });
      await client.replaceSubscription(made.id, commentHook({ url: `${HOOK_URL}-budget` }));
      await client.subscriptions();
      const err = await failure(client.replaceSubscription(made.id, commentHook()));
      expect(err).toMatchObject({ kind: 'budget' });
      expect(services.requests.map((r) => r.method)).toEqual(['PUT', 'GET']);
      expect(MAX_AZURE_REQUESTS).toBe(400);
    });
  });
});

describe('task 2 fix round 1', () => {
  const repo = () => services.repositories[0]!;

  it('F1: an identity the service does not find is null, as a positional null or an empty list', async () => {
    for (const body of [
      { count: 1, value: [null] },
      { count: 0, value: [] },
    ]) {
      services.inject('GET', /\/_apis\/identities$/, { status: 200, body });
      expect(await clientOf(services).identityDescriptor(services.patUser.id)).toBeNull();
    }
  });

  it('F2: the hook password is cut from an error text that echoes it, on create and replace', async () => {
    const password = 'echoed-hook-password-77f1';
    const input = {
      eventType: 'ms.vss-code.git-pullrequest-comment-event',
      resourceVersion: '2.0',
      projectId: repo().projectId,
      repositoryId: repo().id,
      url: 'https://qualor.example/hook',
      password,
    };
    const echo = { message: `Bad inputs: basicAuthPassword=${password}` };
    const made = await clientOf(services).createSubscription(input);
    services.inject('POST', /hooks\/subscriptions$/, { status: 400, body: echo });
    services.inject('PUT', /hooks\/subscriptions\//, { status: 400, body: echo });
    const errors = [
      await failure(clientOf(services).createSubscription(input)),
      await failure(clientOf(services).replaceSubscription(made.id, input)),
    ];
    for (const err of errors) {
      expect(err).toMatchObject({ kind: 'refused', status: 400 });
      expect((err as AzureError).azureMessage).toContain('[credential]');
      expect(written(err)).not.toContain(password);
      expect(err.request).not.toContain(password);
    }
  });

  it('F3: a Services client without the identities mapping cannot look an identity up', async () => {
    services.clearRequests();
    const client = new AzureDevOpsClient(
      { baseUrl: services.url, credential: patOf(services), allowInternalHosts: true },
      { timeoutMs: 2_000 },
    );
    expect(await failure(client.identityDescriptor(services.patUser.id))).toMatchObject({
      kind: 'not_found',
    });
    expect(services.requests.at(-1)?.path).toBe('/_apis/identities');
  });
});

describe('fix writes: branches, pushes, refs, raw reads and pull requests (sub-plan 6, task 2)', () => {
  let fake: FakeAzureDevOps;
  let repoId: string;
  const lastRequest = () => fake.requests.at(-1)!;
  const bodyOf = (r: { body: string }) => JSON.parse(r.body) as Record<string, unknown>;
  const ZERO = '0'.repeat(40);

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({
      deployment: 'services',
      repositories: [{ name: 'fixes', projectName: 'Payments' }],
    });
    repoId = fake.repositories[0]!.id;
  });
  afterAll(async () => {
    await fake.close();
  });
  beforeEach(() => {
    fake.clearRequests();
  });

  const seed = () => {
    const head = fake.addCommit(repoId, { files: { 'src/a.ts': 'one\r\ntwo\r\n', 'b.txt': 'b' } });
    fake.setBranch(repoId, 'main', head);
    return head;
  };

  describe('branchHead', () => {
    it('picks refs/heads/a out of a and a-2', async () => {
      const a = fake.addCommit(repoId, { files: { x: '1' } });
      const a2 = fake.addCommit(repoId, { files: { x: '2' } });
      fake.setBranch(repoId, 'qualor/a', a);
      fake.setBranch(repoId, 'qualor/a-2', a2);
      const client = clientOf(fake);
      expect(await client.branchHead(repoId, 'qualor/a')).toBe(a);
      expect(await client.branchHead(repoId, 'qualor/a-2')).toBe(a2);
      expect(await client.branchHead(repoId, 'qualor/a-3')).toBeNull();
      expect(await client.branchHead(repoId, 'qualor')).toBeNull();
      expect(Object.fromEntries(new URLSearchParams(lastRequest().query))).toEqual({
        filter: 'heads/qualor',
        'api-version': '7.0',
      });
    });
  });

  describe('commonCommit', () => {
    it('is the ancestor for an ancestor and the fork point for a diverged commit', async () => {
      const root = fake.addCommit(repoId, { files: { x: '0' } });
      const left = fake.addCommit(repoId, { parents: [root], files: { x: 'l' } });
      const right = fake.addCommit(repoId, { parents: [root], files: { x: 'r' } });
      const tip = fake.addCommit(repoId, { parents: [left], files: { x: 'l2' } });
      const client = clientOf(fake);
      expect(await client.commonCommit(repoId, left, tip)).toBe(left);
      expect(await client.commonCommit(repoId, right, tip)).toBe(root);
      expect(Object.fromEntries(new URLSearchParams(lastRequest().query))).toMatchObject({
        baseVersion: right,
        baseVersionType: 'commit',
        targetVersion: tip,
        targetVersionType: 'commit',
        $top: '1',
      });
      const stranger = fake.addCommit(repoId, { files: { x: 's' } });
      expect(await client.commonCommit(repoId, stranger, tip)).toBeNull();
    });
  });

  describe('push', () => {
    it('sends base64 edits with parents [base] and the zero old id, and returns the commit', async () => {
      const head = seed();
      const text = 'café\r\ntwo\r\n';
      const commit = await clientOf(fake).push(repoId, {
        ref: 'refs/heads/qualor/fix-1',
        oldObjectId: null,
        parent: head,
        message: 'fix: a',
        files: [{ path: 'src/a.ts', content: text }],
      });
      expect(lastRequest().path).toBe(`/_apis/git/repositories/${repoId}/pushes`);
      expect(lastRequest().method).toBe('POST');
      expect(bodyOf(lastRequest())).toEqual({
        refUpdates: [{ name: 'refs/heads/qualor/fix-1', oldObjectId: ZERO }],
        commits: [
          {
            comment: 'fix: a',
            parents: [head],
            changes: [
              {
                changeType: 'edit',
                item: { path: '/src/a.ts' },
                newContent: {
                  content: Buffer.from(text).toString('base64'),
                  contentType: 'base64encoded',
                },
              },
            ],
          },
        ],
      });
      expect(commit).toMatch(/^[0-9a-f]{40}$/);
      expect(fake.branches(repoId)['qualor/fix-1']).toBe(commit);
      expect(fake.fileAt(repoId, commit, 'src/a.ts')).toBe(text);
      expect(fake.fileAt(repoId, commit, 'b.txt')).toBe('b');
    });

    it('pushes to a temporary ref outside refs/heads', async () => {
      const head = seed();
      const commit = await clientOf(fake).push(repoId, {
        ref: 'refs/qualor/fix-tmp/20261124',
        oldObjectId: null,
        parent: head,
        message: 'tmp',
        files: [{ path: 'b.txt', content: 'tmp' }],
      });
      expect(fake.refs(repoId)['refs/qualor/fix-tmp/20261124']).toBe(commit);
      expect(Object.keys(fake.branches(repoId))).not.toContain('qualor/fix-tmp/20261124');
    });

    it('a parent that is not the ref head, or a stale old id, is the recorded 400 and refused', async () => {
      const head = seed();
      const client = clientOf(fake);
      const first = await client.push(repoId, {
        ref: 'refs/heads/qualor/fix-2',
        oldObjectId: null,
        parent: head,
        message: 'one',
        files: [{ path: 'b.txt', content: '1' }],
      });
      const notHead = await failure(
        client.push(repoId, {
          ref: 'refs/heads/qualor/fix-2',
          oldObjectId: first,
          parent: head,
          message: 'two',
          files: [{ path: 'b.txt', content: '2' }],
        }),
      );
      expect(notHead).toMatchObject({ kind: 'refused', status: 400 });
      const stale = await failure(
        client.push(repoId, {
          ref: 'refs/heads/qualor/fix-2',
          oldObjectId: head,
          parent: first,
          message: 'three',
          files: [{ path: 'b.txt', content: '3' }],
        }),
      );
      expect(stale).toMatchObject({ kind: 'refused', status: 400 });
      expect(fake.fileAt(repoId, 'qualor/fix-2', 'b.txt')).toBe('1');
    });
  });

  describe('refs', () => {
    let NAME = '';
    let counter = 0;
    beforeEach(() => {
      counter += 1;
      NAME = `refs/heads/qualor/refs-${counter}`;
    });
    const pushed = async () => {
      const head = seed();
      const commit = await clientOf(fake).push(repoId, {
        ref: NAME,
        oldObjectId: null,
        parent: head,
        message: 'x',
        files: [{ path: 'b.txt', content: 'x' }],
      });
      return { head, commit };
    };

    it('updateRef moves a ref, also to a commit that is not a fast-forward', async () => {
      const { head, commit } = await pushed();
      fake.clearRequests();
      await clientOf(fake).updateRef(repoId, NAME, commit, head);
      expect(bodyOf(lastRequest())).toEqual([
        { name: NAME, oldObjectId: commit, newObjectId: head },
      ]);
      expect(fake.branches(repoId)[NAME.replace('refs/heads/', '')]).toBe(head);
    });

    it('a stale old id is reason stale (409); a policy refusal is 403 with the update status', async () => {
      const { head } = await pushed();
      const client = clientOf(fake);
      const stale = await failure(client.updateRef(repoId, NAME, azureCommitId('old'), head));
      expect(stale).toMatchObject({ kind: 'refused', status: 409, reason: 'stale' });
      fake.inject('POST', /\/refs$/, {
        status: 200,
        body: { value: [{ success: false, updateStatus: 'rejectedByPolicy', name: NAME }] },
      });
      const refused = await failure(client.updateRef(repoId, NAME, head, head));
      expect(refused).toMatchObject({ kind: 'refused', status: 403 });
      expect((refused as AzureError).azureMessage).toBe('rejectedByPolicy');
    });

    it('deleteRef sends the zero new id; the old id is not enforced (succeededCorruptRef)', async () => {
      await pushed();
      const client = clientOf(fake);
      const wrongOld = azureCommitId('stale');
      await client.deleteRef(repoId, NAME, wrongOld);
      expect(bodyOf(lastRequest())).toEqual([
        { name: NAME, oldObjectId: wrongOld, newObjectId: ZERO },
      ]);
      expect(fake.branches(repoId)[NAME.replace('refs/heads/', '')]).toBeUndefined();
      const again = await pushed();
      await client.deleteRef(repoId, NAME, again.commit);
      expect(fake.branches(repoId)[NAME.replace('refs/heads/', '')]).toBeUndefined();
    });

    it('the recorded succeededCorruptRef answer is a delete', async () => {
      fake.inject('POST', /\/refs$/, recordedAnswer('services', '22-ref-delete-stale'));
      await expect(
        clientOf(fake).deleteRef(repoId, NAME, azureCommitId('x')),
      ).resolves.toBeUndefined();
    });
  });

  describe('fileBytes', () => {
    it('reads a 2 MiB file in full, byte-exact (BOM, CRLF, non-ASCII)', async () => {
      const commit = azureCommitId('raw');
      const big = `${String.fromCharCode(0xfeff)}é\r\n${'a'.repeat(2 * 1024 * 1024)}`;
      fake.addFile(repoId, commit, 'big.txt', big);
      const answer = await clientOf(fake).fileBytes(repoId, 'big.txt', commit, 32 * 1024 * 1024);
      expect(answer).toEqual({ text: big });
      expect(Object.fromEntries(new URLSearchParams(lastRequest().query))).toEqual({
        path: '/big.txt',
        'versionDescriptor.version': commit,
        'versionDescriptor.versionType': 'commit',
        $format: 'octetStream',
        'api-version': '7.0',
      });
    });

    it('skips a file over maxBytes, a binary one (NUL, invalid UTF-8) and a missing one', async () => {
      const commit = azureCommitId('raw-skip');
      fake.addFile(repoId, commit, 'big.txt', 'a'.repeat(1001));
      fake.addFile(repoId, commit, 'nul.bin', Buffer.from([0x61, 0, 0x62]));
      fake.addFile(repoId, commit, 'latin1.txt', Buffer.from([0x63, 0xe9, 0x64]));
      fake.addFile(repoId, commit, 'empty.txt', '');
      const client = clientOf(fake);
      const skipped = (path: string) => client.fileBytes(repoId, path, commit, 1000);
      expect(await skipped('big.txt')).toEqual({ skipped: 'too_large' });
      expect(await skipped('nul.bin')).toEqual({ skipped: 'binary' });
      expect(await skipped('latin1.txt')).toEqual({ skipped: 'binary' });
      expect(await skipped('gone.txt')).toEqual({ skipped: 'missing' });
      expect(await skipped('empty.txt')).toEqual({ text: '' });
    });

    it('does not raise the client-wide limit: another call still refuses an answer over 8 MiB', async () => {
      fake.inject('GET', /\/refs$/, {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ value: [], pad: 'a'.repeat(MAX_AZURE_RESPONSE_BYTES) }),
      });
      expect(await failure(clientOf(fake).branchHead(repoId, 'x'))).toMatchObject({
        kind: 'bad_answer',
      });
    });
  });

  describe('pull requests', () => {
    it('creates, finds and patches one; reads mergeStatus, fork and the repository id', async () => {
      const head = seed();
      fake.setBranch(repoId, 'qualor/pr-1', head);
      const client = clientOf(fake);
      const created = await client.createPullRequest(repoId, {
        sourceBranch: 'qualor/pr-1',
        targetBranch: 'main',
        title: 'Update x',
        description: 'Because',
      });
      expect(bodyOf(lastRequest())).toEqual({
        sourceRefName: 'refs/heads/qualor/pr-1',
        targetRefName: 'refs/heads/main',
        title: 'Update x',
        description: 'Because',
      });
      expect(created).toMatchObject({
        status: 'active',
        title: 'Update x',
        sourceRefName: 'refs/heads/qualor/pr-1',
        targetRefName: 'refs/heads/main',
        mergeStatus: 'succeeded',
        repositoryId: repoId,
        fork: false,
      });
      expect(await client.pullRequest(repoId, created.id)).toEqual(created);
      expect(await client.pullRequestsFrom(repoId, 'qualor/pr-1', 'main')).toEqual([created]);
      // The listed repository has no web URL: the client reads the repository once for it.
      const listing = fake.requests.findLast((r) => r.path.endsWith('/pullrequests'))!;
      expect(Object.fromEntries(new URLSearchParams(listing.query))).toEqual({
        'searchCriteria.sourceRefName': 'refs/heads/qualor/pr-1',
        'searchCriteria.targetRefName': 'refs/heads/main',
        'searchCriteria.status': 'active',
        'api-version': '7.0',
      });
      expect(await client.pullRequestsFrom(repoId, 'qualor/pr-1', 'other')).toEqual([]);

      await client.updatePullRequest(repoId, created.id, { title: 'New', description: 'D' });
      expect(lastRequest().method).toBe('PATCH');
      expect(bodyOf(lastRequest())).toEqual({ title: 'New', description: 'D' });
      fake.setMergeStatus(repoId, created.id, 'conflicts');
      expect(await client.pullRequest(repoId, created.id)).toMatchObject({
        title: 'New',
        mergeStatus: 'conflicts',
      });
      await client.updatePullRequest(repoId, created.id, { status: 'abandoned' });
      expect(bodyOf(lastRequest())).toEqual({ status: 'abandoned' });
      expect(await client.pullRequestsFrom(repoId, 'qualor/pr-1', 'main')).toEqual([]);
      expect(fake.pullRequests(repoId).find((p) => p.id === created.id)?.status).toBe('abandoned');
    });

    it('a pull request from a fork has fork true; a completed one is not listed', async () => {
      const client = clientOf(fake);
      const forked = fake.addPullRequest(repoId, {
        sourceRefName: 'refs/heads/qualor/forked',
        targetRefName: 'refs/heads/main',
        fork: true,
      });
      expect(await client.pullRequest(repoId, forked.id)).toMatchObject({ fork: true });
      fake.completePullRequest(repoId, forked.id);
      expect(await client.pullRequestsFrom(repoId, 'qualor/forked', 'main')).toEqual([]);
    });
  });

  describe('createThread with an anchor', () => {
    it('lines 2-3 send rightFileStart {2, 1} and rightFileEnd {3, endLineLength + 1}', async () => {
      const { pullRequest } = seedAzurePullRequest(fake, repoId);
      await clientOf(fake).createThread(repoId, pullRequest.id, {
        content: 'Suggestion',
        status: 'active',
        anchor: { filePath: 'src/a.ts', startLine: 2, endLine: 3, endLineLength: 7 },
      });
      expect(bodyOf(lastRequest()).threadContext).toEqual({
        filePath: '/src/a.ts',
        rightFileStart: { line: 2, offset: 1 },
        rightFileEnd: { line: 3, offset: 8 },
      });
    });
  });

  describe('the recorded answers parse with the client schemas', () => {
    const body = (name: string) => azureShape<{ body: unknown }>('services', name).body;
    it.each([
      ['pushAnswer', ['22-push-new-branch', '22-push-tmp-ref-first']],
      ['refUpdates', ['22-ref-move', '22-ref-delete', '22-ref-delete-stale', '22-ref-delete-tmp']],
      ['refList', ['22-refs-prefix']],
      ['commitsDiff', ['22-ancestry-ancestor', '22-ancestry-diverged']],
      ['pullRequestList', ['22-pr-find']],
      ['pullRequestWithId', ['22-pr-get', '22-pr-update']],
    ] as const)('%s', (schema, names) => {
      for (const name of names) {
        expect(AZURE_SHAPES[schema].safeParse(body(name)).success, name).toBe(true);
      }
    });
  });
});

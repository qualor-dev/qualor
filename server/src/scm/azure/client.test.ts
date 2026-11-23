import { inspect } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  AZURE_TEST_PRINCIPAL,
  azureCommitId,
  bearerOf,
  entraCredentialOf,
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
        comments: [
          { id: 1, authorId: 'u-1', content: 'first', commentType: 'text' },
          { id: 2, authorId: 'u-2', content: 'second', commentType: 'text' },
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
        filePath: 'src/a.ts',
        line: 5,
        lineLength: 9,
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
      expect(await client.iterationStatuses(repo().id, pullRequest.id, 1)).toEqual([
        { ...STATUS, state: 'failed', targetUrl: null },
      ]);
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

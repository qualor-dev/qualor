import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitHub, githubShape, type FakeGitHub } from '../../../test/fake-github';
import { ScmError } from '../provider';
import {
  credentialsId,
  InstallationTokenCache,
  MutationPacer,
  parseAppPrivateKey,
} from './app-auth';
import {
  GitHubClient,
  githubRateLimit,
  GITHUB_SHAPES,
  GITHUB_TEXT,
  hasNextPage,
  type GitHubClientOptions,
} from './client';

const REPO = { owner: 'acme', repo: 'api' };
const SHA = '1'.repeat(40);

describe('GitHub REST client (github.md §4–§6)', () => {
  let fake: FakeGitHub;
  let clock = Date.now();
  const clientFor = (options: GitHubClientOptions = {}, appId = String(fake.appId)) => {
    const parsed = parseAppPrivateKey(fake.privateKeyPem);
    if (!('key' in parsed)) throw new Error('key');
    return new GitHubClient(
      {
        connectionId: 'c1',
        baseUrl: fake.url,
        appId,
        privateKey: parsed.key,
        credentials: credentialsId(appId, parsed.pkcs8),
        allowInternalHosts: true,
      },
      {
        timeoutMs: 2_000,
        tokens: new InstallationTokenCache(() => clock),
        pacer: new MutationPacer(
          () => clock,
          async (ms) => void (clock += ms),
        ),
        now: () => clock,
        ...options,
      },
    );
  };
  const failure = async (p: Promise<unknown>): Promise<ScmError> => {
    try {
      await p;
    } catch (err) {
      if (err instanceof ScmError) return err;
      throw err;
    }
    throw new Error('expected a failure');
  };

  beforeAll(async () => {
    fake = await createFakeGitHub({ now: () => clock });
    fake.addRepository({ id: 424242, owner: 'acme', name: 'api', installationId: 777 });
    fake.addRepository({ id: 5, owner: 'acme', name: 'other', installationId: 777 });
    fake.addRepository({ id: 6, owner: 'acme', name: 'bare', installationId: null });
    fake.addRepository({
      id: 7,
      owner: 'acme',
      name: 'nochecks',
      installationId: 778,
      permissions: { metadata: 'read', pull_requests: 'write' },
    });
    fake.addRepository({
      id: 9,
      owner: 'acme',
      name: 'paused',
      installationId: 779,
      suspended: true,
    });
    fake.addRepository({
      id: 8,
      owner: 'acme',
      name: 'old',
      installationId: 777,
      movedTo: 'acme/new',
    });
    fake.addPull(424242, {
      number: 7,
      title: 'Refund limits',
      state: 'open',
      headSha: SHA,
      baseSha: 'b'.repeat(40),
      files: Array.from({ length: 250 }, (_, i) => ({
        filename: `f${i}.ts`,
        patch: '@@ -0,0 +1 @@\n+x',
      })),
    });
  });
  afterAll(() => fake.close());
  beforeEach(() => fake.clearRequests());

  it('signs a JWT the fake verifies, with GitHub’s headers', async () => {
    const app = await clientFor().app();
    expect(app.slug).toBe(fake.slug);
    const [request] = fake.requests;
    expect(request?.auth).toBe('jwt');
    expect(request?.headers.accept).toBe('application/vnd.github+json');
    expect(request?.headers['x-github-api-version']).toBe('2022-11-28');
    expect(String(request?.headers['user-agent'])).toMatch(/^Qualor\//);
  });

  it('gets a token scoped to the mapped repository and three permissions, and reuses it', async () => {
    const tokens = new InstallationTokenCache(() => clock);
    const repo = await clientFor({ tokens }).useRepository(REPO);
    expect(repo.id).toBe(424242);
    const [grant] = [...fake.tokens.values()].slice(-1);
    expect(grant).toMatchObject({
      repositories: ['api'],
      permissions: { checks: 'write', pull_requests: 'write', metadata: 'read' },
    });
    fake.clearRequests();
    await clientFor({ tokens }).useRepository(REPO);
    expect(fake.requests.map((r) => r.method + ' ' + r.path)).toEqual([
      'GET /repos/acme/api/installation',
      'GET /repos/acme/api',
    ]);
  });

  it('says the App is not installed, and that it lacks a permission', async () => {
    const notInstalled = await failure(clientFor().useRepository({ owner: 'acme', repo: 'bare' }));
    expect([notInstalled.kind, notInstalled.reason, notInstalled.message]).toEqual([
      'not_found',
      'not_installed',
      GITHUB_TEXT.notInstalled,
    ]);
    const missing = await failure(clientFor().useRepository({ owner: 'acme', repo: 'nochecks' }));
    expect([missing.kind, missing.reason, missing.message]).toEqual([
      'auth',
      'permission_missing',
      GITHUB_TEXT.permission,
    ]);
    const suspended = await failure(clientFor().useRepository({ owner: 'acme', repo: 'paused' }));
    expect([suspended.kind, suspended.reason, suspended.message]).toEqual([
      'auth',
      'permission_missing',
      GITHUB_TEXT.permissionOrSuspended,
    ]);
  });

  it('stops without retry, naming the clock, when GitHub refuses the JWT', async () => {
    const saved = clock;
    const client = clientFor({ now: () => saved + 5 * 60_000 }); // Qualor's clock 5 minutes ahead
    const err = await failure(client.app());
    expect([err.kind, err.status, err.message]).toEqual(['auth', 401, GITHUB_TEXT.appRefused]);
    expect(err.message).toContain("server's clock");
  });

  it('requests a fresh installation token once after a 401, then gives up', async () => {
    const tokens = new InstallationTokenCache(() => clock);
    const issued = () => fake.requests.filter((r) => r.path.endsWith('/access_tokens')).length;
    await clientFor({ tokens }).useRepository(REPO); // a token, now cached
    fake.revokeTokens(); // uninstalled and installed again: the cached token is dead
    fake.clearRequests();
    const client = clientFor({ tokens });
    await client.useRepository(REPO); // 401 with the cached token, one fresh token, success
    expect(issued()).toBe(1);
    fake.revokeTokens();
    const err = await failure(client.pullRequest('7')); // a second 401 in the same job: give up
    expect([err.kind, err.message]).toEqual(['auth', GITHUB_TEXT.tokenRefused]);
    expect(issued()).toBe(1);
  });

  it('never follows a redirect of a renamed repository', async () => {
    const err = await failure(clientFor().useRepository({ owner: 'acme', repo: 'old' }));
    expect([err.kind, err.message]).toEqual(['not_found', GITHUB_TEXT.notFound]);
    expect(fake.requests.map((r) => r.path)).toEqual(['/repos/acme/old/installation']);
  });

  it('reads pages by number and never requests the URL of a Link header', async () => {
    const hosts: string[] = [];
    const client = clientFor({
      resolve: async (host) => {
        hosts.push(host);
        return [{ address: '127.0.0.1', family: 4 }];
      },
    });
    await client.useRepository(REPO);
    fake.inject('GET', /^\/repos\/acme\/api\/pulls\/7\/files/, {
      status: 200,
      body: [{ filename: 'a.ts', status: 'modified' }],
      headers: { link: '<http://evil.example/steal?page=2>; rel="next"' },
    });
    const files = await client.pullRequestFiles('7', 30);
    expect(hosts).not.toContain('evil.example');
    expect(fake.requests.map((r) => r.path)).toContain(
      '/repos/acme/api/pulls/7/files?per_page=100&page=2',
    );
    // Page 1 (injected: one file), then the fake's pages 2 (100 files) and 3 (50 files).
    expect(files.complete).toBe(true);
    expect(files.items).toHaveLength(1 + 100 + 50);
    const cut = await client.pullRequestFiles('7', 2);
    expect([cut.items.length, cut.complete]).toEqual([200, false]);
  });

  it('does not understand a Link header too long to read, rather than taking the list as complete', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    fake.inject('GET', /^\/repos\/acme\/api\/issues\/7\/comments/, {
      status: 200,
      body: [],
      headers: {
        link: `<https://x/?page=2>; rel="next", ${'<https://x/>; rel="x", '.repeat(200)}`,
      },
    });
    const err = await failure(client.issueComments('7', 50));
    expect([err.kind, err.message]).toEqual(['bad_answer', GITHUB_TEXT.badAnswer]);
  });

  it('refuses a pull request id and a revision it would not put into a path, before any request', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    fake.clearRequests();
    expect((await failure(client.pullRequest('pr-12'))).reason).toBe('invalid_input');
    expect((await failure(client.checkRuns('abc', 'qualor/x'))).reason).toBe('invalid_input');
    expect(fake.requests).toHaveLength(0);
  });

  it('refuses a repository that is not owner/repo, or a dot segment, before any request', async () => {
    for (const ref of [
      { owner: 'acme', repo: '..' },
      { owner: 'acme', repo: '.' },
      { owner: '..', repo: 'api' },
      { owner: '.', repo: 'api' },
      { owner: 'acme/..', repo: 'api' },
      { owner: 'acme', repo: '../app' },
      { owner: 'acme', repo: 'api/x' },
      { owner: '', repo: 'api' },
      { owner: 'acme', repo: '' },
    ]) {
      fake.clearRequests();
      const err = await failure(clientFor().useRepository(ref));
      expect([err.kind, err.reason, err.message]).toEqual([
        'refused',
        'invalid_input',
        GITHUB_TEXT.repo,
      ]);
      expect(fake.requests).toHaveLength(0);
    }
  });

  it('refuses an App id that is not a positive safe integer without leading zeros', () => {
    for (const appId of [
      '',
      '0',
      '007',
      '12a',
      '-1',
      '1'.repeat(17),
      '9'.repeat(16),
      ' 1',
      '1\n',
    ]) {
      let caught: unknown;
      try {
        clientFor({}, appId);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(ScmError);
      expect([(caught as ScmError).reason, (caught as ScmError).message]).toEqual([
        'invalid_input',
        GITHUB_TEXT.appId,
      ]);
    }
    expect(() => clientFor({}, '1')).not.toThrow();
    expect(() => clientFor({}, String(Number.MAX_SAFE_INTEGER))).not.toThrow();
  });

  it('stops at 120 requests', async () => {
    const client = clientFor({ maxRequests: 2 });
    await client.app();
    await client.app();
    const err = await failure(client.app());
    expect([err.kind, err.message]).toEqual(['budget', GITHUB_TEXT.budget]);
  });

  it('spaces its mutations at least a second apart', async () => {
    const start = clock;
    const client = clientFor();
    await client.useRepository(REPO);
    const t0 = clock;
    await client.createComment('7', 'a');
    await client.createComment('7', 'b');
    expect(clock - t0).toBeGreaterThanOrEqual(1_000);
    expect(t0).toBeGreaterThanOrEqual(start);
  });

  it('creates and lists review comments on RIGHT-side lines (llm.md §8.4)', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    const one = await client.createReviewComment('7', {
      body: 'one line',
      commitId: SHA,
      path: 'f0.ts',
      line: 1,
      startLine: 1,
    });
    expect(one).toMatchObject({ body: 'one line', user: { login: `${fake.slug}[bot]` } });
    const sent = fake.requests.find((r) => r.method === 'POST' && r.path.endsWith('/comments'));
    // One line: no start_line (GitHub refuses start_line equal to line).
    expect(JSON.parse(sent?.body ?? '{}')).toEqual({
      body: 'one line',
      commit_id: SHA,
      path: 'f0.ts',
      side: 'RIGHT',
      line: 1,
    });
    // A line the patch does not show: GitHub's 422, as position_rejected.
    expect(
      await client.createReviewComment('7', { body: 'x', commitId: SHA, path: 'f1.ts', line: 5 }),
    ).toBe('position_rejected');
    const listed = await client.reviewComments('7', 30);
    expect(listed.complete).toBe(true);
    expect(listed.items.map((c) => c.body)).toEqual(['one line']);
    // Nothing reaches GitHub with a line that is no line number.
    fake.clearRequests();
    const bad = await failure(
      client.createReviewComment('7', {
        body: 'x',
        commitId: SHA,
        path: 'f0.ts',
        line: 2,
        startLine: 3,
      }),
    );
    expect([bad.kind, bad.reason]).toEqual(['refused', 'invalid_input']);
    expect(fake.requests).toHaveLength(0);
  });

  it('answers annotations_rejected when GitHub refuses the annotations', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    fake.inject('POST', /check-runs$/, { status: 422, body: { message: 'Invalid request.' } });
    const created = await client.createCheckRun({
      name: 'qualor/k',
      headSha: SHA,
      conclusion: 'success',
      title: 't',
      summary: 's',
      detailsUrl: null,
      externalId: 'qualor:v1:x',
      annotations: [
        {
          path: 'a.ts',
          start_line: 1,
          end_line: 1,
          annotation_level: 'notice',
          title: 't',
          message: 'm',
        },
      ],
    });
    expect(created).toBe('annotations_rejected');
  });

  it('lists only this App’s check runs of the name', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    await client.createCheckRun({
      name: 'qualor/k',
      headSha: SHA,
      conclusion: 'success',
      title: 't',
      summary: 's',
      detailsUrl: null,
      externalId: 'qualor:v1:x',
      annotations: [],
    });
    fake.checkRuns.push({ ...fake.checkRuns.at(-1)!, id: 9999, appId: 1 });
    const runs = await client.checkRuns(SHA, 'qualor/k');
    expect(runs).toHaveLength(1);
    expect(runs.every((r) => r.app?.id === fake.appId)).toBe(true);
    expect(fake.requests.at(-1)?.path).toContain(`app_id=${fake.appId}`);
  });

  it('is served by a fake that refuses a body GitHub would refuse', async () => {
    await clientFor().useRepository(REPO);
    const [token] = [...fake.tokens.keys()].slice(-1);
    const post = (body: string) =>
      fetch(`${fake.url}/repos/acme/api/check-runs`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token!}`, 'user-agent': 'test' },
        body,
      });
    expect((await post('{not json')).status).toBe(400);
    const run = { name: 'qualor/k', head_sha: SHA, status: 'completed', conclusion: 'success' };
    expect((await post(JSON.stringify({ ...run, output: { summary: 's' } }))).status).toBe(422);
    expect((await post(JSON.stringify({ ...run, output: { title: 't' } }))).status).toBe(422);
    expect(
      (await post(JSON.stringify({ ...run, output: { title: 't', summary: 's' } }))).status,
    ).toBe(201);
  });

  it('keeps every secret out of its errors and its serialisation', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    const [token] = [...fake.tokens.keys()].slice(-1);
    fake.inject('GET', /^\/repos\/acme\/api\/pulls\/7$/, {
      status: 500,
      body: { message: `boom ${token}` },
    });
    const err = await failure(client.pullRequest('7'));
    const everything = JSON.stringify({
      err,
      client,
      message: err.message,
      stack: err.stack,
      provider: err.providerMessage,
    });
    expect(everything).not.toContain(token!);
    expect(everything).not.toContain('PRIVATE KEY');
    expect(everything).not.toMatch(/eyJ[A-Za-z0-9_-]+\./);
  });
});

describe('githubRateLimit (github.md §5.3)', () => {
  const now = 1_800_000_000_000;
  it.each([
    [403, { 'retry-after': '30' }, null, 30],
    [429, { 'retry-after': '5000' }, null, 900],
    [
      403,
      { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(now / 1000 + 120) },
      null,
      120,
    ],
    [403, {}, 'You have exceeded a secondary rate limit.', 60],
    [429, {}, null, null],
  ])('%i %j %s → %s', (status, headers, message, seconds) => {
    expect(githubRateLimit(status, headers, message, now)).toEqual({ retryAfterSeconds: seconds });
  });
  it('is no rate limit for a plain 403 or another status', () => {
    expect(githubRateLimit(403, {}, 'Resource not accessible by integration', now)).toBeNull();
    expect(githubRateLimit(500, { 'retry-after': '1' }, null, now)).toBeNull();
  });
});

describe('hasNextPage', () => {
  it('reads rel="next" only, and nothing out of a header too long to read', () => {
    expect(hasNextPage('<https://x/?page=2>; rel="next", <https://x/?page=9>; rel="last"')).toBe(
      true,
    );
    expect(hasNextPage('<https://x/?page=1>; rel="prev", <https://x/?page=1>; rel="first"')).toBe(
      false,
    );
    expect(hasNextPage(undefined)).toBe(false);
    // Too long to read: neither a next page nor the last one (the client does not understand it).
    expect(hasNextPage('x'.repeat(5_000) + '; rel="next"')).toBeNull();
  });
});

describe('recorded shapes', () => {
  it.each(
    Object.entries({
      app: 'app',
      installation: 'installation',
      installationToken: 'installation_token',
      repository: 'repository',
      checkRun: 'check_run',
      checkRuns: 'check_runs',
      pullRequest: 'pull_request',
      pullRequestFiles: 'pull_request_files',
      issueComment: 'issue_comment',
      issueComments: 'issue_comments',
      reviewComment: 'pull_request_review_comment',
    }),
  )('%s parses', (key, file) => {
    expect(
      GITHUB_SHAPES[key as keyof typeof GITHUB_SHAPES].safeParse(githubShape(file)).success,
    ).toBe(true);
  });
});

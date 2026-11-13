import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  createFakeGitHub,
  githubShape,
  reviewCommentNodeId,
  type FakeGitHub,
} from '../../../test/fake-github';
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
  githubRoute,
  hasNextPage,
  MAX_THREAD_PAGES,
  RESOLVE_THREAD_MUTATION,
  REVIEW_THREADS_QUERY,
  UNRESOLVE_THREAD_MUTATION,
  type GitHubClientOptions,
} from './client';
import { githubGraphqlUrl } from './url';

const REPO = { owner: 'acme', repo: 'api' };
const SHA = '1'.repeat(40);
/** What every token asks for: checks and pull requests (write), and metadata (read). */
const BASE_PERMISSIONS = { checks: 'write', pull_requests: 'write', metadata: 'read' } as const;
/** An installation of an App that lacks Contents (write): one created before Qualor needed it. */
const WITHOUT_CONTENTS = {
  checks: 'write',
  issues: 'read',
  metadata: 'read',
  pull_requests: 'write',
} as const;
/** The documented App's (docs/guide/github.md), as GitHub answers for its installation. */
const DOCUMENTED = {
  permissions: { ...WITHOUT_CONTENTS, contents: 'write' },
  events: ['check_run', 'issue_comment', 'pull_request_review_comment'],
};

/** A pacer that records the keys it is asked to wait for; the waiting itself is the fake clock's. */
class SpyPacer extends MutationPacer {
  readonly waits: string[] = [];
  override async wait(key: string): Promise<void> {
    this.waits.push(key);
    await super.wait(key);
  }
}

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
          async (ms) => {
            clock += ms;
          },
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
    fake.addRepository({
      id: 10,
      owner: 'acme',
      name: 'nocontents',
      installationId: 780,
      permissions: WITHOUT_CONTENTS,
      events: ['check_run'],
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

  it('gets a token scoped to the mapped repository and its permissions, and reuses it', async () => {
    const tokens = new InstallationTokenCache(() => clock);
    const repo = await clientFor({ tokens }).useRepository(REPO);
    expect(repo.id).toBe(424242);
    const [grant] = [...fake.tokens.values()].slice(-1);
    // The installation grants Contents (write): the token carries it, to resolve conversations.
    expect(grant).toMatchObject({ repositories: ['api'] });
    expect(grant?.permissions).toEqual({ ...BASE_PERMISSIONS, contents: 'write' });
    fake.clearRequests();
    await clientFor({ tokens }).useRepository(REPO);
    expect(fake.requests.map((r) => r.method + ' ' + r.path)).toEqual([
      'GET /repos/acme/api/installation',
      'GET /repos/acme/api',
    ]);
  });

  describe('what the installation grants the App (Contents: write, and the rest the Test lists)', () => {
    /** The permissions each token request of the requests so far asked for. */
    const asked = () =>
      fake.requests
        .filter((r) => r.path.endsWith('/access_tokens'))
        .map((r) => (JSON.parse(r.body) as { permissions?: unknown }).permissions);

    it('asks for contents: write only where the installation grants it, and says what it learnt', async () => {
      fake.clearRequests();
      const granted = clientFor();
      await granted.useRepository(REPO);
      expect(granted.mayResolveThreads).toBe(true);
      expect(granted.installationAccess).toEqual(DOCUMENTED);
      const lacking = clientFor();
      await lacking.useRepository({ owner: 'acme', repo: 'nocontents' });
      expect(lacking.mayResolveThreads).toBe(false);
      expect(lacking.installationAccess).toEqual({
        permissions: WITHOUT_CONTENTS,
        events: ['check_run'],
      });
      // A permission the installation does not grant is never asked for: GitHub would refuse the
      // token (a 422).
      expect(asked()).toEqual([{ ...BASE_PERMISSIONS, contents: 'write' }, BASE_PERMISSIONS]);
      // Nothing is known before the repository is.
      expect([clientFor().mayResolveThreads, clientFor().installationAccess]).toEqual([
        false,
        null,
      ]);
    });

    it('never reuses a token asked without contents: write where it is asked for, nor the other way round', async () => {
      const repo = {
        id: 11,
        owner: 'acme',
        name: 'granted-later',
        installationId: 781,
        permissions: { ...WITHOUT_CONTENTS } as Record<string, 'read' | 'write'>,
      };
      fake.addRepository(repo);
      const tokens = new InstallationTokenCache(() => clock);
      const use = async () => {
        const client = clientFor({ tokens });
        await client.useRepository({ owner: 'acme', repo: 'granted-later' });
        return client.mayResolveThreads;
      };
      fake.clearRequests();
      expect([await use(), await use()]).toEqual([false, false]);
      // The owner grants Contents (write): a token without it is not the one to use.
      repo.permissions = { ...WITHOUT_CONTENTS, contents: 'write' };
      expect([await use(), await use()]).toEqual([true, true]);
      // ... and takes it away again: the token asked with it is not either.
      repo.permissions = { ...WITHOUT_CONTENTS };
      expect(await use()).toBe(false);
      // One token of each kind, each reused from the cache.
      expect(asked()).toEqual([BASE_PERMISSIONS, { ...BASE_PERMISSIONS, contents: 'write' }]);
    });

    it('reads the installation’s permissions and events leniently: absent or malformed is none', async () => {
      const recorded = githubShape('installation');
      expect({ permissions: recorded['permissions'], events: recorded['events'] }).toEqual(
        DOCUMENTED,
      );
      const bare = Object.fromEntries(
        Object.entries(recorded).filter(([key]) => key !== 'permissions' && key !== 'events'),
      );
      /** The installation answered with `fields` in place of its permissions and events. */
      const read = async (fields: Record<string, unknown>) => {
        fake.inject('GET', /^\/repos\/acme\/api\/installation$/, {
          status: 200,
          body: { ...bare, id: 777, app_id: fake.appId, ...fields },
        });
        fake.clearRequests();
        const client = clientFor();
        await client.useRepository(REPO);
        return [client.installationAccess, client.mayResolveThreads, asked()[0]];
      };
      const none = [{ permissions: {}, events: [] }, false, BASE_PERMISSIONS];
      expect(await read({})).toEqual(none);
      for (const [permissions, events] of [
        ['contents', 'check_run'],
        [null, null],
        [['contents'], { check_run: true }],
        [7, 7],
      ]) {
        expect(await read({ permissions, events }), JSON.stringify(permissions)).toEqual(none);
      }
      // Only what is malformed is left out.
      expect(
        await read({
          permissions: { contents: true, issues: 'read', checks: 'write', pull_requests: 7 },
          events: ['check_run', 7, null, 'issue_comment'],
        }),
      ).toEqual([
        {
          permissions: { issues: 'read', checks: 'write' },
          events: ['check_run', 'issue_comment'],
        },
        false,
        BASE_PERMISSIONS,
      ]);
      // Contents to read is not Contents to write.
      expect(
        (await read({ permissions: { ...WITHOUT_CONTENTS, contents: 'read' }, events: [] })).slice(
          1,
        ),
      ).toEqual([false, BASE_PERMISSIONS]);
    });
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

  it('stops at its request budget, 350 a job by default', async () => {
    const client = clientFor({ maxRequests: 2 });
    await client.app();
    await client.app();
    const err = await failure(client.app());
    expect([err.kind, err.message]).toEqual(['budget', GITHUB_TEXT.budget]);
    expect(GITHUB_TEXT.budget).toBe('More than 350 GitHub requests in one job');
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

  it('posts review comments together as one review, in one paced request (github.md §6.4)', async () => {
    const tokens = new InstallationTokenCache(() => clock);
    await clientFor({ tokens }).useRepository(REPO); // a token, now cached
    const pacer = new SpyPacer(
      () => clock,
      async (ms) => {
        clock += ms;
      },
    );
    const client = clientFor({ tokens, pacer });
    await client.useRepository(REPO);
    const comments = fake.reviewComments.length;
    const reviews = fake.reviews.length;
    fake.clearRequests();
    const review = await client.createReview('7', {
      commitId: SHA,
      body: 'Qualor: 2 new issues on changed lines.',
      comments: [
        { path: 'f2.ts', line: 1, body: 'two' },
        { path: 'f3.ts', line: 1, body: 'three' },
      ],
    });
    expect(review).toMatchObject({ state: 'COMMENTED' });
    // One request and one pacing wait for both: GitHub notifies once, with one timeline entry.
    expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      'POST /repos/acme/api/pulls/7/reviews',
    ]);
    expect(pacer.waits).toHaveLength(1);
    // `event: COMMENT` needs a `body` (GitHub's REST reference); each comment is on the RIGHT side.
    expect(JSON.parse(fake.requests[0]?.body ?? '{}')).toEqual({
      commit_id: SHA,
      event: 'COMMENT',
      body: 'Qualor: 2 new issues on changed lines.',
      comments: [
        { path: 'f2.ts', line: 1, side: 'RIGHT', body: 'two' },
        { path: 'f3.ts', line: 1, side: 'RIGHT', body: 'three' },
      ],
    });
    // Its comments are review comments of the App, each the first of a thread; its body is none.
    expect(
      fake.reviewComments
        .slice(comments)
        .map((c) => [c.path, c.line, c.body, c.user.login, c.inReplyToId]),
    ).toEqual([
      ['f2.ts', 1, 'two', `${fake.slug}[bot]`, null],
      ['f3.ts', 1, 'three', `${fake.slug}[bot]`, null],
    ]);
    expect(fake.reviews.slice(reviews)).toEqual([
      expect.objectContaining({ body: 'Qualor: 2 new issues on changed lines.', event: 'COMMENT' }),
    ]);
    // A position GitHub will not place refuses the whole review: none of its comments is made.
    const refused = await client.createReview('7', {
      commitId: SHA,
      body: 'x',
      comments: [
        { path: 'f4.ts', line: 1, body: 'on the diff' },
        { path: 'f4.ts', line: 9, body: 'off the diff' },
      ],
    });
    expect(refused).toBe('position_rejected');
    expect(fake.reviewComments).toHaveLength(comments + 2);
    // Nothing reaches GitHub with a line that is no line number.
    fake.clearRequests();
    const bad = await failure(
      client.createReview('7', {
        commitId: SHA,
        body: 'x',
        comments: [{ path: 'f5.ts', line: 0, body: 'x' }],
      }),
    );
    expect([bad.kind, bad.reason]).toEqual(['refused', 'invalid_input']);
    expect(fake.requests).toHaveLength(0);
  });

  it('posts a comment over several lines with start_line and start_side, in a review and alone', async () => {
    fake.addPull(424242, {
      number: 8,
      title: 'Several lines',
      state: 'open',
      headSha: SHA,
      baseSha: 'b'.repeat(40),
      files: [{ filename: 'm.ts', patch: '@@ -0,0 +1,4 @@\n+a\n+b\n+c\n+d' }],
    });
    const client = clientFor();
    await client.useRepository(REPO);
    const made = fake.reviewComments.length;
    fake.clearRequests();
    const review = await client.createReview('8', {
      commitId: SHA,
      body: 'Qualor: 3 new issues on changed lines.',
      comments: [
        { path: 'm.ts', line: 3, startLine: 2, body: 'two lines' },
        // A range of one line is one line: GitHub refuses a start_line equal to line.
        { path: 'm.ts', line: 4, startLine: 4, body: 'one line' },
        { path: 'm.ts', line: 1, body: 'plain' },
      ],
    });
    expect(review).toMatchObject({ state: 'COMMENTED' });
    expect(JSON.parse(fake.requests[0]?.body ?? '{}')).toMatchObject({
      comments: [
        {
          path: 'm.ts',
          line: 3,
          side: 'RIGHT',
          start_line: 2,
          start_side: 'RIGHT',
          body: 'two lines',
        },
        { path: 'm.ts', line: 4, side: 'RIGHT', body: 'one line' },
        { path: 'm.ts', line: 1, side: 'RIGHT', body: 'plain' },
      ],
    });
    const sent = (JSON.parse(fake.requests[0]?.body ?? '{}') as { comments: object[] }).comments;
    expect(Object.keys(sent[1] ?? {}).sort()).toEqual(['body', 'line', 'path', 'side']);
    // The fake keeps the range of a comment of a review, as GitHub lists it.
    expect(fake.reviewComments.slice(made).map((c) => [c.line, c.startLine])).toEqual([
      [3, 2],
      [4, null],
      [1, null],
    ]);
    const listed = await client.reviewComments('8', 30);
    expect(listed.items.map((c) => [c['start_line'], c['start_side'], c['line']])).toEqual([
      [2, 'RIGHT', 3],
      [null, null, 4],
      [null, null, 1],
    ]);

    // A comment posted alone keeps its range: GitHub refuses one that reaches a line off the diff.
    fake.clearRequests();
    const alone = await client.createReviewComment('8', {
      commitId: SHA,
      path: 'm.ts',
      line: 4,
      startLine: 3,
      body: 'lines three and four',
    });
    expect(alone).toMatchObject({ body: 'lines three and four' });
    expect(JSON.parse(fake.requests[0]?.body ?? '{}')).toMatchObject({
      line: 4,
      side: 'RIGHT',
      start_line: 3,
      start_side: 'RIGHT',
    });
    expect(
      await client.createReviewComment('8', {
        commitId: SHA,
        path: 'm.ts',
        line: 6,
        startLine: 4,
        body: 'reaches off the diff',
      }),
    ).toBe('position_rejected');
    expect(
      await client.createReview('8', {
        commitId: SHA,
        body: 'x',
        comments: [{ path: 'm.ts', line: 6, startLine: 4, body: 'reaches off the diff' }],
      }),
    ).toBe('position_rejected');

    // Nothing reaches GitHub with a range that is none.
    fake.clearRequests();
    for (const [line, startLine] of [
      [2, 3],
      [3, 0],
      [3, 1.5],
    ] as const) {
      const bad = await failure(
        client.createReview('8', {
          commitId: SHA,
          body: 'x',
          comments: [{ path: 'm.ts', line, startLine, body: 'x' }],
        }),
      );
      expect([bad.kind, bad.reason]).toEqual(['refused', 'invalid_input']);
    }
    expect(fake.requests).toHaveLength(0);
  });

  it('is served by a fake that refuses a review GitHub would refuse', async () => {
    await clientFor().useRepository(REPO);
    const [token] = [...fake.tokens.keys()].slice(-1);
    const post = async (body: Record<string, unknown>) =>
      (
        await fetch(`${fake.url}/repos/acme/api/pulls/7/reviews`, {
          method: 'POST',
          headers: { authorization: `Bearer ${token!}`, 'user-agent': 'test' },
          body: JSON.stringify(body),
        })
      ).status;
    const comment = { path: 'f6.ts', line: 1, side: 'RIGHT', body: 'x' };
    const review = { commit_id: SHA, event: 'COMMENT', body: 'b', comments: [comment] };
    const before = fake.reviewComments.length;
    // GitHub requires a body with COMMENT.
    expect(await post({ ...review, body: undefined })).toBe(422);
    expect(await post({ ...review, body: '' })).toBe(422);
    // A review without an event stays pending, which Qualor never makes and the fake does not model.
    expect(await post({ ...review, event: undefined })).toBe(422);
    expect(await post({ ...review, event: 'MERGE' })).toBe(422);
    expect(await post({ ...review, commit_id: 'b'.repeat(40) })).toBe(422);
    expect(await post({ ...review, comments: [{ ...comment, side: 'LEFT' }] })).toBe(422);
    expect(await post({ ...review, comments: [{ ...comment, body: '' }] })).toBe(422);
    expect(fake.reviewComments).toHaveLength(before);
    expect(await post(review)).toBe(200);
    expect(fake.reviewComments).toHaveLength(before + 1);
  });

  it('reads a review comment whose in_reply_to_id is null, and needs its node id', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    const comments = /^\/repos\/acme\/api\/pulls\/7\/comments$/;
    const recorded = githubShape('pull_request_review_comment');
    // A first comment may come with `in_reply_to_id: null`: the listing is still read (M1).
    fake.inject('GET', comments, { status: 200, body: [{ ...recorded, in_reply_to_id: null }] });
    const listed = await client.reviewComments('7', 1);
    expect(listed.items.map((c) => [c.id, c.in_reply_to_id, c.node_id])).toEqual([
      [10, null, 'PRRC_kwDOAAABc84AAAAK'],
    ]);
    // The node id is what ties a comment to its thread (C1): a comment without one is not understood.
    const { node_id: omitted, ...withoutNodeId } = recorded;
    expect(omitted).toBe('PRRC_kwDOAAABc84AAAAK');
    fake.inject('GET', comments, { status: 200, body: [withoutNodeId] });
    const err = await failure(client.reviewComments('7', 1));
    expect([err.kind, err.message]).toEqual(['bad_answer', GITHUB_TEXT.badAnswer]);
  });

  it('creates a check run whose output is a title and a summary, never annotations', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    fake.clearRequests();
    const created = await client.createCheckRun({
      name: 'qualor/k',
      headSha: SHA,
      conclusion: 'success',
      title: 't',
      summary: 's',
      detailsUrl: null,
      externalId: 'qualor:v1:x',
    });
    expect(created).toMatchObject({ name: 'qualor/k', conclusion: 'success' });
    expect(created.output.annotations_count).toBe(0);
    const sent = fake.requests.find((r) => r.method === 'POST' && r.path.endsWith('/check-runs'));
    expect((JSON.parse(sent?.body ?? '{}') as { output: unknown }).output).toEqual({
      title: 't',
      summary: 's',
    });
  });

  it('refuses a check run GitHub answers 422 to, with no second attempt of any kind', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    fake.inject('POST', /check-runs$/, { status: 422, body: { message: 'Invalid request.' } });
    fake.clearRequests();
    const refused = await failure(
      client.createCheckRun({
        name: 'qualor/k',
        headSha: SHA,
        conclusion: 'success',
        title: 't',
        summary: 's',
        detailsUrl: null,
        externalId: 'qualor:v1:x',
      }),
    );
    expect([refused.kind, refused.status]).toEqual(['refused', 422]);
    expect(fake.requests.filter((r) => r.path.endsWith('/check-runs'))).toHaveLength(1);
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

  describe('replies in a review thread', () => {
    let nextPull = 300;
    /** The clock as GitHub writes it in `created_at`: UTC, to the second. */
    const stamp = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

    /** A pull request of its own, with a review comment of the App: the first of a thread. */
    const threadOn = async () => {
      const number = nextPull++;
      fake.addPull(424242, {
        number,
        title: `Replies ${number}`,
        state: 'open',
        headSha: SHA,
        baseSha: 'b'.repeat(40),
        files: [{ filename: 'f.ts', patch: '@@ -0,0 +1 @@\n+x' }],
      });
      const author = clientFor();
      await author.useRepository(REPO);
      const first = await author.createReviewComment(String(number), {
        body: '<!-- qualor:issue 1 -->\nIssue one',
        commitId: SHA,
        path: 'f.ts',
        line: 1,
      });
      if (first === 'position_rejected') throw new Error('the fake refused the position');
      // Pacing waited before the request, so the clock now is the fake's time of the comment.
      return { number: String(number), first, firstAt: stamp(clock) };
    };

    it("a reply to a review comment uses its first comment's id", async () => {
      const { number, first } = await threadOn();
      const client = clientFor();
      await client.useRepository(REPO);
      fake.clearRequests();
      const reply = await client.replyToReviewComment(
        number,
        first.id,
        'That guard is on purpose.',
      );
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        `POST /repos/acme/api/pulls/${number}/comments/${first.id}/replies`,
      ]);
      expect(JSON.parse(fake.requests[0]?.body ?? '{}')).toEqual({
        body: 'That guard is on purpose.',
      });
      expect(reply).toMatchObject({
        body: 'That guard is on purpose.',
        in_reply_to_id: first.id,
        path: 'f.ts',
        user: { login: `${fake.slug}[bot]`, type: 'Bot' },
      });
      // The thread keeps its first comment and gains the reply, which starts no thread of its own.
      expect(
        fake.reviewThreads.filter((t) => t.pull === Number(number)).map((t) => t.commentIds),
      ).toEqual([[first.id, reply.id]]);
      const listed = await client.reviewComments(number, 5);
      expect(listed.items.map((c) => [c.id, c.in_reply_to_id ?? null])).toEqual([
        [first.id, null],
        [reply.id, first.id],
      ]);
    });

    it('refuses a comment id and a pull request id it would not put into a path, before any request', async () => {
      const { number, first } = await threadOn();
      const client = clientFor();
      await client.useRepository(REPO);
      fake.clearRequests();
      for (const id of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
        const err = await failure(client.replyToReviewComment(number, id, 'x'));
        expect([err.kind, err.reason, err.message], String(id)).toEqual([
          'refused',
          'invalid_input',
          GITHUB_TEXT.id,
        ]);
      }
      for (const pull of ['', 'pr-7', '7/../x', '1e3', '12345678901']) {
        const err = await failure(client.replyToReviewComment(pull, first.id, 'x'));
        expect([err.reason, err.message], pull).toEqual(['invalid_input', GITHUB_TEXT.prNumber]);
      }
      expect(fake.requests).toHaveLength(0);
    });

    it('a 404 is not_found', async () => {
      const { number, first } = await threadOn();
      const other = await threadOn();
      const client = clientFor();
      await client.useRepository(REPO);
      const reply = await client.replyToReviewComment(number, first.id, 'one reply');
      fake.clearRequests();
      const tries = [
        ['a comment GitHub does not have', number, first.id + 1_000_000],
        // GitHub documents a 404 for a reply to a reply (not seen live): the fake answers so.
        ['a reply, which GitHub documents it takes no reply to', number, reply.id],
        ['a comment of another pull request', number, other.first.id],
        ['a pull request GitHub does not have', '99999', first.id],
      ] as const;
      for (const [label, pull, id] of tries) {
        const err = await failure(client.replyToReviewComment(pull, id, 'x'));
        expect([err.kind, err.status, err.message], label).toEqual([
          'not_found',
          404,
          GITHUB_TEXT.notFound,
        ]);
      }
      expect(fake.requests).toHaveLength(tries.length); // each tried once
      expect(
        fake.reviewComments.filter((c) => c.pull === Number(number) && c.inReplyToId !== null),
      ).toHaveLength(1); // only the reply made before
    });

    it("both requests count against the client's budget", async () => {
      const { number, first } = await threadOn();
      const tokens = new InstallationTokenCache(() => clock);
      await clientFor({ tokens }).useRepository(REPO); // a token, now cached
      const probe = clientFor({ tokens });
      await probe.useRepository(REPO);
      const setup = probe.requests;
      const pacer = new SpyPacer(
        () => clock,
        async (ms) => {
          clock += ms;
        },
      );
      const client = clientFor({ tokens, pacer, maxRequests: setup + 2 });
      await client.useRepository(REPO);
      fake.clearRequests();
      await client.replyToReviewComment(number, first.id, 'one');
      await client.replyToReviewComment(number, first.id, 'two');
      expect(client.requests).toBe(setup + 2);
      const refused = await failure(client.replyToReviewComment(number, first.id, 'three'));
      expect([refused.kind, refused.message]).toEqual(['budget', GITHUB_TEXT.budget]);
      expect(client.requests).toBe(setup + 2);
      expect(fake.requests.map((r) => r.method)).toEqual(['POST', 'POST']);
      // A reply is a mutation: it waits for its turn like every other.
      expect(pacer.waits).toHaveLength(2);
    });

    it("reads a user's permission on the repository, and none for a 404 or a login GitHub could not have", async () => {
      const client = clientFor();
      await client.useRepository(REPO);
      fake.setPermission(424242, 'octocat', { permission: 'write', roleName: 'write' });
      fake.setPermission(424242, 'mona', { permission: 'read', roleName: 'triage' });
      fake.clearRequests();
      expect(await client.repositoryPermission('octocat')).toEqual({
        permission: 'write',
        roleName: 'write',
      });
      // GitHub compares logins without case.
      expect(await client.repositoryPermission('Mona')).toEqual({
        permission: 'read',
        roleName: 'triage',
      });
      // GitHub's 404: no permission at all.
      expect(await client.repositoryPermission('stranger')).toBeNull();
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'GET /repos/acme/api/collaborators/octocat/permission',
        'GET /repos/acme/api/collaborators/Mona/permission',
        'GET /repos/acme/api/collaborators/stranger/permission',
      ]);
      // An Enterprise Managed User's login, `<handle>_<short code>`, and its setup user's.
      fake.setPermission(424242, 'mona-cat_octo', { permission: 'write', roleName: 'maintain' });
      fake.clearRequests();
      expect(await client.repositoryPermission('mona-cat_octo')).toEqual({
        permission: 'write',
        roleName: 'maintain',
      });
      expect(await client.repositoryPermission('octo_admin')).toBeNull();
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'GET /repos/acme/api/collaborators/mona-cat_octo/permission',
        'GET /repos/acme/api/collaborators/octo_admin/permission',
      ]);
      // A login GitHub could not have, a bot's among them, has no rights, and is never sent.
      fake.clearRequests();
      for (const login of [
        '',
        `${fake.slug}[bot]`,
        'a'.repeat(40),
        '-octocat',
        'octocat-',
        'octo--cat',
        'octo cat',
        'octo/cat',
        '..',
        'ü',
        '_octo',
        'octo_',
        'mona_cat_octo',
        'mona_cat-octo',
        'octo-_cat',
        `${'a'.repeat(35)}_octo`,
      ]) {
        expect(await client.repositoryPermission(login), login).toBeNull();
      }
      expect(fake.requests).toEqual([]);
      // The longest logins GitHub allows are asked for.
      expect(await client.repositoryPermission(`a${'-b'.repeat(19)}`)).toBeNull();
      expect(await client.repositoryPermission(`${'a'.repeat(34)}_octo`)).toBeNull();
      expect(fake.requests).toHaveLength(2);
      // An older GitHub Enterprise Server names no role: the legacy permission is all there is.
      fake.inject(
        'GET',
        /\/collaborators\/octocat\/permission$/,
        { status: 200, body: { permission: 'write' } },
        { status: 200, body: { permission: 'read', user: { login: 'octocat' } } },
      );
      expect(await client.repositoryPermission('octocat')).toEqual({
        permission: 'write',
        roleName: null,
      });
      expect(await client.repositoryPermission('octocat')).toEqual({
        permission: 'read',
        roleName: null,
      });
      // An answer with no permission is not understood, and any other error is no answer either.
      fake.inject(
        'GET',
        /\/collaborators\/octocat\/permission$/,
        { status: 200, body: { role_name: 'write' } },
        { status: 502, body: { message: 'Bad Gateway' } },
      );
      expect((await failure(client.repositoryPermission('octocat'))).kind).toBe('bad_answer');
      expect((await failure(client.repositoryPermission('octocat'))).kind).toBe('transient');
      // Each lookup is a request of the job's budget: the installation, its token and the
      // repository take three.
      const small = clientFor({ maxRequests: 4 });
      await small.useRepository(REPO);
      expect(await small.repositoryPermission('octocat')).toMatchObject({ roleName: 'write' });
      expect((await failure(small.repositoryPermission('octocat'))).kind).toBe('budget');
      fake.setPermission(424242, 'octocat', null);
      fake.setPermission(424242, 'mona', null);
      fake.setPermission(424242, 'mona-cat_octo', null);
    });

    it('created_at is read from review comments and issue comments', async () => {
      const { number, first, firstAt } = await threadOn();
      const client = clientFor();
      await client.useRepository(REPO);
      expect(first.created_at).toBe(firstAt);
      // The fake's clock dates every comment it makes, and a reply has a date of its own.
      clock += 60_000;
      const asked = fake.addComment(424242, Number(number), {
        body: 'qualor review',
        login: 'octocat',
      });
      const askedAt = stamp(clock);
      clock += 90_000;
      const reply = fake.replyToReviewComment(424242, Number(number), first.id, {
        body: 'Why?',
        login: 'octocat',
      });
      const replyAt = stamp(clock);
      expect(new Set([firstAt, askedAt, replyAt]).size).toBe(3);
      const reviewComments = await client.reviewComments(number, 5);
      expect(reviewComments.items.map((c) => [c.id, c.created_at])).toEqual([
        [first.id, firstAt],
        [reply.id, replyAt],
      ]);
      const issueComments = await client.issueComments(number, 5);
      expect(issueComments.items.map((c) => [c.id, c.created_at])).toEqual([[asked.id, askedAt]]);
      // GitHub dates every comment: one without a date is not understood.
      const withoutDate = (shape: string) =>
        Object.fromEntries(
          Object.entries(githubShape(shape)).filter(([key]) => key !== 'created_at'),
        );
      fake.inject('GET', new RegExp(`/pulls/${number}/comments$`), {
        status: 200,
        body: [withoutDate('pull_request_review_comment')],
      });
      fake.inject('GET', new RegExp(`/issues/${number}/comments$`), {
        status: 200,
        body: [withoutDate('issue_comment')],
      });
      for (const read of [
        () => client.reviewComments(number, 1),
        () => client.issueComments(number, 1),
      ]) {
        const err = await failure(read());
        expect([err.kind, err.message]).toEqual(['bad_answer', GITHUB_TEXT.badAnswer]);
      }
    });

    it('is served by a fake that answers a reply as GitHub does, and takes its injected answers', async () => {
      const { number, first } = await threadOn();
      const client = clientFor();
      await client.useRepository(REPO);
      const [token] = [...fake.tokens.keys()].slice(-1);
      const post = (
        id: number,
        body: string,
        headers: Record<string, string> = { authorization: `Bearer ${token!}` },
      ) =>
        fetch(`${fake.url}/repos/acme/api/pulls/${number}/comments/${id}/replies`, {
          method: 'POST',
          headers: { 'user-agent': 'test', ...headers },
          body,
        });
      const replies = () =>
        fake.reviewComments.filter((c) => c.pull === Number(number) && c.inReplyToId !== null);
      expect((await post(first.id, '{"body":"x"}', {})).status).toBe(401);
      expect((await post(first.id, '{not json')).status).toBe(400);
      const refused = [
        '{}',
        '{"body":""}',
        '{"body":5}',
        JSON.stringify({ body: 'x'.repeat(65_537) }),
      ];
      for (const body of refused) expect((await post(first.id, body)).status, body).toBe(422);
      expect((await post(first.id + 1_000_000, '{"body":"x"}')).status).toBe(404);
      // Writing needs the pull requests permission.
      const grant = fake.tokens.get(token!)!;
      grant.permissions = { metadata: 'read', checks: 'write', pull_requests: 'read' };
      expect((await post(first.id, '{"body":"x"}')).status).toBe(403);
      grant.permissions = { metadata: 'read', checks: 'write', pull_requests: 'write' };
      expect(replies()).toHaveLength(0);
      // The answer is the recorded reply: its fields, a review comment of the App naming the first.
      const created = await post(first.id, '{"body":"x"}');
      expect(created.status).toBe(201);
      const answer = (await created.json()) as Record<string, unknown>;
      expect(Object.keys(answer).sort()).toEqual(
        Object.keys(githubShape('pull_request_review_comment_reply')).sort(),
      );
      expect(GITHUB_SHAPES.reviewCommentReply.safeParse(answer).success).toBe(true);
      expect(answer).toMatchObject({
        body: 'x',
        in_reply_to_id: first.id,
        user: { login: `${fake.slug}[bot]`, type: 'Bot' },
      });
      expect(replies()).toHaveLength(1);
      // Through the client: a refused body is a 422, and the fake's injected answers reach the route.
      const blank = await failure(client.replyToReviewComment(number, first.id, ''));
      expect([blank.kind, blank.status]).toEqual(['refused', 422]);
      fake.inject('POST', /\/comments\/\d+\/replies$/, {
        status: 403,
        body: { message: 'Resource not accessible by integration' },
      });
      const forbidden = await failure(client.replyToReviewComment(number, first.id, 'y'));
      expect([forbidden.kind, forbidden.reason]).toEqual(['auth', 'permission_missing']);
      expect(replies()).toHaveLength(1);
    });
  });

  describe('review threads over GraphQL (github.md §6.4, ruling R6)', () => {
    const GRAPHQL = /^\/api\/graphql$/;
    let nextPull = 100;

    /**
     * A pull request of its own (no test reads another's threads) with `count` review comments by
     * the App, each the first comment of a thread, in the order they were made.
     */
    const pullWithThreads = async (count: number) => {
      const number = nextPull++;
      fake.addPull(424242, {
        number,
        title: `Threads ${number}`,
        state: 'open',
        headSha: SHA,
        baseSha: 'b'.repeat(40),
        files: [{ filename: 'f.ts', patch: '@@ -0,0 +1 @@\n+x' }],
      });
      const author = clientFor({ maxRequests: count + 10 });
      await author.useRepository(REPO);
      const commentIds: number[] = [];
      const nodeIds: string[] = [];
      for (let i = 0; i < count; i++) {
        const created = await author.createReviewComment(String(number), {
          body: `<!-- qualor:issue ${i} -->\nissue ${i}`,
          commitId: SHA,
          path: 'f.ts',
          line: 1,
        });
        if (created === 'position_rejected') throw new Error('the fake refused the position');
        commentIds.push(created.id);
        nodeIds.push(created.node_id);
      }
      const threadIds = commentIds.map(
        (id) => fake.reviewThreads.find((t) => t.commentIds[0] === id)!.id,
      );
      return { number: String(number), commentIds, nodeIds, threadIds };
    };
    let many: Awaited<ReturnType<typeof pullWithThreads>>;
    beforeAll(async () => {
      many = await pullWithThreads(150);
    }, 60_000);

    /** A client on the repository, its requests so far forgotten. */
    const reader = async (options: GitHubClientOptions = {}) => {
      const client = clientFor(options);
      await client.useRepository(REPO);
      fake.clearRequests();
      return client;
    };
    /** The next GraphQL request is answered with this (HTTP 200 unless said otherwise). */
    const answer = (body: unknown, status = 200, headers?: Record<string, string>) =>
      fake.inject('POST', GRAPHQL, { status, body, ...(headers ? { headers } : {}) });
    /** A thread node whose first comment has the node id `commentId` (REST's `node_id`). */
    const node = (id: string, resolvedBy: string | null, commentId: string) => ({
      id,
      isResolved: resolvedBy !== null,
      resolvedBy: resolvedBy === null ? null : { login: resolvedBy },
      comments: { nodes: [{ id: commentId }] },
    });
    const threadsData = (nodes: unknown[], pageInfo = { hasNextPage: false, endCursor: null }) => ({
      data: { repository: { pullRequest: { reviewThreads: { pageInfo, nodes } } } },
    });
    const sent = (index: number) =>
      JSON.parse(fake.requests[index]?.body ?? '{}') as {
        query: string;
        variables: Record<string, unknown>;
      };

    it('reads every page and the resolver’s login', async () => {
      // A person, another App, and the fake's own App (a resolve through the API with an
      // installation token): GitHub names each by its login, an App as `<slug>[bot]` (R6).
      fake.resolveThreadAs(many.threadIds[3]!, 'octocat');
      fake.resolveThreadAs(many.threadIds[60]!, 'other-app[bot]');
      const client = await reader();
      expect(await client.setThreadResolved(many.threadIds[120]!, true)).toBe('done');
      fake.clearRequests();
      const threads = await client.reviewThreads(many.number, MAX_THREAD_PAGES);
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'POST /api/graphql',
        'POST /api/graphql',
      ]);
      expect(threads.complete).toBe(true);
      expect(threads.items).toHaveLength(150);
      expect(threads.items.filter((t) => t.isResolved)).toEqual([
        {
          id: many.threadIds[3],
          isResolved: true,
          resolvedByLogin: 'octocat',
          firstCommentNodeId: many.nodeIds[3],
        },
        {
          id: many.threadIds[60],
          isResolved: true,
          resolvedByLogin: 'other-app[bot]',
          firstCommentNodeId: many.nodeIds[60],
        },
        {
          id: many.threadIds[120],
          isResolved: true,
          resolvedByLogin: `${fake.slug}[bot]`,
          firstCommentNodeId: many.nodeIds[120],
        },
      ]);
      // An open thread names nobody.
      const open = threads.items.filter((t) => !t.isResolved);
      expect(open).toHaveLength(147);
      expect(open.every((t) => t.resolvedByLogin === null)).toBe(true);
      expect(threads.items.map((t) => t.id)).toEqual(many.threadIds);
      // Each thread names its first comment by the node id REST lists as `node_id` (C1): GitHub's
      // REST ids are past 2^31, which GraphQL's 32-bit `databaseId` cannot hold.
      expect(threads.items.map((t) => t.firstCommentNodeId)).toEqual(many.nodeIds);
      expect(new Set(many.nodeIds).size).toBe(150);
      expect(many.commentIds.every((id) => id > 2 ** 31)).toBe(true);
    });

    it('stops at maxPages and says the list is not complete', async () => {
      const client = await reader();
      const threads = await client.reviewThreads(many.number, 1);
      expect([threads.items.length, threads.complete]).toEqual([100, false]);
      expect(fake.requests).toHaveLength(1);
    });

    it('posts the document with the variables GraphQL types, to the endpoint beside /api/v3', async () => {
      const client = await reader();
      await client.reviewThreads(many.number, MAX_THREAD_PAGES);
      const [first, second] = fake.requests;
      expect([first?.method, first?.path, first?.auth]).toEqual(['POST', '/api/graphql', 'token']);
      expect(first?.headers['content-type']).toBe('application/json');
      expect(first?.headers.accept).toBe('application/vnd.github+json');
      expect(String(first?.headers['user-agent'])).toMatch(/^Qualor\//);
      // `number` is an Int!, and the first page has no cursor.
      expect(sent(0)).toEqual({
        query: REVIEW_THREADS_QUERY,
        variables: { owner: 'acme', name: 'api', number: Number(many.number), after: null },
      });
      // The first comment is asked for by its node id only (C1): never `databaseId`, deprecated
      // because it cannot hold GitHub's 64-bit ids, nor `fullDatabaseId`, which an older GitHub
      // Enterprise Server does not have (an unknown field fails the whole query).
      expect(REVIEW_THREADS_QUERY).toContain('comments(first: 1) { nodes { id } }');
      expect(REVIEW_THREADS_QUERY).not.toMatch(/databaseid/i);
      // The second page continues after the first one's end cursor.
      expect(second?.path).toBe('/api/graphql');
      expect(sent(1).variables).toEqual({
        owner: 'acme',
        name: 'api',
        number: Number(many.number),
        after: expect.stringMatching(/^.+$/),
      });
    });

    it.each([
      ['NOT_FOUND', 'not_found', 'http', GITHUB_TEXT.notFound, null],
      ['FORBIDDEN', 'auth', 'permission_missing', GITHUB_TEXT.permission, null],
      ['RATE_LIMITED', 'rate_limited', 'http', GITHUB_TEXT.graphqlRateLimit, 60],
      ['MAX_NODE_LIMIT_EXCEEDED', 'bad_answer', 'bad_answer', GITHUB_TEXT.badAnswer, null],
    ])(
      'a GraphQL %s error is an ScmError of kind %s, never an empty list',
      async (type, kind, reason, text, retryAfterSeconds) => {
        const client = await reader();
        answer({ data: null, errors: [{ type, message: 'x' }] });
        const err = await failure(client.reviewThreads(many.number, 1));
        expect([err.kind, err.reason, err.message, err.retryAfterSeconds, err.status]).toEqual([
          kind,
          reason,
          text,
          retryAfterSeconds,
          200,
        ]);
      },
    );

    it('waits for the reset a GraphQL rate limit names, and a minute when it names none (M3)', async () => {
      const client = await reader();
      const limited = {
        data: null,
        errors: [{ type: 'RATE_LIMITED', message: 'API rate limit exceeded' }],
      };
      const inSeconds = (s: number) => String(Math.floor(clock / 1000) + s);
      const waits = async (headers?: Record<string, string>) => {
        answer(limited, 200, headers);
        const err = await failure(client.reviewThreads(many.number, 1));
        expect([err.kind, err.status]).toEqual(['rate_limited', 200]);
        return err.retryAfterSeconds;
      };
      // The primary limit is spent: its reset says when, as REST's does (githubRateLimit).
      const spent = { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': inSeconds(120) };
      expect(await waits(spent)).toBe(120);
      // Retry-After wins, as for REST; a reset far off is clamped to 15 minutes.
      expect(await waits({ ...spent, 'retry-after': '30' })).toBe(30);
      expect(await waits({ ...spent, 'x-ratelimit-reset': inSeconds(7_200) })).toBe(900);
      // A limit that is not spent (a secondary one), an unreadable reset, or no header at all:
      // GitHub's advice of a minute.
      expect(await waits({ ...spent, 'x-ratelimit-remaining': '4000' })).toBe(60);
      expect(await waits({ ...spent, 'x-ratelimit-reset': 'soon' })).toBe(60);
      expect(await waits()).toBe(60);
      // A mutation reads them the same way. It is paced first (the fake clock moves on up to a
      // second), so the wait is counted from when the answer came.
      const reset = inSeconds(300);
      answer(limited, 200, { ...spent, 'x-ratelimit-reset': reset });
      const mutation = await failure(client.setThreadResolved(many.threadIds[0]!, true));
      expect([mutation.kind, mutation.retryAfterSeconds]).toEqual([
        'rate_limited',
        Math.ceil(Number(reset) - clock / 1000),
      ]);
      expect(mutation.retryAfterSeconds).toBeGreaterThanOrEqual(299);
    });

    it('is never fooled by data next to an error, or by an answer without data', async () => {
      const client = await reader();
      // An empty list beside a FORBIDDEN error is a failure, not "no threads".
      answer({ ...threadsData([]), errors: [{ type: 'FORBIDDEN', message: 'x' }] });
      expect((await failure(client.reviewThreads(many.number, 1))).kind).toBe('auth');
      for (const body of [
        { data: null },
        {},
        [],
        null,
        { data: {} },
        { data: { repository: 5 } },
      ]) {
        answer(body);
        const err = await failure(client.reviewThreads(many.number, 1));
        expect([err.kind, err.message]).toEqual(['bad_answer', GITHUB_TEXT.badAnswer]);
      }
      // `errors: []` is no error.
      answer({ ...threadsData([node('PRRT_a', null, 'PRRC_a')]), errors: [] });
      expect((await client.reviewThreads(many.number, 1)).items).toHaveLength(1);
    });

    it('says not_found for a pull request that is not there, never an empty list', async () => {
      const client = await reader();
      const err = await failure(client.reviewThreads('2147483647', 1)); // the fake: a NOT_FOUND error
      expect([err.kind, err.message]).toEqual(['not_found', GITHUB_TEXT.notFound]);
      for (const data of [{ repository: { pullRequest: null } }, { repository: null }]) {
        answer({ data });
        const gone = await failure(client.reviewThreads(many.number, 1));
        expect([gone.kind, gone.message]).toEqual(['not_found', GITHUB_TEXT.notFound]);
      }
    });

    it('does not read a missing resolvedBy as "nobody resolved it"', async () => {
      const client = await reader();
      answer(threadsData([{ id: 'PRRT_a', isResolved: true, comments: { nodes: [{ id: 'x' }] } }]));
      expect((await failure(client.reviewThreads(many.number, 1))).kind).toBe('bad_answer');
      // A next page without a cursor to ask for it is not the last page either.
      answer(threadsData([node('PRRT_a', null, 'PRRC_a')], { hasNextPage: true, endCursor: null }));
      expect((await failure(client.reviewThreads(many.number, 5))).kind).toBe('bad_answer');
    });

    it('leaves out a null node, and has no first comment id for a thread without a readable comment', async () => {
      const client = await reader();
      answer(
        threadsData([
          null,
          { ...node('PRRT_a', null, 'PRRC_a'), comments: { nodes: [] } },
          { ...node('PRRT_c', 'octocat', 'PRRC_c'), comments: { nodes: [null] } },
        ]),
      );
      const threads = await client.reviewThreads(many.number, 1);
      expect(threads.items).toEqual([
        { id: 'PRRT_a', isResolved: false, resolvedByLogin: null, firstCommentNodeId: null },
        { id: 'PRRT_c', isResolved: true, resolvedByLogin: 'octocat', firstCommentNodeId: null },
      ]);
    });

    it('does not understand a first comment without a node id, such as an answer of databaseId', async () => {
      const client = await reader();
      for (const comment of [{ databaseId: 5 }, { id: null }, { id: '' }, { id: 5 }, {}]) {
        answer(
          threadsData([{ ...node('PRRT_a', null, 'PRRC_a'), comments: { nodes: [comment] } }]),
        );
        const err = await failure(client.reviewThreads(many.number, 1));
        expect([err.kind, err.message]).toEqual(['bad_answer', GITHUB_TEXT.badAnswer]);
      }
    });

    it('reads the recorded answer: an open thread, a person’s resolution and an App’s', async () => {
      const client = await reader();
      answer(githubShape('graphql_review_threads'));
      const threads = await client.reviewThreads(many.number, 1);
      expect(threads.complete).toBe(false); // the recorded page has a next one
      expect(
        threads.items.map((t) => [t.isResolved, t.resolvedByLogin, t.firstCommentNodeId]),
      ).toEqual([
        [false, null, 'PRRC_kwDOAAABc84AAAAK'],
        [true, 'octocat', 'PRRC_kwDOAAABc84AAAAL'],
        [true, 'qualor-acme[bot]', 'PRRC_kwDOAAABc84AAAAM'],
      ]);
    });

    it('keeps a resolved thread GitHub names nobody for resolved, with no login', async () => {
      const client = await reader();
      // E.g. the resolver's account is gone: the caller can tell it is not Qualor's own.
      answer(threadsData([{ ...node('PRRT_d', null, 'PRRC_d'), isResolved: true }]));
      expect((await client.reviewThreads(many.number, 1)).items).toEqual([
        { id: 'PRRT_d', isResolved: true, resolvedByLogin: null, firstCommentNodeId: 'PRRC_d' },
      ]);
    });

    it('keeps GitHub’s own words and the installation token out of the error text', async () => {
      const client = await reader();
      const [token] = [...fake.tokens.keys()].slice(-1);
      answer({ data: null, errors: [{ type: 'FORBIDDEN', message: `denied for ${token}` }] });
      const err = await failure(client.reviewThreads(many.number, 1));
      expect(err.message).toBe(GITHUB_TEXT.permission);
      expect(err.providerMessage).toBe('denied for [secret]');
      expect(JSON.stringify({ err, client, message: err.message, stack: err.stack })).not.toContain(
        token!,
      );
    });

    it('maps the HTTP errors of the endpoint as REST’s are mapped', async () => {
      const client = await reader();
      answer({ message: 'You have exceeded a secondary rate limit.' }, 403, {
        'retry-after': '30',
      });
      const limited = await failure(client.reviewThreads(many.number, 1));
      expect([limited.kind, limited.status, limited.retryAfterSeconds]).toEqual([
        'rate_limited',
        403,
        30,
      ]);
      answer({ message: 'Resource not accessible by integration' }, 403);
      const forbidden = await failure(client.reviewThreads(many.number, 1));
      expect([forbidden.kind, forbidden.reason]).toEqual(['auth', 'permission_missing']);
      answer({ message: 'Server Error' }, 502);
      expect((await failure(client.reviewThreads(many.number, 1))).kind).toBe('transient');
    });

    it('asks for one fresh installation token after a 401, as every repository call does', async () => {
      const client = await reader();
      fake.revokeTokens();
      const threads = await client.reviewThreads(many.number, 1);
      expect(threads.items).toHaveLength(100);
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'POST /api/graphql',
        'POST /app/installations/777/access_tokens',
        'POST /api/graphql',
      ]);
    });

    it('refuses a pull request number GraphQL’s Int cannot hold, and an id it would not send, before any request', async () => {
      const client = await reader();
      for (const bad of ['2147483648', '9999999999', 'pr-12', '']) {
        expect((await failure(client.reviewThreads(bad, 1))).reason).toBe('invalid_input');
      }
      for (const bad of ['', 'two words', 'x'.repeat(256), 'PRRT\n1']) {
        expect((await failure(client.setThreadResolved(bad, true))).reason).toBe('invalid_input');
      }
      expect(fake.requests).toHaveLength(0);
    });

    it('setThreadResolved resolves and reopens a thread, as an App', async () => {
      const { number, threadIds } = await pullWithThreads(1);
      const id = threadIds[0]!;
      const client = await reader();
      expect(await client.setThreadResolved(id, true)).toBe('done');
      const thread = fake.reviewThreads.find((t) => t.id === id)!;
      const app = `${fake.slug}[bot]`;
      expect([thread.resolved, thread.resolvedBy]).toEqual([true, app]);
      expect(sent(0)).toEqual({ query: RESOLVE_THREAD_MUTATION, variables: { id } });
      // Read back, GitHub names the App like any other resolver, `<slug>[bot]` (R6).
      expect((await client.reviewThreads(number, 1)).items).toEqual([
        expect.objectContaining({ id, isResolved: true, resolvedByLogin: app }),
      ]);
      expect(await client.setThreadResolved(id, false)).toBe('done');
      expect([thread.resolved, thread.resolvedBy]).toEqual([false, null]);
      expect(sent(2)).toEqual({ query: UNRESOLVE_THREAD_MUTATION, variables: { id } });
      // Reopened, it names nobody.
      expect((await client.reviewThreads(number, 1)).items).toEqual([
        expect.objectContaining({ id, isResolved: false, resolvedByLogin: null }),
      ]);
    });

    it('says not_found for a thread GitHub does not know, and lets every other error through', async () => {
      const client = await reader();
      expect(await client.setThreadResolved('PRRT_kwDOgone', true)).toBe('not_found');
      expect(await client.setThreadResolved('PRRT_kwDOgone', false)).toBe('not_found');
      answer({ data: null, errors: [{ type: 'RATE_LIMITED', message: 'x' }] });
      const limited = await failure(client.setThreadResolved(many.threadIds[0]!, true));
      expect([limited.kind, limited.retryAfterSeconds]).toEqual(['rate_limited', 60]);
      // GitHub does not report the state asked for: not "done".
      answer({ data: { resolveReviewThread: { thread: { id: 'PRRT_a', isResolved: false } } } });
      expect((await failure(client.setThreadResolved(many.threadIds[0]!, true))).kind).toBe(
        'bad_answer',
      );
      answer({ data: { unresolveReviewThread: { thread: { id: 'PRRT_a', isResolved: false } } } });
      expect(await client.setThreadResolved(many.threadIds[0]!, false)).toBe('done');
      answer({ data: { unresolveReviewThread: null } });
      expect((await failure(client.setThreadResolved(many.threadIds[0]!, false))).kind).toBe(
        'bad_answer',
      );
    });

    it('counts GraphQL calls against the request budget', async () => {
      const { number, threadIds } = await pullWithThreads(1);
      const tokens = new InstallationTokenCache(() => clock);
      await clientFor({ tokens }).useRepository(REPO); // a token, now cached
      const client = clientFor({ tokens, maxRequests: 3 });
      await client.useRepository(REPO); // the installation and the repository: two requests
      await client.reviewThreads(number, 1); // the third
      expect(client.requests).toBe(3);
      const query = await failure(client.reviewThreads(number, 1));
      const mutation = await failure(client.setThreadResolved(threadIds[0]!, true));
      expect([query.kind, query.message, mutation.kind]).toEqual([
        'budget',
        GITHUB_TEXT.budget,
        'budget',
      ]);
      expect(client.requests).toBe(3);
      expect(fake.reviewThreads.find((t) => t.id === threadIds[0])?.resolved).toBe(false);
    });

    it('paces its mutations with the REST ones, and its queries not at all', async () => {
      const { number, threadIds } = await pullWithThreads(1);
      const tokens = new InstallationTokenCache(() => clock);
      await clientFor({ tokens }).useRepository(REPO); // a token, now cached
      const pacer = new SpyPacer(
        () => clock,
        async (ms) => {
          clock += ms;
        },
      );
      const client = clientFor({ tokens, pacer });
      await client.useRepository(REPO); // reads only
      await client.reviewThreads(number, 1); // a query is a POST, but no mutation
      expect(pacer.waits).toEqual([]);
      const t0 = clock;
      await client.setThreadResolved(threadIds[0]!, true);
      await client.setThreadResolved(threadIds[0]!, false);
      expect(pacer.waits).toHaveLength(2);
      expect(clock - t0).toBeGreaterThanOrEqual(1_000);
      await client.createComment(number, 'a REST mutation');
      expect(pacer.waits).toHaveLength(3);
      expect(new Set(pacer.waits).size).toBe(1); // one key: the installation's
    });

    it('lists a reply with its in_reply_to_id and its path, and a reply starts no thread', async () => {
      const { number, commentIds, nodeIds, threadIds } = await pullWithThreads(2);
      const reply = fake.replyToReviewComment(424242, Number(number), commentIds[0]!, {
        body: 'On it',
        login: 'octocat',
      });
      expect(() =>
        fake.replyToReviewComment(424242, Number(number), reply.id, { body: 'x', login: 'a' }),
      ).toThrow(); // GitHub documents that it takes no reply to a reply
      const client = await reader();
      const listed = await client.reviewComments(number, 5);
      expect(listed.items.map((c) => [c.id, c.in_reply_to_id, c.path, c.user?.login])).toEqual([
        [commentIds[0], undefined, 'f.ts', `${fake.slug}[bot]`],
        [commentIds[1], undefined, 'f.ts', `${fake.slug}[bot]`],
        [reply.id, commentIds[0], 'f.ts', 'octocat'],
      ]);
      expect(listed.items[2]?.user?.type).toBe('User');
      // Every comment has a node id of its own, `PRRC_` and its id in base 62, as the fake makes them.
      expect(listed.items.map((c) => c.node_id)).toEqual([
        nodeIds[0],
        nodeIds[1],
        reviewCommentNodeId(reply.id),
      ]);
      expect(nodeIds[0]).toBe(reviewCommentNodeId(commentIds[0]!));
      expect(reply.id).toBeGreaterThan(2 ** 31);
      const threads = await client.reviewThreads(number, 1);
      expect(threads.items.map((t) => [t.id, t.firstCommentNodeId])).toEqual([
        [threadIds[0], nodeIds[0]],
        [threadIds[1], nodeIds[1]],
      ]);
      expect(fake.reviewThreads.find((t) => t.id === threadIds[0])?.commentIds).toEqual([
        commentIds[0],
        reply.id,
      ]);
      expect(() => fake.resolveThreadAs('PRRT_nope', 'octocat')).toThrow();
    });

    it('is served by a fake that refuses what GitHub’s GraphQL endpoint refuses', async () => {
      const client = await reader();
      const [token] = [...fake.tokens.keys()].slice(-1);
      const post = (headers: Record<string, string>, body: unknown) =>
        fetch(githubGraphqlUrl(fake.url), {
          method: 'POST',
          headers: { 'user-agent': 'test', ...headers },
          body: typeof body === 'string' ? body : JSON.stringify(body),
        });
      const auth = { authorization: `Bearer ${token!}` };
      const variables = { owner: 'acme', name: 'api', number: Number(many.number), after: null };
      expect((await post({}, { query: REVIEW_THREADS_QUERY, variables })).status).toBe(401);
      expect((await post(auth, '{not json')).status).toBe(400);
      // A string where the document says Int!: HTTP 200, errors and no data.
      const wrong = await post(auth, {
        query: REVIEW_THREADS_QUERY,
        variables: { ...variables, number: many.number },
      });
      const body = (await wrong.json()) as { data?: unknown; errors?: { message: string }[] };
      expect([wrong.status, body.data, body.errors?.[0]?.message]).toEqual([
        200,
        undefined,
        expect.stringContaining('$number'),
      ]);
      // A field the schema does not have fails the whole query, as on a GitHub Enterprise Server
      // without `fullDatabaseId`; the fake has neither that nor the deprecated `databaseId` (C1).
      for (const field of ['databaseId', 'fullDatabaseId']) {
        const old = await post(auth, {
          query: REVIEW_THREADS_QUERY.replace('nodes { id } }', `nodes { ${field} } }`),
          variables,
        });
        const refused = (await old.json()) as {
          data?: unknown;
          errors?: { message: string; extensions?: { code?: string } }[];
        };
        expect([old.status, refused.data, refused.errors?.[0]?.extensions?.code]).toEqual([
          200,
          undefined,
          'undefinedField',
        ]);
        expect(refused.errors?.[0]?.message).toContain(field);
      }
      // Only the repositories the token is for, and only with the permission the operation needs:
      // Pull requests (read) for the query, Contents (write) to resolve, which GitHub refuses with
      // its FORBIDDEN, and the client answers `refused`.
      const grant = fake.tokens.get(token!)!;
      grant.permissions = { metadata: 'read', checks: 'write', pull_requests: 'read' };
      expect((await client.reviewThreads(many.number, 1)).items).toHaveLength(100);
      expect(await client.setThreadResolved(many.threadIds[0]!, true)).toBe('refused');
      grant.permissions = { metadata: 'read', checks: 'write' };
      const read = await failure(client.reviewThreads(many.number, 1));
      expect([read.kind, read.reason]).toEqual(['auth', 'permission_missing']);
      grant.permissions = { metadata: 'read', checks: 'write', pull_requests: 'write' };
      grant.repositories = ['other'];
      expect((await failure(client.reviewThreads(many.number, 1))).kind).toBe('not_found');
      expect(await client.setThreadResolved(many.threadIds[0]!, true)).toBe('not_found');
      expect(fake.reviewThreads.find((t) => t.id === many.threadIds[0])?.resolved).toBe(false);
    });

    it('is served by a fake that resolves a thread only with a token that carries contents: write, as GitHub does', async () => {
      const { threadIds } = await pullWithThreads(1);
      await reader();
      const [token] = [...fake.tokens.keys()].slice(-1);
      const grant = fake.tokens.get(token!)!;
      const thread = fake.reviewThreads.find((t) => t.id === threadIds[0])!;
      const send = async (query: string) =>
        (await (
          await fetch(githubGraphqlUrl(fake.url), {
            method: 'POST',
            headers: { authorization: `Bearer ${token!}`, 'user-agent': 'test' },
            body: JSON.stringify({ query, variables: { id: thread.id } }),
          })
        ).json()) as { data?: unknown; errors?: { type?: string; message?: string }[] };
      // Measured on github.com (2026-10-26): a token without Contents (write) is refused, its
      // Pull requests (write) notwithstanding, with HTTP 200 and GitHub's FORBIDDEN ...
      grant.permissions = { ...BASE_PERMISSIONS };
      for (const query of [RESOLVE_THREAD_MUTATION, UNRESOLVE_THREAD_MUTATION]) {
        const refused = await send(query);
        expect([refused.errors?.[0]?.type, refused.errors?.[0]?.message]).toEqual([
          'FORBIDDEN',
          'Resource not accessible by integration',
        ]);
      }
      expect([thread.resolved, thread.resolvedBy]).toEqual([false, null]);
      // ... and a token with it needs nothing more.
      grant.permissions = { metadata: 'read', contents: 'write' };
      expect(await send(RESOLVE_THREAD_MUTATION)).toEqual({
        data: { resolveReviewThread: { thread: { id: thread.id, isResolved: true } } },
      });
      expect(await send(UNRESOLVE_THREAD_MUTATION)).toEqual({
        data: { unresolveReviewThread: { thread: { id: thread.id, isResolved: false } } },
      });
    });

    describe('a resolution the App may not make (Contents: write)', () => {
      const mutations = () =>
        fake.requests.filter((r) => r.path === '/api/graphql' && r.body.includes('mutation'));

      it('is refused with no request where the installation does not grant contents: write, the reopening too', async () => {
        const client = clientFor();
        await client.useRepository({ owner: 'acme', repo: 'nocontents' });
        fake.clearRequests();
        expect(await client.setThreadResolved('PRRT_kwDOanything', true)).toBe('refused');
        expect(await client.setThreadResolved('PRRT_kwDOanything', false)).toBe('refused');
        expect(fake.requests).toEqual([]);
        expect(client.requests).toBe(3); // the installation, its token and the repository
        // An id it would never send is still not an id.
        expect((await failure(client.setThreadResolved('two words', true))).reason).toBe(
          'invalid_input',
        );
      });

      it('is refused, with no exception, when GitHub answers FORBIDDEN: a token from before the grant, or a permission taken away', async () => {
        const { threadIds } = await pullWithThreads(1);
        const client = await reader();
        expect(client.mayResolveThreads).toBe(true);
        const [token] = [...fake.tokens.keys()].slice(-1);
        const thread = fake.reviewThreads.find((t) => t.id === threadIds[0])!;
        fake.tokens.get(token!)!.permissions = { ...BASE_PERMISSIONS };
        expect(await client.setThreadResolved(thread.id, true)).toBe('refused');
        expect(thread.resolved).toBe(false);
        fake.resolveThreadAs(thread.id, `${fake.slug}[bot]`);
        expect(await client.setThreadResolved(thread.id, false)).toBe('refused');
        expect(thread.resolved).toBe(true);
        // Each was asked of GitHub, which refused it.
        expect(mutations()).toHaveLength(2);
        // GitHub's own words, as the measured answer has them.
        answer({
          data: { resolveReviewThread: null },
          errors: [
            {
              type: 'FORBIDDEN',
              path: ['resolveReviewThread'],
              locations: [{ line: 1, column: 38 }],
              message: 'Resource not accessible by integration',
            },
          ],
        });
        expect(await client.setThreadResolved(thread.id, true)).toBe('refused');
      });

      it.each([
        ['FORBIDDEN', 'refused'],
        ['NOT_FOUND', 'not_found'],
        ['RATE_LIMITED', 'rate_limited'],
        ['MAX_NODE_LIMIT_EXCEEDED', 'bad_answer'],
      ] as const)(
        'takes only GraphQL’s FORBIDDEN for a refusal: %s comes to %s, for a resolution and a reopening',
        async (type, outcome) => {
          const client = await reader();
          for (const resolved of [true, false]) {
            const field = resolved ? 'resolveReviewThread' : 'unresolveReviewThread';
            answer({ data: { [field]: null }, errors: [{ type, path: [field], message: 'x' }] });
            const settled = await client.setThreadResolved(many.threadIds[0]!, resolved).then(
              (result) => result,
              (err: unknown) => {
                if (!(err instanceof ScmError)) throw err;
                // A refusal is read from the `auth` failure of HTTP 200: no other type is one.
                expect([err.kind, err.status]).not.toEqual(['auth', 200]);
                return err.kind;
              },
            );
            expect(settled, `${type}, resolved: ${String(resolved)}`).toBe(outcome);
          }
        },
      );

      it('lets every other refusal through: an HTTP 403, and the threads query’s FORBIDDEN', async () => {
        const client = await reader();
        answer({ message: 'Resource not accessible by integration' }, 403);
        const http = await failure(client.setThreadResolved(many.threadIds[0]!, true));
        expect([http.kind, http.reason, http.status]).toEqual(['auth', 'permission_missing', 403]);
        answer({ data: null, errors: [{ type: 'FORBIDDEN', message: 'x' }] });
        const query = await failure(client.reviewThreads(many.number, 1));
        expect([query.kind, query.reason, query.message]).toEqual([
          'auth',
          'permission_missing',
          GITHUB_TEXT.permission,
        ]);
      });
    });
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
      reviewCommentReply: 'pull_request_review_comment_reply',
      review: 'pull_request_review',
      reviewThreads: 'graphql_review_threads',
      resolveThread: 'graphql_resolve_thread',
      collaboratorPermission: 'collaborator_permission',
    }),
  )('%s parses', (key, file) => {
    expect(
      GITHUB_SHAPES[key as keyof typeof GITHUB_SHAPES].safeParse(githubShape(file)).success,
    ).toBe(true);
  });

  it('records a reply as a review comment that names the first comment of its thread', () => {
    const first = githubShape('pull_request_review_comment');
    const reply = githubShape('pull_request_review_comment_reply');
    expect(reply['in_reply_to_id']).toBe(first['id']);
    expect(reply['id']).not.toBe(first['id']);
    expect(reply['node_id']).not.toBe(first['node_id']);
    expect(reply['path']).toBe(first['path']);
  });
});

describe('githubRoute: a request as a fixed text for the logs', () => {
  it('names every value Qualor put in the path, and drops the query', () => {
    const sha = 'a'.repeat(40);
    const cases: [string, string, string][] = [
      ['GET', '/repos/jane/site', 'GET /repos/{owner}/{repo}'],
      [
        'GET',
        '/repos/jane/site/actions/organization-secrets?per_page=100&page=1',
        'GET /repos/{owner}/{repo}/actions/organization-secrets',
      ],
      [
        'GET',
        '/repos/jane/site/actions/secrets/public-key',
        'GET /repos/{owner}/{repo}/actions/secrets/public-key',
      ],
      [
        'PUT',
        '/repos/jane/site/actions/secrets/QUALOR_TOKEN',
        'PUT /repos/{owner}/{repo}/actions/secrets/{name}',
      ],
      [
        'GET',
        '/repos/jane/site/git/ref/heads/qualor/setup',
        'GET /repos/{owner}/{repo}/git/ref/heads/{branch}',
      ],
      ['POST', '/repos/jane/site/git/refs', 'POST /repos/{owner}/{repo}/git/refs'],
      ['GET', '/repos/jane/site/contents', 'GET /repos/{owner}/{repo}/contents'],
      [
        'PUT',
        '/repos/jane/site/contents/.github/workflows/qualor.yml',
        'PUT /repos/{owner}/{repo}/contents/{path}',
      ],
      [
        'GET',
        '/repos/jane/site/pulls?state=open&head=jane%3Aqualor%2Fsetup',
        'GET /repos/{owner}/{repo}/pulls',
      ],
      [
        'POST',
        '/repos/jane/site/pulls/12/comments/345/replies',
        'POST /repos/{owner}/{repo}/pulls/{id}/comments/{id}/replies',
      ],
      [
        'GET',
        `/repos/jane/site/commits/${sha}/check-runs?check_name=qualor%2Fsite`,
        'GET /repos/{owner}/{repo}/commits/{sha}/check-runs',
      ],
      [
        'GET',
        '/repos/jane/site/collaborators/bob/permission',
        'GET /repos/{owner}/{repo}/collaborators/{login}/permission',
      ],
      ['POST', '/app/installations/42/access_tokens', 'POST /app/installations/{id}/access_tokens'],
      ['GET', '/installation/repositories?per_page=100&page=2', 'GET /installation/repositories'],
    ];
    for (const [method, target, route] of cases) {
      expect(githubRoute(method as 'GET', target)).toBe(route);
    }
    expect(githubRoute('POST', new URL('https://ghe.example.com/api/graphql'))).toBe(
      'POST /api/graphql',
    );
  });
});

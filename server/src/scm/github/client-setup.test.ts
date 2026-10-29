import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitHub, type FakeGitHub } from '../../../test/fake-github';
import { ScmError } from '../provider';
import {
  credentialsId,
  InstallationTokenCache,
  MutationPacer,
  parseAppPrivateKey,
} from './app-auth';
import { GitHubClient, type GitHubClientOptions } from './client';

const REPO = { owner: 'acme', repo: 'api' };
const WITH_CI = {
  checks: 'write',
  contents: 'write',
  issues: 'read',
  metadata: 'read',
  pull_requests: 'write',
  secrets: 'write',
  workflows: 'write',
} as const;
const WITHOUT_CI = {
  checks: 'write',
  contents: 'write',
  issues: 'read',
  metadata: 'read',
  pull_requests: 'write',
} as const;

describe('GitHub client: files, pull requests and Actions secrets (onboarding)', () => {
  let fake: FakeGitHub;
  let clock = Date.now();
  const clientFor = (options: GitHubClientOptions = {}) => {
    const parsed = parseAppPrivateKey(fake.privateKeyPem);
    if (!('key' in parsed)) throw new Error('key');
    const appId = String(fake.appId);
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
  const requests = () => fake.requests.map((r) => `${r.method} ${r.path}`);
  const asked = () =>
    fake.requests
      .filter((r) => r.path.endsWith('/access_tokens'))
      .map((r) => JSON.parse(r.body) as { repositories?: string[]; permissions?: unknown });

  beforeAll(async () => {
    fake = await createFakeGitHub({ now: () => clock });
    // 777 grants CI setup (Workflows and Secrets write); 778 and 779 do not.
    fake.addRepository({
      id: 1,
      owner: 'acme',
      name: 'api',
      installationId: 777,
      permissions: WITH_CI,
      defaultBranch: 'trunk',
      language: 'TypeScript',
      languages: { TypeScript: 9000, HTML: 300, Shell: 12 },
    });
    fake.addRepository({ id: 2, owner: 'other', name: 'web', installationId: 778 });
    fake.addRepository({
      id: 3,
      owner: 'acme',
      name: 'noci',
      installationId: 779,
      permissions: WITHOUT_CI,
    });
  });
  afterAll(() => fake.close());
  beforeEach(() => fake.clearRequests());

  describe('useRepository with ciSetup', () => {
    it('asks for workflows and secrets (write) only where the installation grants them', async () => {
      const granted = clientFor();
      const repo = await granted.useRepository(REPO, { ciSetup: true });
      expect(repo).toMatchObject({ default_branch: 'trunk', language: 'TypeScript' });
      expect(repo.archived).toBe(false);
      expect(repo.private).toBe(true);
      const lacking = clientFor();
      await lacking.useRepository({ owner: 'acme', repo: 'noci' }, { ciSetup: true });
      expect(asked().map((a) => a.permissions)).toEqual([
        {
          checks: 'write',
          pull_requests: 'write',
          metadata: 'read',
          contents: 'write',
          workflows: 'write',
          secrets: 'write',
        },
        { checks: 'write', pull_requests: 'write', metadata: 'read', contents: 'write' },
      ]);
    });

    it('is the request of today without ciSetup', async () => {
      await clientFor().useRepository(REPO);
      expect(asked()).toEqual([
        {
          repositories: ['api'],
          permissions: {
            checks: 'write',
            pull_requests: 'write',
            metadata: 'read',
            contents: 'write',
          },
        },
      ]);
    });

    it('never mixes a token with CI scopes and one without', async () => {
      const tokens = new InstallationTokenCache(() => clock);
      await clientFor({ tokens }).useRepository(REPO);
      fake.clearRequests();
      await clientFor({ tokens }).useRepository(REPO, { ciSetup: true });
      expect(asked()).toHaveLength(1);
      fake.clearRequests();
      // Both are cached now, each under its own key.
      await clientFor({ tokens }).useRepository(REPO);
      await clientFor({ tokens }).useRepository(REPO, { ciSetup: true });
      expect(asked()).toHaveLength(0);
    });
  });

  describe('files and branches', () => {
    it('reads a file, a directory and a branch sha', async () => {
      fake.addFile(1, '.github/workflows/ci.yml', 'name: ci\n');
      fake.addFile(1, 'README.md', 'héllo\n');
      const client = clientFor();
      await client.useRepository(REPO, { ciSetup: true });
      fake.clearRequests();
      expect(await client.fileText('README.md')).toBe('héllo\n');
      expect(await client.fileText('missing.md')).toBeNull();
      expect(await client.fileText('README.md', 'no-such-branch')).toBeNull();
      expect(await client.listDirectory('.github/workflows')).toEqual(['ci.yml']);
      expect(await client.listDirectory('nothing/here')).toEqual([]);
      expect(await client.branchSha('trunk')).toBe(fake.branchSha(1, 'trunk'));
      expect(await client.branchSha('qualor/none')).toBeNull();
      expect(requests()).toEqual([
        'GET /repos/acme/api/contents/README.md',
        'GET /repos/acme/api/contents/missing.md',
        'GET /repos/acme/api/contents/README.md?ref=no-such-branch',
        'GET /repos/acme/api/contents/.github/workflows',
        'GET /repos/acme/api/contents/nothing/here',
        'GET /repos/acme/api/git/ref/heads/trunk',
        'GET /repos/acme/api/git/ref/heads/qualor/none',
      ]);
    });

    it('refuses a path that could leave the repository', async () => {
      const client = clientFor();
      await client.useRepository(REPO);
      fake.clearRequests();
      for (const bad of ['../x', 'a/../b', '/abs', 'a//b', 'a\\b', '']) {
        expect((await failure(client.fileText(bad))).reason).toBe('invalid_input');
      }
      expect(fake.requests).toHaveLength(0);
    });

    it('creates a branch from a sha and writes a file to it', async () => {
      const client = clientFor();
      await client.useRepository(REPO, { ciSetup: true });
      const from = await client.branchSha('trunk');
      fake.clearRequests();
      await client.createBranch('qualor/setup', from!);
      await client.putFile({
        path: '.github/workflows/qualor.yml',
        branch: 'qualor/setup',
        content: 'name: Qualor\n',
        message: 'Add Qualor',
      });
      expect(fake.fileText(1, '.github/workflows/qualor.yml', 'qualor/setup')).toBe(
        'name: Qualor\n',
      );
      expect(fake.fileText(1, '.github/workflows/qualor.yml')).toBeNull();
      const sent = fake.requests.map((r) => ({ call: `${r.method} ${r.path}`, body: r.body }));
      expect(sent[0]).toEqual({
        call: 'POST /repos/acme/api/git/refs',
        body: JSON.stringify({ ref: 'refs/heads/qualor/setup', sha: from }),
      });
      expect(sent[1]?.call).toBe('PUT /repos/acme/api/contents/.github/workflows/qualor.yml');
      expect(JSON.parse(sent[1]!.body)).toEqual({
        message: 'Add Qualor',
        content: Buffer.from('name: Qualor\n').toString('base64'),
        branch: 'qualor/setup',
      });
      // A file that exists is replaced only with its sha.
      const refused = await failure(
        client.putFile({
          path: '.github/workflows/qualor.yml',
          branch: 'qualor/setup',
          content: 'name: Changed\n',
          message: 'Change',
        }),
      );
      expect(refused.status).toBe(422);
    });

    it('sends the sha of the file it replaces', async () => {
      fake.addFile(1, 'docs/a.md', 'one');
      const client = clientFor();
      await client.useRepository(REPO, { ciSetup: true });
      fake.clearRequests();
      const found = await client.fileSha('docs/a.md');
      expect(found).toMatch(/^[0-9a-f]{40}$/);
      expect(await client.fileSha('docs/none.md')).toBeNull();
      await client.putFile({
        path: 'docs/a.md',
        branch: 'trunk',
        content: 'two',
        message: 'Edit',
        sha: found!,
      });
      expect(fake.fileText(1, 'docs/a.md')).toBe('two');
      expect(JSON.parse(fake.requests.at(-1)!.body)).toMatchObject({ sha: found });
    });

    it('cannot write a workflow file with a token that lacks Workflows', async () => {
      const client = clientFor();
      await client.useRepository({ owner: 'acme', repo: 'noci' }, { ciSetup: true });
      const from = await client.branchSha('main');
      await client.createBranch('qualor/setup', from!);
      const refused = await failure(
        client.putFile({
          path: '.github/workflows/qualor.yml',
          branch: 'qualor/setup',
          content: 'x',
          message: 'm',
        }),
      );
      expect(refused).toMatchObject({ kind: 'auth', status: 403 });
    });
  });

  describe('pull requests', () => {
    it('opens a pull request and finds it by its head branch', async () => {
      const client = clientFor();
      await client.useRepository(REPO, { ciSetup: true });
      const from = (await client.branchSha('trunk'))!;
      await client.createBranch('qualor/pr', from);
      expect(await client.findOpenPullRequest('qualor/pr')).toBeNull();
      fake.clearRequests();
      const pr = await client.openPullRequest({
        head: 'qualor/pr',
        base: 'trunk',
        title: 'Add Qualor',
        body: 'Runs the analysis.',
      });
      expect(pr.url).toMatch(/\/acme\/api\/pull\/\d+$/);
      expect(requests()).toEqual(['POST /repos/acme/api/pulls']);
      expect(JSON.parse(fake.requests[0]!.body)).toEqual({
        head: 'qualor/pr',
        base: 'trunk',
        title: 'Add Qualor',
        body: 'Runs the analysis.',
      });
      fake.clearRequests();
      expect(await client.findOpenPullRequest('qualor/pr')).toEqual(pr);
      expect(requests()).toEqual([
        `GET /repos/acme/api/pulls?state=open&head=${encodeURIComponent('acme:qualor/pr')}&per_page=1`,
      ]);
      const again = await failure(
        client.openPullRequest({ head: 'qualor/pr', base: 'trunk', title: 't', body: '' }),
      );
      expect(again.status).toBe(422);
    });
  });

  describe('Actions secrets', () => {
    it('stores a secret sealed for the repository and tells whether one exists', async () => {
      const client = clientFor();
      await client.useRepository(REPO, { ciSetup: true });
      fake.clearRequests();
      expect(await client.hasActionsSecret('QUALOR_TOKEN')).toBe(false);
      await client.putActionsSecret('QUALOR_TOKEN', 'qlr_abc123');
      expect(await client.hasActionsSecret('QUALOR_TOKEN')).toBe(true);
      // The fake opened the box with its own key: it is the sealed box GitHub takes.
      expect(fake.actionsSecrets.get('1|QUALOR_TOKEN')).toBe('qlr_abc123');
      expect(requests()).toEqual([
        'GET /repos/acme/api/actions/secrets/QUALOR_TOKEN',
        'GET /repos/acme/api/actions/secrets/public-key',
        'PUT /repos/acme/api/actions/secrets/QUALOR_TOKEN',
        'GET /repos/acme/api/actions/secrets/QUALOR_TOKEN',
      ]);
      const put = JSON.parse(fake.requests[2]!.body) as Record<string, string>;
      expect(Object.keys(put).sort()).toEqual(['encrypted_value', 'key_id']);
      expect(put['key_id']).toBe(fake.actionsKey.keyId);
      expect(fake.requests[2]!.body).not.toContain('qlr_abc123');
      // Replacing the value is allowed (HTTP 204).
      await client.putActionsSecret('QUALOR_TOKEN', 'qlr_new');
      expect(fake.actionsSecrets.get('1|QUALOR_TOKEN')).toBe('qlr_new');
    });

    it('is refused without Secrets, and never names the value in the error', async () => {
      const client = clientFor();
      await client.useRepository({ owner: 'other', repo: 'web' }, { ciSetup: true });
      const err = await failure(client.putActionsSecret('QUALOR_TOKEN', 'qlr_topsecret'));
      expect(err.kind).toBe('auth');
      expect(JSON.stringify(err) + err.message).not.toContain('qlr_topsecret');
    });

    it('refuses a secret name that is not an Actions secret name', async () => {
      const client = clientFor();
      await client.useRepository(REPO, { ciSetup: true });
      for (const bad of ['', '1ABC', 'a/b', 'A-B', 'a'.repeat(101)]) {
        expect((await failure(client.hasActionsSecret(bad))).reason).toBe('invalid_input');
      }
    });
  });

  it('lists the languages of the repository, the biggest first', async () => {
    const client = clientFor();
    await client.useRepository(REPO);
    expect(await client.languages()).toEqual(['TypeScript', 'HTML', 'Shell']);
  });

  it('paces every mutation through the MutationPacer', async () => {
    const waits: string[] = [];
    class Spy extends MutationPacer {
      override async wait(key: string): Promise<void> {
        waits.push(key);
        await super.wait(key);
      }
    }
    const client = clientFor({
      pacer: new Spy(
        () => clock,
        async (ms) => {
          clock += ms;
        },
      ),
    });
    await client.useRepository(REPO, { ciSetup: true });
    waits.length = 0;
    await client.createBranch('qualor/paced', (await client.branchSha('trunk'))!);
    await client.putFile({ path: 'p.txt', branch: 'qualor/paced', content: 'x', message: 'm' });
    await client.openPullRequest({ head: 'qualor/paced', base: 'trunk', title: 't', body: '' });
    await client.putActionsSecret('PACED', 'v');
    expect(waits).toHaveLength(4);
    expect(new Set(waits)).toEqual(new Set([`${fake.url}|777`]));
  });
});

import { afterEach, describe, expect, it } from 'vitest';
import { createFakeGitHub, type FakeGitHub } from '../../../test/fake-github';
import { encryptionKey } from '../../crypto/secrets';
import type { ScmConnectionRow, ScmDeps } from '../connections';
import { ScmError } from '../provider';
import { createScmRuntime } from '../runtime';
import { parseAppPrivateKey } from './app-auth';
import { encryptPrivateKey } from './credentials';
import { listInstallationRepositories } from './installations';

const SECRET_KEY = 'k'.repeat(32);

describe('listInstallationRepositories', () => {
  let fake: FakeGitHub | null = null;
  afterEach(async () => {
    await fake?.close();
    fake = null;
  });

  async function setup() {
    fake = await createFakeGitHub();
    const parsed = parseAppPrivateKey(fake.privateKeyPem);
    if (!('pkcs8' in parsed)) throw new Error('key');
    const deps: ScmDeps = {
      secretKey: SECRET_KEY,
      internalHosts: new Set([new URL(fake.url).host]),
      githubClientOptions: { timeoutMs: 5_000 },
    };
    const row = {
      id: 'c1',
      organizationId: 'o1',
      provider: 'github',
      baseUrl: fake.url,
      appId: String(fake.appId),
      tokenEnc: encryptPrivateKey(encryptionKey(deps.secretKey), parsed.pkcs8),
      webhookSecretEnc: null,
      createdAt: new Date(),
    } as unknown as ScmConnectionRow;
    return { fake, deps, row, runtime: createScmRuntime() };
  }

  it('merges the repositories of two installations, 100 to a page', async () => {
    const { fake: f, deps, row, runtime } = await setup();
    // Installation 1 (acme) holds 150 repositories and grants CI setup; installation 2 holds 5.
    for (let i = 1; i <= 150; i++) {
      f.addRepository({
        id: i,
        owner: 'acme',
        name: `r${String(i).padStart(3, '0')}`,
        installationId: 1,
        permissions: { metadata: 'read', workflows: 'write', secrets: 'write' },
        ...(i === 1 ? { language: 'Go', defaultBranch: 'trunk', archived: true } : {}),
      });
    }
    for (let i = 1; i <= 5; i++) {
      f.addRepository({ id: 1000 + i, owner: 'beta', name: `b${i}`, installationId: 2 });
    }
    f.clearRequests();
    const first = await listInstallationRepositories(row, deps, runtime, { page: 1, perPage: 100 });
    expect(first.repositories).toHaveLength(100);
    expect(first.hasMore).toBe(true);
    expect(first.repositories[0]).toEqual({
      ref: 'acme/r001',
      defaultBranch: 'trunk',
      language: 'Go',
      archived: true,
    });
    expect(first.repositories[1]).toEqual({
      ref: 'acme/r002',
      defaultBranch: 'main',
      language: null,
      archived: false,
    });
    expect(first.installations).toEqual([
      { installationId: 1, account: 'acme', workflowsWrite: true, secretsWrite: true },
      { installationId: 2, account: 'beta', workflowsWrite: false, secretsWrite: false },
    ]);
    // The App's JWT lists installations; each installation's token asks for Metadata (read) only.
    expect(f.requests[0]).toMatchObject({ method: 'GET', auth: 'jwt' });
    expect(f.requests[0]?.path).toBe('/app/installations?per_page=100&page=1');
    const tokenRequests = f.requests.filter((r) => r.path.endsWith('/access_tokens'));
    expect(tokenRequests.map((r) => JSON.parse(r.body) as unknown)).toEqual([
      { permissions: { metadata: 'read' } },
    ]);
    const second = await listInstallationRepositories(row, deps, runtime, {
      page: 2,
      perPage: 100,
    });
    expect(second.hasMore).toBe(false);
    expect(second.repositories.map((r) => r.ref)).toEqual([
      ...Array.from({ length: 50 }, (_, i) => `acme/r${String(101 + i).padStart(3, '0')}`),
      'beta/b1',
      'beta/b2',
      'beta/b3',
      'beta/b4',
      'beta/b5',
    ]);
    const third = await listInstallationRepositories(row, deps, runtime, { page: 3, perPage: 100 });
    expect(third).toMatchObject({ repositories: [], hasMore: false });
  });

  it('pages the installations too', async () => {
    const { fake: f, deps, row, runtime } = await setup();
    for (let i = 1; i <= 101; i++) {
      f.addRepository({ id: i, owner: `o${i}`, name: 'x', installationId: i });
    }
    const page = await listInstallationRepositories(row, deps, runtime, { page: 2, perPage: 100 });
    expect(page.installations).toHaveLength(101);
    expect(page.repositories.map((r) => r.ref)).toEqual(['o101/x']);
    expect(page.hasMore).toBe(false);
    expect(f.requests.filter((r) => r.path.startsWith('/app/installations?'))).toHaveLength(2);
  });

  it('answers an App without installations with nothing', async () => {
    const { deps, row, runtime } = await setup();
    expect(
      await listInstallationRepositories(row, deps, runtime, { page: 1, perPage: 100 }),
    ).toEqual({
      repositories: [],
      installations: [],
      hasMore: false,
    });
  });

  it('maps a refused App to a ScmError', async () => {
    const { fake: f, deps, row, runtime } = await setup();
    f.inject('GET', /^\/app\/installations$/, { status: 401, body: { message: 'Bad' } });
    const err = await listInstallationRepositories(row, deps, runtime, {
      page: 1,
      perPage: 100,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ScmError);
    expect(err).toMatchObject({ kind: 'auth', status: 401 });
  });
});

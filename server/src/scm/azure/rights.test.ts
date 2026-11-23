import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AZURE_TEST_PRINCIPAL, identitiesOf, patOf } from '../../../test/azure';
import { createFakeAzureDevOps, type FakeAzureDevOps } from '../../../test/fake-azure-devops';
import { trustTestCa } from '../../../test/tls';
import { MAX_AUTHORS_LOOKED_UP } from '../rights-limits';
import { AzureDevOpsClient } from './client';
import { azureMayTriage } from './rights';

const MARKER = 'azure-answer-marker-91c2';
const ACL = /[/]_apis[/]accesscontrollists[/]/;

let fake: FakeAzureDevOps;
let untrust: () => void;

beforeAll(async () => {
  untrust = trustTestCa();
  fake = await createFakeAzureDevOps({
    deployment: 'services',
    principal: AZURE_TEST_PRINCIPAL,
    repositories: [{ name: 'api', projectName: 'Payments' }],
  });
});

afterAll(async () => {
  await fake.close();
  untrust();
});

beforeEach(() => {
  fake.clearRequests();
  fake.identityAdded = true;
});

function clientOf(): AzureDevOpsClient {
  const identities = identitiesOf(fake);
  return new AzureDevOpsClient(
    {
      baseUrl: fake.url,
      credential: patOf(fake),
      allowInternalHosts: true,
      ...(identities ? { identities } : {}),
    },
    { timeoutMs: 2_000 },
  );
}

const repositoryId = () => fake.repositories[0]!.id;
const logger = () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() });

describe('azureMayTriage', () => {
  it('is true for an owner', async () => {
    const user = fake.addUser({ role: 'owner' });
    expect(await azureMayTriage(clientOf(), repositoryId(), [user.id])).toBe(true);
  });

  it('is true for a contributor', async () => {
    const user = fake.addUser({ role: 'contributor' });
    expect(await azureMayTriage(clientOf(), repositoryId(), [user.id])).toBe(true);
  });

  it('is false for a reader', async () => {
    const user = fake.addUser({ role: 'reader' });
    expect(await azureMayTriage(clientOf(), repositoryId(), [user.id])).toBe(false);
  });

  it('is false for an identity the organisation does not know', async () => {
    const unknown = '11111111-2222-4333-8444-555555555555';
    expect(await azureMayTriage(clientOf(), repositoryId(), [unknown])).toBe(false);
  });

  it('is false when one of several authors is a reader, true when all may', async () => {
    const a = fake.addUser({ role: 'contributor' });
    const b = fake.addUser({ role: 'reader' });
    const c = fake.addUser({ role: 'owner' });
    expect(await azureMayTriage(clientOf(), repositoryId(), [a.id, b.id])).toBe(false);
    expect(await azureMayTriage(clientOf(), repositoryId(), [a.id, c.id, a.id])).toBe(true);
  });

  it('asks the repository once, and each distinct author once', async () => {
    const a = fake.addUser({ role: 'contributor' });
    const b = fake.addUser({ role: 'owner' });
    fake.clearRequests();
    await azureMayTriage(clientOf(), repositoryId(), [a.id, b.id, a.id]);
    const paths = fake.requests.map((r) => r.path);
    expect(paths.filter((p) => /\/_apis\/git\/repositories\/[^/]+$/.test(p))).toHaveLength(1);
    expect(paths.filter((p) => p.endsWith('/_apis/identities'))).toHaveLength(2);
    expect(paths.filter((p) => p.includes('/_apis/accesscontrollists/'))).toHaveLength(2);
  });

  it('is false for no authors, and for more than the limit without a request', async () => {
    expect(await azureMayTriage(clientOf(), repositoryId(), [])).toBe(false);
    const ids = Array.from({ length: MAX_AUTHORS_LOOKED_UP + 1 }, () =>
      fake.addUser({ role: 'owner' }),
    ).map((u) => u.id);
    fake.clearRequests();
    expect(await azureMayTriage(clientOf(), repositoryId(), ids)).toBe(false);
    expect(fake.requests).toHaveLength(0);
  });

  it('counts a GUID that differs only in case once', async () => {
    const user = fake.addUser({ role: 'contributor' });
    fake.clearRequests();
    const ok = await azureMayTriage(clientOf(), repositoryId(), [user.id, user.id.toUpperCase()]);
    expect(ok).toBe(true);
    expect(fake.requests.filter((r) => r.path.endsWith('/_apis/identities'))).toHaveLength(1);
  });

  it('is false for an unknown identity and asks no ACL after it', async () => {
    fake.clearRequests();
    const unknown = '11111111-2222-4333-8444-555555555555';
    expect(await azureMayTriage(clientOf(), repositoryId(), [unknown])).toBe(false);
    expect(fake.requests.filter((r) => r.path.includes('/_apis/accesscontrollists/'))).toHaveLength(
      0,
    );
  });

  it('is false on a 403 from the ACL, with one warn that holds no text of the answer', async () => {
    const user = fake.addUser({ role: 'owner' });
    // The client never retries: the one injected answer is the one ACL request of this call.
    fake.inject('GET', ACL, {
      status: 403,
      body: { message: MARKER },
    });
    const log = logger();
    expect(await azureMayTriage(clientOf(), repositoryId(), [user.id], log)).toBe(false);
    expect(log.warn).toHaveBeenCalledTimes(1);
    const line = JSON.stringify(log.warn.mock.calls[0]);
    expect(line).toContain('kind');
    expect(line).not.toContain(MARKER);
  });

  it('rejects, so the job retries, on a 503 (transient)', async () => {
    const user = fake.addUser({ role: 'owner' });
    fake.inject('GET', ACL, { status: 503 });
    await expect(azureMayTriage(clientOf(), repositoryId(), [user.id])).rejects.toMatchObject({
      kind: 'transient',
    });
  });

  it('rejects on a timeout', async () => {
    const user = fake.addUser({ role: 'owner' });
    fake.inject('GET', ACL, { status: 200, hang: true });
    const client = new AzureDevOpsClient(
      {
        baseUrl: fake.url,
        credential: patOf(fake),
        allowInternalHosts: true,
        identities: identitiesOf(fake)!,
      },
      { timeoutMs: 300 },
    );
    await expect(azureMayTriage(client, repositoryId(), [user.id])).rejects.toMatchObject({
      kind: 'transient',
      reason: 'timeout',
    });
  });
});

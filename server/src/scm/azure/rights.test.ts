import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AZURE_TEST_PRINCIPAL, identitiesOf, patOf } from '../../../test/azure';
import { createFakeAzureDevOps, type FakeAzureDevOps } from '../../../test/fake-azure-devops';
import { trustTestCa } from '../../../test/tls';
import { MAX_AUTHORS_LOOKED_UP } from '../../review/reply-sides';
import { AzureDevOpsClient } from './client';
import { azureMayTriage } from './rights';

const MARKER = 'azure-answer-marker-91c2';

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

  it('is false on a 500 from the ACL, with one warn that holds no text of the answer', async () => {
    const user = fake.addUser({ role: 'owner' });
    fake.inject(
      'GET',
      /\/_apis\/accesscontrollists\//,
      ...Array(4).fill({
        status: 500,
        body: { message: MARKER },
      }),
    );
    const log = logger();
    expect(await azureMayTriage(clientOf(), repositoryId(), [user.id], log)).toBe(false);
    expect(log.warn).toHaveBeenCalledTimes(1);
    const line = JSON.stringify(log.warn.mock.calls[0]);
    expect(line).toContain('kind');
    expect(line).not.toContain(MARKER);
  });
});

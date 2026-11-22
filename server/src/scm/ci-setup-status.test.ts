import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { recordingListener, type RecordingListener } from '../../test/azure-pending';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { createCiSetupStatus, readCiSetupStatus } from './ci-setup-status';
import { SCM_TOKEN_AAD, type ScmConnectionRow, type ScmDeps } from './connections';
import { parseInternalHosts } from './url';

const SECRET_KEY = 'ci-setup-status-test-key-of-at-least-32-characters';
const PUBLIC_URL = 'https://qualor.example.com';

describe('the CI-setup status of an Azure DevOps connection: not available yet (Azure sub-plan 2, Task 2)', () => {
  let listener: RecordingListener;
  let deps: ScmDeps;
  let row: ScmConnectionRow;

  beforeAll(async () => {
    listener = await recordingListener();
    // The listener's host is allowed: a request the stub made would reach it.
    deps = { secretKey: SECRET_KEY, internalHosts: parseInternalHosts(listener.host) };
    row = {
      id: randomUUID(),
      organizationId: randomUUID(),
      provider: 'azure',
      baseUrl: `${listener.url}/DefaultCollection`,
      tokenEnc: encryptSecret(encryptionKey(SECRET_KEY), 'azure-pat-test', SCM_TOKEN_AAD),
      appId: null,
      webhookSecretEnc: null,
      // Allowed in the row (the API cannot set it for Azure yet), so the Azure arm itself answers.
      ciSetupAllowed: true,
      fixMrsAllowed: false,
      azureAuth: 'pat',
      azureTenantId: null,
      azureClientId: null,
      createdAt: new Date(),
    };
  });
  afterAll(() => listener.close());

  it('is not allowed, with or without a public URL, and nothing is asked', async () => {
    const warned: string[] = [];
    const warn = (message: string) => warned.push(message);
    const notAllowed = { available: false, reason: 'not_allowed', missing: [] };
    for (const publicUrl of [PUBLIC_URL, null]) {
      expect(await createCiSetupStatus({ deps, publicUrl, warn })(row)).toEqual(notAllowed);
      expect(await readCiSetupStatus(row, deps, publicUrl)).toEqual(notAllowed);
    }
    expect(warned).toEqual([]);
    expect(listener.requests).toEqual([]);
  });
});

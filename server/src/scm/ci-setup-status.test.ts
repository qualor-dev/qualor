import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { recordingListener, type RecordingListener } from '../../test/azure-pending';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { createCiSetupStatus, readCiSetupStatus } from './ci-setup-status';
import { SCM_TOKEN_AAD, type ScmConnectionRow, type ScmDeps } from './connections';
import { parseInternalHosts } from './url';

const SECRET_KEY = 'ci-setup-status-test-key-of-at-least-32-characters';
const PUBLIC_URL = 'https://qualor.example.com';

describe('the CI-setup status of an Azure DevOps connection (Azure sub-plan 7)', () => {
  let listener: RecordingListener;
  let deps: ScmDeps;
  let row: ScmConnectionRow;

  beforeAll(async () => {
    listener = await recordingListener();
    // The listener's host is allowed: a request the stub made would reach it.
    deps = {
      secretKey: SECRET_KEY,
      internalHosts: parseInternalHosts(listener.host),
      azureTokenOrigin: null,
      azureTestOrigin: null,
    };
    row = {
      id: randomUUID(),
      organizationId: randomUUID(),
      provider: 'azure',
      baseUrl: `${listener.url}/DefaultCollection`,
      tokenEnc: encryptSecret(encryptionKey(SECRET_KEY), 'azure-pat-test', SCM_TOKEN_AAD),
      appId: null,
      webhookSecretEnc: null,
      ciSetupAllowed: true,
      fixMrsAllowed: false,
      azureAuth: 'pat',
      azureTenantId: null,
      azureClientId: null,
      problem: null,
      createdAt: new Date(),
    };
  });
  afterAll(() => listener.close());

  it('is available with the setting and a public URL, and nothing is asked', async () => {
    const warned: string[] = [];
    const warn = (message: string) => warned.push(message);
    const available = { available: true, reason: null, missing: [] };
    expect(await createCiSetupStatus({ deps, publicUrl: PUBLIC_URL, warn })(row)).toEqual(
      available,
    );
    expect(await readCiSetupStatus(row, deps, PUBLIC_URL)).toEqual(available);
    expect(warned).toEqual([]);
    expect(listener.requests).toEqual([]);
  });

  it('is not available without a public URL, or without the setting', async () => {
    const warn = () => undefined;
    const noUrl = { available: false, reason: 'no_public_url', missing: [] };
    expect(await createCiSetupStatus({ deps, publicUrl: null, warn })(row)).toEqual(noUrl);
    expect(await readCiSetupStatus(row, deps, null)).toEqual(noUrl);
    // The missing URL is told first, as for GitLab.
    const off = { ...row, ciSetupAllowed: false };
    expect(await createCiSetupStatus({ deps, publicUrl: null, warn })(off)).toEqual(noUrl);
    const notAllowed = { available: false, reason: 'not_allowed', missing: [] };
    expect(await createCiSetupStatus({ deps, publicUrl: PUBLIC_URL, warn })(off)).toEqual(
      notAllowed,
    );
    expect(await readCiSetupStatus(off, deps, PUBLIC_URL)).toEqual(notAllowed);
    expect(listener.requests).toEqual([]);
  });
});

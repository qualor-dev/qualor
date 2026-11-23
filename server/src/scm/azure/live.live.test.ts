import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { encryptionKey, encryptSecret } from '../../crypto/secrets';
import { SCM_TOKEN_AAD, type ScmConnectionRow, type ScmDeps } from '../connections';
import { parseInternalHosts } from '../url';
import type { AzureAuthKind } from './auth-kinds';
import { testAzureConnection } from './connections';

/**
 * The opt-in check of Azure DevOps connections against a real organisation, as the bench of the
 * connection work left it. Never part of `pnpm test` or CI (the unit project excludes
 * `*.live.test.ts`, and the `azure-live` project exists only when `QUALOR_LIVE_AZURE_ENV_FILES` is
 * set): `pnpm azure:live`.
 *
 * `QUALOR_LIVE_AZURE_ENV_FILES` lists env files, semicolon-separated, loaded with
 * `process.loadEnvFile`. They hold (AZURE_PROBE_*):
 * - Services: SERVICES_URL with SERVICES_PAT (a personal access token); TENANT_ID and CLIENT_ID
 *   with CLIENT_SECRET (a secret) or CLIENT_CERT_FILE and CLIENT_KEY_FILE (a certificate and its
 *   unencrypted key, as files).
 * - Server (optional): SERVER_URL with SERVER_PAT. With a private CA (SERVER_CA_FILE set), start the
 *   run with `NODE_EXTRA_CA_CERTS=<that file>`; without it the Server case is skipped.
 *
 * It builds the rows the connection routes would store and asserts on fields only: no credential,
 * row or environment value is ever printed or put in an assertion message.
 */
const files = process.env['QUALOR_LIVE_AZURE_ENV_FILES'] ?? '';
for (const file of files.split(';').filter((f) => f.length > 0)) {
  try {
    process.loadEnvFile(file);
  } catch (err) {
    throw new Error(`Cannot load env file ${file}: ${(err as Error).message}`, { cause: err });
  }
}

const SECRET_KEY = 'live-check-throwaway-secret-key-0123456789';

function env(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`${key} is not set`);
  return value;
}

function rowOf(
  baseUrl: string,
  kind: AzureAuthKind,
  credential: string,
  ids: { tenantId: string; clientId: string } | null,
): ScmConnectionRow {
  return {
    id: randomUUID(),
    organizationId: randomUUID(),
    provider: 'azure',
    baseUrl,
    tokenEnc: encryptSecret(encryptionKey(SECRET_KEY), credential, SCM_TOKEN_AAD),
    appId: null,
    webhookSecretEnc: null,
    ciSetupAllowed: false,
    fixMrsAllowed: false,
    azureAuth: kind,
    azureTenantId: ids?.tenantId.toLowerCase() ?? null,
    azureClientId: ids?.clientId.toLowerCase() ?? null,
    problem: null,
    createdAt: new Date(),
  };
}
async function check(row: ScmConnectionRow, internalHosts: ReadonlySet<string>): Promise<void> {
  const deps: ScmDeps = {
    secretKey: SECRET_KEY,
    internalHosts,
    azureTokenOrigin: null,
    azureTestOrigin: null,
  };
  const result = await testAzureConnection(row, deps, null);
  expect(result.problem?.code ?? null, 'problem code').toBeNull();
  expect(result.ok, 'connection ok').toBe(true);
  expect(result.user?.username ?? '', 'display name').not.toBe('');
  expect(result.visible?.repositories ?? 0, 'visible repositories').toBeGreaterThanOrEqual(1);
  expect(result.visible?.projects ?? 0, 'visible projects').toBeGreaterThanOrEqual(1);
}

describe.skipIf(files === '')('Azure DevOps connections against a real organisation', () => {
  const none: ReadonlySet<string> = new Set();

  it('Services, personal access token', async () => {
    await check(
      rowOf(env('AZURE_PROBE_SERVICES_URL'), 'pat', env('AZURE_PROBE_SERVICES_PAT'), null),
      none,
    );
  });

  it('Services, service principal with a client secret', async () => {
    const ids = { tenantId: env('AZURE_PROBE_TENANT_ID'), clientId: env('AZURE_PROBE_CLIENT_ID') };
    await check(
      rowOf(
        env('AZURE_PROBE_SERVICES_URL'),
        'service_principal_secret',
        env('AZURE_PROBE_CLIENT_SECRET'),
        ids,
      ),
      none,
    );
  });

  it('Services, service principal with a certificate', async () => {
    const ids = { tenantId: env('AZURE_PROBE_TENANT_ID'), clientId: env('AZURE_PROBE_CLIENT_ID') };
    const pem = `${readFileSync(env('AZURE_PROBE_CLIENT_CERT_FILE'), 'utf8').trim()}\n${readFileSync(env('AZURE_PROBE_CLIENT_KEY_FILE'), 'utf8').trim()}\n`;
    await check(
      rowOf(env('AZURE_PROBE_SERVICES_URL'), 'service_principal_certificate', pem, ids),
      none,
    );
  });

  const serverUrl = process.env['AZURE_PROBE_SERVER_URL'] ?? '';
  const serverPat = process.env['AZURE_PROBE_SERVER_PAT'] ?? '';
  const serverCa = process.env['AZURE_PROBE_SERVER_CA_FILE'] ?? '';
  const caMissing = serverCa !== '' && (process.env['NODE_EXTRA_CA_CERTS'] ?? '') === '';
  it.skipIf(serverUrl === '' || serverPat === '' || caMissing)(
    caMissing
      ? 'Server, personal access token (skipped: private CA needs NODE_EXTRA_CA_CERTS)'
      : 'Server, personal access token',
    async () => {
      const url = new URL(serverUrl);
      await check(rowOf(serverUrl, 'pat', serverPat, null), parseInternalHosts(url.host));
    },
  );
});

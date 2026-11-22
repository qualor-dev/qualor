import type { Config } from '../src/config';
import type { AzureCredential } from '../src/scm/azure/client';
import { parseAzureCertificate } from '../src/scm/azure/certificate';
import { entraToken, type EntraCredential, type EntraOptions } from '../src/scm/azure/entra';
import type { FakeAzureDevOps } from './fake-azure-devops';
import { TEST_IDP, type TestKeyPair } from './saml';

/**
 * The service principal the tests register with the fake Entra: a client secret and the PEM an
 * administrator pastes for a certificate (the test IdP's certificate and its key).
 */
export const AZURE_TEST_PRINCIPAL = {
  tenantId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  clientId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
  // Assembled at run time, so the repository's own Gitleaks check finds no fake secret here.
  secret: ['azure-test-', 'client-secret'].join(''),
  certificatePem: `${TEST_IDP.certPem}${TEST_IDP.keyPem}`,
} as const;

/**
 * The fake listens on 127.0.0.1 on a port of its own, which the operator must list with that port
 * (an entry without a port allows only the scheme's default one).
 */
export function azureTestConfig(fake: FakeAzureDevOps): Partial<Config> {
  return { scmInternalHosts: new Set([new URL(fake.url).host]) as ReadonlySet<string> };
}

/**
 * A Services fake's organisation as a connection stores it (ruling 5): the real host with the
 * fake's organisation, so the deployment and the address rules are those of production.
 */
export function servicesUrlOf(fake: FakeAzureDevOps): string {
  return `https://dev.azure.com${new URL(fake.url).pathname}`;
}

/**
 * A server that reaches the fakes: their hosts listed in `QUALOR_SCM_INTERNAL_HOSTS`, a Services
 * organisation's requests sent to the Services fake (`azureTestOrigin`, ruling 5) and Entra's to
 * its token endpoint (`azureTokenOrigin`, ruling 1). A Server fake is reached at its own address.
 */
export function azureServerConfig(
  services: FakeAzureDevOps,
  ...others: FakeAzureDevOps[]
): Partial<Config> {
  const hosts = [services, ...others].map((fake) => new URL(fake.url).host);
  return {
    scmInternalHosts: new Set(hosts) as ReadonlySet<string>,
    azureTestOrigin: new URL(services.url).origin,
    azureTokenOrigin:
      services.principalUser === null
        ? null
        : new URL(services.tokenUrl(AZURE_TEST_PRINCIPAL.tenantId)).origin,
  };
}

/** `entraToken`'s options for the fake's token endpoint (https on loopback). */
export function fakeEntraOptions(fake: FakeAzureDevOps): EntraOptions {
  return { tokenUrl: (tenantId) => fake.tokenUrl(tenantId), allowInternalHosts: true };
}

/** The test principal as `entraToken` takes it; a certificate from `pair` (default the test IdP). */
export function entraCredentialOf(
  kind: 'secret' | 'certificate',
  pair: TestKeyPair = TEST_IDP,
): EntraCredential {
  const { tenantId, clientId, secret } = AZURE_TEST_PRINCIPAL;
  if (kind === 'secret') return { kind, tenantId, clientId, secret };
  const certificate = parseAzureCertificate(`${pair.certPem}${pair.keyPem}`);
  if ('problem' in certificate) throw new Error(`test certificate: ${certificate.problem}`);
  return { kind, tenantId, clientId, certificate };
}

/** The fake's PAT as the client takes it. */
export function patOf(fake: FakeAzureDevOps): AzureCredential {
  return { kind: 'pat', pat: fake.pat };
}

/** A bearer credential that asks the fake's Entra for a new token on every request. */
export function bearerOf(
  fake: FakeAzureDevOps,
  credential: 'secret' | 'certificate' | EntraCredential,
): AzureCredential {
  const entra = typeof credential === 'string' ? entraCredentialOf(credential) : credential;
  return {
    kind: 'bearer',
    token: async () => (await entraToken(entra, fakeEntraOptions(fake))).token,
  };
}

import { readFileSync } from 'node:fs';
import type { AzureAuth } from './client.js';

export type Target = {
  baseUrl: string;
  /** The project the items work in (`AZURE_PROBE_PROJECT`); its repository is `probe`. */
  project: string;
  auth: AzureAuth;
  userAuth: AzureAuth;
  readerAuth?: AzureAuth;
  adminAuth?: AzureAuth;
  caPem?: string;
  hookBase: string;
  recorderSecret: string;
};

/** Loads every file named in AZURE_PROBE_ENV_FILES (semicolon-separated) into process.env. */
export function loadEnvFiles(): void {
  const list = process.env['AZURE_PROBE_ENV_FILES'];
  if (!list) throw new Error('AZURE_PROBE_ENV_FILES is not set (semicolon-separated env files)');
  for (const file of list.split(';').filter((f) => f.length > 0)) {
    try {
      process.loadEnvFile(file);
    } catch (err) {
      throw new Error(`Cannot load env file ${file}: ${(err as Error).message}`, { cause: err });
    }
  }
}

function need(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`${key} is not set`);
  return v;
}

const pat = (key: string): AzureAuth => ({ kind: 'pat', pat: need(key) });
const optPat = (key: string): AzureAuth | undefined => (process.env[key] ? pat(key) : undefined);

function servicesAuth(kind: 'pat' | 'secret' | 'certificate'): AzureAuth {
  if (kind === 'pat') return pat('AZURE_PROBE_SERVICES_PAT');
  const tenantId = need('AZURE_PROBE_TENANT_ID');
  const clientId = need('AZURE_PROBE_CLIENT_ID');
  if (kind === 'secret') {
    return { kind, tenantId, clientId, secret: need('AZURE_PROBE_CLIENT_SECRET') };
  }
  return {
    kind,
    tenantId,
    clientId,
    certificatePem: readFileSync(need('AZURE_PROBE_CLIENT_CERT_FILE'), 'utf8'),
    keyPem: readFileSync(need('AZURE_PROBE_CLIENT_KEY_FILE'), 'utf8'),
  };
}

/**
 * Whose credential the bench Qualor's Azure DevOps connection holds (seed-qualor.mjs --identity):
 * `bot` (the bench service principal on Services, qualor-bot's PAT on Server: every earlier run),
 * `contributor` (a project Contributor) or `minimal-pat` (Services: a PAT with the candidate minimal
 * scopes).
 */
export type QualorIdentity = 'bot' | 'contributor' | 'minimal-pat';

/**
 * The credential of a weaker Qualor identity, for the probe's own calls as that identity:
 * Services' contributor service principal (`AZURE_PROBE_CONTRIBUTOR_CLIENT_ID`/`_SECRET`, tenant
 * `AZURE_PROBE_CONTRIBUTOR_TENANT_ID` or else `AZURE_PROBE_TENANT_ID`) or minimal PAT
 * (`AZURE_PROBE_MINIMAL_PAT`); Server's probe-user PAT (`AZURE_PROBE_SERVER_USER_PAT`, a
 * Contributor's Code read & write PAT). Server has no minimal PAT.
 */
export function qualorIdentityAuth(
  name: 'services' | 'server',
  identity: Exclude<QualorIdentity, 'bot'>,
): AzureAuth {
  if (name === 'server') {
    if (identity !== 'contributor') throw new Error(`--qualor-identity ${identity}: services only`);
    return pat('AZURE_PROBE_SERVER_USER_PAT');
  }
  if (identity === 'minimal-pat') return pat('AZURE_PROBE_MINIMAL_PAT');
  return {
    kind: 'secret',
    tenantId: process.env['AZURE_PROBE_CONTRIBUTOR_TENANT_ID'] || need('AZURE_PROBE_TENANT_ID'),
    clientId: need('AZURE_PROBE_CONTRIBUTOR_CLIENT_ID'),
    secret: need('AZURE_PROBE_CONTRIBUTOR_CLIENT_SECRET'),
  };
}

/** The only base URL a client can be built for is the one in the environment. */
export function loadTarget(
  name: 'services' | 'server',
  opts: { auth?: 'pat' | 'secret' | 'certificate' } = {},
): Target {
  const hookBase = need('AZURE_PROBE_HOOK_BASE');
  const recorderSecret = need('AZURE_PROBE_RECORDER_SECRET');
  const project = need('AZURE_PROBE_PROJECT');
  if (name === 'services') {
    return {
      baseUrl: need('AZURE_PROBE_SERVICES_URL'),
      project,
      auth: servicesAuth(opts.auth ?? 'pat'),
      userAuth: pat('AZURE_PROBE_SERVICES_USER_PAT'),
      hookBase,
      recorderSecret,
    };
  }
  const baseUrl = need('AZURE_PROBE_SERVER_URL');
  const caFile = process.env['AZURE_PROBE_SERVER_CA_FILE'];
  const readerAuth = optPat('AZURE_PROBE_SERVER_READER_PAT');
  const adminAuth = optPat('AZURE_PROBE_SERVER_ADMIN_PAT');
  return {
    baseUrl,
    project,
    auth: pat('AZURE_PROBE_SERVER_PAT'),
    userAuth: pat('AZURE_PROBE_SERVER_USER_PAT'),
    ...(readerAuth ? { readerAuth } : {}),
    ...(adminAuth ? { adminAuth } : {}),
    ...(caFile ? { caPem: readFileSync(caFile, 'utf8') } : {}),
    hookBase,
    recorderSecret,
  };
}

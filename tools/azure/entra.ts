import { createHash, createSign, randomUUID, X509Certificate } from 'node:crypto';
import type { AzureAuth } from './client.js';

const SCOPE = '499b84ac-1321-427f-aa17-267ca6975798/.default';

export type EntraAuth = Exclude<AzureAuth, { kind: 'pat' }>;

const b64u = (b: Buffer | string): string => Buffer.from(b).toString('base64url');

function assertion(auth: Extract<EntraAuth, { kind: 'certificate' }>, tokenUrl: string): string {
  const der = new X509Certificate(auth.certificatePem).raw;
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT', x5t: b64u(createHash('sha1').update(der).digest()) };
  const claims = {
    aud: tokenUrl,
    iss: auth.clientId,
    sub: auth.clientId,
    jti: randomUUID(),
    nbf: now,
    exp: now + 600,
  };
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
  const sig = createSign('RSA-SHA256').update(signingInput).sign(auth.keyPem);
  return `${signingInput}.${b64u(sig)}`;
}

/** Client-credentials token for Azure DevOps. */
export async function entraToken(
  auth: EntraAuth,
  opts: { tokenUrl?: string; fetch?: typeof fetch } = {},
): Promise<{ token: string; expiresAt: number }> {
  const tokenUrl =
    opts.tokenUrl ?? `https://login.microsoftonline.com/${auth.tenantId}/oauth2/v2.0/token`;
  const form = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: auth.clientId,
    scope: SCOPE,
  });
  if (auth.kind === 'secret') {
    form.set('client_secret', auth.secret);
  } else {
    form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    form.set('client_assertion', assertion(auth, tokenUrl));
  }
  const started = Date.now();
  const res = await (opts.fetch ?? fetch)(tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  const body = (await res.json()) as { access_token?: string; expires_in?: number };
  if (!res.ok || !body.access_token) {
    // Never echo the body: it can carry the assertion's details.
    throw new Error(`Entra token request failed with HTTP ${res.status}`);
  }
  return { token: body.access_token, expiresAt: started + (body.expires_in ?? 3600) * 1000 };
}

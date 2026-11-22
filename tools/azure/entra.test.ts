import { createPublicKey, createVerify, X509Certificate } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { entraToken } from './entra.js';

import { TEST_SERVER_CERT_PEM as crt, TEST_SERVER_KEY_PEM as key } from '../../cli/test/tls.js';

let server: Server | undefined;
afterEach(() => {
  server?.close();
});

async function fakeEndpoint(): Promise<{ url: string; forms: URLSearchParams[] }> {
  const forms: URLSearchParams[] = [];
  const s = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      forms.push(new URLSearchParams(body));
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ access_token: 'tok', expires_in: 3599 }));
    });
  });
  server = s;
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${(s.address() as AddressInfo).port}/token`, forms };
}

const b64u = (s: string): Buffer => Buffer.from(s, 'base64url');

describe('entraToken', () => {
  it('secret: posts client_credentials with the Azure DevOps scope', async () => {
    const ep = await fakeEndpoint();
    const before = Date.now();
    const out = await entraToken(
      { kind: 'secret', tenantId: 't', clientId: 'c', secret: 'shh' },
      { tokenUrl: ep.url },
    );
    const f = ep.forms[0]!;
    expect(f.get('grant_type')).toBe('client_credentials');
    expect(f.get('scope')).toBe('499b84ac-1321-427f-aa17-267ca6975798/.default');
    expect(f.get('client_id')).toBe('c');
    expect(f.get('client_secret')).toBe('shh');
    expect(out.token).toBe('tok');
    expect(out.expiresAt).toBeGreaterThanOrEqual(before + 3599_000);
  });

  it('certificate: posts a signed assertion', async () => {
    const ep = await fakeEndpoint();
    await entraToken(
      { kind: 'certificate', tenantId: 't', clientId: 'cid', certificatePem: crt, keyPem: key },
      { tokenUrl: ep.url },
    );
    const f = ep.forms[0]!;
    expect(f.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    expect(f.get('client_secret')).toBeNull();
    const [h, p, s] = f.get('client_assertion')!.split('.') as [string, string, string];
    const verify = createVerify('RSA-SHA256').update(`${h}.${p}`);
    expect(verify.verify(createPublicKey(crt), b64u(s))).toBe(true);
    const header = JSON.parse(b64u(h).toString()) as Record<string, string>;
    const claims = JSON.parse(b64u(p).toString()) as Record<string, string | number>;
    const thumb = new X509Certificate(crt).fingerprint.replaceAll(':', '');
    expect(header.alg).toBe('RS256');
    expect(header.x5t).toBe(Buffer.from(thumb, 'hex').toString('base64url'));
    expect(claims.aud).toBe(ep.url);
    expect(claims.iss).toBe('cid');
    expect(claims.sub).toBe('cid');
    expect(typeof claims.jti).toBe('string');
    expect((claims.exp as number) - (claims.nbf as number)).toBe(600);
  });
});

import { createServer } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startFakeOp, type FakeOp } from '../../test/fake-oidc';
import type { LoadedConnection } from './connections';
import { forgetOidcConfiguration, oidcConfiguration } from './oidc-config';

let op: FakeOp;
beforeAll(async () => {
  op = await startFakeOp();
});
afterAll(async () => op.close());

function connection(issuer: string): LoadedConnection {
  return {
    row: { id: 'c1', updatedAt: new Date(0) } as never,
    parsed: {
      protocol: 'oidc',
      config: {
        issuer,
        clientId: op.clientId,
        clientAuth: 'client_secret_basic',
        scopes: ['openid'],
        claims: {
          username: 'preferred_username',
          email: 'email',
          displayName: 'name',
          groups: 'groups',
        },
        userinfo: false,
        jit: true,
        linkByEmail: false,
        groupSource: 'claims',
        requiredClaims: [],
      },
    },
    clientSecret: op.clientSecret,
    spKey: null,
  };
}
const hosts = () => new Set([new URL(op.issuer).host]);

describe('OIDC discovery (sso-scim.md §4.2, §14)', () => {
  it('discovers and allows only the named endpoints', async () => {
    forgetOidcConfiguration('c1');
    const { config, fetch } = await oidcConfiguration(connection(op.issuer), {
      internalHosts: hosts(),
    });
    expect(config.serverMetadata().token_endpoint).toBe(`${op.issuer}/token`);
    await expect(
      fetch(`${op.issuer}/elsewhere`, {
        method: 'GET',
        headers: {},
        body: undefined,
        redirect: 'manual',
      }),
    ).rejects.toThrow(/not_allowed/);
  });

  it('refuses a discovery document naming another issuer', async () => {
    forgetOidcConfiguration('c1');
    op.tweak({ issuerInDiscovery: 'https://evil.example' });
    await expect(
      oidcConfiguration(connection(op.issuer), { internalHosts: hosts() }),
    ).rejects.toThrow();
    op.tweak({ issuerInDiscovery: undefined });
  });

  it('caches for an hour, and forgets on a new updated_at', async () => {
    forgetOidcConfiguration('c1');
    let clock = 0;
    const a = await oidcConfiguration(connection(op.issuer), {
      internalHosts: hosts(),
      now: () => clock,
    });
    clock = 59 * 60_000;
    expect(
      (await oidcConfiguration(connection(op.issuer), { internalHosts: hosts(), now: () => clock }))
        .config,
    ).toBe(a.config);
    clock = 61 * 60_000;
    expect(
      (await oidcConfiguration(connection(op.issuer), { internalHosts: hosts(), now: () => clock }))
        .config,
    ).not.toBe(a.config);
  });

  it('allows the JWKS and token endpoints discovery named', async () => {
    forgetOidcConfiguration('c1');
    const { fetch } = await oidcConfiguration(connection(op.issuer), { internalHosts: hosts() });
    const res = await fetch(`${op.issuer}/jwks`, {
      method: 'GET',
      headers: {},
      body: undefined,
      redirect: 'manual',
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { keys: unknown[] }).keys).toHaveLength(1);
  });

  it('pins the issuer exactly: a trailing slash the library would accept is refused', async () => {
    forgetOidcConfiguration('c1');
    op.tweak({ issuerInDiscovery: `${op.issuer}/` });
    try {
      await expect(
        oidcConfiguration(connection(op.issuer), { internalHosts: hosts() }),
      ).rejects.toThrow(/another issuer/);
    } finally {
      op.tweak({ issuerInDiscovery: undefined });
    }
  });

  it('refuses an http issuer that QUALOR_SSO_INTERNAL_HOSTS does not list', async () => {
    forgetOidcConfiguration('c1');
    await expect(
      oidcConfiguration(connection(op.issuer), { internalHosts: new Set() }),
    ).rejects.toThrow(/QUALOR_SSO_INTERNAL_HOSTS/);
  });

  it('refuses a discovery URL given as the issuer (it would skip the issuer check)', async () => {
    forgetOidcConfiguration('c1');
    await expect(
      oidcConfiguration(connection(`${op.issuer}/.well-known/openid-configuration`), {
        internalHosts: hosts(),
      }),
    ).rejects.toThrow(/not an issuer URL/);
  });

  it('discovers an issuer with one trailing slash that the document states the same way', async () => {
    forgetOidcConfiguration('c1');
    op.tweak({ issuerInDiscovery: `${op.issuer}/` });
    try {
      const { config } = await oidcConfiguration(connection(`${op.issuer}/`), {
        internalHosts: hosts(),
      });
      expect(config.serverMetadata().issuer).toBe(`${op.issuer}/`);
    } finally {
      op.tweak({ issuerInDiscovery: undefined });
      forgetOidcConfiguration('c1');
    }
  });

  it('fails when the discovery endpoint answers with a redirect', async () => {
    const redirecting = createServer((req, res) => {
      res.writeHead(302, { location: `${op.issuer}/.well-known/openid-configuration` });
      res.end();
    });
    await new Promise<void>((r) => redirecting.listen(0, '127.0.0.1', r));
    const issuer = `http://127.0.0.1:${(redirecting.address() as { port: number }).port}`;
    try {
      forgetOidcConfiguration('c1');
      await expect(
        oidcConfiguration(connection(issuer), {
          internalHosts: new Set([new URL(issuer).host, new URL(op.issuer).host]),
        }),
      ).rejects.toThrow();
    } finally {
      await new Promise<void>((r) => redirecting.close(() => r()));
    }
  });
});

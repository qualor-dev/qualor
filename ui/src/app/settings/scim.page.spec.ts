import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import type { ScimToken, SsoConnection } from '../api/ee';
import { SessionStore } from '../auth/session';
import { ScimPage } from './scim.page';

const CONNECTION = '0190a6c2-0000-7000-8000-0000000000c1';
const TOKEN_ID = '0190a6c2-0000-7000-8000-0000000000f1';
const TOKENS = '/api/v0/ee/scim/tokens';
const PUBLIC = 'https://qualor.example.com';
/** Split so no scanner takes the test value for a real token. */
const TOKEN = ['qlr', 'scim', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6'].join('_');

function connection(overrides: Partial<SsoConnection> = {}): SsoConnection {
  return {
    id: CONNECTION,
    name: 'Acme SSO',
    protocol: 'oidc',
    enabled: true,
    inEffect: true,
    configValid: true,
    jit: true,
    linkByEmail: false,
    groupSource: 'scim',
    requiredClaims: [],
    claims: { username: 'preferred_username', email: 'email', displayName: 'name', groups: null },
    oidc: {
      issuer: 'https://idp.example.com',
      clientId: 'qualor',
      clientAuth: 'client_secret_basic',
      scopes: ['openid'],
      userinfo: false,
      clientSecretSet: true,
    },
    saml: null,
    urls: {
      redirectUri: `${PUBLIC}/api/v0/ee/sso/oidc/${CONNECTION}/callback`,
      acsUrl: `${PUBLIC}/api/v0/ee/sso/saml/${CONNECTION}/acs`,
      entityId: `${PUBLIC}/api/v0/ee/sso/saml/${CONNECTION}/metadata`,
      metadataUrl: `${PUBLIC}/api/v0/ee/sso/saml/${CONNECTION}/metadata`,
      startUrl: `/api/v0/ee/sso/${CONNECTION}/start`,
    },
    createdAt: '2026-09-01T10:00:00.000Z',
    updatedAt: '2026-09-01T10:00:00.000Z',
    ...overrides,
  };
}

function token(overrides: Partial<ScimToken> = {}): ScimToken {
  return {
    id: TOKEN_ID,
    connectionId: CONNECTION,
    name: 'Entra ID',
    prefix: 'qlr_scim_A1b',
    expiresAt: null,
    lastUsedAt: '2026-09-20T10:00:00.000Z',
    revokedAt: null,
    createdAt: '2026-09-01T10:00:00.000Z',
    ...overrides,
  };
}

function setup(
  options: { features?: string[]; tokens?: ScimToken[]; connections?: SsoConnection[] } = {},
) {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', { body: page([]) });
  server.on('GET', '/api/v0/system/info', {
    body: {
      version: '0.1.0',
      edition: 'enterprise',
      features: options.features ?? ['sso', 'scim'],
      extensions: [],
    },
  });
  server.on('GET', '/api/v0/ee/sso/connections', {
    body: options.connections ?? [connection()],
  });
  server.on('GET', TOKENS, { body: options.tokens ?? [token()] });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: true }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(ScimPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

function button(root: HTMLElement, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

describe('ScimPage (sso-scim.md §12, §18)', () => {
  it('shows the base URL with a copy button', async () => {
    setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const { fixture, root } = await render();
    const field = root.querySelector<HTMLInputElement>(`#scim-url-${CONNECTION}`)!;
    expect(field.value).toBe(`${PUBLIC}/api/v0/ee/scim/v2`);
    button(root, 'Copy').click();
    await settle(fixture);
    expect(writeText).toHaveBeenCalledWith(`${PUBLIC}/api/v0/ee/scim/v2`);
    expect(root.textContent).toContain('Copied.');
  });

  it('says so when QUALOR_PUBLIC_URL is unset', async () => {
    setup({ connections: [connection({ urls: null })] });
    const { root } = await render();
    expect(root.querySelector(`#scim-url-${CONNECTION}`)).toBeNull();
    expect(root.textContent).toContain('QUALOR_PUBLIC_URL is not set');
  });

  it('lists the tokens with their prefix and last use, never the token', async () => {
    setup({
      tokens: [
        token(),
        token({ id: 'x', name: 'Old', lastUsedAt: null, revokedAt: '2026-09-10T00:00:00.000Z' }),
      ],
    });
    const { root } = await render();
    const table = root.querySelector(`#scim-tokens-${CONNECTION}`)!.textContent ?? '';
    expect(table).toContain('Entra ID');
    expect(table).toContain('qlr_scim_A1b…');
    expect(table).toContain('Sep 20, 2026, 10:00 AM UTC');
    expect(table).toContain('Not used yet');
    expect(table).toContain('Revoked');
  });

  it('creates a token and shows it once', async () => {
    const server = setup({ tokens: [] });
    server.on('POST', TOKENS, {
      status: 201,
      body: { ...token({ name: 'Okta', lastUsedAt: null }), token: TOKEN },
    });
    const { fixture, root } = await render();
    type(root, `#scim-name-${CONNECTION}`, 'Okta');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', TOKENS).map((r) => r.body)).toEqual([
      { connectionId: CONNECTION, name: 'Okta', expiresAt: null },
    ]);
    expect(root.querySelector<HTMLInputElement>('#secret-once')?.value).toBe(TOKEN);
    expect(root.querySelector(`#scim-tokens-${CONNECTION}`)?.textContent).toContain('Okta');
    button(root, 'Done').click();
    await settle(fixture);
    expect(root.querySelector('#secret-once')).toBeNull();
    expect(root.textContent).not.toContain(TOKEN);
    expect([...root.querySelectorAll('input')].map((i) => i.value)).not.toContain(TOKEN);
  });

  it('sends an expiry date as the end of that day in UTC', async () => {
    const server = setup({ tokens: [] });
    server.on('POST', TOKENS, { status: 201, body: { ...token(), token: TOKEN } });
    const { fixture, root } = await render();
    type(root, `#scim-name-${CONNECTION}`, 'Okta');
    type(root, `#scim-expiry-${CONNECTION}`, '2027-01-31');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', TOKENS)[0]?.body).toEqual({
      connectionId: CONNECTION,
      name: 'Okta',
      expiresAt: '2027-01-31T23:59:59Z',
    });
  });

  it('shows the token limit clearly', async () => {
    const server = setup();
    server.on('POST', TOKENS, { status: 409, body: problem(409, 'SCIM_TOKEN_LIMIT_REACHED') });
    const { fixture, root } = await render();
    type(root, `#scim-name-${CONNECTION}`, 'Sixth');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'as many active SCIM tokens as it can have (5)',
    );
  });

  it('revokes a token after a confirmation', async () => {
    const server = setup();
    server.on('DELETE', `${TOKENS}/${TOKEN_ID}`, { status: 204 });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const { fixture, root } = await render();
    button(root, 'Revoke').click();
    await settle(fixture);
    expect(confirm).toHaveBeenCalledWith(
      'Revoke the SCIM token Entra ID? The identity provider can no longer provision people with it.',
    );
    expect(server.requestsTo('DELETE', `${TOKENS}/${TOKEN_ID}`)).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Token Entra ID revoked.');
    confirm.mockRestore();
  });

  it('revokes nothing when the confirmation is declined', async () => {
    const server = setup();
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const { fixture, root } = await render();
    button(root, 'Revoke').click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', `${TOKENS}/${TOKEN_ID}`)).toHaveLength(0);
    confirm.mockRestore();
  });

  it('asks nothing of the enterprise API while scim is inactive', async () => {
    const server = setup({ features: ['sso'] });
    const { root } = await render();
    expect(root.textContent).toContain('the scim feature');
    expect(server.requestsTo('GET', TOKENS)).toHaveLength(0);
  });
});

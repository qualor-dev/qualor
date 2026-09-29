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

/** Opens "New token" of the connection's panel and returns the dialog (step 9). */
async function openCreate(
  fixture: { whenStable(): Promise<unknown> },
  root: HTMLElement,
): Promise<HTMLDialogElement> {
  button(
    root.querySelector<HTMLElement>(`section[data-key="${CONNECTION}"]`)!,
    'New token',
  ).click();
  await settle(fixture);
  const dialog = root.querySelector<HTMLDialogElement>('dialog#create-dialog')!;
  expect(dialog.open).toBe(true);
  return dialog;
}

async function submit(fixture: { whenStable(): Promise<unknown> }, dialog: HTMLDialogElement) {
  dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
  await settle(fixture);
}

/**
 * Answers the page's confirmation dialog (step 9: it replaces the browser's `confirm()`) with
 * the button `choice`, and returns the question it asked.
 */
async function answer(
  fixture: { whenStable(): Promise<unknown> },
  root: HTMLElement,
  choice: string,
): Promise<string> {
  const ask = root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!;
  expect(ask.open).toBe(true);
  const question = ask.querySelector('#confirm-text')?.textContent?.trim() ?? '';
  button(ask, choice).click();
  await settle(fixture);
  expect(ask.open).toBe(false);
  return question;
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

  it("creates a token in its connection's New token dialog, which shows it once", async () => {
    const server = setup({ tokens: [] });
    server.on('POST', TOKENS, {
      status: 201,
      body: { ...token({ name: 'Okta', lastUsedAt: null }), token: TOKEN },
    });
    const { fixture, root } = await render();
    const newToken = button(root, 'New token');
    expect(newToken.getAttribute('aria-label')).toBe('New token for Acme SSO');
    const dialog = await openCreate(fixture, root);
    expect(dialog.querySelector('h2')?.textContent?.trim()).toBe('New token for Acme SSO');
    type(dialog, '#scim-token-name', 'Okta');
    await submit(fixture, dialog);
    expect(server.requestsTo('POST', TOKENS).map((r) => r.body)).toEqual([
      { connectionId: CONNECTION, name: 'Okta', expiresAt: null },
    ]);
    // The dialog now holds the token instead of the form.
    expect(dialog.open).toBe(true);
    expect(dialog.querySelector<HTMLInputElement>('#secret-once')?.value).toBe(TOKEN);
    expect(dialog.querySelector('#scim-token-name')).toBeNull();
    expect(root.querySelector(`#scim-tokens-${CONNECTION}`)?.textContent).toContain('Okta');
    // Done closes the dialog from its footer, once (the secret box has none of its own).
    const dones = [...dialog.querySelectorAll('button')].filter(
      (b) => b.textContent?.trim() === 'Done',
    );
    expect(dones).toHaveLength(1);
    expect(dones[0]!.closest('.dialog-actions')).not.toBeNull();
    button(dialog, 'Done').click();
    await settle(fixture);
    expect(dialog.open).toBe(false);
    expect(root.querySelector('#secret-once')).toBeNull();
    expect(root.textContent).not.toContain(TOKEN);
    expect([...root.querySelectorAll('input')].map((i) => i.value)).not.toContain(TOKEN);
    // Opened again: an empty form, never the earlier token.
    const again = await openCreate(fixture, root);
    expect(again.querySelector('#secret-once')).toBeNull();
    expect(again.querySelector<HTMLInputElement>('#scim-token-name')?.value).toBe('');
  });

  it('forgets the token when its dialog closes', async () => {
    const server = setup({ tokens: [] });
    server.on('POST', TOKENS, { status: 201, body: { ...token(), token: TOKEN } });
    const { fixture, root } = await render();
    const dialog = await openCreate(fixture, root);
    type(dialog, '#scim-token-name', 'Okta');
    await submit(fixture, dialog);
    expect(dialog.querySelector('#secret-once')).not.toBeNull();
    dialog.removeAttribute('open');
    dialog.dispatchEvent(new Event('close'));
    await settle(fixture);
    expect(root.querySelector('#secret-once')).toBeNull();
  });

  it('opens its dialog again on the token when it was closed while the token was made', async () => {
    const server = setup({ tokens: [] });
    let reply = (): void => undefined;
    server.on(
      'POST',
      TOKENS,
      () =>
        new Promise((resolve) => {
          reply = () => resolve({ status: 201, body: { ...token(), token: TOKEN } });
        }),
    );
    const { fixture, root } = await render();
    const dialog = await openCreate(fixture, root);
    type(dialog, '#scim-token-name', 'Okta');
    await submit(fixture, dialog);
    dialog.removeAttribute('open');
    dialog.dispatchEvent(new Event('close'));
    await settle(fixture);
    reply();
    await settle(fixture);
    expect(dialog.open).toBe(true);
    expect(dialog.querySelector<HTMLInputElement>('#secret-once')?.value).toBe(TOKEN);
  });

  it('keeps its dialog open on Escape while the token shows', async () => {
    const server = setup({ tokens: [] });
    server.on('POST', TOKENS, { status: 201, body: { ...token(), token: TOKEN } });
    const { fixture, root } = await render();
    const dialog = await openCreate(fixture, root);
    type(dialog, '#scim-token-name', 'Okta');
    await submit(fixture, dialog);
    const onSecret = new Event('cancel', { cancelable: true });
    dialog.dispatchEvent(onSecret);
    await settle(fixture);
    expect(onSecret.defaultPrevented).toBe(true);
    expect(dialog.querySelector<HTMLInputElement>('#secret-once')?.value).toBe(TOKEN);
  });

  it('drops a token that arrives after the page was left', async () => {
    const server = setup({ tokens: [] });
    let reply = (): void => undefined;
    server.on(
      'POST',
      TOKENS,
      () =>
        new Promise((resolve) => {
          reply = () => resolve({ status: 201, body: { ...token(), token: TOKEN } });
        }),
    );
    const { fixture, root } = await render();
    const dialog = await openCreate(fixture, root);
    type(dialog, '#scim-token-name', 'Okta');
    await submit(fixture, dialog);
    // Closed, then the page left, while the server makes the token: nothing opens again.
    dialog.removeAttribute('open');
    dialog.dispatchEvent(new Event('close'));
    const page_ = fixture.componentInstance as unknown as { secret: () => unknown };
    fixture.destroy();
    reply();
    await settle();
    expect(page_.secret()).toBeNull();
    expect(dialog.open).toBe(false);
  });

  it('sends an expiry date as the end of that day in UTC', async () => {
    const server = setup({ tokens: [] });
    server.on('POST', TOKENS, { status: 201, body: { ...token(), token: TOKEN } });
    const { fixture, root } = await render();
    const dialog = await openCreate(fixture, root);
    type(dialog, '#scim-token-name', 'Okta');
    type(dialog, '#scim-token-expiry', '2027-01-31');
    await submit(fixture, dialog);
    expect(server.requestsTo('POST', TOKENS)[0]?.body).toEqual({
      connectionId: CONNECTION,
      name: 'Okta',
      expiresAt: '2027-01-31T23:59:59Z',
    });
  });

  it('shows the token limit clearly, in the dialog that stays open', async () => {
    const server = setup();
    server.on('POST', TOKENS, { status: 409, body: problem(409, 'SCIM_TOKEN_LIMIT_REACHED') });
    const { fixture, root } = await render();
    const dialog = await openCreate(fixture, root);
    type(dialog, '#scim-token-name', 'Sixth');
    await submit(fixture, dialog);
    expect(dialog.open).toBe(true);
    expect(dialog.querySelector('[role="alert"]')?.textContent).toContain(
      'as many active SCIM tokens as it can have (5)',
    );
  });

  it('asks for a name before sending anything', async () => {
    const server = setup();
    const { fixture, root } = await render();
    const dialog = await openCreate(fixture, root);
    await submit(fixture, dialog);
    expect(server.requestsTo('POST', TOKENS)).toHaveLength(0);
    const name = dialog.querySelector<HTMLInputElement>('#scim-token-name')!;
    expect(name.getAttribute('aria-invalid')).toBe('true');
    expect(dialog.querySelector('#scim-token-name-error')?.textContent).toContain(
      'Give the token a name of 1 to 200 characters',
    );
  });

  it('revokes a token after a confirmation', async () => {
    const server = setup();
    server.on('DELETE', `${TOKENS}/${TOKEN_ID}`, { status: 204 });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    button(root, 'Revoke').click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', `${TOKENS}/${TOKEN_ID}`)).toHaveLength(0);
    expect(await answer(fixture, root, 'Revoke')).toBe(
      'Revoke the SCIM token Entra ID? The identity provider can no longer provision people with it.',
    );
    expect(confirm).not.toHaveBeenCalled();
    expect(server.requestsTo('DELETE', `${TOKENS}/${TOKEN_ID}`)).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Token Entra ID revoked.');
    confirm.mockRestore();
  });

  it('revokes nothing when the confirmation is declined', async () => {
    const server = setup();
    const { fixture, root } = await render();
    button(root, 'Revoke').click();
    await settle(fixture);
    await answer(fixture, root, 'Cancel');
    expect(server.requestsTo('DELETE', `${TOKENS}/${TOKEN_ID}`)).toHaveLength(0);
  });

  it('asks nothing of the enterprise API while scim is inactive', async () => {
    const server = setup({ features: ['sso'] });
    const { root } = await render();
    expect(root.textContent).toContain('the scim feature');
    expect(server.requestsTo('GET', TOKENS)).toHaveLength(0);
  });
});

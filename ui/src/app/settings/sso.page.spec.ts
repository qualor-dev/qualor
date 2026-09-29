import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  expectNoPasswordManager,
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import type { SsoConnection, SsoMapping } from '../api/ee';
import { SessionStore } from '../auth/session';
import { SettingsPage } from './settings.page';
import { SsoPage } from './sso.page';

const OIDC_ID = '0190a6c2-0000-7000-8000-0000000000c1';
const SAML_ID = '0190a6c2-0000-7000-8000-0000000000c2';
const PROJECT_ID = '0190a6c2-0000-7000-8000-0000000000d1';
const CONNECTIONS = '/api/v0/ee/sso/connections';
const PUBLIC = 'https://qualor.example.com';
const FINGERPRINT = 'AB:CD:'.repeat(15) + 'EF:01';
const PEM = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n';
const NEW_PEM = '-----BEGIN CERTIFICATE-----\nMIIBnew\n-----END CERTIFICATE-----\n';
/** Split so no scanner takes the test value for a real secret. */
const SECRET = ['client', 'secret', 'value'].join('-');

function urls(id: string) {
  return {
    redirectUri: `${PUBLIC}/api/v0/ee/sso/oidc/${id}/callback`,
    acsUrl: `${PUBLIC}/api/v0/ee/sso/saml/${id}/acs`,
    entityId: `${PUBLIC}/api/v0/ee/sso/saml/${id}/metadata`,
    metadataUrl: `${PUBLIC}/api/v0/ee/sso/saml/${id}/metadata`,
    startUrl: `/api/v0/ee/sso/${id}/start`,
  };
}

function oidc(overrides: Partial<SsoConnection> = {}): SsoConnection {
  return {
    id: OIDC_ID,
    name: 'Acme SSO',
    protocol: 'oidc',
    enabled: true,
    inEffect: true,
    configValid: true,
    jit: true,
    linkByEmail: false,
    groupSource: 'claims',
    requiredClaims: [],
    claims: {
      username: 'preferred_username',
      email: 'email',
      displayName: 'name',
      groups: 'groups',
    },
    oidc: {
      issuer: 'https://idp.example.com/realms/acme',
      clientId: 'qualor',
      clientAuth: 'client_secret_basic',
      scopes: ['openid', 'email', 'profile'],
      userinfo: false,
      clientSecretSet: true,
    },
    saml: null,
    urls: urls(OIDC_ID),
    createdAt: '2026-09-01T10:00:00.000Z',
    updatedAt: '2026-09-01T10:00:00.000Z',
    ...overrides,
  };
}

function saml(overrides: Partial<SsoConnection> = {}): SsoConnection {
  return {
    id: SAML_ID,
    name: 'Corp SAML',
    protocol: 'saml',
    enabled: false,
    inEffect: false,
    configValid: true,
    jit: true,
    linkByEmail: false,
    groupSource: 'none',
    requiredClaims: [],
    claims: { username: null, email: 'email', displayName: 'displayName', groups: null },
    oidc: null,
    saml: {
      idpEntityId: 'https://idp.corp.example/saml',
      idpSsoUrl: 'https://idp.corp.example/saml/sso',
      idpCertificates: [
        { pem: PEM, sha256: FINGERPRINT, notAfter: '2030-01-01T00:00:00.000Z', expired: false },
      ],
      metadataUrl: 'https://idp.corp.example/saml/metadata',
      nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      emailVerified: false,
      wantResponseSigned: false,
      spCertificate: null,
      spKeySet: false,
    },
    urls: urls(SAML_ID),
    createdAt: '2026-09-01T10:00:00.000Z',
    updatedAt: '2026-09-01T10:00:00.000Z',
    ...overrides,
  };
}

function mapping(overrides: Partial<SsoMapping> = {}): SsoMapping {
  return {
    id: '0190a6c2-0000-7000-8000-0000000000e1',
    group: 'engineering',
    organizationId: ORG_ID,
    organizationKey: 'default',
    projectId: null,
    projectKey: null,
    role: 'member',
    ...overrides,
  };
}

interface Setup {
  features?: string[];
  admin?: boolean;
  extensions?: string[];
  connections?: SsoConnection[];
  mappings?: SsoMapping[];
}

function setup(options: Setup = {}): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([
      {
        id: ORG_ID,
        key: 'default',
        name: 'Default',
        createdAt: '2026-09-01T00:00:00.000Z',
      },
    ]),
  });
  server.on('GET', '/api/v0/system/info', {
    body: {
      version: '0.1.0',
      edition: 'enterprise',
      features: options.features ?? ['sso'],
      extensions: (options.extensions ?? []).map((id) => ({
        point: 'settings.nav',
        id,
        label: `Plugin label ${id}`,
        path: `/settings/ee/${id}`,
      })),
    },
  });
  server.on('GET', CONNECTIONS, { body: options.connections ?? [oidc(), saml()] });
  server.on('GET', `${CONNECTIONS}/${OIDC_ID}/mappings`, { body: options.mappings ?? [] });
  server.on('GET', `${CONNECTIONS}/${SAML_ID}/mappings`, { body: [] });
  server.on('GET', '/api/v0/projects', {
    body: page([
      { id: PROJECT_ID, organizationId: ORG_ID, key: 'acme/web-shop', name: 'Web Shop' },
    ]),
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? true }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(SsoPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

function choose(root: HTMLElement, selector: string, value: string): void {
  const select = root.querySelector<HTMLSelectElement>(selector)!;
  select.value = value;
  select.dispatchEvent(new Event('change'));
}

function button(root: HTMLElement, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

async function click(fixture: { whenStable(): Promise<unknown> }, target: HTMLElement) {
  target.click();
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
  await click(fixture, button(ask, choice));
  expect(ask.open).toBe(false);
  return question;
}

/** A connection's panel in the list (step 9: a panel per connection, not a table row). */
function panel(root: HTMLElement, id: string): HTMLElement | null {
  return root.querySelector<HTMLElement>(`#sso-connections section.panel[data-key="${id}"]`);
}

async function openRow(fixture: { whenStable(): Promise<unknown> }, root: HTMLElement, id: string) {
  await click(fixture, panel(root, id)!.querySelector<HTMLButtonElement>('button')!);
}

describe('SsoPage (sso-scim.md §4, §9, §18)', () => {
  it('shows each connection as a panel with its protocol, its identity provider and its state', async () => {
    setup({ connections: [oidc(), saml({ configValid: false })] });
    const { root } = await render();
    const panels = [...root.querySelectorAll<HTMLElement>('#sso-connections section.panel')];
    const text = panels.map((p) => p.textContent?.replace(/\s+/g, ' ').trim());
    expect(panels.map((p) => p.dataset['key'])).toEqual([OIDC_ID, SAML_ID]);
    const first = panels[0]!;
    expect(first.getAttribute('aria-labelledby')).toBe(first.querySelector('h4')?.id);
    expect(first.querySelector('h4')?.textContent?.trim()).toBe('Acme SSO');
    expect(text[0]).toContain('OpenID Connect');
    expect(text[0]).toContain('https://idp.example.com/realms/acme');
    expect(text[0]).toContain('Enabled');
    expect(text[1]).toContain('Corp SAML');
    expect(text[1]).toContain('SAML');
    expect(text[1]).toContain('https://idp.corp.example/saml');
    expect(text[1]).toContain('Disabled');
    expect(text[1]).toContain('Configuration not valid');
    // The state is a word with an icon, never a colour alone.
    expect(first.querySelector('.connection-state q-icon')).not.toBeNull();
  });

  it('says so, with the ways to add one, when there is no connection', async () => {
    setup({ connections: [] });
    const { root } = await render();
    expect(root.querySelector('#sso-connections')?.textContent).toContain('No connections yet.');
    expect(button(root, 'Add an OpenID Connect connection')).toBeDefined();
    expect(button(root, 'Add a SAML connection')).toBeDefined();
  });

  it('asks nothing of the enterprise API while sso is inactive', async () => {
    const server = setup({ features: ['audit-log'] });
    const { root } = await render();
    expect(root.textContent).toContain('needs an enterprise licence with the sso feature');
    expect(server.requestsTo('GET', CONNECTIONS)).toHaveLength(0);
  });

  it('asks nothing of the enterprise API for someone who is not an instance admin', async () => {
    const server = setup({ admin: false });
    const { root } = await render();
    expect(root.textContent).toContain('Only instance administrators manage single sign-on.');
    expect(server.requestsTo('GET', CONNECTIONS)).toHaveLength(0);
  });

  it('posts a new OIDC connection with every field of the form', async () => {
    const server = setup({ connections: [] });
    const created = oidc({ enabled: false });
    server.on('POST', CONNECTIONS, { status: 201, body: created });
    server.on('GET', CONNECTIONS, () => ({
      body: server.requestsTo('POST', CONNECTIONS).length > 0 ? [created] : [],
    }));
    const { fixture, root } = await render();
    await click(fixture, button(root, 'Add an OpenID Connect connection'));
    type(root, '#sso-name', 'Acme SSO');
    type(root, '#sso-issuer', 'https://idp.example.com/realms/acme');
    type(root, '#sso-client-id', 'qualor');
    type(root, '#sso-client-secret', SECRET);
    choose(root, '#sso-client-auth', 'client_secret_post');
    type(root, '#sso-claim-groups', 'groups');
    choose(root, '#sso-group-source', 'claims');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', CONNECTIONS).map((r) => r.body)).toEqual([
      {
        name: 'Acme SSO',
        protocol: 'oidc',
        enabled: false,
        jit: true,
        linkByEmail: false,
        groupSource: 'claims',
        requiredClaims: [],
        claims: {
          username: 'preferred_username',
          email: 'email',
          displayName: 'name',
          groups: 'groups',
        },
        oidc: {
          issuer: 'https://idp.example.com/realms/acme',
          clientId: 'qualor',
          clientAuth: 'client_secret_post',
          scopes: ['openid', 'email', 'profile'],
          userinfo: false,
          clientSecret: SECRET,
        },
      },
    ]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Acme SSO saved.');
    // The saved view never has the secret: the field is gone behind "Set" and "Change".
    expect(root.querySelector('#sso-client-secret')).toBeNull();
    expect(root.textContent).not.toContain(SECRET);
  });

  it('never shows a stored secret: "Set", and Change reveals an empty field', async () => {
    const server = setup();
    server.on('PATCH', `${CONNECTIONS}/${OIDC_ID}`, { body: oidc() });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    expect(root.querySelector('#sso-client-secret')).toBeNull();
    expect(root.querySelector('#sso-client-secret-state')?.textContent).toContain('Set.');
    // A save without a new secret sends none: the stored one is kept.
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const first = server.requestsTo('PATCH', `${CONNECTIONS}/${OIDC_ID}`)[0]?.body as {
      oidc: Record<string, unknown>;
    };
    expect(first.oidc).not.toHaveProperty('clientSecret');

    await click(fixture, button(root, 'Change'));
    const field = root.querySelector<HTMLInputElement>('#sso-client-secret')!;
    expect(field.value).toBe('');
    expect(field.type).toBe('password');
    expectNoPasswordManager(field);
    type(root, '#sso-client-secret', SECRET);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const second = server.requestsTo('PATCH', `${CONNECTIONS}/${OIDC_ID}`)[1]?.body as {
      oidc: Record<string, unknown>;
    };
    expect(second.oidc['clientSecret']).toBe(SECRET);
  });

  it('never shows a stored SP key: "Set", and Change reveals an empty field', async () => {
    const stored = saml({
      saml: {
        ...saml().saml!,
        spKeySet: true,
        spCertificate: NEW_PEM,
      },
    });
    const server = setup({ connections: [oidc(), stored] });
    server.on('PATCH', `${CONNECTIONS}/${SAML_ID}`, { body: stored });
    const { fixture, root } = await render();
    await openRow(fixture, root, SAML_ID);
    expect(root.querySelector('#sso-sp-key')).toBeNull();
    expect(root.querySelector('#sso-sp-key-state')?.textContent).toContain('Set.');
    expect(root.textContent).not.toContain('PRIVATE KEY');
    // A save without a new key sends none: the stored one is kept.
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const first = server.requestsTo('PATCH', `${CONNECTIONS}/${SAML_ID}`)[0]?.body as {
      saml: Record<string, unknown>;
    };
    expect(first.saml).not.toHaveProperty('spKey');
    expect(first.saml['spCertificate']).toBe(NEW_PEM.trim());

    const change = root.querySelector<HTMLButtonElement>(
      'button[aria-describedby="sso-sp-key-state"]',
    )!;
    await click(fixture, change);
    const field = root.querySelector<HTMLTextAreaElement>('#sso-sp-key')!;
    expect(field.value).toBe('');
    expectNoPasswordManager(field);
    // Opening the field without typing still keeps the stored key.
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const second = server.requestsTo('PATCH', `${CONNECTIONS}/${SAML_ID}`)[1]?.body as {
      saml: Record<string, unknown>;
    };
    expect(second.saml).not.toHaveProperty('spKey');
  });

  it('shows the values to copy into the identity provider', async () => {
    setup();
    const { fixture, root } = await render();
    await openRow(fixture, root, SAML_ID);
    expect(root.querySelector<HTMLInputElement>('#sso-url-entity')?.value).toBe(
      `${PUBLIC}/api/v0/ee/sso/saml/${SAML_ID}/metadata`,
    );
    expect(root.querySelector<HTMLInputElement>('#sso-url-acs')?.value).toBe(
      `${PUBLIC}/api/v0/ee/sso/saml/${SAML_ID}/acs`,
    );
    expect(root.querySelector<HTMLInputElement>('#sso-url-metadata')?.value).toBe(
      `${PUBLIC}/api/v0/ee/sso/saml/${SAML_ID}/metadata`,
    );
    expect(root.querySelector('#sso-certificates')?.textContent?.replace(/\s+/g, ' ')).toContain(
      `SHA-256 ${FINGERPRINT}`,
    );
  });

  it('says so when QUALOR_PUBLIC_URL is unset instead of showing addresses', async () => {
    setup({ connections: [oidc({ urls: null })] });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    expect(root.querySelector('#sso-url-redirect')).toBeNull();
    expect(root.textContent).toContain('QUALOR_PUBLIC_URL is not set');
  });

  it('shows what Read metadata found, fingerprints and an expired warning, before saving', async () => {
    const server = setup();
    server.on('POST', `${CONNECTIONS}/${SAML_ID}/saml/metadata`, {
      body: {
        idpEntityId: 'https://idp.corp.example/saml2',
        idpSsoUrl: 'https://idp.corp.example/saml/sso',
        certificates: [
          {
            pem: NEW_PEM,
            sha256: '01:02:03',
            notAfter: '2020-01-01T00:00:00.000Z',
            expired: true,
          },
        ],
      },
    });
    server.on('PATCH', `${CONNECTIONS}/${SAML_ID}`, { body: saml() });
    const { fixture, root } = await render();
    await openRow(fixture, root, SAML_ID);
    await click(fixture, button(root, 'Read metadata'));
    const preview = root.querySelector('#sso-metadata-preview')!.textContent ?? '';
    expect(preview).toContain('https://idp.corp.example/saml2');
    expect(preview).toContain('01:02:03');
    expect(preview).toContain('Expired');
    expect(preview).toContain('Changed');
    // Nothing is saved until the admin says so.
    expect(server.requestsTo('PATCH', `${CONNECTIONS}/${SAML_ID}`)).toHaveLength(0);
    await click(fixture, button(root, 'Save these values'));
    expect(server.requestsTo('PATCH', `${CONNECTIONS}/${SAML_ID}`).map((r) => r.body)).toEqual([
      {
        saml: {
          idpEntityId: 'https://idp.corp.example/saml2',
          idpSsoUrl: 'https://idp.corp.example/saml/sso',
          idpCertificates: [NEW_PEM],
        },
      },
    ]);
    expect(root.querySelector('#sso-metadata-preview')).toBeNull();
  });

  it('shows a refused metadata document on the metadata URL field', async () => {
    const server = setup();
    server.on('POST', `${CONNECTIONS}/${SAML_ID}/saml/metadata`, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'saml.metadataUrl', message: 'The metadata was refused (doctype) <b>x</b>' },
      ]),
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, SAML_ID);
    await click(fixture, button(root, 'Read metadata'));
    expect(root.querySelector('#sso-metadata-url-error')?.textContent).toContain(
      'could not be read or was refused',
    );
    expect(root.textContent).not.toContain('doctype');
  });

  it('says why Read metadata failed, from the reason the server gives', async () => {
    const server = setup();
    server.on('POST', `${CONNECTIONS}/${SAML_ID}/saml/metadata`, {
      status: 422,
      body: {
        ...problem(422, 'VALIDATION_FAILED', [
          { path: 'saml.metadataUrl', message: 'The metadata URL could not be read: 10.0.0.7' },
        ]),
        reason: 'fetch.not_public',
      },
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, SAML_ID);
    await click(fixture, button(root, 'Read metadata'));
    expect(root.querySelector('#sso-metadata-url-error')?.textContent).toContain(
      'The host is not public. List it in QUALOR_SSO_INTERNAL_HOSTS',
    );
    // The server's own words (with the address it refused) are never shown.
    expect(root.textContent).not.toContain('10.0.0.7');
  });

  it('Test shows the endpoints Qualor will contact', async () => {
    const server = setup();
    server.on('POST', `${CONNECTIONS}/${OIDC_ID}/test`, {
      body: {
        ok: true,
        problem: null,
        endpoints: {
          authorization: 'https://idp.example.com/auth',
          token: 'https://idp.example.com/token',
          jwks: 'https://idp.example.com/jwks',
          userinfo: null,
        },
        certificates: null,
      },
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    await click(fixture, button(root, 'Test'));
    const result = root.querySelector('#sso-test')!.textContent ?? '';
    expect(result).toContain('The test passed.');
    expect(result).toContain('https://idp.example.com/token');
    expect(result).toContain('https://idp.example.com/jwks');
  });

  it("Test shows a fixed text for the problem, never the server's message", async () => {
    const server = setup();
    server.on('POST', `${CONNECTIONS}/${OIDC_ID}/test`, {
      body: {
        ok: false,
        problem: { code: 'fetch.unresolved', message: 'evil.example says <script>hi</script>' },
        endpoints: null,
        certificates: null,
      },
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    await click(fixture, button(root, 'Test'));
    const result = root.querySelector('#sso-test')!.textContent ?? '';
    expect(result).toContain('The host name could not be resolved.');
    expect(result).not.toContain('evil.example');
  });

  it('adds a mapping row and saves the whole list with PUT', async () => {
    const server = setup({ mappings: [mapping()] });
    server.on('PUT', `${CONNECTIONS}/${OIDC_ID}/mappings`, (request) => ({
      body: (request.body as SsoMapping[]).map((m, i) => ({
        ...m,
        id: `0190a6c2-0000-7000-8000-00000000${String(i).padStart(4, '0')}`,
        organizationKey: 'default',
        projectKey: m.projectId ? 'acme/web-shop' : null,
      })),
    }));
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    expect(root.querySelector('#sso-mappings')?.textContent).toContain('engineering');
    type(root, '#sso-mapping-group', 'qa');
    choose(root, '#sso-mapping-org', ORG_ID);
    await settle(fixture);
    choose(root, '#sso-mapping-project', PROJECT_ID);
    choose(root, '#sso-mapping-role', 'viewer');
    await click(fixture, button(root, 'Add'));
    expect(root.querySelector('#sso-mappings')?.textContent).toContain('acme/web-shop');
    await click(fixture, button(root, 'Save mappings'));
    expect(
      server.requestsTo('PUT', `${CONNECTIONS}/${OIDC_ID}/mappings`).map((r) => r.body),
    ).toEqual([
      [
        { group: 'engineering', organizationId: ORG_ID, projectId: null, role: 'member' },
        { group: 'qa', organizationId: ORG_ID, projectId: PROJECT_ID, role: 'viewer' },
      ],
    ]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Group mappings saved.');
  });

  it('offers every role and project mappings with sso alone', async () => {
    const server = setup({ features: ['sso'] });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    expect(root.querySelector<HTMLSelectElement>('#sso-mapping-project')?.disabled).toBe(false);
    const roles = [...root.querySelectorAll<HTMLOptionElement>('#sso-mapping-role option')];
    expect(roles.map((o) => o.textContent?.trim())).toEqual([
      'Organization admin',
      'Project admin',
      'Maintainer',
      'Viewer',
    ]);
    expect(roles.filter((o) => o.disabled)).toEqual([]);
    expect(root.textContent).not.toContain('Project mappings, and the roles');
    choose(root, '#sso-mapping-org', ORG_ID);
    await settle(fixture);
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(1);
    choose(root, '#sso-mapping-project', PROJECT_ID);
    await settle(fixture);
    const disabled = [...root.querySelectorAll<HTMLOptionElement>('#sso-mapping-role option')]
      .filter((o) => o.disabled)
      .map((o) => o.value);
    expect(disabled).toEqual(['admin']);
  });

  it('asks before deleting, with the counts it knows, then deletes', async () => {
    const server = setup({ features: ['sso', 'scim'], mappings: [mapping()] });
    server.on('GET', '/api/v0/ee/scim/tokens', {
      body: [
        {
          id: '0190a6c2-0000-7000-8000-0000000000f1',
          connectionId: OIDC_ID,
          name: 'Entra',
          prefix: 'qlr_scim_abc',
          expiresAt: null,
          lastUsedAt: null,
          revokedAt: null,
          createdAt: '2026-09-01T10:00:00.000Z',
        },
      ],
    });
    server.on('DELETE', `${CONNECTIONS}/${OIDC_ID}`, { status: 204 });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    await click(fixture, button(root, 'Delete'));
    const question = await answer(fixture, root, 'Delete');
    expect(confirm).not.toHaveBeenCalled();
    expect(question).toContain('Delete Acme SSO?');
    expect(question).toContain('1 group mappings');
    expect(question).toContain('1 active SCIM tokens');
    expect(server.requestsTo('DELETE', `${CONNECTIONS}/${OIDC_ID}`)).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Acme SSO deleted.');
    confirm.mockRestore();
  });

  it('says why the last enabled connection cannot be deleted (409 LAST_SSO_CONNECTION)', async () => {
    const server = setup({ features: ['sso', 'sso.multi'] });
    server.on('DELETE', `${CONNECTIONS}/${OIDC_ID}`, {
      status: 409,
      body: problem(409, 'LAST_SSO_CONNECTION'),
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    await click(fixture, button(root, 'Delete'));
    await answer(fixture, root, 'Delete');
    const alert = root.querySelector('[role="alert"]')?.textContent ?? '';
    expect(alert).toContain('This is the last enabled connection');
    expect(alert).toContain('Enable another connection');
  });

  it('does not advise enabling another connection without sso.multi (409 LAST_SSO_CONNECTION on Business)', async () => {
    const server = setup({ features: ['sso'] });
    server.on('DELETE', `${CONNECTIONS}/${OIDC_ID}`, {
      status: 409,
      body: problem(409, 'LAST_SSO_CONNECTION'),
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    await click(fixture, button(root, 'Delete'));
    await answer(fixture, root, 'Delete');
    const alert = root.querySelector('[role="alert"]')?.textContent ?? '';
    expect(alert).toContain('This is the last enabled connection');
    expect(alert).toContain('Set password sign-in back to everyone first (Settings → Sign-in).');
    expect(alert).not.toContain('Enable another connection');
  });

  it('deletes nothing when the confirmation is cancelled', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    await click(fixture, button(root, 'Delete'));
    await answer(fixture, root, 'Cancel');
    expect(server.requestsTo('DELETE', `${CONNECTIONS}/${OIDC_ID}`)).toHaveLength(0);
  });

  it("shows the server's 422 on the field it names", async () => {
    const server = setup();
    server.on('PATCH', `${CONNECTIONS}/${OIDC_ID}`, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.oidc.issuer', message: 'The issuer URL: not https' },
      ]),
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    type(root, '#sso-issuer', 'http://idp.example.com');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#sso-issuer')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#sso-issuer-error')?.textContent).toContain(
      'exactly as the identity provider publishes it',
    );
  });

  it('shows a taken name on the name field and the public URL conflict at the top', async () => {
    const server = setup();
    server.on('PATCH', `${CONNECTIONS}/${OIDC_ID}`, {
      status: 409,
      body: problem(409, 'SSO_CONNECTION_NAME_TAKEN'),
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, OIDC_ID);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#sso-name-error')?.textContent).toContain(
      'Another connection has this name.',
    );

    server.on('PATCH', `${CONNECTIONS}/${OIDC_ID}`, {
      status: 409,
      body: problem(409, 'PUBLIC_URL_REQUIRED'),
    });
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('QUALOR_PUBLIC_URL');
  });
});

/** Connections 1 to n, OIDC, disabled unless the test says otherwise. */
function many(n: number): SsoConnection[] {
  return Array.from({ length: n }, (_, i) =>
    oidc({
      id: `0190a6c2-0000-7000-8000-0000000001${String(i).padStart(2, '0')}`,
      name: `Connection ${i + 1}`,
      enabled: false,
      inEffect: false,
    }),
  );
}

describe('SsoPage without sso.multi, and with it (sso-scim.md §4.4, §18)', () => {
  const ONE_LINE =
    'Your plan signs people in through one single sign-on connection at a time. Connecting several identity providers needs the Enterprise plan.';

  it('creates a second connection disabled without sso.multi, with the note', async () => {
    const server = setup();
    const created = oidc({
      id: '0190a6c2-0000-7000-8000-0000000000c3',
      name: 'Second SSO',
      enabled: false,
      inEffect: false,
    });
    server.on('POST', CONNECTIONS, { status: 201, body: created });
    const { fixture, root } = await render();
    expect(root.querySelector('#sso-multi-not-licensed')?.textContent?.trim()).toBe(ONE_LINE);
    expect(root.querySelector('#sso-count')).toBeNull();
    await click(fixture, button(root, 'Add an OpenID Connect connection'));
    const enabled = root.querySelector<HTMLInputElement>('#sso-enabled')!;
    expect(enabled.checked).toBe(false);
    expect(enabled.disabled).toBe(true);
    expect(enabled.getAttribute('aria-describedby')).toBe('sso-enabled-note');
    expect(root.querySelector('#sso-enabled-note')?.textContent).toContain(
      'It stays disabled while another connection is enabled.',
    );
    type(root, '#sso-name', 'Second SSO');
    type(root, '#sso-issuer', 'https://idp.example.com/realms/second');
    type(root, '#sso-client-id', 'qualor');
    type(root, '#sso-client-secret', SECRET);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const body = server.requestsTo('POST', CONNECTIONS)[0]?.body as { enabled: boolean };
    expect(body.enabled).toBe(false);
  });

  it('lets the first enabled connection be created without sso.multi', async () => {
    setup({ connections: [saml()] });
    const { fixture, root } = await render();
    await click(fixture, button(root, 'Add an OpenID Connect connection'));
    const enabled = root.querySelector<HTMLInputElement>('#sso-enabled')!;
    expect(enabled.disabled).toBe(false);
    expect(root.querySelector('#sso-enabled-note')).toBeNull();
  });

  it("disables a connection's Enabled switch while another is enabled without sso.multi", async () => {
    setup();
    const { fixture, root } = await render();
    await openRow(fixture, root, SAML_ID);
    const enabled = root.querySelector<HTMLInputElement>('#sso-enabled')!;
    expect(enabled.disabled).toBe(true);
    expect(enabled.checked).toBe(false);
    expect(root.querySelector('#sso-enabled-note')?.textContent).toContain(
      'It stays disabled while another connection is enabled.',
    );
    // The enabled one may still be switched off, which lets another take over.
    await openRow(fixture, root, OIDC_ID);
    expect(root.querySelector<HTMLInputElement>('#sso-enabled')?.disabled).toBe(false);
    expect(root.querySelector('#sso-enabled-note')).toBeNull();

    TestBed.resetTestingModule();
    setup({ features: ['sso', 'sso.multi'] });
    const second = await render();
    await openRow(second.fixture, second.root, SAML_ID);
    expect(second.root.querySelector<HTMLInputElement>('#sso-enabled')?.disabled).toBe(false);
    expect(second.root.querySelector('#sso-multi-not-licensed')).toBeNull();
  });

  it('marks an enabled connection that is not in effect', async () => {
    setup({ connections: [oidc(), saml({ enabled: true, inEffect: false })] });
    const { root } = await render();
    const row = (id: string) => panel(root, id)?.textContent?.replace(/\s+/g, ' ') ?? '';
    expect(row(SAML_ID)).toContain('Enabled');
    expect(row(SAML_ID)).toContain('Not in effect');
    expect(row(OIDC_ID)).not.toContain('Not in effect');
    expect(root.querySelector('#sso-not-in-effect')?.textContent).toContain(
      'Only the oldest enabled connection signs people in on your plan. Disable the one in effect to use this one instead, or restore the Enterprise plan.',
    );
  });

  it('says nothing about effect while every enabled connection is in effect', async () => {
    setup({
      features: ['sso', 'sso.multi'],
      connections: [oidc(), saml({ enabled: true, inEffect: true })],
    });
    const { root } = await render();
    expect(root.textContent).not.toContain('Not in effect');
    expect(root.querySelector('#sso-not-in-effect')).toBeNull();
  });

  it('allows ten connections with sso.multi', async () => {
    setup({ features: ['sso', 'sso.multi'], connections: many(9) });
    const { fixture, root } = await render();
    expect(root.querySelector('#sso-count')?.textContent?.trim()).toBe('9 of 10 connections');
    expect(button(root, 'Add a SAML connection')).toBeDefined();
    await click(fixture, button(root, 'Add a SAML connection'));
    expect(root.querySelector<HTMLInputElement>('#sso-enabled')?.disabled).toBe(false);

    TestBed.resetTestingModule();
    setup({ features: ['sso', 'sso.multi'], connections: many(10) });
    const full = await render();
    expect(full.root.querySelector('#sso-count')?.textContent?.trim()).toBe('10 of 10 connections');
    expect(button(full.root, 'Add a SAML connection')).toBeUndefined();
    expect(full.root.textContent).toContain('Qualor allows at most 10 connections.');
  });

  it('offers Add connection up to 10 connections without sso.multi too', async () => {
    setup({ connections: many(9) });
    const { root } = await render();
    expect(button(root, 'Add an OpenID Connect connection')).toBeDefined();
    TestBed.resetTestingModule();
    setup({ connections: many(10) });
    const full = await render();
    expect(button(full.root, 'Add an OpenID Connect connection')).toBeUndefined();
  });

  it('says why a second connection cannot be enabled (409 SSO_MULTI_NOT_LICENSED)', async () => {
    // Another admin enabled a connection meanwhile: the list here still shows none enabled.
    const server = setup({ connections: [oidc({ enabled: false, inEffect: false }), saml()] });
    server.on('PATCH', `${CONNECTIONS}/${SAML_ID}`, {
      status: 409,
      body: problem(409, 'SSO_MULTI_NOT_LICENSED'),
    });
    const { fixture, root } = await render();
    await openRow(fixture, root, SAML_ID);
    await click(fixture, root.querySelector<HTMLInputElement>('#sso-enabled')!);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const patch = server.requestsTo('PATCH', `${CONNECTIONS}/${SAML_ID}`)[0]?.body as {
      enabled: boolean;
    };
    expect(patch.enabled).toBe(true);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'Your plan allows one enabled single sign-on connection. Disable the enabled one first, or keep this one disabled; several enabled connections need the Enterprise plan.',
    );
  });
});

describe('Settings → Single sign-on, Sign-in and SCIM tabs (sso-scim.md §18)', () => {
  const ALL = ['sso', 'sign-in', 'scim'];

  function links(root: HTMLElement): string[] {
    return [...root.querySelectorAll('nav a')].map((a) => a.textContent?.trim() ?? '');
  }

  it('lists the three screens with their own labels for instance admins, once', async () => {
    setup({ features: ['sso', 'scim'], extensions: ALL });
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    const tabs = links(fixture.nativeElement as HTMLElement);
    expect(tabs).toEqual(expect.arrayContaining(['Single sign-on', 'Sign-in', 'SCIM']));
    expect(tabs.filter((t) => t.startsWith('Plugin label'))).toEqual([]);
  });

  it('lists SCIM only while scim is active, and none of them for other users', async () => {
    setup({ features: ['sso'], extensions: ALL });
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    expect(links(fixture.nativeElement as HTMLElement)).not.toContain('SCIM');
    TestBed.resetTestingModule();
    setup({ features: ['sso', 'scim'], extensions: ALL, admin: false });
    const member = TestBed.createComponent(SettingsPage);
    await settle(member);
    const tabs = links(member.nativeElement as HTMLElement);
    expect(tabs).not.toContain('Single sign-on');
    expect(tabs).not.toContain('Sign-in');
    expect(tabs).not.toContain('SCIM');
  });
});

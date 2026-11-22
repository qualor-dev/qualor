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
import { SessionStore } from '../auth/session';
import { AzureDevOpsPage } from './azure-devops.page';
import { azureProblemText, azureTestText } from './azure-text';
import type { Connection } from './gitlab.page';

const TENANT = '11111111-2222-4333-8444-555555555555';
const CLIENT = '66666666-7777-4888-8999-aaaaaaaaaaaa';

const PAT: Connection = {
  id: 'a1',
  organizationId: ORG_ID,
  provider: 'azure',
  baseUrl: 'https://dev.azure.com/acme',
  createdAt: '2026-09-20T10:00:00.000Z',
  github: null,
  gitlab: null,
  azure: {
    deployment: 'services',
    auth: 'pat',
    tenantId: null,
    clientId: null,
    credentialReadable: true,
    certificate: null,
  },
  ciSetup: { available: false, reason: 'not_allowed', missing: [] },
  fixMrsAllowed: false,
};

const CERTIFICATE: Connection = {
  ...PAT,
  id: 'a2',
  azure: {
    deployment: 'services',
    auth: 'service_principal_certificate',
    tenantId: TENANT,
    clientId: CLIENT,
    credentialReadable: true,
    certificate: { thumbprint: 'AB12CD34', notAfter: '2099-01-01T00:00:00.000Z' },
  },
};

const GITLAB: Connection = {
  ...PAT,
  id: 'g1',
  provider: 'gitlab',
  baseUrl: 'https://gitlab.example.com',
  azure: null,
};

// Assembled at run time, so the repository's own Gitleaks check finds no fake secret here.
const SECRET = ['azure-ui-', 'secret-value'].join('');
const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

type Stable = { whenStable(): Promise<unknown> };

function setup(connections: Connection[] = [PAT], admin = true): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
  server.on('GET', '/api/v0/scm-connections', () => ({ body: page(connections) }));
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin }));
  return server;
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

function button(root: HTMLElement, text: string, within: ParentNode = root): HTMLButtonElement {
  return [...within.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

function radio(root: HTMLElement, name: string, value: string): HTMLInputElement {
  return root.querySelector<HTMLInputElement>(
    `input[type="radio"][name="${name}"][value="${value}"]`,
  )!;
}

async function choose(fixture: Stable, input: HTMLInputElement) {
  input.checked = true;
  input.dispatchEvent(new Event('change'));
  await settle(fixture);
}

async function render() {
  const fixture = TestBed.createComponent(AzureDevOpsPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

async function openCreate(fixture: Stable, root: HTMLElement) {
  button(root, 'New connection').click();
  await settle(fixture);
}

async function submitCreate(fixture: Stable, root: HTMLElement) {
  root.querySelector<HTMLFormElement>('#create-dialog form')!.dispatchEvent(new Event('submit'));
  await settle(fixture);
}

const postsTo = (server: FakeServer) => server.requestsTo('POST', '/api/v0/scm-connections');

describe('AzureDevOpsPage', () => {
  it('lists only Azure DevOps connections, with what the row knows of them', async () => {
    setup([PAT, GITLAB, CERTIFICATE]);
    const { root } = await render();
    const rows = [...root.querySelectorAll('section.panel')];
    expect(rows).toHaveLength(2);
    expect(root.textContent).not.toContain('gitlab.example.com');
    const text = rows[1]?.textContent ?? '';
    expect(text).toContain('https://dev.azure.com/acme');
    expect(text).toContain('Service principal with a certificate');
    expect(text).toContain(CLIENT);
    expect(text).toContain('AB12CD34');
    expect(text).toContain('Jan 1, 2099');
    expect(rows[0]?.textContent).toContain('Personal access token');
    expect(root.querySelector('.alert-error')).toBeNull();
  });

  it('says so when there is none', async () => {
    setup([GITLAB]);
    const { root } = await render();
    expect(root.textContent).toContain('No Azure DevOps connection yet.');
  });

  it('offers nothing to a viewer', async () => {
    setup([PAT], false);
    const { root } = await render();
    expect(root.textContent).toContain('Only organization administrators connect Azure DevOps.');
    expect(root.querySelector('section.panel')).toBeNull();
  });

  it('warns about an unreadable credential and an expired certificate', async () => {
    setup([
      { ...PAT, azure: { ...PAT.azure!, credentialReadable: false } },
      {
        ...CERTIFICATE,
        azure: {
          ...CERTIFICATE.azure!,
          certificate: { thumbprint: 'OLD', notAfter: '2020-01-01T00:00:00.000Z' },
        },
      },
    ]);
    const { root } = await render();
    const [unreadable, expired] = [...root.querySelectorAll('section.panel')];
    expect(unreadable?.textContent).toContain('The stored credential can no longer be read');
    expect(expired?.querySelector('.alert-error')?.textContent).toContain('expired');
  });

  it('adds a personal access token: only its fields are sent, and the field is emptied', async () => {
    const server = setup([]);
    server.on('POST', '/api/v0/scm-connections', { status: 201, body: PAT });
    const { fixture, root } = await render();
    await openCreate(fixture, root);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#create-dialog')!;
    expect(dialog.open).toBe(true);
    await choose(fixture, radio(root, 'azure-kind', 'pat'));
    expect(root.querySelector('#azure-tenant')).toBeNull();
    type(root, '#azure-url', 'https://dev.azure.com/acme');
    const field = root.querySelector<HTMLInputElement>('#azure-credential')!;
    expect(field.type).toBe('password');
    expectNoPasswordManager(field);
    type(root, '#azure-credential', SECRET);
    await submitCreate(fixture, root);
    expect(postsTo(server)[0]?.body).toEqual({
      organizationId: ORG_ID,
      provider: 'azure',
      baseUrl: 'https://dev.azure.com/acme',
      azureAuth: 'pat',
      token: SECRET,
    });
    expect(root.querySelector<HTMLInputElement>('#azure-credential')?.value ?? '').toBe('');
    expect(root.textContent).not.toContain(SECRET);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Azure DevOps connection added.',
    );
    expect(dialog.open).toBe(false);
  });

  it('adds a service principal with a client secret', async () => {
    const server = setup([]);
    server.on('POST', '/api/v0/scm-connections', { status: 201, body: PAT });
    const { fixture, root } = await render();
    await openCreate(fixture, root);
    await choose(fixture, radio(root, 'azure-kind', 'service_principal_secret'));
    type(root, '#azure-url', 'https://dev.azure.com/acme');
    type(root, '#azure-tenant', TENANT);
    type(root, '#azure-client', CLIENT);
    type(root, '#azure-credential', SECRET);
    await submitCreate(fixture, root);
    expect(postsTo(server)[0]?.body).toEqual({
      organizationId: ORG_ID,
      provider: 'azure',
      baseUrl: 'https://dev.azure.com/acme',
      azureAuth: 'service_principal_secret',
      tenantId: TENANT,
      clientId: CLIENT,
      token: SECRET,
    });
    expect(root.querySelector<HTMLInputElement>('#azure-credential')?.value ?? '').toBe('');
  });

  it('adds a service principal with a certificate, pasted or picked from a file', async () => {
    const server = setup([]);
    server.on('POST', '/api/v0/scm-connections', { status: 201, body: CERTIFICATE });
    const { fixture, root } = await render();
    await openCreate(fixture, root);
    await choose(fixture, radio(root, 'azure-kind', 'service_principal_certificate'));
    type(root, '#azure-url', 'https://dev.azure.com/acme');
    type(root, '#azure-tenant', TENANT);
    type(root, '#azure-client', CLIENT);
    const file = root.querySelector<HTMLInputElement>('#azure-credential-file')!;
    Object.defineProperty(file, 'files', {
      value: [new File([PEM], 'cert.pem', { type: 'application/x-pem-file' })],
    });
    file.dispatchEvent(new Event('change'));
    await settle(fixture);
    expect(root.querySelector<HTMLTextAreaElement>('#azure-credential')?.value).toBe(PEM);
    await submitCreate(fixture, root);
    expect(postsTo(server)[0]?.body).toEqual({
      organizationId: ORG_ID,
      provider: 'azure',
      baseUrl: 'https://dev.azure.com/acme',
      azureAuth: 'service_principal_certificate',
      tenantId: TENANT,
      clientId: CLIENT,
      certificate: PEM,
    });
    expect(root.querySelector<HTMLTextAreaElement>('#azure-credential')?.value ?? '').toBe('');
  });

  it('refuses an empty address and credential and ids that are not GUIDs before any request', async () => {
    const server = setup([]);
    const { fixture, root } = await render();
    await openCreate(fixture, root);
    await choose(fixture, radio(root, 'azure-kind', 'service_principal_secret'));
    type(root, '#azure-tenant', 'not-a-guid');
    await submitCreate(fixture, root);
    expect(postsTo(server)).toHaveLength(0);
    for (const field of ['url', 'tenant', 'client', 'credential']) {
      expect(root.querySelector(`#azure-${field}`)?.getAttribute('aria-invalid')).toBe('true');
      expect(root.querySelector(`#azure-${field}-error`)).not.toBeNull();
    }
  });

  it('maps the server’s refusals to their fields, in the UI’s own words', async () => {
    const server = setup([]);
    server.on('POST', '/api/v0/scm-connections', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.baseUrl', message: 'The URL points at this machine' },
        { path: 'body.token', message: 'raw token text' },
        { path: 'body.tenantId', message: 'raw tenant text' },
        { path: 'body.clientId', message: 'raw client text' },
      ]),
    });
    const { fixture, root } = await render();
    await openCreate(fixture, root);
    await choose(fixture, radio(root, 'azure-kind', 'service_principal_secret'));
    type(root, '#azure-url', 'https://dev.azure.com/acme');
    type(root, '#azure-tenant', TENANT);
    type(root, '#azure-client', CLIENT);
    type(root, '#azure-credential', SECRET);
    await submitCreate(fixture, root);
    expect(postsTo(server)).toHaveLength(1);
    for (const field of ['url', 'tenant', 'client', 'credential']) {
      expect(root.querySelector(`#azure-${field}`)?.getAttribute('aria-invalid')).toBe('true');
    }
    expect(root.querySelector('#azure-url-error')?.textContent).toContain(
      'QUALOR_SCM_INTERNAL_HOSTS',
    );
    expect(root.textContent).not.toContain('The URL points at this machine');
    expect(root.textContent).not.toContain('raw token text');
    expect(root.querySelector<HTMLInputElement>('#azure-credential')?.value).toBe('');
  });

  it('maps a refused certificate and a refused authentication kind to their fields', async () => {
    const server = setup([]);
    server.on('POST', '/api/v0/scm-connections', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.certificate', message: 'raw certificate text' },
        { path: 'body.azureAuth', message: 'Azure DevOps Server takes a personal access token' },
      ]),
    });
    const { fixture, root } = await render();
    await openCreate(fixture, root);
    await choose(fixture, radio(root, 'azure-kind', 'service_principal_certificate'));
    type(root, '#azure-url', 'https://dev.azure.com/acme');
    type(root, '#azure-tenant', TENANT);
    type(root, '#azure-client', CLIENT);
    type(root, '#azure-credential', PEM);
    await submitCreate(fixture, root);
    expect(root.querySelector('#azure-credential-error')?.textContent).toContain('PEM');
    expect(root.querySelector('#azure-kind-error')?.textContent).toContain('personal access token');
    expect(root.textContent).not.toContain('raw certificate text');
  });

  it('disables the service principal kinds for an Azure DevOps Server address', async () => {
    const server = setup([]);
    const { fixture, root } = await render();
    await openCreate(fixture, root);
    type(root, '#azure-url', 'https://dev.azure.com/acme');
    await settle(fixture);
    expect(radio(root, 'azure-kind', 'service_principal_secret').disabled).toBe(false);
    type(root, '#azure-url', 'https://acme.visualstudio.com');
    await settle(fixture);
    expect(radio(root, 'azure-kind', 'service_principal_secret').disabled).toBe(false);
    type(root, '#azure-url', 'https://ado.example.com/DefaultCollection');
    await settle(fixture);
    expect(radio(root, 'azure-kind', 'service_principal_secret').disabled).toBe(true);
    expect(radio(root, 'azure-kind', 'service_principal_certificate').disabled).toBe(true);
    expect(radio(root, 'azure-kind', 'pat').disabled).toBe(false);
    expect(radio(root, 'azure-kind', 'pat').checked).toBe(true);
    expect(root.querySelector('#azure-kind-hint')?.textContent).toContain(
      'Azure DevOps Server takes a personal access token',
    );
    expect(root.querySelector('fieldset legend')?.textContent).toContain('Authentication');
    expect(postsTo(server)).toHaveLength(0);
  });

  it('tests a connection and says what it sees', async () => {
    const server = setup();
    let answer: unknown = {
      ok: true,
      user: { username: 'Qualor Bot' },
      project: null,
      problem: null,
      missingAccess: null,
      visible: { repositories: 12, projects: 3 },
    };
    server.on('POST', '/api/v0/scm-connections/a1/test', () => ({ body: answer }));
    const { fixture, root } = await render();
    const state = () => root.querySelector('section .connection-state')?.textContent?.trim();
    expect(state()).toBe('Not tested yet');
    button(root, 'Test').click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections/a1/test')[0]?.body).toEqual({});
    expect(state()).toBe('Connected');
    expect(root.querySelector('section')?.textContent).toContain(
      'Connected as Qualor Bot; 12 repositories in 3 projects visible',
    );
    answer = {
      ok: false,
      user: null,
      project: null,
      problem: { code: 'token_refused', message: 'raw (HTTP 401)' },
      missingAccess: null,
      visible: null,
    };
    button(root, 'Test').click();
    await settle(fixture);
    expect(state()).toBe('Test failed');
    expect(root.querySelector('section')?.textContent).not.toContain('HTTP 401');
    expect(root.querySelector('p[role="alert"]')?.textContent).toContain('refused the credential');
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe('');
  });

  it('words the counts of a test in the singular and the plural', () => {
    const text = (repositories: number, projects: number) =>
      azureTestText({
        ok: true,
        user: { username: 'Bot' },
        project: null,
        problem: null,
        missingAccess: null,
        visible: { repositories, projects },
      });
    expect(text(1, 1)).toBe('Connected as Bot; 1 repository in 1 project visible.');
    expect(text(0, 0)).toBe('Connected as Bot; 0 repositories in 0 projects visible.');
    expect(text(12, 3)).toBe('Connected as Bot; 12 repositories in 3 projects visible.');
  });

  it('words each problem code, and shows the server’s own text for a token endpoint refusal', () => {
    const codes = [
      'undecryptable',
      'url_not_allowed',
      'not_public',
      'unresolved',
      'timeout',
      'unreachable',
      'token_refused',
      'sign_in_required',
      'html_answer',
      'permission_missing',
      'not_found',
      'http_error',
      'bad_answer',
    ] as const;
    const texts = codes.map((code) => azureProblemText({ code, message: 'raw server text' }));
    expect(new Set(texts).size).toBe(codes.length);
    for (const text of texts) expect(text).not.toContain('raw server text');
    expect(texts[7]).toContain('sign-in');
    expect(texts[8]).toContain('web page');
    expect(
      azureProblemText({ code: 'token_endpoint', message: 'The stored certificate expired.' }),
    ).toBe('The stored certificate expired.');
    const result = azureTestText({
      ok: false,
      user: null,
      project: null,
      problem: { code: 'token_endpoint', message: 'The stored certificate expired.' },
      missingAccess: null,
      visible: null,
    });
    expect(result).toBe('The stored certificate expired.');
    expect(result).not.toContain('refused');
  });

  it('replaces a credential: the kind’s fields only, the field emptied, the old kind’s ids not sent', async () => {
    const server = setup([CERTIFICATE]);
    server.on('PATCH', '/api/v0/scm-connections/a2', { body: CERTIFICATE });
    const { fixture, root } = await render();
    const form = root.querySelector<HTMLFormElement>('details form')!;
    expect(root.querySelector<HTMLInputElement>('#row-a2-url')?.value).toBe(
      'https://dev.azure.com/acme',
    );
    expect(root.querySelector<HTMLInputElement>('#row-a2-tenant')?.value).toBe(TENANT);
    // The credential is never prefilled.
    expect(root.querySelector<HTMLTextAreaElement>('#row-a2-credential')?.value).toBe('');
    type(root, '#row-a2-credential', PEM);
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/a2')[0]?.body).toEqual({
      azureAuth: 'service_principal_certificate',
      tenantId: TENANT,
      clientId: CLIENT,
      certificate: PEM,
    });
    expect(root.querySelector<HTMLTextAreaElement>('#row-a2-credential')?.value).toBe('');
    // Moving to a token sends the token and nothing of the service principal.
    await choose(fixture, radio(root, 'row-a2-kind', 'pat'));
    type(root, '#row-a2-credential', SECRET);
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/a2')[1]?.body).toEqual({
      azureAuth: 'pat',
      token: SECRET,
    });
  });

  it('asks for the credential again when the address changes, and sends the new address with it', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/scm-connections/a1', { body: PAT });
    const { fixture, root } = await render();
    const form = root.querySelector<HTMLFormElement>('details form')!;
    type(root, '#row-a1-url', 'https://dev.azure.com/other');
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/a1')).toHaveLength(0);
    expect(root.querySelector('#row-a1-credential-error')?.textContent).toContain(
      'Changing the address needs the credential again',
    );
    type(root, '#row-a1-credential', SECRET);
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/a1')[0]?.body).toEqual({
      baseUrl: 'https://dev.azure.com/other',
      azureAuth: 'pat',
      token: SECRET,
    });
  });

  it('deletes a connection after the page’s own confirmation', async () => {
    let connections = [PAT];
    const server = setup();
    server.on('GET', '/api/v0/scm-connections', () => ({ body: page(connections) }));
    server.on('DELETE', '/api/v0/scm-connections/a1', () => {
      connections = [];
      return { status: 204 };
    });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    button(root, 'Delete').click();
    await settle(fixture);
    const ask = root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!;
    expect(ask.open).toBe(true);
    expect(ask.querySelector('#confirm-text')?.textContent).toContain(
      'Delete the Azure DevOps connection to https://dev.azure.com/acme?',
    );
    button(root, 'Cancel', ask).click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', '/api/v0/scm-connections/a1')).toHaveLength(0);
    button(root, 'Delete').click();
    await settle(fixture);
    button(root, 'Delete', ask).click();
    await settle(fixture);
    expect(confirm).not.toHaveBeenCalled();
    expect(server.requestsTo('DELETE', '/api/v0/scm-connections/a1')).toHaveLength(1);
    expect(root.textContent).toContain('No Azure DevOps connection yet.');
    confirm.mockRestore();
  });
});

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
import { OrgContext } from '../org/org-context';
import { AzureDevOpsPage } from './azure-devops.page';
import {
  azureBackgroundProblemText,
  azureCertificateExpiredOn,
  azureProblemText,
  azureTestText,
} from './azure-text';
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
    ciSetupAllowed: false,
    deployment: 'services',
    auth: 'pat',
    tenantId: null,
    clientId: null,
    credentialReadable: true,
    certificate: null,
    webhookSecretSet: false,
    webhookUrl: null,
    webhookSecretReadable: false,
    hooksCurrent: false,
    publicUrlHttps: true,
  },
  ciSetup: { available: false, reason: 'not_allowed', missing: [] },
  fixMrsAllowed: false,
  problem: null,
};

const CERTIFICATE: Connection = {
  ...PAT,
  id: 'a2',
  azure: {
    ciSetupAllowed: false,
    deployment: 'services',
    auth: 'service_principal_certificate',
    tenantId: TENANT,
    clientId: CLIENT,
    credentialReadable: true,
    certificate: { thumbprint: 'AB12CD34', notAfter: '2099-01-01T00:00:00.000Z' },
    webhookSecretSet: false,
    webhookUrl: null,
    webhookSecretReadable: false,
    hooksCurrent: false,
    publicUrlHttps: true,
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
    // The credential's facts sit under the address, as GitHub's App id does: a label and a value each.
    const squash = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
    const facts = [...rows[1]!.querySelectorAll('.connection-title dl.app-facts > div')].map(
      (pair) => [squash(pair.querySelector('dt')), squash(pair.querySelector('dd'))],
    );
    expect(facts.slice(0, 2)).toEqual([
      ['Authentication', 'Service principal with a certificate · Azure DevOps Services'],
      ['Client id', CLIENT],
    ]);
    expect(facts[2]?.[0]).toBe('Certificate');
    expect(facts[2]?.[1]).toContain('AB12CD34 expires Jan 1, 2099');
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

  it('shows the background problem of a connection in the UI’s own words, and a passing test clears it', async () => {
    const server = setup([
      { ...PAT, problem: { code: 'token_refused', at: '2026-11-23T10:00:00.000Z' } },
      { ...CERTIFICATE, problem: null },
    ]);
    server.on('POST', '/api/v0/scm-connections/a1/test', () => ({
      body: {
        ok: true,
        user: { username: 'Qualor Bot' },
        project: null,
        problem: null,
        missingAccess: null,
        visible: { repositories: 1, projects: 1 },
      },
    }));
    const { fixture, root } = await render();
    const banner = (key: string) =>
      root.querySelector(`section[data-key="${key}"] .connection-problem`)?.textContent ?? null;
    expect(banner('a1')).toContain('Problem since');
    expect(banner('a1')).toContain('refused the credential');
    expect(banner('a1')).not.toContain('token_refused');
    expect(banner('a2')).toBeNull();
    button(root.querySelector('section[data-key="a1"]')!, 'Test').click();
    await settle(fixture);
    expect(banner('a1')).toBeNull();
  });

  it('points a hook problem to the Service hooks button', async () => {
    setup([
      { ...PAT, problem: { code: 'hook_probation', at: '2026-11-23T10:00:00.000Z' } },
      { ...CERTIFICATE, problem: { code: 'hook_disabled', at: '2026-11-23T10:00:00.000Z' } },
    ]);
    const { root } = await render();
    const banner = (key: string) =>
      root.querySelector(`section[data-key="${key}"] .connection-problem`)?.textContent ?? '';
    expect(banner('a1')).toContain('on probation');
    expect(banner('a2')).toContain('disabled');
    for (const key of ['a1', 'a2']) {
      expect(banner(key)).toContain('Create or update Qualor');
      expect(banner(key)).not.toContain('_');
    }
  });

  it('advises Contribute to pull requests for a permission the decoration lacked, not the Test’s read access', async () => {
    setup([{ ...PAT, problem: { code: 'permission_missing', at: '2026-11-23T10:00:00.000Z' } }]);
    const { root } = await render();
    const banner =
      root.querySelector('section[data-key="a1"] .connection-problem')?.textContent ?? '';
    expect(banner).toContain('Problem since');
    expect(banner).toContain('Contribute to pull requests on the repository');
    expect(banner).toContain('Code: Read & write');
    expect(banner).not.toContain('read access to Code');
    // The Test reads only: its words stay.
    expect(azureProblemText({ code: 'permission_missing' })).toContain('read access to Code');
  });

  it('words the other background problems as the Test does', () => {
    for (const code of [
      'token_refused',
      'sign_in_required',
      'html_answer',
      'token_endpoint',
      'undecryptable',
      'url_not_allowed',
    ] as const) {
      expect(azureBackgroundProblemText({ code }), code).toBe(azureProblemText({ code }));
    }
    expect(azureBackgroundProblemText({ code: 'token_endpoint' }, '1 Dec 2026')).toBe(
      azureProblemText({ code: 'token_endpoint' }, '1 Dec 2026'),
    );
  });

  it('names an expired certificate and its day when Entra refuses the service principal', async () => {
    const server = setup([
      {
        ...CERTIFICATE,
        azure: {
          ...CERTIFICATE.azure!,
          certificate: { thumbprint: 'OLD', notAfter: '2020-01-01T00:00:00.000Z' },
        },
      },
    ]);
    server.on('POST', '/api/v0/scm-connections/a2/test', {
      body: {
        ok: false,
        user: null,
        project: null,
        problem: { code: 'token_endpoint', message: 'The stored certificate has expired' },
        missingAccess: null,
        visible: null,
      },
    });
    const { fixture, root } = await render();
    button(root, 'Test').click();
    await settle(fixture);
    expect(root.querySelector('p[role="alert"]')?.textContent).toContain(
      'The certificate expired on Jan 1, 2020.',
    );
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
        hooks: [],
      });
    expect(text(1, 1)).toBe('Connected as Bot; 1 repository in 1 project visible.');
    expect(text(0, 0)).toBe('Connected as Bot; 0 repositories in 0 projects visible.');
    expect(text(12, 3)).toBe('Connected as Bot; 12 repositories in 3 projects visible.');
  });

  it('words each problem code in the UI’s own words, never the server’s', () => {
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
      'token_endpoint',
      'permission_missing',
      'not_found',
      'http_error',
      'bad_answer',
    ] as const;
    const texts = codes.map((code) => azureProblemText({ code, message: 'raw server text' }));
    expect(new Set(texts).size).toBe(codes.length);
    for (const text of texts) expect(text).not.toContain('raw server text');
    // TF401444: the identity was never added, not a wrong credential.
    expect(texts[7]).toContain('not a member of this Azure DevOps organization');
    expect(texts[7]).toContain('Basic access level');
    expect(texts[7]).not.toContain('credential was not accepted');
    expect(texts[8]).toContain('web page');
    expect(texts[8]).toContain('Check the credential and the address');
    expect(texts[9]).toBe(
      'Microsoft Entra refused the service principal. Check the tenant id, client id and the secret or certificate.',
    );
  });

  it('names the cause when Microsoft Entra could not be reached, not Azure DevOps', () => {
    const text = (
      code: 'token_endpoint_unreachable' | 'token_endpoint_timeout' | 'token_endpoint_error',
    ) => azureProblemText({ code, message: 'raw server text' });
    expect(text('token_endpoint_unreachable')).toContain('Microsoft Entra could not be reached');
    expect(text('token_endpoint_timeout')).toContain('did not answer in time');
    expect(text('token_endpoint_error')).toContain('answered with an error');
    for (const code of [
      'token_endpoint_unreachable',
      'token_endpoint_timeout',
      'token_endpoint_error',
    ] as const) {
      expect(text(code)).not.toMatch(/refused|Azure DevOps (host|did)/);
    }
  });

  it('keys on the code, never on the words of the server message', () => {
    const misleading = 'Microsoft Entra could not be reached';
    expect(azureProblemText({ code: 'token_endpoint', message: misleading })).toBe(
      'Microsoft Entra refused the service principal. Check the tenant id, client id and the secret or certificate.',
    );
  });

  it('says a certificate expired, and when, only for a connection whose certificate has', () => {
    const entra = {
      code: 'token_endpoint',
      message: 'Microsoft Entra refused the service principal',
    } as const;
    const expired = { azure: { certificate: { notAfter: '2025-03-04T00:00:00.000Z' } } };
    const valid = { azure: { certificate: { notAfter: '2099-01-01T00:00:00.000Z' } } };
    const now = new Date('2026-11-22T00:00:00.000Z');
    expect(azureCertificateExpiredOn(expired, 'en-US', now)).toBe('Mar 4, 2025');
    expect(azureCertificateExpiredOn(valid, 'en-US', now)).toBeNull();
    expect(azureCertificateExpiredOn({ azure: null }, 'en-US', now)).toBeNull();
    expect(azureCertificateExpiredOn(undefined, 'en-US', now)).toBeNull();
    expect(azureProblemText(entra, 'Mar 4, 2025')).toBe(
      'The certificate expired on Mar 4, 2025. Replace it, then test again.',
    );
    const result = azureTestText(
      {
        ok: false,
        user: null,
        project: null,
        problem: entra,
        missingAccess: null,
        visible: null,
        hooks: null,
      },
      'Mar 4, 2025',
    );
    expect(result).toContain('expired on Mar 4, 2025');
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

describe('AzureDevOpsPage fix pull requests', () => {
  const LABEL = 'Allow fix pull requests';
  const nameOf = (input: HTMLInputElement | null) =>
    (input?.labels?.[0]?.querySelector('.sw-name')?.textContent ?? '').replace(/\s+/g, ' ').trim();

  it('the fix pull request switch patches fixMrsAllowed and shows the saved state', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/scm-connections/a1', {
      body: { ...PAT, fixMrsAllowed: true },
    });
    const { fixture, root } = await render();
    const toggle = root.querySelector<HTMLInputElement>('#fix-mrs-a1')!;
    expect(toggle.getAttribute('role')).toBe('switch');
    expect(nameOf(toggle)).toBe(LABEL);
    expect(toggle.checked).toBe(false);
    toggle.click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/a1').map((r) => r.body)).toEqual([
      { fixMrsAllowed: true },
    ]);
    expect(root.querySelector<HTMLInputElement>('#fix-mrs-a1')!.checked).toBe(true);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Fix pull requests are on for https://dev.azure.com/acme.',
    );
  });

  it('describes the switch in one sentence and links the guide for the details and rights', async () => {
    setup();
    const { root } = await render();
    const toggle = root.querySelector<HTMLInputElement>('#fix-mrs-a1')!;
    const help = root.querySelector('#fix-mrs-help-a1')!;
    expect(toggle.getAttribute('aria-describedby')).toBe('fix-mrs-help-a1');
    expect((help.textContent ?? '').replace(/\s+/g, ' ').trim()).toBe(
      'Projects that turn them on get pull requests that bump vulnerable dependencies. Details and the rights it needs',
    );
    const link = help.querySelector('a')!;
    expect(link.getAttribute('href')).toBe('/docs/azure-devops#fix-pull-requests');
    // The link is no part of the switch's name: the label holds the name alone.
    expect(toggle.labels?.[0]?.contains(link)).toBe(false);
    expect((toggle.labels?.[0]?.textContent ?? '').trim()).toBe(LABEL);
  });

  it('shows the saved state of a connection and puts the switch back when refused', async () => {
    const server = setup([{ ...PAT, fixMrsAllowed: true }]);
    server.on('PATCH', '/api/v0/scm-connections/a1', {
      status: 403,
      body: problem(403, 'FORBIDDEN'),
    });
    const { fixture, root } = await render();
    const toggle = root.querySelector<HTMLInputElement>('#fix-mrs-a1')!;
    expect(toggle.checked).toBe(true);
    toggle.click();
    await settle(fixture);
    expect(root.querySelector<HTMLInputElement>('#fix-mrs-a1')!.checked).toBe(true);
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
  });
});

describe('AzureDevOpsPage CI setup', () => {
  const LABEL = 'Allow Qualor to set up CI (opens pull requests, creates pipelines and policies)';
  const nameOf = (input: HTMLInputElement | null) =>
    (input?.labels?.[0]?.querySelector('.sw-name')?.textContent ?? '').replace(/\s+/g, ' ').trim();
  const withCi = (allowed: boolean): Connection => ({
    ...PAT,
    azure: { ...PAT.azure!, ciSetupAllowed: allowed },
  });

  it('the CI setup switch patches ciSetupAllowed and shows the saved state', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/scm-connections/a1', { body: withCi(true) });
    const { fixture, root } = await render();
    const toggle = root.querySelector<HTMLInputElement>('#ci-setup-a1')!;
    expect(toggle.getAttribute('role')).toBe('switch');
    expect(nameOf(toggle)).toBe(LABEL);
    expect(toggle.checked).toBe(false);
    toggle.click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/a1').map((r) => r.body)).toEqual([
      { ciSetupAllowed: true },
    ]);
    expect(root.querySelector<HTMLInputElement>('#ci-setup-a1')!.checked).toBe(true);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'CI setup is on for https://dev.azure.com/acme.',
    );
  });

  it('describes the switch in one sentence and links the guide for the details and rights', async () => {
    setup();
    const { root } = await render();
    const toggle = root.querySelector<HTMLInputElement>('#ci-setup-a1')!;
    const help = root.querySelector('#ci-setup-help-a1')!;
    expect(toggle.getAttribute('aria-describedby')).toBe('ci-setup-help-a1');
    expect((help.textContent ?? '').replace(/\s+/g, ' ').trim()).toBe(
      'When you add repositories, Qualor opens a pull request in each and creates its pipeline. Details and the rights it needs',
    );
    const link = help.querySelector('a')!;
    expect(link.getAttribute('href')).toBe('/docs/azure-devops#add-repositories-and-set-up-ci');
    expect(toggle.labels?.[0]?.contains(link)).toBe(false);
    expect((toggle.labels?.[0]?.textContent ?? '').replace(/\s+/g, ' ').trim()).toBe(LABEL);
  });

  it('shows the saved state and puts the switch back when refused', async () => {
    const server = setup([withCi(true)]);
    server.on('PATCH', '/api/v0/scm-connections/a1', {
      status: 403,
      body: problem(403, 'FORBIDDEN'),
    });
    const { fixture, root } = await render();
    const toggle = root.querySelector<HTMLInputElement>('#ci-setup-a1')!;
    expect(toggle.checked).toBe(true);
    toggle.click();
    await settle(fixture);
    expect(root.querySelector<HTMLInputElement>('#ci-setup-a1')!.checked).toBe(true);
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
  });
});

describe('AzureDevOpsPage service hooks', () => {
  const HTTPS_URL = 'https://qualor.example.com/api/v0/scm-connections/a1/azure-webhook';
  const SUBSCRIBE = "Create or update Qualor's subscriptions";
  const WITH_SECRET: Connection = {
    ...PAT,
    azure: {
      ...PAT.azure!,
      webhookSecretSet: true,
      webhookSecretReadable: true,
      hooksCurrent: true,
      webhookUrl: HTTPS_URL,
    },
  };
  /** Subscribed by hand, or a new password not yet given to Azure DevOps. */
  const NOT_CURRENT: Connection = {
    ...WITH_SECRET,
    azure: { ...WITH_SECRET.azure!, hooksCurrent: false },
  };
  const TEST_OK = {
    ok: true,
    user: { username: 'Qualor Bot' },
    project: null,
    problem: null,
    missingAccess: null,
    visible: { repositories: 2, projects: 2 },
  };
  const hooks = (root: HTMLElement) =>
    root.querySelector<HTMLElement>('section[data-key="a1"] .service-hooks')!;
  const text = (el: Element) => (el.textContent ?? '').replace(/\s+/g, ' ');
  const PASSWORD = ['hook-pass-', 'word-value'].join('');

  it('shows the hook state of each project after a Test, the stale one as an older password', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/test', () => ({
      body: {
        ...TEST_OK,
        hooks: [
          { projectId: 'proj-api', state: 'enabled' },
          { projectId: 'proj-docs', state: 'stale' },
          { projectId: 'proj-web', state: 'onProbation' },
          { projectId: 'proj-old', state: 'disabled' },
          { projectId: 'proj-new', state: 'missing' },
        ],
      },
    }));
    const { fixture, root } = await render();
    expect(text(hooks(root))).toContain('Service hooks');
    expect(text(hooks(root))).toContain('Test the connection to see');
    button(root, 'Test').click();
    await settle(fixture);
    const rows = [...hooks(root).querySelectorAll('li')].map((li) => text(li));
    expect(rows).toHaveLength(5);
    expect(rows[0]).toContain('proj-api');
    expect(rows[0]).toContain('Active');
    expect(rows[1]).toContain('proj-docs');
    expect(rows[1]).toContain('Older password');
    expect(rows[2]).toContain('On probation');
    expect(rows[3]).toContain('Switched off');
    expect(rows[4]).toContain('Not subscribed');
  });

  it('creates or updates the subscriptions and lists what happened in each project', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks', () => ({
      body: {
        projects: [
          { projectId: 'proj-api', comment: 'created', updated: 'replaced' },
          { projectId: 'proj-docs', comment: 'unchanged', updated: 'refused' },
        ],
      },
    }));
    const { fixture, root } = await render();
    button(hooks(root), SUBSCRIBE).click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections/a1/azure-hooks')).toHaveLength(1);
    const rows = [...hooks(root).querySelectorAll('.hook-outcomes li')].map((li) => text(li));
    expect(rows[0]).toContain('proj-api');
    expect(rows[0]).toContain('Comments: created');
    expect(rows[0]).toContain('pull request updates: replaced');
    expect(rows[1]).toContain('Comments: unchanged');
    expect(rows[1]).toContain('pull request updates: refused');
  });

  it('shows a new password once, with the address and the user, and forgets it on Done', async () => {
    const server = setup([NOT_CURRENT]);
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks/secret', () => ({
      body: { url: HTTPS_URL, user: 'qualor', password: PASSWORD },
    }));
    const { fixture, root } = await render();
    expect(root.textContent).not.toContain(PASSWORD);
    button(hooks(root), 'Show a new password').click();
    await settle(fixture);
    const url = root.querySelector<HTMLInputElement>('#hook-url-a1')!;
    const user = root.querySelector<HTMLInputElement>('#hook-user-a1')!;
    const password = root.querySelector<HTMLInputElement>('#hook-password-a1')!;
    expect([url.value, user.value, password.value]).toEqual([HTTPS_URL, 'qualor', PASSWORD]);
    expect(url.readOnly && user.readOnly && password.readOnly).toBe(true);
    expect(text(hooks(root))).toContain('Copy it now: it is shown only this once.');
    expect(text(hooks(root)).match(/Copy it now/g)).toHaveLength(1);
    button(hooks(root), 'Done').click();
    await settle(fixture);
    expect(root.querySelector('#hook-password-a1')).toBeNull();
    expect(root.textContent).not.toContain(PASSWORD);
  });

  it('FW14: disables the button without an https public URL and says why, with or without a password', async () => {
    const reason =
      'Azure DevOps sends service hooks with a password only to an https address. Set QUALOR_PUBLIC_URL to one; until then Qualor reads replies every 15 minutes.';
    const plain = { publicUrlHttps: false };
    for (const connection of [
      {
        ...WITH_SECRET,
        azure: { ...WITH_SECRET.azure!, ...plain, webhookUrl: 'http://q.example/x' },
      },
      { ...WITH_SECRET, azure: { ...WITH_SECRET.azure!, ...plain, webhookUrl: null } },
      { ...PAT, azure: { ...PAT.azure!, ...plain } },
    ]) {
      TestBed.resetTestingModule();
      const server = setup([connection]);
      const { fixture, root } = await render();
      const subscribe = button(hooks(root), SUBSCRIBE);
      expect(subscribe.disabled).toBe(true);
      expect(text(hooks(root))).toContain(reason);
      subscribe.click();
      await settle(fixture);
      expect(server.requestsTo('POST', '/api/v0/scm-connections/a1/azure-hooks')).toHaveLength(0);
    }
  });

  it('says the same when the server answers 409 PUBLIC_URL_NOT_HTTPS', async () => {
    const server = setup([PAT]);
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks', () => ({
      status: 409,
      body: problem(409, 'PUBLIC_URL_NOT_HTTPS'),
    }));
    const { fixture, root } = await render();
    button(hooks(root), SUBSCRIBE).click();
    await settle(fixture);
    expect(text(root.querySelector('p[role="alert"]')!)).toContain(
      'Set QUALOR_PUBLIC_URL to one; until then Qualor reads replies every 15 minutes.',
    );
  });

  it('on a 502 says some subscriptions may be written already, in its own words', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks', () => ({
      status: 502,
      body: { ...problem(502, 'SCM_UNAVAILABLE'), detail: 'raw Azure answer' },
    }));
    const { fixture, root } = await render();
    button(hooks(root), SUBSCRIBE).click();
    await settle(fixture);
    const alert = text(root.querySelector('p[role="alert"]')!);
    expect(alert).toContain('Some subscriptions may already be written');
    expect(alert).not.toContain('raw Azure answer');
  });

  it('warns that Azure DevOps may hold an older password, and about an unreadable one', async () => {
    setup([
      { ...WITH_SECRET, azure: { ...WITH_SECRET.azure!, hooksCurrent: false } },
      {
        ...WITH_SECRET,
        id: 'a3',
        azure: { ...WITH_SECRET.azure!, webhookSecretReadable: false, hooksCurrent: false },
      },
      { ...WITH_SECRET, id: 'a4' },
    ]);
    const { root } = await render();
    const blocks = [...root.querySelectorAll('.service-hooks')].map((el) => text(el));
    expect(blocks[0]).toContain(
      "Azure DevOps may hold an older password: create or update Qualor's subscriptions.",
    );
    expect(blocks[1]).toContain('The stored password can no longer be read');
    expect(blocks[1]).not.toContain('may hold an older password');
    expect(blocks[2]).not.toContain('older password');
  });

  it('shows the states of a Test after a subscribe, and after a 502', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/test', () => ({
      body: { ...TEST_OK, hooks: [{ projectId: 'proj-api', state: 'stale' }] },
    }));
    let fail = false;
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks', () =>
      fail
        ? { status: 502, body: problem(502, 'SCM_UNAVAILABLE') }
        : {
            body: { projects: [{ projectId: 'proj-api', comment: 'created', updated: 'created' }] },
          },
    );
    const { fixture, root } = await render();
    button(hooks(root), SUBSCRIBE).click();
    await settle(fixture);
    expect(text(hooks(root))).toContain('Comments: created');
    button(root, 'Test').click();
    await settle(fixture);
    expect(text(hooks(root))).toContain('Older password');
    expect(text(hooks(root))).not.toContain('Comments: created');
    button(hooks(root), SUBSCRIBE).click();
    await settle(fixture);
    fail = true;
    button(hooks(root), SUBSCRIBE).click();
    await settle(fixture);
    button(root, 'Test').click();
    await settle(fixture);
    expect(text(hooks(root))).toContain('Older password');
    expect(text(hooks(root))).not.toContain('Comments: created');
  });

  it('announces the outcomes politely', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks', () => ({
      body: { projects: [{ projectId: 'proj-api', comment: 'created', updated: 'created' }] },
    }));
    const { fixture, root } = await render();
    button(hooks(root), SUBSCRIBE).click();
    await settle(fixture);
    const live = hooks(root).querySelector('.hook-outcomes')!.closest('[aria-live]');
    expect(live?.getAttribute('aria-live')).toBe('polite');
  });

  it('forgets a shown password on subscribe, and a second one replaces the first', async () => {
    const server = setup([NOT_CURRENT]);
    const passwords = [PASSWORD, PASSWORD + '-2'];
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks/secret', () => ({
      body: { url: HTTPS_URL, user: 'qualor', password: passwords.shift()! },
    }));
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks', () => ({
      body: { projects: [] },
    }));
    const { fixture, root } = await render();
    button(hooks(root), 'Show a new password').click();
    await settle(fixture);
    button(hooks(root), 'Show a new password').click();
    await settle(fixture);
    expect(root.querySelector<HTMLInputElement>('#hook-password-a1')!.value).toBe(PASSWORD + '-2');
    expect(root.textContent).not.toContain(PASSWORD + '-3');
    button(hooks(root), SUBSCRIBE).click();
    await settle(fixture);
    expect(root.querySelector('#hook-password-a1')).toBeNull();
  });

  it('shows a reader the states but no buttons', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/test', () => ({
      body: { ...TEST_OK, hooks: [{ projectId: 'proj-api', state: 'stale' }] },
    }));
    vi.spyOn(TestBed.inject(OrgContext), 'canChange').mockReturnValue(false);
    const { fixture, root } = await render();
    button(root, 'Test').click();
    await settle(fixture);
    expect(text(hooks(root))).toContain('Older password');
    expect(button(hooks(root), SUBSCRIBE)).toBeUndefined();
    expect(button(hooks(root), 'Show a new password')).toBeUndefined();
  });

  it('FW8: a passing Test clears a credential problem on the page but keeps a hook problem', async () => {
    const AT = '2026-11-23T10:00:00.000Z';
    const server = setup([
      { ...WITH_SECRET, problem: { code: 'hook_disabled', at: AT } },
      { ...WITH_SECRET, id: 'a5', problem: { code: 'sign_in_required', at: AT } },
    ]);
    for (const id of ['a1', 'a5']) {
      server.on('POST', `/api/v0/scm-connections/${id}/test`, () => ({
        body: { ...TEST_OK, hooks: [] },
      }));
    }
    const { fixture, root } = await render();
    const banner = (key: string) =>
      root.querySelector(`section[data-key="${key}"] .connection-problem`)?.textContent ?? null;
    for (const id of ['a1', 'a5']) {
      button(root.querySelector(`section[data-key="${id}"]`)!, 'Test').click();
      await settle(fixture);
    }
    expect(banner('a1')).toContain('disabled');
    expect(banner('a5')).toBeNull();
  });

  it('FW9: after a passing Test whose subscriptions could not be read, says so instead of asking for a Test', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/test', () => ({
      body: { ...TEST_OK, hooks: null },
    }));
    const { fixture, root } = await render();
    button(root, 'Test').click();
    await settle(fixture);
    expect(text(hooks(root))).toContain(
      'Qualor could not read the subscriptions from Azure DevOps.',
    );
    expect(text(hooks(root))).not.toContain('Test the connection to see');
  });

  it('FW10: asks before a new password replaces one Azure DevOps holds, and sends nothing on Cancel', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks/secret', () => ({
      body: { url: HTTPS_URL, user: 'qualor', password: PASSWORD },
    }));
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    const ask = root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!;
    const secrets = () =>
      server.requestsTo('POST', '/api/v0/scm-connections/a1/azure-hooks/secret');
    button(hooks(root), 'Show a new password').click();
    await settle(fixture);
    expect(ask.open).toBe(true);
    expect(text(ask)).toContain('Qualor refuses every delivery');
    expect(secrets()).toHaveLength(0);
    button(root, 'Cancel', ask).click();
    await settle(fixture);
    expect(ask.open).toBe(false);
    expect(secrets()).toHaveLength(0);
    button(hooks(root), 'Show a new password').click();
    await settle(fixture);
    button(root, 'Show a new password', ask).click();
    await settle(fixture);
    expect(secrets()).toHaveLength(1);
    expect(root.querySelector<HTMLInputElement>('#hook-password-a1')!.value).toBe(PASSWORD);
    expect(server.requestsTo('DELETE', '/api/v0/scm-connections/a1')).toHaveLength(0);
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it('FW10: shows a new password at once while Azure DevOps may hold another', async () => {
    const server = setup([NOT_CURRENT]);
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks/secret', () => ({
      body: { url: HTTPS_URL, user: 'qualor', password: PASSWORD },
    }));
    const { fixture, root } = await render();
    button(hooks(root), 'Show a new password').click();
    await settle(fixture);
    expect(root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!.open).toBe(false);
    expect(root.querySelector<HTMLInputElement>('#hook-password-a1')!.value).toBe(PASSWORD);
  });

  it('FW14: a new password with an address that is not https says why next to it, once', async () => {
    const httpUrl = 'http://qualor.example.com/api/v0/azure-devops/webhooks/a1';
    const plain = { ...NOT_CURRENT, azure: { ...NOT_CURRENT.azure!, publicUrlHttps: false } };
    const server = setup([plain]);
    server.on('POST', '/api/v0/scm-connections/a1/azure-hooks/secret', () => ({
      body: { url: httpUrl, user: 'qualor', password: PASSWORD },
    }));
    const { fixture, root } = await render();
    button(hooks(root), 'Show a new password').click();
    await settle(fixture);
    expect(root.querySelector<HTMLInputElement>('#hook-url-a1')!.value).toBe(httpUrl);
    const block = hooks(root).querySelector('.webhook-address')!;
    expect(text(block)).toContain('only to an https address');
    expect(text(hooks(root)).match(/only to an https address/g)).toHaveLength(1);
    const reason = root.querySelector('#hooks-reason-a1');
    expect(button(hooks(root), SUBSCRIBE).getAttribute('aria-describedby')).toBe('hooks-reason-a1');
    expect(block.contains(reason)).toBe(true);
  });

  it('FW4: a passing Test says when the identity cannot read who may change findings', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/test', () => ({
      body: { ...TEST_OK, missingAccess: ['read_permissions'], hooks: [] },
    }));
    const { fixture, root } = await render();
    button(root, 'Test').click();
    await settle(fixture);
    const result = text(root.querySelector('section[data-key="a1"] .connection-result')!);
    expect(result).toContain('Connected as Qualor Bot');
    expect(result).toContain('cannot read who may change findings');
    expect(result).toContain('Project Administrators');
    expect(result).not.toContain('read_permissions');
  });

  it('FB8: a passing Test says when the identity cannot create work items', async () => {
    const server = setup([WITH_SECRET]);
    server.on('POST', '/api/v0/scm-connections/a1/test', () => ({
      body: { ...TEST_OK, missingAccess: ['read_permissions', 'work_items'], hooks: [] },
    }));
    const { fixture, root } = await render();
    button(root, 'Test').click();
    await settle(fixture);
    const result = text(root.querySelector('section[data-key="a1"] .connection-result')!);
    expect(result).toContain('Connected as Qualor Bot');
    expect(result).toContain(
      'Create work items in the mapped Azure Boards project (Work items: Read & write)',
    );
    expect(result).toContain('Project Administrators');
    expect(result).not.toContain('work_items');
  });
});

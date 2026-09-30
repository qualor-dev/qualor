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
import { testProblemText } from './gitlab-text';
import { type Connection, GitLabPage } from './gitlab.page';

const CONNECTION: Connection = {
  id: 'c1',
  organizationId: ORG_ID,
  provider: 'gitlab',
  baseUrl: 'https://gitlab.example.com',
  createdAt: '2026-09-20T10:00:00.000Z',
  github: null,
};

const GITHUB: Connection = {
  id: 'g1',
  organizationId: ORG_ID,
  provider: 'github',
  baseUrl: 'https://api.github.com',
  createdAt: '2026-09-20T10:00:00.000Z',
  github: {
    appId: '123456',
    keyReadable: true,
    webhookSecretSet: false,
    webhookSecretReadable: false,
    webhookUrl: null,
  },
};

function project(id: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    organizationId: ORG_ID,
    key: `acme/${id}`,
    name: `Project ${id}`,
    mainBranchName: 'main',
    qualityGateId: null,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    mainBranch: null,
    ...overrides,
  };
}

function setup(admin = true): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
  server.on('GET', '/api/v0/scm-connections', { body: page([CONNECTION]) });
  server.on('GET', '/api/v0/projects', { body: page([project('p1')]) });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin }));
  return server;
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

function button(root: HTMLElement, text: string, within: ParentNode = root): HTMLButtonElement {
  return [...within.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

async function render() {
  const fixture = TestBed.createComponent(GitLabPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

describe('GitLabPage (scm.md §2)', () => {
  it('adds a connection: the token is sent once, never shown, and the field is emptied', async () => {
    const server = setup();
    server.on('POST', '/api/v0/scm-connections', {
      status: 201,
      body: { ...CONNECTION, id: 'c2' },
    });
    const { fixture, root } = await render();
    expect(root.querySelector('section')?.textContent).toContain('https://gitlab.example.com');
    // Step 8: the short create form is in the New connection dialog.
    const create = root.querySelector<HTMLDialogElement>('dialog#create-dialog')!;
    button(root, 'New connection').click();
    await settle(fixture);
    expect(create.open).toBe(true);
    const token = root.querySelector<HTMLInputElement>('#gitlab-token')!;
    expect(token.type).toBe('password');
    expect(token.getAttribute('autocomplete')).toBe('new-password');
    expectNoPasswordManager(token);
    type(root, '#gitlab-url', 'https://gitlab.acme.test');
    type(root, '#gitlab-token', 'glpat-secret-value');
    root.querySelector<HTMLFormElement>('#create-dialog form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections')[0]?.body).toEqual({
      organizationId: ORG_ID,
      provider: 'gitlab',
      baseUrl: 'https://gitlab.acme.test',
      token: 'glpat-secret-value',
    });
    expect(token.value).toBe('');
    expect(root.textContent).not.toContain('glpat-secret-value');
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'GitLab connection added.',
    );
    expect(create.open).toBe(false);
  });

  it('maps a refused address and token to their fields, in the UI’s own words', async () => {
    const server = setup();
    server.on('POST', '/api/v0/scm-connections', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.baseUrl', message: 'The URL points at this machine' },
      ]),
    });
    const { fixture, root } = await render();
    type(root, '#gitlab-url', 'https://localhost');
    type(root, '#gitlab-token', 'glpat-x');
    root.querySelector<HTMLFormElement>('#create-dialog form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#gitlab-url')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#gitlab-url-error')?.textContent).toContain(
      'QUALOR_SCM_INTERNAL_HOSTS',
    );
    expect(root.textContent).not.toContain('The URL points at this machine');
    // A missing token is refused before any request.
    type(root, '#gitlab-token', '');
    root.querySelector<HTMLFormElement>('#create-dialog form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#gitlab-token-error')?.textContent).toContain(
      'Paste the access token',
    );
    expect(server.requestsTo('POST', '/api/v0/scm-connections')).toHaveLength(1);
  });

  it('tests a connection and says what went wrong without GitLab’s own words', async () => {
    const server = setup();
    let answer: unknown = {
      ok: true,
      user: { username: 'project_7_bot' },
      project: null,
      problem: null,
    };
    server.on('POST', '/api/v0/scm-connections/c1/test', () => ({ body: answer }));
    const { fixture, root } = await render();
    const state = () => root.querySelector('section .connection-state')?.textContent?.trim();
    expect(state()).toBe('Not tested yet');
    button(root, 'Test').click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections/c1/test')[0]?.body).toEqual({});
    expect(state()).toBe('Connected');
    expect(root.querySelector('section')?.textContent).toContain('Connected as project_7_bot.');
    answer = {
      ok: false,
      user: null,
      project: null,
      problem: { code: 'token_refused', message: 'GitLab refused the token (HTTP 401)' },
    };
    button(root, 'Test').click();
    await settle(fixture);
    const text = root.querySelector('section')?.textContent;
    expect(text).toContain(testProblemText('token_refused'));
    expect(text).not.toContain('HTTP 401');
    expect(state()).toBe('Test failed');
    // A failed test reads as the failure it is, never in the green news of a success.
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe('');
    expect(root.querySelector('p[role="alert"]')?.textContent).toContain(
      testProblemText('token_refused'),
    );
    // A 403 is a missing permission of a valid token, in words of its own.
    expect(testProblemText('permission_missing')).toContain('Maintainer role');
  });

  it("replaces a token without echoing it, and deletes a connection after the page's own confirmation", async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/scm-connections/c1', { body: CONNECTION });
    let connections = [CONNECTION];
    server.on('GET', '/api/v0/scm-connections', () => ({ body: page(connections) }));
    server.on('DELETE', '/api/v0/scm-connections/c1', () => {
      connections = [];
      return { status: 204 };
    });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    const field = root.querySelector<HTMLInputElement>('#token-c1')!;
    field.value = 'glpat-new';
    field.closest('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/c1')[0]?.body).toEqual({
      token: 'glpat-new',
    });
    expect(field.value).toBe('');
    button(root, 'Delete').click();
    await settle(fixture);
    const ask = root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!;
    expect(ask.open).toBe(true);
    expect(ask.querySelector('#confirm-text')?.textContent?.trim()).toBe(
      'Delete the GitLab connection to https://gitlab.example.com? Its projects stop being decorated.',
    );
    button(root, 'Delete', ask).click();
    await settle(fixture);
    expect(confirm).not.toHaveBeenCalled();
    expect(server.requestsTo('DELETE', '/api/v0/scm-connections/c1')).toHaveLength(1);
    expect(root.textContent).toContain('No GitLab connection yet.');
    confirm.mockRestore();
  });

  it('asks for the token again when the address changes, and names the address it replaces (scm.md §2.1)', async () => {
    const server = setup();
    let status = 422;
    server.on('PATCH', '/api/v0/scm-connections/c1', (request) =>
      status === 422
        ? {
            status,
            body: problem(422, 'VALIDATION_FAILED', [
              { path: 'body.token', message: 'Changing the base URL needs the token' },
            ]),
          }
        : { body: { ...CONNECTION, baseUrl: (request.body as { baseUrl: string }).baseUrl } },
    );
    const { fixture, root } = await render();
    const form = root.querySelector<HTMLInputElement>('#token-c1')!.closest('form')!;
    // The form says which connection's token it replaces, and that a new address needs it.
    expect(form.textContent).toContain('https://gitlab.example.com');
    expect(form.textContent).toContain('Changing the address needs the token again');
    expect(root.querySelector<HTMLInputElement>('#url-c1')?.value).toBe(
      'https://gitlab.example.com',
    );
    // Another address without a token is refused before any request, on the token field.
    type(root, '#url-c1', 'https://gitlab.other.test');
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/c1')).toHaveLength(0);
    const token = root.querySelector<HTMLInputElement>('#token-c1')!;
    expect(token.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#token-error-c1')?.textContent).toContain(
      'Changing the address needs the token again',
    );
    expect(document.activeElement).toBe(token);
    // The server's 422 on body.token lands on the same field, in the UI's words.
    token.value = 'glpat-new';
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/c1')[0]?.body).toEqual({
      baseUrl: 'https://gitlab.other.test',
      token: 'glpat-new',
    });
    expect(token.value).toBe('');
    expect(root.querySelector('#token-error-c1')?.textContent).toContain(
      'Changing the address needs the token again',
    );
    expect(root.textContent).not.toContain('Changing the base URL needs the token');
    status = 200;
    token.value = 'glpat-new';
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(token.value).toBe('');
    expect(root.textContent).not.toContain('glpat-new');
    expect(root.querySelector('section')?.getAttribute('aria-label')).toBe(
      'https://gitlab.other.test',
    );
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'The connection now points at https://gitlab.other.test.',
    );
  });

  it('says what a connection’s own form replaces: its token, and its address when changed', async () => {
    setup();
    const { root } = await render();
    const form = root.querySelector<HTMLInputElement>('#token-c1')!.closest('form')!;
    expect(form.textContent?.replace(/\s+/g, ' ')).toContain(
      'Replacing https://gitlab.example.com (token and address)',
    );
  });

  it('lists only GitLab connections', async () => {
    const server = setup();
    server.on('GET', '/api/v0/scm-connections', { body: page([CONNECTION, GITHUB]) });
    const { root } = await render();
    const cards = root.querySelectorAll('.connection-list section.card');
    expect(cards).toHaveLength(1);
    expect(cards[0]?.textContent).toContain('https://gitlab.example.com');
    expect(cards[0]?.textContent).not.toContain('api.github.com');
  });

  it('leaves the project mapping to Repositories, and links to it', async () => {
    setup();
    const { root } = await render();
    expect(root.querySelector('table')).toBeNull();
    expect(root.querySelector('a[href="/settings/repositories"]')?.textContent?.trim()).toBe(
      'Repositories',
    );
  });

  it('tells a member who is not an organization admin, and asks the server nothing', async () => {
    const server = setup(false);
    const { root } = await render();
    expect(root.textContent).toContain('Only organization administrators connect GitLab.');
    expect(server.requestsTo('GET', '/api/v0/scm-connections')).toHaveLength(0);
    expect(root.querySelector('form')).toBeNull();
  });
});

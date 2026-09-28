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
import { type Connection, GitLabPage, testProblemText } from './gitlab.page';

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

function choose(root: HTMLElement, selector: string, value: string): void {
  const select = root.querySelector<HTMLSelectElement>(selector)!;
  select.value = value;
  select.dispatchEvent(new Event('change'));
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
    const token = root.querySelector<HTMLInputElement>('#gitlab-token')!;
    expect(token.type).toBe('password');
    expect(token.getAttribute('autocomplete')).toBe('new-password');
    expectNoPasswordManager(token);
    type(root, '#gitlab-url', 'https://gitlab.acme.test');
    type(root, '#gitlab-token', 'glpat-secret-value');
    root.querySelector<HTMLFormElement>('form.card')!.dispatchEvent(new Event('submit'));
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
    root.querySelector<HTMLFormElement>('form.card')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#gitlab-url')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#gitlab-url-error')?.textContent).toContain(
      'QUALOR_SCM_INTERNAL_HOSTS',
    );
    expect(root.textContent).not.toContain('The URL points at this machine');
    // A missing token is refused before any request.
    type(root, '#gitlab-token', '');
    root.querySelector<HTMLFormElement>('form.card')!.dispatchEvent(new Event('submit'));
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
    button(root, 'Test').click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections/c1/test')[0]?.body).toEqual({});
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
  });

  it('replaces a token without echoing it, and deletes a connection after a confirmation', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/scm-connections/c1', { body: CONNECTION });
    let connections = [CONNECTION];
    server.on('GET', '/api/v0/scm-connections', () => ({ body: page(connections) }));
    server.on('DELETE', '/api/v0/scm-connections/c1', () => {
      connections = [];
      return { status: 204 };
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(true);
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
    expect(confirm).toHaveBeenCalledWith(
      'Delete the GitLab connection to https://gitlab.example.com? Its projects stop being decorated.',
    );
    expect(server.requestsTo('DELETE', '/api/v0/scm-connections/c1')).toHaveLength(1);
    expect(root.textContent).toContain('No GitLab connection yet.');
    confirm.mockRestore();
  });

  it('maps a project to a connection and a GitLab project, checks it, and shows a refused path', async () => {
    const server = setup();
    let status = 200;
    server.on('PATCH', '/api/v0/projects/p1', (request) =>
      status === 200
        ? {
            body: project('p1', {
              scmConnectionId: (request.body as { scmConnectionId: string }).scmConnectionId,
              scmProjectRef: (request.body as { scmProjectRef: string }).scmProjectRef,
            }),
          }
        : {
            status,
            body: problem(422, 'VALIDATION_FAILED', [
              { path: 'body.scmProjectRef', message: 'Use the GitLab project id' },
            ]),
          },
    );
    server.on('POST', '/api/v0/scm-connections/c1/test', {
      body: {
        ok: true,
        user: { username: 'bot' },
        project: { id: 7, pathWithNamespace: 'acme/api' },
        problem: null,
      },
    });
    const { fixture, root } = await render();
    const row = root.querySelector('tbody tr')!;
    // Check needs a connection and a project first.
    expect(button(root, 'Check', row).getAttribute('aria-disabled')).toBe('true');
    choose(root, '#conn-p1', 'c1');
    type(root, '#ref-p1', 'acme/api');
    await settle(fixture);
    button(root, 'Check', row).click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections/c1/test')[0]?.body).toEqual({
      projectRef: 'acme/api',
    });
    expect(row.textContent).toContain('Connected as bot; the project acme/api is reachable.');
    button(root, 'Save', row).click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/projects/p1')[0]?.body).toEqual({
      scmConnectionId: 'c1',
      scmProjectRef: 'acme/api',
    });
    expect(row.textContent).toContain('Decorated in GitLab.');
    status = 422;
    type(root, '#ref-p1', 'acme');
    button(root, 'Save', row).click();
    await settle(fixture);
    expect(root.querySelector('#ref-p1')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#ref-error-p1')?.textContent).toContain(
      'Use the GitLab project id or its full path',
    );
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

  it('drops a check answer when the mapping changed while it was on its way', async () => {
    const server = setup();
    let answer: (reply: { body: unknown }) => void = () => undefined;
    server.on(
      'POST',
      '/api/v0/scm-connections/c1/test',
      () =>
        new Promise((resolve) => {
          answer = resolve;
        }),
    );
    const { fixture, root } = await render();
    const row = root.querySelector('tbody tr')!;
    choose(root, '#conn-p1', 'c1');
    type(root, '#ref-p1', 'acme/api');
    await settle(fixture);
    button(root, 'Check', row).click();
    await settle(fixture);
    type(root, '#ref-p1', 'acme/web');
    answer({
      body: {
        ok: true,
        user: { username: 'bot' },
        project: { id: 7, pathWithNamespace: 'acme/api' },
        problem: null,
      },
    });
    await settle(fixture);
    expect(row.textContent).not.toContain('Connected as bot');
  });

  it('announces a check’s answer, and drops a refusal for a mapping edited while it was on its way', async () => {
    const server = setup();
    let answer: (reply: { status?: number; body: unknown }) => void = () => undefined;
    server.on(
      'POST',
      '/api/v0/scm-connections/c1/test',
      () =>
        new Promise((resolve) => {
          answer = resolve;
        }),
    );
    const { fixture, root } = await render();
    const row = root.querySelector('tbody tr')!;
    choose(root, '#conn-p1', 'c1');
    type(root, '#ref-p1', 'acme/api');
    await settle(fixture);
    button(root, 'Check', row).click();
    await settle(fixture);
    answer({
      body: {
        ok: true,
        user: { username: 'bot' },
        project: { id: 7, pathWithNamespace: 'acme/api' },
        problem: null,
      },
    });
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Connected as bot; the project acme/api is reachable.',
    );
    // A refusal of a reference that is no longer the one on screen does not mark the field.
    button(root, 'Check', row).click();
    await settle(fixture);
    type(root, '#ref-p1', 'acme/web');
    answer({
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.projectRef', message: 'Use the GitLab project id' },
      ]),
    });
    await settle(fixture);
    expect(root.querySelector('#ref-p1')?.getAttribute('aria-invalid')).toBeNull();
    expect(root.querySelector('#ref-error-p1')).toBeNull();
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
    const cards = root.querySelectorAll('section.card');
    expect(cards).toHaveLength(1);
    expect(cards[0]?.textContent).toContain('https://gitlab.example.com');
    expect(cards[0]?.textContent).not.toContain('api.github.com');
  });

  it('maps a project to a GitHub connection with the owner/repo hint', async () => {
    const server = setup();
    server.on('GET', '/api/v0/scm-connections', { body: page([CONNECTION, GITHUB]) });
    let status = 200;
    server.on('PATCH', '/api/v0/projects/p1', (request) =>
      status === 200
        ? {
            body: project('p1', {
              scmConnectionId: (request.body as { scmConnectionId: string }).scmConnectionId,
              scmProjectRef: (request.body as { scmProjectRef: string }).scmProjectRef,
            }),
          }
        : {
            status,
            body: problem(422, 'VALIDATION_FAILED', [
              { path: 'body.scmProjectRef', message: 'Use owner/repo' },
            ]),
          },
    );
    const { fixture, root } = await render();
    const options = [...root.querySelectorAll<HTMLOptionElement>('#conn-p1 option')].map((o) =>
      o.textContent?.trim(),
    );
    expect(options).toEqual([
      'None',
      'GitLab · https://gitlab.example.com',
      'GitHub · https://api.github.com (App 123456)',
    ]);
    const ref = root.querySelector<HTMLInputElement>('#ref-p1')!;
    expect(ref.placeholder).toBe('group/project');
    choose(root, '#conn-p1', 'g1');
    await settle(fixture);
    expect(ref.placeholder).toBe('owner/repo');
    expect(root.querySelector('#ref-hint-p1')?.textContent).toContain('owner/repo');
    expect(ref.getAttribute('aria-describedby')).toBe('ref-hint-p1');
    type(root, '#ref-p1', 'acme/api');
    const row = root.querySelector('tbody tr')!;
    button(root, 'Save', row).click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/projects/p1')[0]?.body).toEqual({
      scmConnectionId: 'g1',
      scmProjectRef: 'acme/api',
    });
    expect(row.textContent).toContain('Decorated in GitHub.');
    status = 422;
    type(root, '#ref-p1', '42');
    button(root, 'Save', row).click();
    await settle(fixture);
    expect(root.querySelector('#ref-error-p1')?.textContent).toContain('Use owner/repo');
  });

  it('tells a member who is not an organization admin, and asks the server nothing', async () => {
    const server = setup(false);
    const { root } = await render();
    expect(root.textContent).toContain('Only organization administrators connect GitLab.');
    expect(server.requestsTo('GET', '/api/v0/scm-connections')).toHaveLength(0);
    expect(root.querySelector('form')).toBeNull();
  });
});

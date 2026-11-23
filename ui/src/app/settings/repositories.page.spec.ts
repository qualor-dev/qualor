import { noAnswerYet } from '../../testing/pending';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import type { Connection } from './gitlab.page';
import { testProblemText } from './gitlab-text';
import { RepositoriesPage } from './repositories.page';

const CONNECTION: Connection = {
  id: 'c1',
  organizationId: ORG_ID,
  provider: 'gitlab',
  baseUrl: 'https://gitlab.example.com',
  createdAt: '2026-09-20T10:00:00.000Z',
  github: null,
  gitlab: {
    webhookSecretSet: false,
    webhookSecretReadable: false,
    webhookUrl: null,
    ciSetupAllowed: false,
  },
  azure: null,
  ciSetup: { available: false, reason: 'not_allowed', missing: [] },
  fixMrsAllowed: false,
  problem: null,
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
  gitlab: null,
  azure: null,
  ciSetup: { available: false, reason: 'missing_permissions', missing: [] },
  fixMrsAllowed: false,
  problem: null,
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
  const fixture = TestBed.createComponent(RepositoriesPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

describe('RepositoriesPage (scm.md §2.3, github.md §2.3)', () => {
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
        project: { id: 7, pathWithNamespace: 'acme/api', accessLevel: 30 },
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
    // A Developer's token: comments work, a status on a protected branch would be refused.
    expect(row.textContent).toContain('The token is below Maintainer');
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

  it('drops a check answer when the mapping changed while it was on its way', async () => {
    const server = setup();
    let answer: (reply: { body: unknown }) => void = noAnswerYet;
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
        project: { id: 7, pathWithNamespace: 'acme/api', accessLevel: 40 },
        problem: null,
      },
    });
    await settle(fixture);
    expect(row.textContent).not.toContain('Connected as bot');
  });

  it('announces a check’s answer, and drops a refusal for a mapping edited while it was on its way', async () => {
    const server = setup();
    let answer: (reply: { status?: number; body: unknown }) => void = noAnswerYet;
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
        project: { id: 7, pathWithNamespace: 'acme/api', accessLevel: 40 },
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

  it('says a failed check in the error colour, not in the green news', async () => {
    const server = setup();
    server.on('POST', '/api/v0/scm-connections/c1/test', {
      body: { ok: false, user: null, project: null, problem: { code: 'not_found', message: 'x' } },
    });
    const { fixture, root } = await render();
    const row = root.querySelector('tbody tr')!;
    choose(root, '#conn-p1', 'c1');
    type(root, '#ref-p1', 'acme/api');
    await settle(fixture);
    button(root, 'Check', row).click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe('');
    expect(root.querySelector('p[role="alert"]')?.textContent).toContain(
      testProblemText('not_found'),
    );
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
    // No connection chosen yet: no provider's example.
    expect(ref.placeholder).toBe('');
    choose(root, '#conn-p1', 'c1');
    await settle(fixture);
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

  it('a mapping whose connection is unknown shows no provider hint and the generic placeholder', async () => {
    const server = setup();
    server.on('GET', '/api/v0/projects', {
      body: page([project('p1', { scmConnectionId: 'gone', scmProjectRef: 'acme/api' })]),
    });
    const { root } = await render();
    const ref = root.querySelector<HTMLInputElement>('#ref-p1')!;
    expect(ref.placeholder).toBe('');
    expect(root.querySelector('#ref-hint-p1')?.textContent?.trim()).toBe('');
    expect(root.querySelector('label[for="ref-p1"]')?.textContent).not.toMatch(/GitLab|GitHub/);
    // Check has nothing to test against: it is disabled, not a silent no-op.
    expect(button(root, 'Check').getAttribute('aria-disabled')).toBe('true');
  });

  it('points to GitLab, GitHub and Azure DevOps while the organization has no connection', async () => {
    const server = setup();
    server.on('GET', '/api/v0/scm-connections', { body: page([]) });
    const { root } = await render();
    const note = root.querySelector('#repositories-no-connection');
    expect(note?.textContent).toContain('Connect GitLab, GitHub or Azure DevOps first');
    const links = [...(note?.querySelectorAll('a') ?? [])].map((a) => a.getAttribute('href'));
    expect(links).toEqual(['/settings/gitlab', '/settings/github', '/settings/azure-devops']);
  });

  it('tells a member who is not an organization admin, and asks the server nothing', async () => {
    const server = setup(false);
    const { root } = await render();
    expect(root.textContent).toContain(
      'Only organization administrators map projects to repositories.',
    );
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(0);
    expect(root.querySelector('table')).toBeNull();
  });
});

describe('RepositoriesPage with Azure DevOps', () => {
  const GUID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
  const AZURE: Connection = {
    ...CONNECTION,
    id: 'a1',
    provider: 'azure',
    baseUrl: 'https://dev.azure.com/acme',
    gitlab: null,
    azure: {
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
  };

  function azureSetup(): FakeServer {
    const server = setup();
    server.on('GET', '/api/v0/scm-connections', { body: page([CONNECTION, AZURE]) });
    server.on('GET', '/api/v0/scm-connections/a1/repositories', {
      body: {
        items: [
          {
            ref: GUID,
            name: 'Shop/api',
            defaultBranch: 'main',
            language: null,
            archived: false,
            project: null,
          },
          {
            ref: '11111111-2222-4333-8444-555555555555',
            name: 'Shop/web',
            defaultBranch: 'main',
            language: null,
            archived: false,
            project: null,
          },
        ],
        hasMore: false,
      },
    });
    return server;
  }

  it('offers the connection’s repositories in a list and saves the repository id', async () => {
    const server = azureSetup();
    server.on('PATCH', '/api/v0/projects/p1', (request) => ({
      body: project('p1', request.body as Record<string, unknown>),
    }));
    const { fixture, root } = await render();
    const row = root.querySelector('tbody tr')!;
    expect(root.querySelector('#conn-p1')?.textContent).toContain(
      'Azure DevOps · https://dev.azure.com/acme',
    );
    choose(root, '#conn-p1', 'a1');
    await settle(fixture);
    const select = root.querySelector<HTMLSelectElement>('select#ref-p1')!;
    expect(root.querySelector('input#ref-p1')).toBeNull();
    expect(server.requestsTo('GET', '/api/v0/scm-connections/a1/repositories')).toHaveLength(1);
    expect([...select.options].map((o) => o.textContent?.trim())).toEqual([
      'Choose a repository',
      'Shop / api',
      'Shop / web',
    ]);
    choose(root, 'select#ref-p1', GUID);
    await settle(fixture);
    button(root, 'Save', row).click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/projects/p1')[0]?.body).toEqual({
      scmConnectionId: 'a1',
      scmProjectRef: GUID,
    });
    expect(row.textContent).toContain('Mapped to Azure DevOps.');
  });

  it('checks the chosen repository and words the answer for Azure DevOps', async () => {
    const server = azureSetup();
    server.on('POST', '/api/v0/scm-connections/a1/test', {
      body: {
        ok: true,
        user: { username: 'Qualor Bot' },
        project: { id: GUID, pathWithNamespace: 'Shop/api', accessLevel: null },
        problem: null,
        missingAccess: null,
        visible: null,
      },
    });
    const { fixture, root } = await render();
    const row = root.querySelector('tbody tr')!;
    choose(root, '#conn-p1', 'a1');
    await settle(fixture);
    choose(root, 'select#ref-p1', GUID);
    await settle(fixture);
    button(root, 'Check', row).click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections/a1/test')[0]?.body).toEqual({
      projectRef: GUID,
    });
    expect(row.textContent).toContain(
      'Connected as Qualor Bot; the repository Shop/api is reachable.',
    );
  });

  it('keeps an already mapped repository selectable while the list is on its way', async () => {
    const server = azureSetup();
    server.on('GET', '/api/v0/projects', {
      body: page([
        project('p1', {
          scmConnectionId: 'a1',
          scmProjectRef: 'ffffffff-0000-4000-8000-000000000000',
        }),
      ]),
    });
    const { root } = await render();
    expect(server.requestsTo('GET', '/api/v0/scm-connections/a1/repositories')).toHaveLength(1);
    const select = root.querySelector<HTMLSelectElement>('select#ref-p1')!;
    expect(select.value).toBe('ffffffff-0000-4000-8000-000000000000');
  });

  it('says so when the list cannot be read', async () => {
    const server = azureSetup();
    server.on('GET', '/api/v0/scm-connections/a1/repositories', {
      status: 502,
      body: problem(502, 'SCM_UNREACHABLE'),
    });
    const { fixture, root } = await render();
    choose(root, '#conn-p1', 'a1');
    await settle(fixture);
    expect(root.querySelector('tbody tr')?.textContent).toContain(
      'The repositories could not be listed',
    );
  });

  it('searches the list on the server and says when more remain than were listed', async () => {
    const server = azureSetup();
    let full = true;
    server.on('GET', '/api/v0/scm-connections/a1/repositories', (request) => {
      const filter = request.query.get('filter');
      const page = Number(request.query.get('page'));
      if (filter) {
        return {
          body: {
            items: [
              {
                ref: GUID,
                name: 'Shop/api',
                defaultBranch: null,
                language: null,
                archived: false,
                project: null,
              },
            ],
            hasMore: false,
          },
        };
      }
      return {
        body: {
          items: [
            {
              ref: `id-${page}`,
              name: `Shop/r${page}`,
              defaultBranch: null,
              language: null,
              archived: false,
              project: null,
            },
          ],
          hasMore: full,
        },
      };
    });
    const { fixture, root } = await render();
    choose(root, '#conn-p1', 'a1');
    await settle(fixture);
    expect(server.requestsTo('GET', '/api/v0/scm-connections/a1/repositories')).toHaveLength(10);
    expect(root.querySelector('#ref-hint-p1')?.textContent).toContain('Showing the first 10');
    full = false;
    type(root, '#search-p1', 'api');
    root.querySelector('#search-p1')!.dispatchEvent(new Event('change'));
    await settle(fixture);
    const requests = server.requests.filter((r) => r.query.get('filter') === 'api');
    expect(requests).toHaveLength(1);
    expect(
      [...root.querySelectorAll<HTMLOptionElement>('select#ref-p1 option')].map((o) =>
        o.textContent?.trim(),
      ),
    ).toEqual(['Choose a repository', 'Shop / api']);
    expect(root.querySelector('#ref-hint-p1')?.textContent?.trim()).toBe('');
  });

  it('lists again after a failed list, when the connection is chosen again', async () => {
    const server = azureSetup();
    let failing = true;
    server.on('GET', '/api/v0/scm-connections/a1/repositories', () =>
      failing
        ? { status: 502, body: problem(502, 'SCM_UNREACHABLE') }
        : { body: { items: [], hasMore: false } },
    );
    const { fixture, root } = await render();
    choose(root, '#conn-p1', 'a1');
    await settle(fixture);
    expect(root.querySelector('#ref-hint-p1')?.textContent).toContain('could not be listed');
    failing = false;
    choose(root, '#conn-p1', '');
    await settle(fixture);
    choose(root, '#conn-p1', 'a1');
    await settle(fixture);
    expect(server.requestsTo('GET', '/api/v0/scm-connections/a1/repositories')).toHaveLength(2);
    expect(root.querySelector('#ref-hint-p1')?.textContent?.trim()).toBe('');
  });

  it('clears a reference of another provider when the connection changes provider', async () => {
    azureSetup();
    const { fixture, root } = await render();
    choose(root, '#conn-p1', 'c1');
    await settle(fixture);
    type(root, '#ref-p1', 'acme/api');
    choose(root, '#conn-p1', 'a1');
    await settle(fixture);
    const select = root.querySelector<HTMLSelectElement>('select#ref-p1')!;
    expect([...select.options].map((o) => o.value)).not.toContain('acme/api');
    expect(select.value).toBe('');
    // Within one provider the reference stays.
    choose(root, '#conn-p1', 'c1');
    await settle(fixture);
    type(root, '#ref-p1', 'acme/web');
    choose(root, '#conn-p1', 'c1');
    await settle(fixture);
    expect(root.querySelector<HTMLInputElement>('input#ref-p1')?.value).toBe('acme/web');
  });
});

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
import { RepositoriesPage } from './repositories.page';

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
        project: { id: 7, pathWithNamespace: 'acme/api', accessLevel: 40 },
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

  it('points to GitLab and GitHub while the organization has no connection', async () => {
    const server = setup();
    server.on('GET', '/api/v0/scm-connections', { body: page([]) });
    const { root } = await render();
    const note = root.querySelector('#repositories-no-connection');
    expect(note?.textContent).toContain('Connect GitLab or GitHub first');
    const links = [...(note?.querySelectorAll('a') ?? [])].map((a) => a.getAttribute('href'));
    expect(links).toEqual(['/settings/gitlab', '/settings/github']);
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

import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
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
import { type Project, ProjectsPage } from './projects.page';

function project(id: string, name: string, overrides: Partial<Project> = {}): Project {
  return {
    id,
    organizationId: ORG_ID,
    key: `acme/${id}`,
    name,
    mainBranchName: 'main',
    qualityGateId: null,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '2026-09-01T00:00:00.000Z',
    updatedAt: '2026-09-01T00:00:00.000Z',
    mainBranch: {
      id: `${id}-main`,
      name: 'main',
      gateStatus: 'failed',
      lastAnalysisId: `${id}-a1`,
      lastAnalyzedAt: '2026-09-15T09:00:00.000Z',
      measures: { issues: 9, coverage: 65.74, duplicated_lines_density: 1.25, ncloc: 12345 },
    },
    permissions: ['project.read'],
    ...overrides,
  };
}

describe('ProjectsPage', () => {
  let server: FakeServer;

  function configure(admin: boolean) {
    server = new FakeServer();
    server.on('GET', '/api/v0/organizations', {
      body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
    });
    TestBed.configureTestingModule({
      imports: [ProjectsPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me({ admin }));
  }

  beforeEach(() => configure(true));

  async function render(q?: string) {
    const fixture = TestBed.createComponent(ProjectsPage);
    if (q !== undefined) fixture.componentRef.setInput('q', q);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  const type = (root: HTMLElement, id: string, value: string) => {
    const input = root.querySelector<HTMLInputElement>(id)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
  };

  it('lists projects of the current organization with gate and formatted measures', async () => {
    server.on('GET', '/api/v0/projects', {
      body: page([
        project('payments', 'Payments API'),
        project('legacy', 'Legacy Billing', { mainBranch: null }),
      ]),
    });
    const { root } = await render();
    const rows = [...root.querySelectorAll('tbody tr')].map((tr) =>
      [...tr.querySelectorAll('td')].map((td) => td.textContent?.replace(/\s+/g, ' ').trim()),
    );
    expect(rows[0]?.slice(0, 6)).toEqual([
      'Payments APIacme/payments',
      'Failed',
      '9',
      '65.7 %',
      '1.3 %',
      '12,345',
    ]);
    expect(rows[1]).toEqual([
      'Legacy Billingacme/legacy',
      'Not analyzed',
      '–',
      '–',
      '–',
      '–',
      'Never',
    ]);
    expect(server.requestsTo('GET', '/api/v0/projects')[0]?.query.get('organizationId')).toBe(
      ORG_ID,
    );
  });

  it('pages with "Load more" and searches through the URL', async () => {
    server.on('GET', '/api/v0/projects', (request) =>
      request.query.get('cursor') === 'next'
        ? { body: page([project('b', 'Beta')]) }
        : { body: page([project('a', 'Alpha')], 'next') },
    );
    const { fixture, root } = await render('al');
    expect(server.requestsTo('GET', '/api/v0/projects')[0]?.query.get('q')).toBe('al');
    const more = [...root.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Load more'),
    );
    more!.click();
    await settle(fixture);
    expect([...root.querySelectorAll('tbody tr a')].map((a) => a.textContent)).toEqual([
      'Alpha',
      'Beta',
    ]);
    const input = root.querySelector<HTMLInputElement>('#projects-search')!;
    input.value = 'pay';
    input.dispatchEvent(new Event('input'));
    root.querySelector('form[role="search"]')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?q=pay');
  });

  it('keeps "Load more" focusable while the next page loads', async () => {
    let answer: (reply: { body: unknown }) => void = () => undefined;
    server.on('GET', '/api/v0/projects', (request) =>
      request.query.get('cursor') === 'next'
        ? new Promise((resolve) => (answer = resolve))
        : { body: page([project('a', 'Alpha')], 'next') },
    );
    const { fixture, root } = await render();
    const more = [...root.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Load more'),
    )!;
    more.focus();
    more.click();
    await settle(fixture);
    expect(more.disabled).toBe(false);
    expect(more.getAttribute('aria-disabled')).toBe('true');
    expect(document.activeElement).toBe(more);
    more.click();
    await settle(fixture);
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(2);
    answer({ body: page([project('b', 'Beta')]) });
    await settle(fixture);
  });

  it('sends the search text encoded, as typed, and within the API limit', async () => {
    server.on('GET', '/api/v0/projects', { body: page([]) });
    const tricky = 'a&b=c #/%20?x';
    await render(tricky);
    const request = server.requestsTo('GET', '/api/v0/projects')[0]!;
    expect(request.query.get('q')).toBe(tricky);
    expect([...request.query.keys()].sort()).toEqual(['limit', 'organizationId', 'q']);
    expect(request.query.get('limit')).toBe('50');

    const { root } = await render('x'.repeat(400));
    expect(server.requestsTo('GET', '/api/v0/projects')[1]?.query.get('q')).toBe('x'.repeat(255));
    expect(root.querySelector('#projects-search')?.getAttribute('maxlength')).toBe('255');
  });

  it('renders server text only as text, and a failed load as an alert', async () => {
    server.on('GET', '/api/v0/projects', {
      body: page([project('x', '<img src=x onerror="alert(1)">')]),
    });
    const { root } = await render();
    expect(root.querySelector('tbody tr a')?.textContent).toBe('<img src=x onerror="alert(1)">');
    expect(root.querySelector('tbody img')).toBeNull();

    server.on('GET', '/api/v0/projects', { status: 500, body: problem(500, 'INTERNAL') });
    const failed = await render();
    expect(failed.root.querySelector('[role="alert"]')?.textContent).toContain('HTTP 500');
  });

  it('lets an organization admin create a project and opens it', async () => {
    server.on('GET', '/api/v0/projects', { body: page([]) });
    server.on('POST', '/api/v0/projects', { status: 201, body: project('new', 'New Service') });
    const { fixture, root } = await render();
    expect(root.textContent).toContain('No projects match.');
    type(root, '#project-key', 'acme/new');
    type(root, '#project-name', 'New Service');
    root.querySelector('details form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/projects')[0]?.body).toEqual({
      organizationId: ORG_ID,
      key: 'acme/new',
      name: 'New Service',
    });
    expect(TestBed.inject(Router).url).toBe('/projects/new');
  });

  it('explains a taken key', async () => {
    server.on('GET', '/api/v0/projects', { body: page([]) });
    server.on('POST', '/api/v0/projects', {
      status: 409,
      body: problem(409, 'PROJECT_KEY_TAKEN'),
    });
    const { fixture, root } = await render();
    type(root, '#project-key', 'acme/payments');
    type(root, '#project-name', 'Payments');
    root.querySelector('details form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('details [role="alert"]')?.textContent).toBe(
      'A project with this key already exists.',
    );
  });

  it('puts a taken key, a refused key and a refused name on their fields, and focuses the first', async () => {
    server.on('GET', '/api/v0/projects', { body: page([]) });
    let reply = { status: 409, body: problem(409, 'PROJECT_KEY_TAKEN') as unknown };
    server.on('POST', '/api/v0/projects', () => reply);
    const { fixture, root } = await render();
    root.querySelector('details')!.open = true;
    const submit = () => root.querySelector('details form')!.dispatchEvent(new Event('submit'));
    type(root, '#project-key', 'acme/payments');
    type(root, '#project-name', 'Payments');
    submit();
    await settle(fixture);
    const key = root.querySelector<HTMLInputElement>('#project-key')!;
    const name = root.querySelector<HTMLInputElement>('#project-name')!;
    expect(key.getAttribute('aria-invalid')).toBe('true');
    expect(key.getAttribute('aria-describedby')).toBe('project-key-error project-key-hint');
    expect(root.querySelector('#project-key-error')?.getAttribute('role')).toBe('alert');
    expect(root.querySelector('#project-key-error')?.textContent).toBe(
      'A project with this key already exists.',
    );
    expect(document.activeElement).toBe(key);
    expect(name.getAttribute('aria-invalid')).toBeNull();
    // Typing in the field clears its error.
    type(root, '#project-key', 'acme/payments-2');
    await settle(fixture);
    expect(root.querySelector('#project-key-error')).toBeNull();

    reply = {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.key', message: 'Invalid' },
        { path: 'body.name', message: 'Too long' },
      ]),
    };
    submit();
    await settle(fixture);
    expect(root.querySelector('#project-key-error')?.textContent).toBe(
      'Use letters, digits and . _ - / : for the key.',
    );
    expect(name.getAttribute('aria-invalid')).toBe('true');
    expect(name.getAttribute('aria-describedby')).toBe('project-name-error');
    expect(root.querySelector('#project-name-error')?.textContent).toContain(
      'Enter a name of at most 255 characters',
    );
    // The server's English messages are never shown.
    expect(root.textContent).not.toContain('Too long');
    expect(document.activeElement).toBe(key);
  });

  it('checks for a blank key or name before asking the server', async () => {
    server.on('GET', '/api/v0/projects', { body: page([]) });
    const { fixture, root } = await render();
    type(root, '#project-key', 'acme/new');
    type(root, '#project-name', '   ');
    root.querySelector('details form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/projects')).toHaveLength(0);
    expect(root.querySelector('#project-name-error')?.textContent).toBe('Enter a name.');
    expect(root.querySelector('#project-key-error')).toBeNull();
    type(root, '#project-key', ' ');
    root.querySelector('details form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#project-key-error')?.textContent).toBe('Enter a key.');
  });

  it('keeps the submit button focusable while creating, and announces the result', async () => {
    server.on('GET', '/api/v0/projects', { body: page([]) });
    let answer: (reply: { status: number; body: unknown }) => void = () => undefined;
    server.on('POST', '/api/v0/projects', () => new Promise((resolve) => (answer = resolve)));
    const { fixture, root } = await render();
    const status = root.querySelector('[role="status"]');
    expect(status).not.toBeNull();
    type(root, '#project-key', 'acme/new');
    type(root, '#project-name', 'New Service');
    const button = root.querySelector<HTMLButtonElement>('details form button[type="submit"]')!;
    root.querySelector('details form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    // A second submit while the first runs sends nothing.
    root.querySelector('details form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/projects')).toHaveLength(1);
    answer({ status: 201, body: project('new', 'New Service') });
    await settle(fixture);
    expect(root.querySelector('[role="status"]')).toBe(status);
    expect(status?.textContent).toContain('Project New Service created.');
    expect(button.getAttribute('aria-disabled')).toBeNull();
  });

  it('offers project creation to organization admins only', async () => {
    TestBed.resetTestingModule();
    configure(false);
    server.on('GET', '/api/v0/projects', { body: page([project('a', 'Alpha')]) });
    const { root } = await render();
    expect(root.querySelector('tbody tr a')?.textContent).toBe('Alpha');
    expect(root.querySelector('details')).toBeNull();
    expect(root.querySelector('#project-key')).toBeNull();
    expect(root.textContent).not.toContain('New project');
  });
});

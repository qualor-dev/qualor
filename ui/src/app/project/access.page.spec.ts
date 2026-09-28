import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  MEMBER_PROJECT_PERMISSIONS,
  ORG_ADMIN_PERMISSIONS,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import type { ProjectGrant } from '../api/types';
import { SessionStore } from '../auth/session';
import { AccessPage } from './access.page';
import { ProjectPage } from './project.page';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const BOB = '0190a6c2-0000-7000-8000-00000000000b';
const CAROL = '0190a6c2-0000-7000-8000-00000000000c';
const MEMBERS = `/api/v0/projects/${PROJECT}/members`;

function grant(userId: string, username: string, role: ProjectGrant['role']): ProjectGrant {
  return { userId, username, displayName: null, role, createdAt: '2026-09-01T00:00:00.000Z' };
}

interface Setup {
  /** The caller's role in the project's organisation (never an instance admin here). */
  role?: 'admin' | 'member';
  /** The active enterprise features; none (the community edition) by default. */
  features?: string[];
  grants?: ProjectGrant[];
}

function setup(options: Setup = {}): FakeServer {
  const server = new FakeServer();
  const role = options.role ?? 'admin';
  server.on('GET', '/api/v0/organizations', {
    body: page([
      {
        id: ORG_ID,
        key: 'default',
        name: 'Default',
        createdAt: '',
        updatedAt: '',
      },
    ]),
  });
  server.on('GET', '/api/v0/system/info', {
    body: {
      version: '0.1.0',
      edition: options.features?.length ? 'enterprise' : 'community',
      features: options.features ?? [],
      extensions: [],
    },
  });
  server.on('GET', `/api/v0/projects/${PROJECT}`, {
    body: {
      id: PROJECT,
      organizationId: ORG_ID,
      key: 'acme/payments',
      name: 'Payments',
      mainBranchName: 'main',
      qualityGateId: null,
      newCodeDefinition: null,
      scmConnectionId: null,
      scmProjectRef: null,
      createdAt: '',
      updatedAt: '',
      permissions: [...MEMBER_PROJECT_PERMISSIONS],
    },
  });
  server.on('GET', MEMBERS, {
    body: page(options.grants ?? [grant(BOB, 'bob', 'viewer')]),
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  const base = me();
  TestBed.inject(SessionStore).set({
    ...base,
    memberships: [
      {
        ...base.memberships[0]!,
        role,
        permissions: role === 'admin' ? [...ORG_ADMIN_PERMISSIONS] : ['org.read'],
      },
    ],
  });
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(AccessPage);
  fixture.componentRef.setInput('projectId', PROJECT);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
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

function row(root: HTMLElement, userId: string): HTMLElement {
  return root.querySelector<HTMLElement>(`tr[data-key="${userId}"]`)!;
}

function button(root: HTMLElement, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

describe('AccessPage (rbac-audit.md §16, §17)', () => {
  it("lists the project's grants with their role labels, and says organization roles apply on top", async () => {
    setup({ grants: [grant(BOB, 'bob', 'viewer'), grant(CAROL, 'carol', 'project_admin')] });
    const { root } = await render();
    expect(row(root, BOB).textContent).toContain('bob');
    expect(row(root, BOB).querySelector('select')?.value).toBe('viewer');
    expect(
      [...row(root, CAROL).querySelectorAll('option')].map((o) => o.textContent?.trim()),
    ).toEqual(['Project admin', 'Maintainer', 'Viewer']);
    expect(root.textContent).toContain('Organization roles apply on top of these.');
    expect(root.textContent).toContain('2 grants');
  });

  it('adds a grant: looks the name up, then sends PUT with the chosen role', async () => {
    const server = setup({ grants: [] });
    server.on('GET', '/api/v0/users/lookup', {
      body: { id: CAROL, username: 'carol', displayName: 'Carol' },
    });
    server.on('PUT', `${MEMBERS}/${CAROL}`, { body: grant(CAROL, 'carol', 'member') });
    const { fixture, root } = await render();
    expect(root.textContent).toContain('No one has a role on this project alone yet.');
    type(root, '#grant-username', ' carol ');
    choose(root, '#grant-role', 'member');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(
      server.requestsTo('GET', '/api/v0/users/lookup').map((r) => r.query.get('username')),
    ).toEqual(['carol']);
    expect(server.requestsTo('PUT', `${MEMBERS}/${CAROL}`).map((r) => r.body)).toEqual([
      { role: 'member' },
    ]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'carol now has the role Maintainer on this project.',
    );
    expect(root.querySelector<HTMLInputElement>('#grant-username')?.value).toBe('');
  });

  it('offers Viewer first for a new grant, and refuses an unknown name on the field', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users/lookup', { status: 404, body: problem(404, 'NOT_FOUND') });
    const { fixture, root } = await render();
    expect(root.querySelector<HTMLSelectElement>('#grant-role')?.value).toBe('viewer');
    type(root, '#grant-username', 'nobody');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const field = root.querySelector('#grant-username')!;
    expect(root.querySelector('#grant-username-error')?.textContent).toContain(
      'No active user has that name',
    );
    expect(field.getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(field);
    expect(server.requests.filter((r) => r.method === 'PUT')).toEqual([]);
  });

  it('refuses a user who already has a grant, on the field', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users/lookup', {
      body: { id: BOB, username: 'bob', displayName: null },
    });
    const { fixture, root } = await render();
    type(root, '#grant-username', 'bob');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#grant-username-error')?.textContent).toContain(
      'bob already has a role on this project. Change it in the table.',
    );
    expect(server.requests.filter((r) => r.method === 'PUT')).toEqual([]);
  });

  it('changes a grant with PUT after a confirmation', async () => {
    const server = setup();
    server.on('PUT', `${MEMBERS}/${BOB}`, { body: grant(BOB, 'bob', 'project_admin') });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const { fixture, root } = await render();
    choose(row(root, BOB), 'select', 'project_admin');
    button(row(root, BOB), 'Change role').click();
    await settle(fixture);
    expect(confirm).toHaveBeenCalledWith('Change the role of bob on Payments to Project admin?');
    expect(server.requestsTo('PUT', `${MEMBERS}/${BOB}`).map((r) => r.body)).toEqual([
      { role: 'project_admin' },
    ]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'bob now has the role Project admin on this project.',
    );
    confirm.mockRestore();
  });

  it('removes a grant with DELETE after a confirmation, and not without one', async () => {
    const server = setup();
    server.on('DELETE', `${MEMBERS}/${BOB}`, { status: 204 });
    const confirm = vi
      .spyOn(window, 'confirm')
      .mockReturnValueOnce(false)
      .mockReturnValueOnce(true);
    const { fixture, root } = await render();
    button(row(root, BOB), 'Remove').click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', `${MEMBERS}/${BOB}`)).toEqual([]);
    button(row(root, BOB), 'Remove').click();
    await settle(fixture);
    expect(confirm).toHaveBeenLastCalledWith(
      'Remove the role of bob on Payments? Their organization role, if they have one, still applies.',
    );
    expect(server.requestsTo('DELETE', `${MEMBERS}/${BOB}`)).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'The role of bob on this project was removed.',
    );
    confirm.mockRestore();
  });

  it('explains the grant limit when the server refuses one more', async () => {
    const server = setup({ grants: [] });
    server.on('GET', '/api/v0/users/lookup', {
      body: { id: CAROL, username: 'carol', displayName: null },
    });
    server.on('PUT', `${MEMBERS}/${CAROL}`, {
      status: 409,
      body: problem(409, 'PROJECT_GRANT_LIMIT_REACHED'),
    });
    const { fixture, root } = await render();
    type(root, '#grant-username', 'carol');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This project has as many role grants as it can have',
    );
  });

  it('lists, adds, changes and removes grants through the core API without any feature', async () => {
    const server = setup({ features: [] });
    server.on('GET', '/api/v0/users/lookup', {
      body: { id: CAROL, username: 'carol', displayName: null },
    });
    server.on('PUT', `${MEMBERS}/${CAROL}`, { body: grant(CAROL, 'carol', 'viewer') });
    server.on('PUT', `${MEMBERS}/${BOB}`, { body: grant(BOB, 'bob', 'member') });
    server.on('DELETE', `${MEMBERS}/${BOB}`, { status: 204 });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const { fixture, root } = await render();
    expect(row(root, BOB).textContent).toContain('bob');
    expect(root.textContent).not.toContain('enterprise licence');
    type(root, '#grant-username', 'carol');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    choose(row(root, BOB), 'select', 'member');
    button(row(root, BOB), 'Change role').click();
    await settle(fixture);
    button(row(root, BOB), 'Remove').click();
    await settle(fixture);
    expect(server.requestsTo('GET', MEMBERS).length).toBeGreaterThan(0);
    expect(server.requestsTo('PUT', `${MEMBERS}/${CAROL}`).map((r) => r.body)).toEqual([
      { role: 'viewer' },
    ]);
    expect(server.requestsTo('PUT', `${MEMBERS}/${BOB}`).map((r) => r.body)).toEqual([
      { role: 'member' },
    ]);
    expect(server.requestsTo('DELETE', `${MEMBERS}/${BOB}`)).toHaveLength(1);
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
    confirm.mockRestore();
  });

  it('shows the grants when the server information cannot be loaded', async () => {
    const server = setup();
    server.on('GET', '/api/v0/system/info', { status: 500, body: problem(500, 'INTERNAL') });
    const { root } = await render();
    expect(row(root, BOB).textContent).toContain('bob');
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
  });

  it('asks nothing, and shows nothing to change, for someone who does not manage members', async () => {
    const server = setup({ role: 'member' });
    const { root } = await render();
    expect(root.textContent).toContain('Only organization administrators manage project access.');
    expect(server.requestsTo('GET', MEMBERS)).toEqual([]);
    expect(root.querySelector('form')).toBeNull();
  });
});

describe('ProjectPage Access tab (rbac-audit.md §17)', () => {
  async function tabs(): Promise<(string | undefined)[]> {
    const fixture = TestBed.createComponent(ProjectPage);
    fixture.componentRef.setInput('projectId', PROJECT);
    await settle(fixture);
    const nav = (fixture.nativeElement as HTMLElement).querySelector('nav[aria-label="Project"]');
    return [...(nav?.querySelectorAll('a') ?? [])].map((a) => a.textContent?.trim());
  }

  it('shows Access to an organization admin in the community edition', async () => {
    setup({ features: [] });
    expect(await tabs()).toEqual(['Overview', 'Branches and merge requests', 'Issues', 'Access']);
  });

  it('hides Access from a maintainer', async () => {
    setup({ role: 'member' });
    expect(await tabs()).not.toContain('Access');
  });
});

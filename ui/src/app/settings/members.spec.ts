import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ADMIN_PERMISSIONS,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { type Member, MembersPage } from './members.page';
import { SettingsPage } from './settings.page';

const ALICE = '0190a6c2-0000-7000-8000-00000000000a';
const BOB = '0190a6c2-0000-7000-8000-00000000000b';
const CAROL = '0190a6c2-0000-7000-8000-00000000000c';
const DAN = '0190a6c2-0000-7000-8000-00000000000d';

function member(userId: string, username: string, role: Member['role']): Member {
  return {
    userId,
    username,
    displayName: null,
    role,
    createdAt: '2026-09-01T00:00:00.000Z',
    managedBy: null,
  };
}

interface Setup {
  /** The caller's role in the organisation (not an instance admin). */
  role?: 'admin' | 'member';
  features?: string[];
  members?: Member[];
}

function setup(options: Setup = {}): FakeServer {
  const server = new FakeServer();
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
  server.on('GET', `/api/v0/organizations/${ORG_ID}/members`, {
    body: page(options.members ?? [member(ALICE, 'alice', 'admin'), member(BOB, 'bob', 'member')]),
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  const base = me();
  const role = options.role ?? 'admin';
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
  const fixture = TestBed.createComponent(MembersPage);
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

function button(root: ParentNode, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

function options(select: HTMLSelectElement): string[] {
  return [...select.options].filter((o) => !o.disabled).map((o) => o.textContent?.trim() ?? '');
}

function dialog(root: HTMLElement, id: string): HTMLDialogElement {
  return root.querySelector<HTMLDialogElement>(`dialog#${id}`)!;
}

/**
 * Answers the page's confirmation dialog (step 8: it replaces the browser's `confirm()`) with the
 * button `choice`, and returns the question it asked.
 */
async function answer(
  fixture: { whenStable(): Promise<unknown> },
  root: HTMLElement,
  choice: string,
): Promise<string> {
  const ask = dialog(root, 'confirm-dialog');
  expect(ask.open).toBe(true);
  const question = ask.querySelector('#confirm-text')?.textContent?.trim() ?? '';
  button(ask, choice).click();
  await settle(fixture);
  expect(ask.open).toBe(false);
  return question;
}

/** Opens the "Add member" dialog (step 8: the add form lives in it). */
async function openAdd(root: HTMLElement, fixture: { whenStable(): Promise<unknown> }) {
  button(root, 'Add member').click();
  await settle(fixture);
  const add = dialog(root, 'add-dialog');
  expect(add.open).toBe(true);
  return add;
}

describe('MembersPage (rbac-audit.md §17)', () => {
  it('lists the members with their role labels', async () => {
    setup({
      members: [
        member(ALICE, 'alice', 'admin'),
        member(BOB, 'bob', 'member'),
        member(CAROL, 'carol', 'viewer'),
      ],
    });
    const { root } = await render();
    expect(row(root, ALICE).textContent).toContain('Organization admin');
    expect(row(root, BOB).textContent).toContain('Maintainer');
    expect(row(root, CAROL).textContent).toContain('Viewer');
  });

  it('offers the four roles without any feature', async () => {
    const server = setup({ features: [] });
    server.on('PUT', `/api/v0/organizations/${ORG_ID}/members/${BOB}`, {
      body: member(BOB, 'bob', 'viewer'),
    });
    const { fixture, root } = await render();
    expect(options(root.querySelector<HTMLSelectElement>('#member-role')!)).toEqual([
      'Organization admin',
      'Project admin',
      'Maintainer',
      'Viewer',
    ]);
    expect(options(row(root, BOB).querySelector('select')!)).toEqual([
      'Organization admin',
      'Project admin',
      'Maintainer',
      'Viewer',
    ]);
    choose(row(root, BOB), 'select', 'viewer');
    button(row(root, BOB), 'Change role').click();
    await settle(fixture);
    expect(await answer(fixture, root, 'Change role')).toBe(
      'Change the role of bob in Default to Viewer?',
    );
    expect(
      server.requestsTo('PUT', `/api/v0/organizations/${ORG_ID}/members/${BOB}`).map((r) => r.body),
    ).toEqual([{ role: 'viewer' }]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('bob is now Viewer.');
  });

  it('shows no lapse note', async () => {
    setup({ members: [member(ALICE, 'alice', 'admin'), member(DAN, 'dan', 'project_admin')] });
    const { root } = await render();
    expect(row(root, DAN).querySelector('select')?.value).toBe('project_admin');
    expect(row(root, DAN).textContent).toContain('Project admin');
    expect(root.textContent).not.toContain('until the licence is renewed');
    expect(root.textContent).not.toContain('read-only');
    expect(root.textContent).not.toContain('enterprise licence');
  });

  it("changes a role with PUT after the page's own confirmation, and announces it", async () => {
    const server = setup();
    server.on('PUT', `/api/v0/organizations/${ORG_ID}/members/${BOB}`, {
      body: member(BOB, 'bob', 'admin'),
    });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    choose(row(root, BOB), 'select', 'admin');
    button(row(root, BOB), 'Change role').click();
    await settle(fixture);
    expect(await answer(fixture, root, 'Change role')).toBe(
      'Change the role of bob in Default to Organization admin?',
    );
    expect(confirm).not.toHaveBeenCalled();
    const puts = server.requestsTo('PUT', `/api/v0/organizations/${ORG_ID}/members/${BOB}`);
    expect(puts.map((r) => r.body)).toEqual([{ role: 'admin' }]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'bob is now Organization admin.',
    );
    confirm.mockRestore();
  });

  it('marks a membership that SSO group sync manages with its connection', async () => {
    setup({
      members: [
        member(ALICE, 'alice', 'admin'),
        {
          ...member(BOB, 'bob', 'member'),
          managedBy: {
            connectionId: '0190a6c2-0000-7000-8000-0000000000c1',
            connectionName: 'Acme SSO',
          },
        },
      ],
    });
    const { root } = await render();
    expect(row(root, BOB).textContent).toContain('From SSO group sync: Acme SSO');
    expect(row(root, ALICE).textContent).not.toContain('group sync');
  });

  it('says that changing a managed role takes it over from group sync', async () => {
    const server = setup({
      members: [
        member(ALICE, 'alice', 'admin'),
        {
          ...member(BOB, 'bob', 'member'),
          managedBy: {
            connectionId: '0190a6c2-0000-7000-8000-0000000000c1',
            connectionName: 'Acme SSO',
          },
        },
      ],
    });
    server.on('PUT', `/api/v0/organizations/${ORG_ID}/members/${BOB}`, {
      body: member(BOB, 'bob', 'admin'),
    });
    const { fixture, root } = await render();
    choose(row(root, BOB), 'select', 'admin');
    button(row(root, BOB), 'Change role').click();
    await settle(fixture);
    expect(await answer(fixture, root, 'Change role')).toBe(
      'Change the role of bob in Default to Organization admin? Changing this role takes it over from group sync.',
    );
    expect(server.requestsTo('PUT', `/api/v0/organizations/${ORG_ID}/members/${BOB}`)).toHaveLength(
      1,
    );
  });

  it('sends nothing when the role change is cancelled, and shows the stored role again', async () => {
    const server = setup();
    const { fixture, root } = await render();
    choose(row(root, BOB), 'select', 'admin');
    button(row(root, BOB), 'Change role').click();
    await settle(fixture);
    await answer(fixture, root, 'Cancel');
    expect(server.requests.filter((r) => r.method === 'PUT')).toEqual([]);
    expect(row(root, BOB).querySelector('select')?.value).toBe('member');
    expect(button(row(root, BOB), 'Change role').getAttribute('aria-disabled')).toBe('true');
  });

  it('puts the role back when the confirmation is closed with Escape', async () => {
    const server = setup();
    const { fixture, root } = await render();
    choose(row(root, BOB), 'select', 'admin');
    button(row(root, BOB), 'Change role').click();
    await settle(fixture);
    const ask = dialog(root, 'confirm-dialog');
    ask.removeAttribute('open');
    ask.dispatchEvent(new Event('close'));
    await settle(fixture);
    expect(server.requests.filter((r) => r.method === 'PUT')).toEqual([]);
    expect(row(root, BOB).querySelector('select')?.value).toBe('member');
  });

  it('asks on a phone as soon as a role is chosen: there the select stands for Change role', async () => {
    // A phone's picker commits once; the row has no room for a Change role button (step 11).
    vi.stubGlobal('matchMedia', (query: string) => ({ matches: query === '(max-width: 40rem)' }));
    try {
      const server = setup();
      const { fixture, root } = await render();
      choose(row(root, BOB), 'select', 'admin');
      await settle(fixture);
      const ask = dialog(root, 'confirm-dialog');
      expect(ask.open).toBe(true);
      expect(ask.querySelector('#confirm-text')?.textContent?.trim()).toBe(
        'Change the role of bob in Default to Organization admin?',
      );
      button(ask, 'Cancel').click();
      await settle(fixture);
      expect(server.requests.filter((r) => r.method === 'PUT')).toEqual([]);
      expect(row(root, BOB).querySelector('select')?.value).toBe('member');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('asks nothing at full width until Change role: arrowing through the roles opens no dialog', async () => {
    setup();
    const { fixture, root } = await render();
    choose(row(root, BOB), 'select', 'admin');
    await settle(fixture);
    expect(dialog(root, 'confirm-dialog').open).toBe(false);
  });

  it('asks in its own words before admins demote themselves', async () => {
    setup();
    const { fixture, root } = await render();
    choose(row(root, ALICE), 'select', 'member');
    button(row(root, ALICE), 'Change role').click();
    await settle(fixture);
    expect(await answer(fixture, root, 'Cancel')).toBe(
      'Change your own role in Default to Maintainer? You can no longer manage its members, and only another administrator can make you an admin again.',
    );
  });

  it('shows a refused self-demotion (409 LAST_ADMIN) and keeps the role', async () => {
    const server = setup();
    server.on('PUT', `/api/v0/organizations/${ORG_ID}/members/${ALICE}`, {
      status: 409,
      body: problem(409, 'LAST_ADMIN'),
    });
    const { fixture, root } = await render();
    choose(row(root, ALICE), 'select', 'member');
    button(row(root, ALICE), 'Change role').click();
    await settle(fixture);
    await answer(fixture, root, 'Change role');
    expect(
      server.requestsTo('PUT', `/api/v0/organizations/${ORG_ID}/members/${ALICE}`),
    ).toHaveLength(1);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'The last active administrator cannot be demoted, removed or deactivated.',
    );
    expect(row(root, ALICE).querySelector('select')?.value).toBe('admin');
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe('');
  });

  it('removes a member with DELETE after a confirmation, and not without one', async () => {
    const server = setup();
    server.on('DELETE', `/api/v0/organizations/${ORG_ID}/members/${BOB}`, { status: 204 });
    const { fixture, root } = await render();
    button(row(root, BOB), 'Remove').click();
    await settle(fixture);
    expect(await answer(fixture, root, 'Cancel')).toBe(
      'Remove bob from Default? They lose access to its projects.',
    );
    expect(server.requestsTo('DELETE', `/api/v0/organizations/${ORG_ID}/members/${BOB}`)).toEqual(
      [],
    );
    button(row(root, BOB), 'Remove').click();
    await settle(fixture);
    await answer(fixture, root, 'Remove');
    expect(
      server.requestsTo('DELETE', `/api/v0/organizations/${ORG_ID}/members/${BOB}`),
    ).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('bob removed.');
  });

  it('adds a member in the Add member dialog: looks the name up, then sends PUT with the chosen role', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users/lookup', {
      body: { id: CAROL, username: 'carol', displayName: 'Carol' },
    });
    server.on('PUT', `/api/v0/organizations/${ORG_ID}/members/${CAROL}`, {
      body: member(CAROL, 'carol', 'admin'),
    });
    const { fixture, root } = await render();
    const add = await openAdd(root, fixture);
    type(root, '#member-username', ' Carol ');
    choose(root, '#member-role', 'admin');
    add.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(
      server.requestsTo('GET', '/api/v0/users/lookup').map((r) => r.query.get('username')),
    ).toEqual(['Carol']);
    expect(
      server
        .requestsTo('PUT', `/api/v0/organizations/${ORG_ID}/members/${CAROL}`)
        .map((r) => r.body),
    ).toEqual([{ role: 'admin' }]);
    expect(add.open).toBe(false);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'carol added as Organization admin.',
    );
    // Opened again: an empty name and the default role, never the last choice.
    await openAdd(root, fixture);
    expect(root.querySelector<HTMLInputElement>('#member-username')?.value).toBe('');
    expect(root.querySelector<HTMLSelectElement>('#member-role')?.value).toBe('member');
  });

  it('says so in the dialog when no active user has that name, on the field', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users/lookup', { status: 404, body: problem(404, 'NOT_FOUND') });
    const { fixture, root } = await render();
    const add = await openAdd(root, fixture);
    type(root, '#member-username', 'nobody');
    add.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const field = root.querySelector('#member-username')!;
    expect(add.open).toBe(true);
    expect(add.querySelector('#member-username-error')?.textContent).toContain(
      'No active user has that name',
    );
    expect(field.getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(field);
    expect(server.requests.filter((r) => r.method === 'PUT')).toEqual([]);
  });

  it('shows nothing to change, and asks nothing, for a member who is not an organization admin', async () => {
    const server = setup({ role: 'member' });
    const { root } = await render();
    expect(root.textContent).toContain('Only organization administrators manage members.');
    expect(server.requestsTo('GET', `/api/v0/organizations/${ORG_ID}/members`)).toEqual([]);
    expect(root.querySelector('form')).toBeNull();
    expect(button(root, 'Add member')).toBeUndefined();
  });
});

describe('SettingsPage navigation for members and enterprise entries (rbac-audit.md §17)', () => {
  function links(root: HTMLElement): (string | undefined)[] {
    return [...root.querySelectorAll('nav a')].map((a) => a.textContent?.trim());
  }

  it('shows Members to an organization admin and not to a member', async () => {
    setup();
    const admin = TestBed.createComponent(SettingsPage);
    await settle(admin);
    expect(links(admin.nativeElement as HTMLElement)).toContain('Members');
    TestBed.resetTestingModule();
    setup({ role: 'member' });
    const other = TestBed.createComponent(SettingsPage);
    await settle(other);
    expect(links(other.nativeElement as HTMLElement)).not.toContain('Members');
  });

  it('groups the entries under Your account, Organization and Instance, with no empty group', async () => {
    const groups = (root: HTMLElement) =>
      [...root.querySelectorAll('nav [role="group"]')].map((g) => ({
        title: g.querySelector('.nav-group-title')?.textContent?.trim(),
        links: [...g.querySelectorAll('a')].map((a) => a.textContent?.trim()),
      }));
    setup();
    const admin = TestBed.createComponent(SettingsPage);
    await settle(admin);
    expect(groups(admin.nativeElement as HTMLElement)).toEqual([
      { title: 'Your account', links: ['Access tokens'] },
      { title: 'Organization', links: ['Members', 'Webhooks', 'GitLab', 'GitHub', 'Repositories'] },
    ]);
    TestBed.resetTestingModule();
    setup({ role: 'member' });
    const other = TestBed.createComponent(SettingsPage);
    await settle(other);
    expect(groups(other.nativeElement as HTMLElement)).toEqual([
      { title: 'Your account', links: ['Access tokens'] },
    ]);
  });

  it('lists Organizations first under Instance, for instance admins', async () => {
    setup();
    TestBed.inject(SessionStore).set(me({ admin: true }));
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    const instance = [
      ...(fixture.nativeElement as HTMLElement).querySelectorAll('nav [role="group"]'),
    ].find((g) => g.querySelector('.nav-group-title')?.textContent?.trim() === 'Instance');
    expect([...(instance?.querySelectorAll('a') ?? [])].map((a) => a.textContent?.trim())).toEqual([
      'Organizations',
      'Users',
      'AI assistant',
      'Licence',
    ]);
  });

  it('hides the audit entries while audit-log is not active', async () => {
    const server = new FakeServer();
    server.on('GET', '/api/v0/organizations', { body: page([]) });
    server.on('GET', '/api/v0/system/info', {
      body: {
        version: '0.0.0',
        edition: 'enterprise',
        features: ['sso'],
        extensions: [
          {
            point: 'settings.nav',
            id: 'audit-log',
            label: 'Audit log',
            path: '/settings/ee/audit-log',
          },
          { point: 'settings.nav', id: 'other', label: 'Other', path: '/settings/ee/other' },
        ],
      },
    });
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me({ admin: true }));
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    const names = links(fixture.nativeElement as HTMLElement);
    expect(names).not.toContain('Audit log');
    expect(names).toContain('Other');
  });
});

import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { type User, UsersPage } from './users.page';

function user(id: string, username: string, overrides: Partial<User> = {}): User {
  return {
    id,
    username,
    displayName: null,
    email: null,
    isInstanceAdmin: false,
    active: true,
    passwordChangeRequired: false,
    hasPassword: true,
    sso: { identities: 0, scim: false },
    invitation: null,
    lastLoginAt: null,
    createdAt: '',
    ...overrides,
  };
}

function setup(): FakeServer {
  const server = new FakeServer();
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: true }));
  return server;
}

const row = (root: HTMLElement, id: string) =>
  root.querySelector<HTMLElement>(`tr[data-key="${id}"]`)!;

describe('UsersPage: sign-in badges and the "No password" filter (sso-scim.md §18)', () => {
  it('marks users without a password, with SSO identities and provisioned by SCIM', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users', {
      body: page([
        user('u1', 'plain'),
        user('u2', 'sso-only', { hasPassword: false, sso: { identities: 1, scim: false } }),
        user('u3', 'scim', { hasPassword: false, sso: { identities: 1, scim: true } }),
      ]),
    });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const plain = row(root, 'u1').textContent ?? '';
    expect(plain).not.toContain('No password');
    expect(plain).not.toContain('SSO');
    expect(plain).not.toContain('SCIM');
    const ssoOnly = row(root, 'u2').textContent ?? '';
    expect(ssoOnly).toContain('No password');
    expect(ssoOnly).toContain('SSO');
    expect(ssoOnly).not.toContain('SCIM');
    expect(ssoOnly).not.toContain('may overwrite');
    const scim = row(root, 'u3').textContent ?? '';
    expect(scim).toContain('SCIM');
    expect(scim).toContain('The identity provider may overwrite changes to this account.');
  });

  it('lists only the users without a password while the filter is on', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users', (request) => ({
      body: page(
        request.query.get('signIn') === 'no-password'
          ? [user('u2', 'sso-only', { hasPassword: false, sso: { identities: 1, scim: false } })]
          : [user('u1', 'plain'), user('u2', 'sso-only', { hasPassword: false })],
      ),
    }));
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelectorAll('tbody tr')).toHaveLength(2);
    const toggle = root.querySelector<HTMLButtonElement>('[data-test=filter-no-password]')!;
    expect(toggle.textContent).toContain('No password');
    expect(toggle.getAttribute('aria-pressed')).toBe('false');
    toggle.click();
    await settle(fixture);
    expect(toggle.getAttribute('aria-pressed')).toBe('true');
    expect(server.requests.at(-1)?.query.get('signIn')).toBe('no-password');
    expect(root.querySelectorAll('tbody tr')).toHaveLength(1);
    expect(row(root, 'u2')).not.toBeNull();
    toggle.click();
    await settle(fixture);
    expect(toggle.getAttribute('aria-pressed')).toBe('false');
    expect(server.requests.at(-1)?.query.has('signIn')).toBe(false);
    expect(root.querySelectorAll('tbody tr')).toHaveLength(2);
  });

  it('asks for the next page with the same filter', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users', (request) => ({
      body: request.query.has('cursor')
        ? page([user('u3', 'third', { hasPassword: false })])
        : page([user('u2', 'second', { hasPassword: false })], 'next'),
    }));
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    root.querySelector<HTMLButtonElement>('[data-test=filter-no-password]')!.click();
    await settle(fixture);
    [...root.querySelectorAll('button')].find((b) => b.textContent?.includes('Load more'))!.click();
    await settle(fixture);
    const last = server.requests.at(-1)!;
    expect(last.query.get('cursor')).toBe('next');
    expect(last.query.get('signIn')).toBe('no-password');
  });
});

describe('UsersPage: the "No password" filter with nobody to show (step 11)', () => {
  it('says every user can sign in with a password, instead of an empty table', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users', (request) => ({
      body: page(request.query.get('signIn') === 'no-password' ? [] : [user('u1', 'plain')]),
    }));
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    root.querySelector<HTMLButtonElement>('[data-test=filter-no-password]')!.click();
    await settle(fixture);
    expect(root.querySelector('tbody')?.textContent?.trim()).toBe(
      'Every user can sign in with a password.',
    );
  });
});

describe('UsersPage: invitations (mail E2 A8)', () => {
  const AVAILABLE = { password: 'everyone', providers: [], demo: false, passwordReset: true };
  const LIVE = '2099-01-01T00:00:00.000Z';
  const type = (root: HTMLElement, selector: string, value: string) => {
    const input = root.querySelector<HTMLInputElement>(selector)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
  };
  const radio = (root: HTMLElement, value: string) =>
    root.querySelector<HTMLInputElement>(`input[name="create-mode"][value="${value}"]`)!;
  async function open(server: FakeServer, methods: object, users: User[] = []) {
    server.on('GET', '/api/v0/auth/methods', { body: methods });
    server.on('GET', '/api/v0/users', { body: page(users) });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    [...root.querySelectorAll('button')].find((b) => b.textContent?.includes('New user'))!.click();
    await settle(fixture);
    return { fixture, root };
  }
  const submit = async (root: HTMLElement, fixture: { whenStable(): Promise<unknown> }) => {
    root.querySelector('#create-dialog form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
  };

  it('invites by default when email works: no password field, the email required', async () => {
    const server = setup();
    server.on('POST', '/api/v0/users', {
      status: 201,
      body: user('u9', 'ivy', {
        email: 'ivy@example.test',
        hasPassword: false,
        invitation: { expiresAt: LIVE },
      }),
    });
    const { fixture, root } = await open(server, AVAILABLE);
    expect(radio(root, 'invite').checked).toBe(true);
    expect(root.querySelector('#user-password')).toBeNull();
    type(root, '#user-username', 'ivy');
    await submit(root, fixture);
    expect(root.querySelector('#user-email-error')?.textContent).toContain(
      'Enter the email address the invitation goes to.',
    );
    expect(server.requestsTo('POST', '/api/v0/users')).toEqual([]);
    type(root, '#user-email', 'ivy@example.test');
    await submit(root, fixture);
    expect(server.requestsTo('POST', '/api/v0/users')[0]?.body).toEqual({
      username: 'ivy',
      invite: true,
      email: 'ivy@example.test',
      isInstanceAdmin: false,
    });
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'ivy gets an email with a link to set a password.',
    );
  });

  it('offers only an initial password, saying why, without email or QUALOR_PUBLIC_URL', async () => {
    const server = setup();
    const { root } = await open(server, { ...AVAILABLE, passwordReset: false });
    expect(radio(root, 'invite').disabled).toBe(true);
    expect(radio(root, 'password').checked).toBe(true);
    expect(root.querySelector('#user-password')).not.toBeNull();
    expect(root.querySelector('#create-mode-hint')?.textContent).toContain(
      'Invitations need an email server and QUALOR_PUBLIC_URL.',
    );
  });

  it('offers only an initial password while password sign-in is limited to break-glass admins', async () => {
    const server = setup();
    const { root } = await open(server, { ...AVAILABLE, password: 'break_glass_only' });
    expect(radio(root, 'invite').disabled).toBe(true);
    expect(root.querySelector('#create-mode-hint')?.textContent).toContain(
      'break-glass administrators',
    );
  });

  it('shows a refused invitation in the dialog', async () => {
    const server = setup();
    server.on('POST', '/api/v0/users', { status: 409, body: problem(409, 'MAIL_NOT_CONFIGURED') });
    const { fixture, root } = await open(server, AVAILABLE);
    type(root, '#user-username', 'ivy');
    type(root, '#user-email', 'ivy@example.test');
    await submit(root, fixture);
    expect(root.querySelector('#create-dialog [role="alert"]')?.textContent).toContain(
      'Invitations need an email server and QUALOR_PUBLIC_URL.',
    );
  });

  it('marks invited users, and resends or revokes their invitation', async () => {
    const server = setup();
    const ivy = user('u1', 'ivy', {
      email: 'ivy@example.test',
      hasPassword: false,
      invitation: { expiresAt: LIVE },
    });
    const old = user('u2', 'old', {
      email: 'old@example.test',
      hasPassword: false,
      invitation: { expiresAt: '2000-01-01T00:00:00.000Z' },
    });
    server.on('POST', '/api/v0/users/u1/invitation', { body: ivy });
    server.on('DELETE', '/api/v0/users/u1/invitation', { status: 204 });
    server.on('GET', '/api/v0/auth/methods', { body: AVAILABLE });
    server.on('GET', '/api/v0/users', { body: page([ivy, old]) });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(row(root, 'u1').querySelector('[data-test=invited]')?.textContent).toContain(
      'Invited · expires',
    );
    expect(row(root, 'u1').textContent).not.toContain('No password');
    expect(row(root, 'u2').querySelector('[data-test=invitation-expired]')?.textContent).toContain(
      'Invitation expired',
    );
    expect(row(root, 'u2').querySelector('[data-test=revoke-invitation]')).toBeNull();
    row(root, 'u1').querySelector<HTMLButtonElement>('[data-test=resend-invitation]')!.click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/users/u1/invitation')).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'ivy gets a new invitation email. The earlier link no longer works.',
    );
    row(root, 'u1').querySelector<HTMLButtonElement>('[data-test=revoke-invitation]')!.click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', '/api/v0/users/u1/invitation')).toHaveLength(1);
    expect(row(root, 'u1').querySelector('[data-test=invited]')).toBeNull();
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'The invitation of ivy no longer works.',
    );
  });
});

describe('UsersPage: a user’s connected apps (6N spec §8)', () => {
  const G1 = '0190a6c2-0000-7000-8000-0000000000f1';
  const GRANTS = '/api/v0/users/u2/oauth-grants';
  const grant = {
    id: G1,
    client: {
      clientId: 'qlr_cli_abc',
      name: 'Agent Studio',
      source: 'dcr',
      logoUri: null,
      clientUri: null,
    },
    scopes: ['mcp:read'],
    createdAt: '2026-10-01T10:00:00.000Z',
    lastUsedAt: null,
  };

  async function open(server: FakeServer) {
    server.on('GET', '/api/v0/users', { body: page([user('u1', 'admin'), user('u2', 'bob')]) });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const show = row(root, 'u2').querySelector<HTMLButtonElement>('[data-test=show-apps]')!;
    expect(show.getAttribute('aria-label')).toBe('Connected apps of bob');
    show.click();
    await settle(fixture);
    return { fixture, root };
  }

  it('lists the apps of the chosen user, and disconnects one after a confirmation', async () => {
    const server = setup();
    server.on('GET', GRANTS, { body: { items: [grant] } });
    server.on('DELETE', `${GRANTS}/${G1}`, { status: 204 });
    const { fixture, root } = await open(server);
    const section = root.querySelector<HTMLElement>('[data-test=user-apps]')!;
    expect(section.querySelector('h3')?.textContent?.trim()).toBe('Connected apps of bob');
    expect(document.activeElement).toBe(section.querySelector('h3'));
    const app = section.querySelector<HTMLElement>(`tr[data-key="${G1}"]`)!;
    expect(app.textContent).toContain('Agent Studio');
    expect(app.textContent).toContain('Not verified');
    server.on('GET', GRANTS, { body: { items: [] } });
    [...app.querySelectorAll('button')]
      .find((b) => b.textContent?.trim() === 'Disconnect')!
      .click();
    await settle(fixture);
    const ask = section.querySelector<HTMLDialogElement>('dialog[data-test=disconnect-dialog]')!;
    expect(ask.querySelector('#disconnect-text')?.textContent?.trim()).toBe(
      'Disconnect Agent Studio from bob? Its access stops at once.',
    );
    [...ask.querySelectorAll('button')]
      .find((b) => b.textContent?.trim() === 'Disconnect')!
      .click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', `${GRANTS}/${G1}`)).toHaveLength(1);
    expect(section.querySelector('[data-test=grants-empty]')?.textContent?.trim()).toBe(
      'bob has no connected apps.',
    );
  });

  it('closes the section and gives focus back to the row', async () => {
    const server = setup();
    server.on('GET', GRANTS, { body: { items: [] } });
    const { fixture, root } = await open(server);
    [...root.querySelectorAll<HTMLButtonElement>('[data-test=user-apps] button')]
      .find((b) => b.textContent?.trim() === 'Close')!
      .click();
    await settle(fixture);
    expect(root.querySelector('[data-test=user-apps]')).toBeNull();
    expect(document.activeElement).toBe(row(root, 'u2').querySelector('[data-test=show-apps]'));
  });
});

describe('UsersPage: edit a user (0.16 issue #37)', () => {
  const ME_ID = '0190a6c2-0000-7000-8000-00000000000a';
  const type = (root: HTMLElement, selector: string, value: string) => {
    const input = root.querySelector<HTMLInputElement>(selector)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
  };
  async function open(server: FakeServer, users: User[]) {
    server.on('GET', '/api/v0/auth/methods', {
      body: { password: 'everyone', providers: [], demo: false, passwordReset: false },
    });
    server.on('GET', '/api/v0/users', { body: page(users) });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    return { fixture, root };
  }
  const edit = async (
    root: HTMLElement,
    fixture: { whenStable(): Promise<unknown> },
    id: string,
  ) => {
    row(root, id).querySelector<HTMLButtonElement>('.row-actions [data-test=edit-user]')!.click();
    await settle(fixture);
  };
  const save = async (root: HTMLElement, fixture: { whenStable(): Promise<unknown> }) => {
    root.querySelector('#edit-dialog form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
  };

  it('opens a dialog with the current username and display name', async () => {
    const server = setup();
    const { fixture, root } = await open(server, [user('u1', 'bob', { displayName: 'Bob B' })]);
    await edit(root, fixture, 'u1');
    const username = root.querySelector<HTMLInputElement>('#edit-username')!;
    expect(username.value).toBe('bob');
    expect(username.getAttribute('pattern')).toBe('^[A-Za-z0-9._-]{1,64}$');
    expect(root.querySelector<HTMLInputElement>('#edit-display')!.value).toBe('Bob B');
    expect(root.querySelector('#edit-dialog')?.textContent).not.toContain('may overwrite');
  });

  it('sends only the changed fields and shows the new name in the row', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/users/u1', {
      body: user('u1', 'robert', { displayName: 'Bob B' }),
    });
    const { fixture, root } = await open(server, [user('u1', 'bob', { displayName: 'Bob B' })]);
    await edit(root, fixture, 'u1');
    type(root, '#edit-username', 'robert');
    await save(root, fixture);
    const sent = server.requestsTo('PATCH', '/api/v0/users/u1');
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body).toEqual({ username: 'robert' });
    expect(row(root, 'u1').textContent).toContain('robert');
    expect(server.requestsTo('GET', '/api/v0/auth/me')).toEqual([]);
  });

  it('clears the display name with null', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/users/u1', { body: user('u1', 'bob') });
    const { fixture, root } = await open(server, [user('u1', 'bob', { displayName: 'Bob B' })]);
    await edit(root, fixture, 'u1');
    type(root, '#edit-display', '');
    await save(root, fixture);
    expect(server.requestsTo('PATCH', '/api/v0/users/u1')[0]?.body).toEqual({
      displayName: null,
    });
  });

  it('sends nothing when nothing changed', async () => {
    const server = setup();
    const { fixture, root } = await open(server, [user('u1', 'bob')]);
    await edit(root, fixture, 'u1');
    await save(root, fixture);
    expect(server.requestsTo('PATCH', '/api/v0/users/u1')).toEqual([]);
  });

  it('refuses a username the pattern does not allow, without asking the server', async () => {
    const server = setup();
    const { fixture, root } = await open(server, [user('u1', 'bob')]);
    await edit(root, fixture, 'u1');
    type(root, '#edit-username', 'a b');
    await save(root, fixture);
    expect(root.querySelector('#edit-username-error')?.textContent).toContain('1 to 64 letters');
    expect(server.requestsTo('PATCH', '/api/v0/users/u1')).toEqual([]);
  });

  it('says next to the field that the username is taken', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/users/u1', { status: 409, body: problem(409, 'USERNAME_TAKEN') });
    const { fixture, root } = await open(server, [user('u1', 'bob')]);
    await edit(root, fixture, 'u1');
    type(root, '#edit-username', 'alice');
    await save(root, fixture);
    expect(root.querySelector('#edit-username-error')?.textContent).toContain(
      'This username is already taken.',
    );
    expect(root.querySelector<HTMLInputElement>('#edit-username')!.value).toBe('alice');
  });

  it('says next to the field that the demo user keeps its name', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/users/u1', { status: 409, body: problem(409, 'DEMO_USER') });
    const { fixture, root } = await open(server, [user('u1', 'guest')]);
    await edit(root, fixture, 'u1');
    type(root, '#edit-username', 'other');
    await save(root, fixture);
    expect(root.querySelector('#edit-username-error')?.textContent).toContain(
      'The demo user keeps its name',
    );
  });

  it('reloads the session when you rename yourself, so the header shows the new name', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/users/${ME_ID}`, {
      body: user(ME_ID, 'alicia', { isInstanceAdmin: true }),
    });
    const renamed = me({ admin: true });
    renamed.user.username = 'alicia';
    server.on('GET', '/api/v0/auth/me', { body: renamed });
    const { fixture, root } = await open(server, [user(ME_ID, 'alice', { isInstanceAdmin: true })]);
    await edit(root, fixture, ME_ID);
    type(root, '#edit-username', 'alicia');
    await save(root, fixture);
    expect(server.requestsTo('GET', '/api/v0/auth/me')).toHaveLength(1);
    expect(TestBed.inject(SessionStore).user()?.username).toBe('alicia');
  });

  it('shows the SCIM note in the dialog of a provisioned user', async () => {
    const server = setup();
    const { fixture, root } = await open(server, [
      user('u3', 'scim', { hasPassword: false, sso: { identities: 1, scim: true } }),
    ]);
    await edit(root, fixture, 'u3');
    const dialog = root.querySelector('#edit-dialog')?.textContent;
    expect(dialog).toContain(
      'The identity provider keeps setting the display name and email at each sync; the username stays as you set it.',
    );
    expect(dialog).not.toContain('may overwrite');
  });

  it('puts a 422 on the username field next to it, and keeps the dialog open', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/users/u1', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.username', message: 'Invalid' }]),
    });
    const { fixture, root } = await open(server, [user('u1', 'bob')]);
    await edit(root, fixture, 'u1');
    type(root, '#edit-username', 'alice');
    await save(root, fixture);
    expect(root.querySelector('#edit-username-error')?.textContent).toContain('1 to 64 letters');
    expect(root.querySelector('#edit-dialog .alert-error')).toBeNull();
    expect(root.querySelector<HTMLDialogElement>('#edit-dialog')!.open).toBe(true);
  });

  it('shows a failed session reload after your own rename on the page, not in the closed dialog', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/users/${ME_ID}`, {
      body: user(ME_ID, 'alicia', { isInstanceAdmin: true }),
    });
    server.on('GET', '/api/v0/auth/me', { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root } = await open(server, [user(ME_ID, 'alice', { isInstanceAdmin: true })]);
    await edit(root, fixture, ME_ID);
    type(root, '#edit-username', 'alicia');
    await save(root, fixture);
    expect(row(root, ME_ID).textContent).toContain('alicia');
    expect(root.querySelector('#edit-dialog .alert-error')).toBeNull();
    expect(root.querySelector('.alert-error')).not.toBeNull();
    expect(root.querySelector<HTMLDialogElement>('#edit-dialog')!.open).toBe(false);
  });
});

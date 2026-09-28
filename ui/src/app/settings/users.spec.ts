import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, page, provideFakeServer, settle } from '../../testing/fake-server';
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

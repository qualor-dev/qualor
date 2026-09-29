import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { ChangePasswordPage } from './change-password.page';
import { SessionStore } from './session';

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

describe('ChangePasswordPage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [ChangePasswordPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me({ passwordChangeRequired: true }));
  });

  async function render() {
    const fixture = TestBed.createComponent(ChangePasswordPage);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  async function fill(
    root: HTMLElement,
    fixture: { whenStable(): Promise<unknown> },
    values: [string, string, string],
  ) {
    type(root, '#password-current', values[0]);
    type(root, '#password-new', values[1]);
    type(root, '#password-confirm', values[2]);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
  }

  it('explains a forced change and checks length and confirmation before asking the server', async () => {
    const { fixture, root } = await render();
    expect(root.querySelector('[role="status"]')?.textContent).toContain('An administrator');
    await fill(root, fixture, ['old password!', 'short', 'short']);
    expect(root.textContent).toContain('Use at least 12 characters.');
    await fill(root, fixture, ['old password!', 'a long new passphrase', 'a different one here']);
    expect(root.textContent).toContain('The two new passwords differ.');
    expect(server.requests).toEqual([]);
  });

  it('marks a wrong current password on its field', async () => {
    server.on('PUT', '/api/v0/auth/me/password', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.currentPassword', message: 'Current password is incorrect' },
      ]),
    });
    const { fixture, root } = await render();
    await fill(root, fixture, ['wrong', 'a long new passphrase', 'a long new passphrase']);
    expect(root.querySelector('#password-current-error')?.textContent).toContain(
      'The current password is not correct.',
    );
    expect(root.querySelector('#password-current')?.getAttribute('aria-invalid')).toBe('true');
  });

  it('changes the password, reloads the session and opens the projects', async () => {
    server.on('PUT', '/api/v0/auth/me/password', { status: 204 });
    server.on('GET', '/api/v0/auth/me', { body: me() });
    const { fixture, root } = await render();
    await fill(root, fixture, ['old password!', 'a long new passphrase', 'a long new passphrase']);
    expect(server.requestsTo('PUT', '/api/v0/auth/me/password')[0]?.body).toEqual({
      currentPassword: 'old password!',
      newPassword: 'a long new passphrase',
    });
    expect(TestBed.inject(SessionStore).user()?.passwordChangeRequired).toBe(false);
    expect(TestBed.inject(Router).url).toBe('/projects');
  });

  it('offers the account name to password managers without showing it', async () => {
    const { root } = await render();
    const username = root.querySelector<HTMLInputElement>('input[autocomplete="username"]');
    expect(username?.value).toBe('alice');
    expect(username?.hidden).toBe(true);
    expect(username?.readOnly).toBe(true);
  });

  it('sits in the auth layout, Sign out a quiet button under the form', async () => {
    const { root } = await render();
    expect(root.querySelector('q-auth-layout main.auth-page .auth-card h1')?.textContent).toContain(
      'Change your password',
    );
    const signOut = [...root.querySelectorAll('button')].find(
      (b) => b.textContent?.trim() === 'Sign out',
    );
    expect(signOut?.classList.contains('btn-quiet')).toBe(true);
  });

  it('lets a user who must change the password sign out instead', async () => {
    server.on('POST', '/api/v0/auth/logout', { status: 204 });
    const { fixture, root } = await render();
    const signOut = [...root.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Sign out'),
    );
    expect(signOut?.type).toBe('button');
    signOut!.click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/auth/logout')[0]?.headers.get('x-qualor-csrf')).toBe(
      'csrf-token',
    );
    expect(server.requestsTo('PUT', '/api/v0/auth/me/password')).toEqual([]);
    expect(TestBed.inject(SessionStore).me()).toBeNull();
    expect(TestBed.inject(Router).url).toBe('/login');
  });
});

import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { safeReturnUrl } from './guards';
import { LoginPage } from './login.page';
import { SSO_ERROR_CODES, SSO_ERROR_GENERIC, ssoErrorText } from './sso-text';

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

describe('LoginPage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [LoginPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
  });

  async function render(returnUrl?: string) {
    const fixture = TestBed.createComponent(LoginPage);
    if (returnUrl) fixture.componentRef.setInput('returnUrl', returnUrl);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  it('labels both fields and signs in, then goes to the return URL', async () => {
    server.on('POST', '/api/v0/auth/login', { status: 204 });
    server.on('GET', '/api/v0/auth/me', { body: me() });
    const { fixture, root } = await render('/projects/p1');
    expect(root.querySelector('label[for="login-username"]')?.textContent).toContain('Username');
    expect(root.querySelector('label[for="login-password"]')?.textContent).toContain('Password');
    type(root, '#login-username', ' alice ');
    type(root, '#login-password', 'a perfectly fine passphrase');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/auth/login')[0]?.body).toEqual({
      username: 'alice',
      password: 'a perfectly fine passphrase',
    });
    expect(TestBed.inject(Router).url).toBe('/projects/p1');
  });

  it('keeps the submit button focusable while signing in, and sends once', async () => {
    let answer: (reply: { status: number }) => void = () => undefined;
    server.on('POST', '/api/v0/auth/login', () => new Promise((resolve) => (answer = resolve)));
    server.on('GET', '/api/v0/auth/me', { body: me() });
    const { fixture, root } = await render();
    type(root, '#login-username', 'alice');
    type(root, '#login-password', 'a perfectly fine passphrase');
    const button = root.querySelector<HTMLButtonElement>('button[type="submit"]')!;
    button.focus();
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(document.activeElement).toBe(button);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/auth/login')).toHaveLength(1);
    answer({ status: 204 });
    await settle(fixture);
  });

  it('shows a localized alert for wrong credentials and clears the password', async () => {
    server.on('POST', '/api/v0/auth/login', {
      status: 401,
      body: problem(401, 'INVALID_CREDENTIALS'),
    });
    const { fixture, root } = await render();
    type(root, '#login-username', 'alice');
    type(root, '#login-password', 'wrong');
    await settle(fixture); // the browser renders between typing and submitting
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'Invalid username or password.',
    );
    expect(root.querySelector<HTMLInputElement>('#login-password')!.value).toBe('');
  });

  it('never follows a return URL that names another host, and keeps secrets out of URLs', async () => {
    server.on('POST', '/api/v0/auth/login', { status: 204 });
    server.on('GET', '/api/v0/auth/me', { body: me() });
    const { fixture, root } = await render('//evil.example/phish');
    expect(root.querySelector('form')?.getAttribute('method')).toBe('post');
    type(root, '#login-username', 'alice');
    type(root, '#login-password', 'a perfectly fine passphrase');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/auth/login')[0]?.query.toString()).toBe('');
    expect(TestBed.inject(Router).url).toBe('/projects');
  });

  it('goes to the password change when the account requires it (ruling R7)', async () => {
    server.on('POST', '/api/v0/auth/login', { status: 204 });
    server.on('GET', '/api/v0/auth/me', { body: me({ passwordChangeRequired: true }) });
    const { fixture, root } = await render('/projects');
    type(root, '#login-username', 'alice');
    type(root, '#login-password', 'temporary password');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/change-password');
  });
});

describe('LoginPage single sign-on (sso-scim.md §18)', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [LoginPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
  });

  type Methods = {
    password: 'everyone' | 'break_glass_only';
    providers: { id: string; name: string; protocol: 'oidc' | 'saml'; startUrl: string }[];
  };

  /** Answers `GET /auth/methods` with `answer` (a status alone is a failure) and renders. */
  async function render(answer: Methods | number, query: { sso_error?: string } = {}) {
    server.on(
      'GET',
      '/api/v0/auth/methods',
      typeof answer === 'number'
        ? { status: answer, body: problem(answer, 'NOT_FOUND') }
        : { body: answer },
    );
    const fixture = TestBed.createComponent(LoginPage);
    fixture.componentRef.setInput('returnUrl', '/projects');
    if (query.sso_error !== undefined) fixture.componentRef.setInput('sso_error', query.sso_error);
    await settle(fixture);
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('shows a button per provider above the password form', async () => {
    const { el } = await render({
      password: 'everyone',
      providers: [
        { id: 'c1', name: 'Acme SSO', protocol: 'oidc', startUrl: '/api/v0/ee/sso/c1/start' },
      ],
    });
    const button = el.querySelector<HTMLAnchorElement>('[data-test=sso-c1]')!;
    expect(button.textContent).toContain('Sign in with Acme SSO');
    expect(button.getAttribute('href')).toBe('/api/v0/ee/sso/c1/start?returnTo=%2Fprojects');
    const form = el.querySelector('form[data-test=password-form]');
    expect(form).not.toBeNull();
    // Above: the button comes before the form in document order.
    expect(button.compareDocumentPosition(form!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('sits in the auth layout, each provider a button with the key icon', async () => {
    const { el } = await render({
      password: 'everyone',
      providers: [
        { id: 'c1', name: 'Acme SSO', protocol: 'oidc', startUrl: '/api/v0/ee/sso/c1/start' },
        { id: 'c2', name: 'Corp SAML', protocol: 'saml', startUrl: '/api/v0/ee/sso/c2/start' },
      ],
    });
    expect(el.querySelector('q-auth-layout main.auth-page .auth-card h1')?.textContent).toContain(
      'Sign in to Qualor',
    );
    for (const id of ['c1', 'c2']) {
      const button = el.querySelector<HTMLAnchorElement>(`[data-test=sso-${id}]`)!;
      expect(button.classList.contains('btn')).toBe(true);
      expect(button.querySelector('q-icon')?.getAttribute('name')).toBe('key');
    }
    // "or sign in with a password" divides the providers from the form.
    expect(el.querySelector('.auth-or')?.textContent?.trim()).toBe('or sign in with a password');
  });

  it('shows no divider without providers', async () => {
    const { el } = await render({ password: 'everyone', providers: [] });
    expect(el.querySelector('form[data-test=password-form]')).not.toBeNull();
    expect(el.querySelector('.auth-or')).toBeNull();
  });

  it('never builds a start link that leaves this server', async () => {
    const { fixture, el } = await render({
      password: 'everyone',
      providers: [
        { id: 'c1', name: 'Acme', protocol: 'oidc', startUrl: '/api/v0/ee/sso/c1/start' },
      ],
    });
    fixture.componentRef.setInput('returnUrl', '//evil.example/phish');
    await settle(fixture);
    expect(el.querySelector('[data-test=sso-c1]')!.getAttribute('href')).toBe(
      '/api/v0/ee/sso/c1/start?returnTo=%2Fprojects',
    );
  });

  it('adds returnTo to a start address that already has a query', async () => {
    const { el } = await render({
      password: 'everyone',
      providers: [
        {
          id: 'c1',
          name: 'Acme',
          protocol: 'oidc',
          startUrl: '/api/v0/ee/sso/c1/start?hint=acme&returnTo=%2Fold',
        },
      ],
    });
    expect(el.querySelector('[data-test=sso-c1]')!.getAttribute('href')).toBe(
      '/api/v0/ee/sso/c1/start?hint=acme&returnTo=%2Fprojects',
    );
  });

  it('folds the password form away when only break-glass admins may use it', async () => {
    const { fixture, el } = await render({
      password: 'break_glass_only',
      providers: [
        { id: 'c1', name: 'Acme SSO', protocol: 'saml', startUrl: '/api/v0/ee/sso/c1/start' },
      ],
    });
    expect(el.querySelector('form[data-test=password-form]')).toBeNull();
    const toggle = el.querySelector<HTMLButtonElement>('[data-test=emergency-sign-in]')!;
    expect(toggle.textContent).toContain('Emergency administrator sign-in');
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    toggle.click();
    await settle(fixture);
    expect(el.querySelector('form[data-test=password-form]')).not.toBeNull();
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
  });

  it.each([
    ['flow_expired', 'took too long'],
    ['flow_mismatch', 'started in another tab'],
    ['email_in_use', 'already has a Qualor account'],
    ['no_account', 'no Qualor account for you yet'],
    ['inactive_user', 'deactivated'],
    ['unavailable', 'not available'],
    ['rate_limited', 'Too many sign-in attempts'],
    ['nonsense', 'Single sign-on failed'],
    ['<script>alert(1)</script>', 'Single sign-on failed'],
  ])('explains ?sso_error=%s', async (code, text) => {
    const { el } = await render({ password: 'everyone', providers: [] }, { sso_error: code });
    const alert = el.querySelector('[data-test=sso-error]')!;
    expect(alert.textContent).toContain(text);
    expect(alert.getAttribute('role')).toBe('alert');
    // The raw query value is never rendered.
    if (code !== 'unavailable') expect(el.textContent).not.toContain(code);
  });

  it('has a fixed message for every code the server sends (SSO_ERROR_REASONS)', () => {
    const generic = SSO_ERROR_GENERIC;
    for (const code of SSO_ERROR_CODES) {
      expect(ssoErrorText(code), code).not.toBe(generic);
      expect(ssoErrorText(code).length, code).toBeGreaterThan(10);
    }
    expect(ssoErrorText('toString')).toBe(generic);
    expect(ssoErrorText('__proto__')).toBe(generic);
  });

  it('shows only the password form when methods cannot be read (an older server)', async () => {
    const { el } = await render(404);
    expect(el.querySelector('form[data-test=password-form]')).not.toBeNull();
    expect(el.querySelector('[data-test^=sso-]')).toBeNull();
    expect(el.querySelector('[data-test=emergency-sign-in]')).toBeNull();
  });
});

describe('safeReturnUrl', () => {
  it('keeps paths of this app and drops anything that names another host', () => {
    expect(safeReturnUrl('/projects/p1?x=1')).toBe('/projects/p1?x=1');
    for (const unsafe of ['//evil.example', '/\\evil.example', 'https://evil.example', '', null]) {
      expect(safeReturnUrl(unsafe)).toBe('/projects');
    }
    // Browsers drop tabs and newlines from URLs, so the first two would read as `//evil.example`.
    for (const unsafe of [
      '/\t/evil.example',
      '/\r\n/evil.example',
      '/projects\\..\\..\\evil',
      'javascript:alert(1)',
      ' /projects',
      undefined,
    ]) {
      expect(safeReturnUrl(unsafe), JSON.stringify(unsafe)).toBe('/projects');
    }
  });
});

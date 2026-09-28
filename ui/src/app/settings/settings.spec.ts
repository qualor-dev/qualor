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
import { OrgContext } from '../org/org-context';
import { type Token, TokensPage } from './tokens.page';
import { type User, UsersPage } from './users.page';
import { excerptText, type Webhook, WebhooksPage } from './webhooks.page';

function setup(admin = true): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
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

function button(root: HTMLElement, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

const TOKEN: Token = {
  id: 't1',
  name: 'laptop',
  prefix: 'qlr_pat_ab',
  scopes: ['read'],
  expiresAt: null,
  lastUsedAt: null,
  createdAt: '',
};

describe('TokensPage', () => {
  it('creates a token with the chosen scopes and shows it once', async () => {
    const server = setup();
    server.on('GET', '/api/v0/tokens', { body: page([TOKEN]) });
    server.on('POST', '/api/v0/tokens', {
      status: 201,
      body: { ...TOKEN, id: 't2', name: 'ci', token: 'qlr_pat_secret-value' },
    });
    const fixture = TestBed.createComponent(TokensPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('tbody')?.textContent).toContain('qlr_pat_ab…');
    type(root, '#token-name', 'ci');
    const upload = [...root.querySelectorAll('fieldset label')].find((l) =>
      l.textContent?.includes('Upload analyses'),
    );
    upload?.querySelector('input')?.click();
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/tokens')[0]?.body).toEqual({
      name: 'ci',
      scopes: ['read', 'analysis:write'],
      expiresInDays: 90,
    });
    expect(root.querySelector<HTMLInputElement>('#secret-once')?.value).toBe(
      'qlr_pat_secret-value',
    );
  });

  it('lists tokens by prefix only, announces a new one, and forgets its secret on Done and on leaving', async () => {
    const server = setup();
    server.on('GET', '/api/v0/tokens', { body: page([TOKEN]) });
    server.on('POST', '/api/v0/tokens', {
      status: 201,
      body: { ...TOKEN, id: 't2', name: 'ci', token: 'qlr_pat_secret-value' },
    });
    const fixture = TestBed.createComponent(TokensPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#token-name', 'ci');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Token ci created. Copy it now: it is shown only this once.',
    );
    // The secret lives only in the one-time field: never in the table, never in the status.
    expect(root.querySelector('table')?.textContent).not.toContain('secret-value');
    expect(root.querySelector('[role="status"]')?.textContent).not.toContain('secret-value');
    expect(root.querySelector<HTMLInputElement>('#secret-once')?.readOnly).toBe(true);
    // The name field is emptied for the next token.
    expect(root.querySelector<HTMLInputElement>('#token-name')?.value).toBe('');

    button(root, 'Done').click();
    await settle(fixture);
    expect(root.querySelector('#secret-once')).toBeNull();

    type(root, '#token-name', 'again');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector<HTMLInputElement>('#secret-once')?.value).toBe(
      'qlr_pat_secret-value',
    );
    const page_ = fixture.componentInstance as unknown as { created: () => unknown };
    fixture.destroy();
    expect(page_.created()).toBeNull();
  });

  it('copies the secret with the Clipboard API and says so, or says how to copy it by hand', async () => {
    const server = setup();
    server.on('GET', '/api/v0/tokens', { body: page([]) });
    server.on('POST', '/api/v0/tokens', {
      status: 201,
      body: { ...TOKEN, id: 't2', name: 'ci', token: 'qlr_pat_secret-value' },
    });
    const writeText = vi.fn().mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error());
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const fixture = TestBed.createComponent(TokensPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#token-name', 'ci');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    button(root, 'Copy').click();
    await settle(fixture);
    expect(writeText).toHaveBeenCalledWith('qlr_pat_secret-value');
    expect(root.querySelector('q-secret-once')?.textContent).toContain('Copied.');
    button(root, 'Copy').click();
    await settle(fixture);
    expect(root.querySelector('q-secret-once')?.textContent).toContain(
      'Copying failed: select the text and copy it yourself.',
    );
    Reflect.deleteProperty(navigator, 'clipboard');
  });

  it('needs a scope, sends no expiry for "Never", and maps a refused name to its field', async () => {
    const server = setup();
    server.on('GET', '/api/v0/tokens', { body: page([]) });
    server.on('POST', '/api/v0/tokens', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.name', message: 'Too long' }]),
    });
    const fixture = TestBed.createComponent(TokensPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#token-name', 'ci');
    const read = [...root.querySelectorAll('fieldset label')].find((l) =>
      l.textContent?.includes('Read'),
    );
    read?.querySelector('input')?.click();
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/tokens')).toHaveLength(0);
    expect(root.querySelector('fieldset')?.textContent).toContain('Choose at least one scope.');
    expect(document.activeElement).toBe(root.querySelector('fieldset input'));

    read?.querySelector('input')?.click();
    choose(root, '#token-expiry', '');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/tokens')[0]?.body).toEqual({
      name: 'ci',
      scopes: ['read'],
    });
    const name = root.querySelector<HTMLInputElement>('#token-name')!;
    expect(name.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#token-name-error')?.textContent).toContain(
      'Enter a name of at most 100 characters',
    );
    // Focus moves to the refused field.
    expect(document.activeElement).toBe(name);
    expect(root.querySelector('#secret-once')).toBeNull();
  });

  it('explains that only a browser session creates tokens (403 SESSION_REQUIRED)', async () => {
    const server = setup();
    server.on('GET', '/api/v0/tokens', { body: page([]) });
    server.on('POST', '/api/v0/tokens', {
      status: 403,
      body: problem(403, 'SESSION_REQUIRED'),
    });
    const fixture = TestBed.createComponent(TokensPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#token-name', 'ci');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'Personal tokens can only be created from a signed-in browser session, not with a token.',
    );
    expect(root.querySelector('#secret-once')).toBeNull();
  });

  it('revokes only after a confirmation that names the token, then drops its row', async () => {
    const server = setup();
    let tokens = [TOKEN, { ...TOKEN, id: 't3', name: 'ci <b>', prefix: 'qlr_pat_cd' }];
    server.on('GET', '/api/v0/tokens', () => ({ body: page(tokens) }));
    server.on('DELETE', '/api/v0/tokens/t1', () => {
      tokens = tokens.filter((t) => t.id !== 't1');
      return { status: 204 };
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false);
    const fixture = TestBed.createComponent(TokensPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const revoke = () => root.querySelector<HTMLButtonElement>('tbody tr button')!;
    revoke().click();
    await settle(fixture);
    expect(confirm).toHaveBeenCalledWith(
      'Revoke the token "laptop"? Scripts using it stop working.',
    );
    expect(server.requestsTo('DELETE', '/api/v0/tokens/t1')).toHaveLength(0);
    confirm.mockReturnValueOnce(true);
    revoke().click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', '/api/v0/tokens/t1')).toHaveLength(1);
    expect(root.querySelector('tbody')?.textContent).not.toContain('laptop');
    expect(root.querySelector('tbody')?.textContent).toContain('ci <b>');
    expect(root.querySelector('tbody b')).toBeNull();
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Token laptop revoked.');
    confirm.mockRestore();
  });
});

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

describe('UsersPage', () => {
  it('creates a user who must change the password, and deactivates one', async () => {
    const server = setup();
    const alice: User = {
      id: 'u1',
      username: 'alice',
      displayName: null,
      email: null,
      isInstanceAdmin: false,
      active: true,
      passwordChangeRequired: true,
      hasPassword: true,
      sso: { identities: 0, scim: false },
      lastLoginAt: null,
      createdAt: '',
    };
    server.on('GET', '/api/v0/users', { body: page([alice]) });
    server.on('POST', '/api/v0/users', {
      status: 201,
      body: { ...alice, id: 'u2', username: 'bob' },
    });
    server.on('PATCH', '/api/v0/users/u1', { body: { ...alice, active: false } });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('tbody')?.textContent).toContain('Must change password');
    type(root, '#user-username', 'bob');
    type(root, '#user-password', 'short');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('at least 12 characters');
    type(root, '#user-password', 'a long initial passphrase');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/users')[0]?.body).toEqual({
      username: 'bob',
      password: 'a long initial passphrase',
      isInstanceAdmin: false,
    });
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'bob can sign in now and must choose a new password first.',
    );
    [...root.querySelectorAll('button')]
      .find((b) => b.textContent?.includes('Deactivate'))!
      .click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/users/u1')[0]?.body).toEqual({ active: false });
  });

  it('patches the changed row in place and keeps no password in the form', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users', { body: page([user('u1', 'alice')]) });
    server.on('PATCH', '/api/v0/users/u1', { body: user('u1', 'alice', { active: false }) });
    server.on('POST', '/api/v0/users', {
      status: 201,
      body: user('u2', 'bob', { passwordChangeRequired: true }),
    });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    for (const id of ['#user-password', '#reset-password']) {
      const input = root.querySelector<HTMLInputElement>(id)!;
      expect(input.type).toBe('password');
      expect(input.getAttribute('autocomplete')).toBe('new-password');
    }
    const row = root.querySelector('tbody tr')!;
    button(root, 'Deactivate').click();
    await settle(fixture);
    expect(root.querySelector('tbody tr')).toBe(row);
    expect(row.textContent).toContain('Deactivated');
    expect(server.requestsTo('GET', '/api/v0/users')).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('alice is deactivated.');

    type(root, '#user-username', 'bob');
    type(root, '#user-password', 'a long initial passphrase');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector<HTMLInputElement>('#user-password')?.value).toBe('');
    expect(root.textContent).not.toContain('a long initial passphrase');
  });

  it('shows the last-admin refusal (409 LAST_ADMIN) and leaves the row as it was', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users', {
      body: page([user('u1', 'root', { isInstanceAdmin: true })]),
    });
    server.on('PATCH', '/api/v0/users/u1', { status: 409, body: problem(409, 'LAST_ADMIN') });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    button(root, 'Remove admin').click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/users/u1')[0]?.body).toEqual({
      isInstanceAdmin: false,
    });
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'The last active administrator cannot be demoted, removed or deactivated.',
    );
    expect(root.querySelector('tbody')?.textContent).toContain('Instance admin');
  });

  it('maps refused fields of a new user to the fields and clears the password', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users', { body: page([]) });
    server.on('POST', '/api/v0/users', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.username', message: 'Invalid' },
        { path: 'body.email', message: 'Invalid' },
      ]),
    });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#user-username', 'bob smith');
    type(root, '#user-email', 'bob@');
    type(root, '#user-password', 'a long initial passphrase');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#user-username')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#user-username-error')?.textContent).toContain(
      'Use 1 to 64 letters, digits, dots, dashes or underscores for the username.',
    );
    expect(root.querySelector('#user-email')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#user-email-error')?.textContent).toContain(
      'Enter a valid email address',
    );
    // Focus moves to the first refused field.
    expect(document.activeElement).toBe(root.querySelector('#user-username'));
    expect(root.querySelector<HTMLInputElement>('#user-password')?.value).toBe('');
  });

  it('resets a password, which the user must change at the next sign-in', async () => {
    const server = setup();
    server.on('GET', '/api/v0/users', { body: page([user('u1', 'alice')]) });
    server.on('PATCH', '/api/v0/users/u1', {
      body: user('u1', 'alice', { passwordChangeRequired: true }),
    });
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    choose(root, '#reset-user', 'u1');
    type(root, '#reset-password', 'a new temporary passphrase');
    root.querySelectorAll('form')[1]!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/users/u1')[0]?.body).toEqual({
      password: 'a new temporary passphrase',
    });
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'alice must choose a new password at the next sign-in.',
    );
    expect(root.querySelector<HTMLInputElement>('#reset-password')?.value).toBe('');
    expect(root.querySelector('tbody')?.textContent).toContain('Must change password');
  });

  it('asks before signing yourself out, and offers no reset of your own password here', async () => {
    const server = setup();
    const self = me({ admin: true }).user;
    server.on('GET', '/api/v0/users', {
      body: page([user(self.id, self.username, { isInstanceAdmin: true }), user('u2', 'bob')]),
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false);
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    root.querySelector<HTMLButtonElement>('tbody tr button')!.click();
    await settle(fixture);
    expect(confirm).toHaveBeenCalledWith(
      'Deactivate your own account? You are signed out at once and cannot sign in again.',
    );
    expect(server.requestsTo('PATCH', `/api/v0/users/${self.id}`)).toHaveLength(0);
    const options = [...root.querySelectorAll('#reset-user option')].map((o) => o.textContent);
    expect(options).not.toContain(self.username);
    expect(options).toContain('bob');
    confirm.mockRestore();
  });

  it('tells a user who is not an instance admin, and asks the server nothing', async () => {
    const server = setup(false);
    const fixture = TestBed.createComponent(UsersPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.textContent).toContain('Only instance administrators manage users.');
    expect(server.requestsTo('GET', '/api/v0/users')).toHaveLength(0);
    expect(root.querySelector('form')).toBeNull();
  });
});

function webhook(id: string, url: string, overrides: Partial<Webhook> = {}): Webhook {
  return {
    id,
    organizationId: ORG_ID,
    projectId: null,
    url,
    events: ['analysis.completed'],
    active: true,
    createdAt: '',
    updatedAt: '',
    ...overrides,
  };
}

describe('WebhooksPage', () => {
  it('adds a webhook for every project and shows the generated secret once', async () => {
    const server = setup();
    const hook: Webhook = {
      id: 'w1',
      organizationId: ORG_ID,
      projectId: null,
      url: 'https://hooks.example.com/qualor',
      events: ['analysis.completed'],
      active: true,
      createdAt: '',
      updatedAt: '',
    };
    server.on('GET', '/api/v0/webhooks', { body: page([hook]) });
    server.on('POST', '/api/v0/webhooks', {
      status: 201,
      body: { ...hook, id: 'w2', secret: 'whsec_generated' },
    });
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('section')?.textContent).toContain('Analysis completed');
    type(root, '#webhook-url', 'https://ci.example.com/hook');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/webhooks')[0]?.body).toEqual({
      organizationId: ORG_ID,
      url: 'https://ci.example.com/hook',
      events: ['analysis.completed', 'gate.status_changed'],
    });
    expect(root.querySelector<HTMLInputElement>('#secret-once')?.value).toBe('whsec_generated');
  });

  it('maps a refused URL (the SSRF checks, 422 body.url) to the URL field', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', { body: page([]) });
    server.on('POST', '/api/v0/webhooks', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.url', message: 'Private address' }]),
    });
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#webhook-url', 'https://127.0.0.1/internal');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const url = root.querySelector<HTMLInputElement>('#webhook-url')!;
    expect(url.getAttribute('aria-invalid')).toBe('true');
    expect(url.getAttribute('aria-describedby')).toBe('webhook-url-error');
    expect(root.querySelector('#webhook-url-error')?.textContent).toContain(
      'Use an https URL of a public host',
    );
    // The server's English message is never shown.
    expect(root.textContent).not.toContain('Private address');
    expect(url.value).toBe('https://127.0.0.1/internal');
    expect(root.querySelector('#secret-once')).toBeNull();
    // Typing again clears the error.
    type(root, '#webhook-url', 'https://ci.example.com/hook');
    await settle(fixture);
    expect(root.querySelector('#webhook-url-error')).toBeNull();
  });

  it('says so when the organization has 50 webhooks (409 WEBHOOK_LIMIT_REACHED)', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', { body: page([]) });
    server.on('POST', '/api/v0/webhooks', {
      status: 409,
      body: problem(409, 'WEBHOOK_LIMIT_REACHED'),
    });
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#webhook-url', 'https://ci.example.com/hook');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This organization has as many webhooks as it can have (50). Delete one first.',
    );
  });

  it('shows the last 10 deliveries, with the receiver excerpt as plain text', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', {
      body: page([webhook('w1', 'https://hooks.example.com/<b>x</b>')]),
    });
    server.on('GET', '/api/v0/webhooks/w1/deliveries', {
      body: page([
        {
          id: 'd1',
          event: 'gate.status_changed',
          status: 'failed',
          attempts: 3,
          responseCode: 500,
          responseExcerpt: '<img src=x onerror="alert(1)">\u0007\u001b[31mboom',
          nextAttemptAt: null,
          createdAt: '2026-09-15T09:00:00.000Z',
        },
      ]),
    });
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('section b')).toBeNull();
    const details = root.querySelector('details')!;
    details.open = true;
    details.dispatchEvent(new Event('toggle'));
    await settle(fixture);
    const request = server.requestsTo('GET', '/api/v0/webhooks/w1/deliveries')[0];
    expect(request?.query.get('limit')).toBe('10');
    const text = details.textContent ?? '';
    expect(text).toContain('Sep 15, 2026, 9:00 AM UTC');
    expect(text).toContain('Quality gate status changed');
    expect(text).toContain('Failed');
    expect(text).toContain('HTTP 500');
    expect(text).toContain('<img src=x onerror="alert(1)">[31mboom');
    expect(text).not.toContain('\u0007');
    expect(details.querySelector('img')).toBeNull();
  });

  it('switches a webhook off in place and deletes one after a confirmation', async () => {
    const server = setup();
    let hooks = [webhook('w1', 'https://a.example.com/'), webhook('w2', 'https://b.example.com/')];
    server.on('GET', '/api/v0/webhooks', () => ({ body: page(hooks) }));
    server.on('PATCH', '/api/v0/webhooks/w1', {
      body: webhook('w1', 'https://a.example.com/', { active: false }),
    });
    server.on('DELETE', '/api/v0/webhooks/w2', () => {
      hooks = hooks.filter((h) => h.id !== 'w2');
      return { status: 204 };
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const first = root.querySelector('section')!;
    first.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/webhooks/w1')[0]?.body).toEqual({ active: false });
    expect(root.querySelector('section')).toBe(first);
    expect(first.querySelector<HTMLInputElement>('input[type="checkbox"]')?.checked).toBe(false);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Webhook https://a.example.com/ switched off.',
    );
    root.querySelectorAll('section')[1]!.querySelector<HTMLButtonElement>('button')!.click();
    await settle(fixture);
    expect(confirm).toHaveBeenCalledWith(
      'Delete the webhook to https://b.example.com/? Its delivery history goes too.',
    );
    expect(server.requestsTo('DELETE', '/api/v0/webhooks/w2')).toHaveLength(1);
    expect(root.querySelectorAll('section')).toHaveLength(1);
    confirm.mockRestore();
  });

  it('tells a member who is not an organization admin, and asks the server nothing', async () => {
    const server = setup(false);
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.textContent).toContain('Only organization administrators manage webhooks.');
    expect(server.requestsTo('GET', '/api/v0/webhooks')).toHaveLength(0);
    expect(root.querySelector('form')).toBeNull();
  });
});

describe('WebhooksPage: answers that arrive after the context changed', () => {
  const OTHER_ORG = '0190a6c2-0000-7000-8000-000000000002';

  /** An admin of ORG_ID who is only a member of OTHER_ORG. */
  function setupTwoOrgs(): FakeServer {
    const server = new FakeServer();
    server.on('GET', '/api/v0/organizations', {
      body: page([
        { id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' },
        { id: OTHER_ORG, key: 'other', name: 'Other', createdAt: '', updatedAt: '' },
      ]),
    });
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    const base = me({ admin: true });
    TestBed.inject(SessionStore).set({
      ...base,
      user: { ...base.user, isInstanceAdmin: false },
      memberships: [
        {
          organizationId: ORG_ID,
          organizationKey: 'default',
          organizationName: 'Default',
          role: 'admin',
          permissions: [...ORG_ADMIN_PERMISSIONS],
        },
        {
          organizationId: OTHER_ORG,
          organizationKey: 'other',
          organizationName: 'Other',
          role: 'member',
          permissions: ['org.read'],
        },
      ],
    });
    return server;
  }

  afterEach(() => localStorage.clear());

  const secretOf = (fixture: { componentInstance: unknown }) =>
    (fixture.componentInstance as { secret: () => string | null }).secret();

  it('forgets a shown secret when the organization changes, also to one the user does not administer', async () => {
    const server = setupTwoOrgs();
    server.on('GET', '/api/v0/webhooks', { body: page([]) });
    server.on('POST', '/api/v0/webhooks', {
      status: 201,
      body: { ...webhook('w2', 'https://ci.example.com/hook'), secret: 'whsec_generated' },
    });
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#webhook-url', 'https://ci.example.com/hook');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(secretOf(fixture)).toBe('whsec_generated');
    TestBed.inject(OrgContext).select(OTHER_ORG);
    await settle(fixture);
    expect(secretOf(fixture)).toBeNull();
    expect(root.textContent).toContain('Only organization administrators manage webhooks.');
  });

  it('drops the answer of an addition made for the previous organization', async () => {
    const server = setupTwoOrgs();
    server.on('GET', '/api/v0/webhooks', { body: page([]) });
    let answer: (reply: { status: number; body: unknown }) => void = () => undefined;
    server.on('POST', '/api/v0/webhooks', () => new Promise((resolve) => (answer = resolve)));
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#webhook-url', 'https://ci.example.com/hook');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    TestBed.inject(OrgContext).select(OTHER_ORG);
    await settle(fixture);
    answer({
      status: 201,
      body: { ...webhook('w2', 'https://ci.example.com/hook'), secret: 'whsec_generated' },
    });
    await settle(fixture);
    expect(secretOf(fixture)).toBeNull();
    expect(root.textContent).not.toContain('Webhook added');
  });

  it('shows the deliveries of the latest opening, never an older answer that arrives late', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', { body: page([webhook('w1', 'https://a.example.com/')]) });
    const answers: ((reply: { body: unknown }) => void)[] = [];
    server.on(
      'GET',
      '/api/v0/webhooks/w1/deliveries',
      () => new Promise((resolve) => answers.push(resolve)),
    );
    const delivery = (id: string, code: number) => ({
      id,
      event: 'analysis.completed',
      status: 'succeeded',
      attempts: 1,
      responseCode: code,
      responseExcerpt: null,
      nextAttemptAt: null,
      createdAt: '2026-09-15T09:00:00.000Z',
    });
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const details = root.querySelector('details')!;
    const toggle = (open: boolean) => {
      details.open = open;
      details.dispatchEvent(new Event('toggle'));
    };
    toggle(true);
    await settle(fixture);
    toggle(false);
    toggle(true);
    await settle(fixture);
    // jsdom also fires its own toggle events: at least one request per opening.
    expect(answers.length).toBeGreaterThanOrEqual(2);
    answers.at(-1)!({ body: page([delivery('new', 204)]) });
    await settle(fixture);
    for (const answer of answers.slice(0, -1)) answer({ body: page([delivery('old', 500)]) });
    await settle(fixture);
    expect(details.textContent).toContain('HTTP 204');
    expect(details.textContent).not.toContain('HTTP 500');
  });
});

describe('excerptText', () => {
  it('drops control characters but keeps line breaks and tabs, and bounds the length', () => {
    expect(excerptText('a\u0000b\u007fc\td\ne\r\nf')).toBe('abc\td\ne\nf');
    expect(excerptText(null)).toBe('');
    expect(excerptText('x'.repeat(5000))).toHaveLength(1024);
  });
});

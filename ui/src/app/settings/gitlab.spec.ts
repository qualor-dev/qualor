import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  expectNoPasswordManager,
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { testProblemText } from './gitlab-text';
import { type Connection, GitLabPage } from './gitlab.page';

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
  ciSetup: { available: false, reason: 'not_allowed', missing: [] },
};

// Assembled at run time, so the repository's own Gitleaks check finds no fake secret here (.gitleaks.toml).
const SECRET = ['glhook-ui-', '0123456789abcdef'].join('');
const WEBHOOK_URL = 'https://q.example/api/v0/gitlab/webhooks/c1';
/** The connection as the server shows it once its webhook secret is set. */
const WITH_SECRET: Connection = {
  ...CONNECTION,
  gitlab: {
    webhookSecretSet: true,
    webhookSecretReadable: true,
    webhookUrl: WEBHOOK_URL,
    ciSetupAllowed: false,
  },
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
  ciSetup: { available: false, reason: 'missing_permissions', missing: [] },
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

function button(root: HTMLElement, text: string, within: ParentNode = root): HTMLButtonElement {
  return [...within.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

async function render() {
  const fixture = TestBed.createComponent(GitLabPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

describe('GitLabPage (scm.md §2)', () => {
  it('adds a connection: the token is sent once, never shown, and the field is emptied', async () => {
    const server = setup();
    server.on('POST', '/api/v0/scm-connections', {
      status: 201,
      body: { ...CONNECTION, id: 'c2' },
    });
    const { fixture, root } = await render();
    expect(root.querySelector('section')?.textContent).toContain('https://gitlab.example.com');
    // Step 8: the short create form is in the New connection dialog.
    const create = root.querySelector<HTMLDialogElement>('dialog#create-dialog')!;
    button(root, 'New connection').click();
    await settle(fixture);
    expect(create.open).toBe(true);
    const token = root.querySelector<HTMLInputElement>('#gitlab-token')!;
    expect(token.type).toBe('password');
    expect(token.getAttribute('autocomplete')).toBe('new-password');
    expectNoPasswordManager(token);
    type(root, '#gitlab-url', 'https://gitlab.acme.test');
    type(root, '#gitlab-token', 'glpat-secret-value');
    root.querySelector<HTMLFormElement>('#create-dialog form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections')[0]?.body).toEqual({
      organizationId: ORG_ID,
      provider: 'gitlab',
      baseUrl: 'https://gitlab.acme.test',
      token: 'glpat-secret-value',
      ciSetupAllowed: true,
    });
    expect(token.value).toBe('');
    expect(root.textContent).not.toContain('glpat-secret-value');
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'GitLab connection added.',
    );
    expect(create.open).toBe(false);
  });

  it('maps a refused address and token to their fields, in the UI’s own words', async () => {
    const server = setup();
    server.on('POST', '/api/v0/scm-connections', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.baseUrl', message: 'The URL points at this machine' },
      ]),
    });
    const { fixture, root } = await render();
    type(root, '#gitlab-url', 'https://localhost');
    type(root, '#gitlab-token', 'glpat-x');
    root.querySelector<HTMLFormElement>('#create-dialog form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#gitlab-url')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#gitlab-url-error')?.textContent).toContain(
      'QUALOR_SCM_INTERNAL_HOSTS',
    );
    expect(root.textContent).not.toContain('The URL points at this machine');
    // A missing token is refused before any request.
    type(root, '#gitlab-token', '');
    root.querySelector<HTMLFormElement>('#create-dialog form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#gitlab-token-error')?.textContent).toContain(
      'Paste the access token',
    );
    expect(server.requestsTo('POST', '/api/v0/scm-connections')).toHaveLength(1);
  });

  it('tests a connection and says what went wrong without GitLab’s own words', async () => {
    const server = setup();
    let answer: unknown = {
      ok: true,
      user: { username: 'project_7_bot' },
      project: null,
      problem: null,
    };
    server.on('POST', '/api/v0/scm-connections/c1/test', () => ({ body: answer }));
    const { fixture, root } = await render();
    const state = () => root.querySelector('section .connection-state')?.textContent?.trim();
    expect(state()).toBe('Not tested yet');
    button(root, 'Test').click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections/c1/test')[0]?.body).toEqual({});
    expect(state()).toBe('Connected');
    expect(root.querySelector('section')?.textContent).toContain('Connected as project_7_bot.');
    answer = {
      ok: false,
      user: null,
      project: null,
      problem: { code: 'token_refused', message: 'GitLab refused the token (HTTP 401)' },
    };
    button(root, 'Test').click();
    await settle(fixture);
    const text = root.querySelector('section')?.textContent;
    expect(text).toContain(testProblemText('token_refused'));
    expect(text).not.toContain('HTTP 401');
    expect(state()).toBe('Test failed');
    // A failed test reads as the failure it is, never in the green news of a success.
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe('');
    expect(root.querySelector('p[role="alert"]')?.textContent).toContain(
      testProblemText('token_refused'),
    );
    // A 403 is a missing permission of a valid token, in words of its own.
    expect(testProblemText('permission_missing')).toContain('Maintainer role');
  });

  it("replaces a token without echoing it, and deletes a connection after the page's own confirmation", async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/scm-connections/c1', { body: CONNECTION });
    let connections = [CONNECTION];
    server.on('GET', '/api/v0/scm-connections', () => ({ body: page(connections) }));
    server.on('DELETE', '/api/v0/scm-connections/c1', () => {
      connections = [];
      return { status: 204 };
    });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    const field = root.querySelector<HTMLInputElement>('#token-c1')!;
    field.value = 'glpat-new';
    field.closest('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/c1')[0]?.body).toEqual({
      token: 'glpat-new',
    });
    expect(field.value).toBe('');
    button(root, 'Delete').click();
    await settle(fixture);
    const ask = root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!;
    expect(ask.open).toBe(true);
    expect(ask.querySelector('#confirm-text')?.textContent?.trim()).toBe(
      'Delete the GitLab connection to https://gitlab.example.com? Its projects stop being decorated.',
    );
    button(root, 'Delete', ask).click();
    await settle(fixture);
    expect(confirm).not.toHaveBeenCalled();
    expect(server.requestsTo('DELETE', '/api/v0/scm-connections/c1')).toHaveLength(1);
    expect(root.textContent).toContain('No GitLab connection yet.');
    confirm.mockRestore();
  });

  it('asks for the token again when the address changes, and names the address it replaces (scm.md §2.1)', async () => {
    const server = setup();
    let status = 422;
    server.on('PATCH', '/api/v0/scm-connections/c1', (request) =>
      status === 422
        ? {
            status,
            body: problem(422, 'VALIDATION_FAILED', [
              { path: 'body.token', message: 'Changing the base URL needs the token' },
            ]),
          }
        : { body: { ...CONNECTION, baseUrl: (request.body as { baseUrl: string }).baseUrl } },
    );
    const { fixture, root } = await render();
    const form = root.querySelector<HTMLInputElement>('#token-c1')!.closest('form')!;
    // The form says which connection's token it replaces, and that a new address needs it.
    expect(form.textContent).toContain('https://gitlab.example.com');
    expect(form.textContent).toContain('Changing the address needs the token again');
    expect(root.querySelector<HTMLInputElement>('#url-c1')?.value).toBe(
      'https://gitlab.example.com',
    );
    // Another address without a token is refused before any request, on the token field.
    type(root, '#url-c1', 'https://gitlab.other.test');
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/c1')).toHaveLength(0);
    const token = root.querySelector<HTMLInputElement>('#token-c1')!;
    expect(token.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#token-error-c1')?.textContent).toContain(
      'Changing the address needs the token again',
    );
    expect(document.activeElement).toBe(token);
    // The server's 422 on body.token lands on the same field, in the UI's words.
    token.value = 'glpat-new';
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/c1')[0]?.body).toEqual({
      baseUrl: 'https://gitlab.other.test',
      token: 'glpat-new',
    });
    expect(token.value).toBe('');
    expect(root.querySelector('#token-error-c1')?.textContent).toContain(
      'Changing the address needs the token again',
    );
    expect(root.textContent).not.toContain('Changing the base URL needs the token');
    status = 200;
    token.value = 'glpat-new';
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(token.value).toBe('');
    expect(root.textContent).not.toContain('glpat-new');
    expect(root.querySelector('section')?.getAttribute('aria-label')).toBe(
      'https://gitlab.other.test',
    );
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'The connection now points at https://gitlab.other.test.',
    );
  });

  it('says what a connection’s own form replaces: its token, and its address when changed', async () => {
    setup();
    const { root } = await render();
    const form = root.querySelector<HTMLInputElement>('#token-c1')!.closest('form')!;
    expect(form.textContent?.replace(/\s+/g, ' ')).toContain(
      'Replacing https://gitlab.example.com (token and address)',
    );
  });

  describe('the webhook (6I-4)', () => {
    function withSecret(server: FakeServer): void {
      server.on('GET', '/api/v0/scm-connections', { body: page([WITH_SECRET]) });
    }
    /** A PATCH answered as the server does: the connection with the secret as the request left it. */
    function patched(server: FakeServer): void {
      server.on('PATCH', '/api/v0/scm-connections/c1', (request) => {
        const body = request.body as { baseUrl?: string; webhookSecret?: string | null };
        const set = body.webhookSecret !== null && body.webhookSecret !== undefined;
        const unset = body.webhookSecret === null;
        return {
          body: {
            ...WITH_SECRET,
            baseUrl: body.baseUrl ?? WITH_SECRET.baseUrl,
            gitlab: unset
              ? {
                  webhookSecretSet: false,
                  webhookSecretReadable: false,
                  webhookUrl: null,
                  ciSetupAllowed: false,
                }
              : {
                  ...WITH_SECRET.gitlab!,
                  webhookSecretSet: set || WITH_SECRET.gitlab!.webhookSecretSet,
                },
          },
        };
      });
    }
    const patches = (server: FakeServer) =>
      server.requestsTo('PATCH', '/api/v0/scm-connections/c1');

    it('shows the webhook URL with its copy button, and what to paste where', async () => {
      const server = setup();
      withSecret(server);
      const writeText = vi.fn().mockResolvedValue(undefined);
      Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
      const { fixture, root } = await render();
      const card = root.querySelector<HTMLElement>('section.card')!;
      const field = card.querySelector<HTMLInputElement>('#webhook-url-c1')!;
      expect(field.value).toBe(WEBHOOK_URL);
      expect(field.readOnly).toBe(true);
      expect(card.querySelector('label[for="webhook-url-c1"]')?.textContent).toContain(
        'Webhook URL',
      );
      expect(card.textContent?.replace(/\s+/g, ' ')).toContain(
        "In the GitLab project's Settings → Webhooks, paste this address and the secret, and tick Comments.",
      );
      button(card, 'Copy').click();
      await settle(fixture);
      expect(writeText).toHaveBeenCalledWith(WEBHOOK_URL);
      expect(card.textContent).toContain('Copied.');
      // Neither the secret nor a hint of one is on the page.
      expect(card.textContent).not.toContain(SECRET);
      expect(card.textContent).not.toContain('No webhook secret');
    });

    it('says when there is no webhook secret, when it can no longer be read, and when the server has no public URL', async () => {
      const server = setup();
      server.on('GET', '/api/v0/scm-connections', {
        body: page([
          CONNECTION,
          {
            ...WITH_SECRET,
            id: 'c2',
            baseUrl: 'https://gitlab.two.test',
            gitlab: {
              webhookSecretSet: true,
              webhookSecretReadable: false,
              webhookUrl: WEBHOOK_URL,
            },
          },
          {
            ...WITH_SECRET,
            id: 'c3',
            baseUrl: 'https://gitlab.three.test',
            gitlab: {
              webhookSecretSet: true,
              webhookSecretReadable: true,
              webhookUrl: null,
              ciSetupAllowed: false,
            },
          },
        ]),
      });
      const { root } = await render();
      const [none, unreadable, nowhere] = [...root.querySelectorAll('section.card')];
      expect(none?.textContent?.replace(/\s+/g, ' ')).toContain(
        'No webhook secret: replies and commands are answered at the next analysis.',
      );
      expect(none?.querySelector('#webhook-url-c1')).toBeNull();
      expect(none?.querySelector('.alert')).toBeNull();
      expect(unreadable?.querySelector('.alert-error')?.textContent?.trim()).toBe(
        'The webhook secret can no longer be read: set it again.',
      );
      expect(unreadable?.textContent).not.toContain('No webhook secret');
      expect(nowhere?.textContent?.replace(/\s+/g, ' ')).toContain(
        'No webhook URL: the server has no QUALOR_PUBLIC_URL.',
      );
      expect(nowhere?.querySelector('#webhook-url-c3')).toBeNull();
      expect(nowhere?.textContent).not.toContain('No webhook secret');
    });

    it('sets, replaces and removes the secret: read once from its field, sent once, never shown', async () => {
      const server = setup();
      patched(server);
      const { fixture, root } = await render();
      expect(button(root, 'Remove the webhook secret')).toBeUndefined();
      const field = root.querySelector<HTMLInputElement>('#secret-c1')!;
      expect(field.type).toBe('password');
      expect(field.getAttribute('autocomplete')).toBe('new-password');
      expectNoPasswordManager(field);
      const form = field.closest('form')!;
      // Too short: refused before any request, under the field, which takes focus.
      field.value = 'short';
      form.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(patches(server)).toHaveLength(0);
      expect(field.value).toBe('');
      expect(field.getAttribute('aria-invalid')).toBe('true');
      expect(root.querySelector('#secret-error-c1')?.textContent).toContain(
        'Use 16 to 256 printable characters without spaces',
      );
      expect(document.activeElement).toBe(field);
      // Spaces are no part of a secret: a long one with them is refused too.
      field.value = 'a secret with spaces in it';
      form.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(patches(server)).toHaveLength(0);
      expect(root.querySelector('#secret-error-c1')?.textContent).toContain('Use 16 to 256');
      // A right one is sent once, the field is emptied, and the page shows the URL to paste.
      field.value = SECRET;
      form.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(patches(server)[0]?.body).toEqual({ webhookSecret: SECRET });
      expect(field.value).toBe('');
      expect(field.getAttribute('aria-invalid')).toBeNull();
      expect(root.textContent).not.toContain(SECRET);
      expect(root.querySelector('[role="status"]')?.textContent).toContain(
        'The webhook secret was set.',
      );
      expect(root.querySelector<HTMLInputElement>('#webhook-url-c1')?.value).toBe(WEBHOOK_URL);
      // Replaced: the same field. Removed: a button that only a stored secret has.
      field.value = `${SECRET}-2`;
      form.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(patches(server)[1]?.body).toEqual({ webhookSecret: `${SECRET}-2` });
      button(root, 'Remove the webhook secret').click();
      await settle(fixture);
      expect(patches(server)[2]?.body).toEqual({ webhookSecret: null });
      expect(root.querySelector('[role="status"]')?.textContent).toContain(
        'The webhook secret was removed: replies and commands are answered at the next analysis.',
      );
      expect(root.querySelector('#webhook-url-c1')).toBeNull();
      expect(root.textContent).toContain('No webhook secret');
      expect(button(root, 'Remove the webhook secret')).toBeUndefined();
    });

    it('maps the server’s refusal of the secret to its field, in the UI’s own words', async () => {
      const server = setup();
      server.on('PATCH', '/api/v0/scm-connections/c1', {
        status: 422,
        body: problem(422, 'VALIDATION_FAILED', [
          { path: 'body.webhookSecret', message: 'Use 16-256 printable ASCII characters' },
        ]),
      });
      const { fixture, root } = await render();
      const field = root.querySelector<HTMLInputElement>('#secret-c1')!;
      field.value = SECRET;
      field.closest('form')!.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(field.value).toBe('');
      expect(root.querySelector('#secret-error-c1')?.textContent).toContain(
        'Use 16 to 256 printable characters',
      );
      expect(root.textContent).not.toContain('Use 16-256 printable ASCII characters');
      expect(root.querySelector('p[role="alert"]')).toBeNull();
    });

    it('offers the secret with a new address only while one is stored', async () => {
      setup();
      const { root } = await render();
      expect(root.querySelector('#new-secret-c1')).toBeNull();
      expect(root.querySelector('#drop-secret-c1')).toBeNull();
    });

    it('needs the secret again with a new address, or "Drop the webhook secret", and sends what it is given', async () => {
      const server = setup();
      withSecret(server);
      patched(server);
      const { fixture, root } = await render();
      const form = root.querySelector<HTMLInputElement>('#token-c1')!.closest('form')!;
      const token = root.querySelector<HTMLInputElement>('#token-c1')!;
      const secret = root.querySelector<HTMLInputElement>('#new-secret-c1')!;
      const drop = root.querySelector<HTMLInputElement>('#drop-secret-c1')!;
      expect(secret.type).toBe('password');
      expectNoPasswordManager(secret);
      expect(form.textContent?.replace(/\s+/g, ' ')).toContain(
        'A new address with a stored webhook secret needs the secret again, or dropping it.',
      );
      const submit = async (fields: {
        url?: string;
        token?: string;
        secret?: string;
        drop?: boolean;
      }) => {
        type(root, '#url-c1', fields.url ?? 'https://gitlab.other.test');
        token.value = fields.token ?? 'glpat-new';
        secret.value = fields.secret ?? '';
        drop.checked = fields.drop ?? false;
        form.dispatchEvent(new Event('submit'));
        await settle(fixture);
      };
      // A new address with neither the secret nor the box: refused before any request.
      await submit({});
      expect(patches(server)).toHaveLength(0);
      expect(root.querySelector('#new-secret-error-c1')?.textContent).toContain(
        'Changing the address needs the webhook secret again, or tick "Drop the webhook secret".',
      );
      expect(document.activeElement).toBe(secret);
      // Both at once, and a secret that is too short: refused too.
      await submit({ secret: SECRET, drop: true });
      expect(root.querySelector('#new-secret-error-c1')?.textContent).toContain(
        'Type a new webhook secret or tick "Drop the webhook secret", not both.',
      );
      await submit({ secret: 'short' });
      expect(root.querySelector('#new-secret-error-c1')?.textContent).toContain(
        'Use 16 to 256 printable characters',
      );
      expect(patches(server)).toHaveLength(0);
      // The secret again is sent with the address and the token, and every field is emptied.
      await submit({ secret: SECRET });
      expect(patches(server)[0]?.body).toEqual({
        baseUrl: 'https://gitlab.other.test',
        token: 'glpat-new',
        webhookSecret: SECRET,
      });
      expect([token.value, secret.value, drop.checked]).toEqual(['', '', false]);
      expect(root.querySelector('#new-secret-error-c1')).toBeNull();
      expect(root.querySelector('[role="status"]')?.textContent).toContain(
        'The connection now points at https://gitlab.other.test, and its webhook secret was replaced.',
      );
      expect(root.textContent).not.toContain(SECRET);
      // The box drops it: null, and the page says so.
      await submit({ url: 'https://gitlab.third.test', drop: true });
      expect(patches(server)[1]?.body).toEqual({
        baseUrl: 'https://gitlab.third.test',
        token: 'glpat-new',
        webhookSecret: null,
      });
      expect(drop.checked).toBe(false);
      expect(root.querySelector('[role="status"]')?.textContent).toContain(
        'The connection now points at https://gitlab.third.test, and its webhook secret was removed: replies and commands are answered at the next analysis.',
      );
    });

    it('sends a replaced secret with the token alone, and drops it with the token alone', async () => {
      const server = setup();
      withSecret(server);
      patched(server);
      const { fixture, root } = await render();
      const form = root.querySelector<HTMLInputElement>('#token-c1')!.closest('form')!;
      root.querySelector<HTMLInputElement>('#token-c1')!.value = 'glpat-new';
      root.querySelector<HTMLInputElement>('#new-secret-c1')!.value = SECRET;
      form.dispatchEvent(new Event('submit'));
      await settle(fixture);
      // Same address: the secret travels with the token, no address.
      expect(patches(server)[0]?.body).toEqual({ token: 'glpat-new', webhookSecret: SECRET });
      // The page says that both were replaced, and shows neither.
      expect(root.querySelector('[role="status"]')?.textContent).toContain(
        'The token and the webhook secret of https://gitlab.example.com were replaced.',
      );
      expect(root.textContent).not.toContain(SECRET);
      expect(root.textContent).not.toContain('glpat-new');
      root.querySelector<HTMLInputElement>('#token-c1')!.value = 'glpat-newer';
      root.querySelector<HTMLInputElement>('#drop-secret-c1')!.checked = true;
      form.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(patches(server)[1]?.body).toEqual({ token: 'glpat-newer', webhookSecret: null });
      expect(root.querySelector('[role="status"]')?.textContent).toContain(
        'The token of https://gitlab.example.com was replaced, and its webhook secret was removed: replies and commands are answered at the next analysis.',
      );
    });

    it('says that only the token was replaced when the stored secret is left as it is', async () => {
      const server = setup();
      withSecret(server);
      patched(server);
      const { fixture, root } = await render();
      const token = root.querySelector<HTMLInputElement>('#token-c1')!;
      token.value = 'glpat-new';
      token.closest('form')!.dispatchEvent(new Event('submit'));
      await settle(fixture);
      // No secret travels: the stored one stays, and the page does not say it was replaced.
      expect(patches(server)[0]?.body).toEqual({ token: 'glpat-new' });
      const status = root.querySelector('[role="status"]')?.textContent;
      expect(status).toContain('The token of https://gitlab.example.com was replaced.');
      expect(status).not.toContain('webhook secret');
    });

    it('maps the server’s demand for the secret again to its field', async () => {
      const server = setup();
      withSecret(server);
      server.on('PATCH', '/api/v0/scm-connections/c1', {
        status: 422,
        body: problem(422, 'VALIDATION_FAILED', [
          { path: 'body.webhookSecret', message: 'The server’s own words about the secret' },
        ]),
      });
      const { fixture, root } = await render();
      const form = root.querySelector<HTMLInputElement>('#token-c1')!.closest('form')!;
      // The page's own check passes (a secret is typed), the server's does not (it holds another).
      type(root, '#url-c1', 'https://gitlab.other.test');
      root.querySelector<HTMLInputElement>('#token-c1')!.value = 'glpat-new';
      root.querySelector<HTMLInputElement>('#new-secret-c1')!.value = SECRET;
      form.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(root.querySelector('#new-secret-error-c1')).not.toBeNull();
      expect(root.textContent).not.toContain('The server’s own words about the secret');
    });
  });

  it('lists only GitLab connections', async () => {
    const server = setup();
    server.on('GET', '/api/v0/scm-connections', { body: page([CONNECTION, GITHUB]) });
    const { root } = await render();
    const cards = root.querySelectorAll('.connection-list section.card');
    expect(cards).toHaveLength(1);
    expect(cards[0]?.textContent).toContain('https://gitlab.example.com');
    expect(cards[0]?.textContent).not.toContain('api.github.com');
  });

  it('leaves the project mapping to Repositories, and links to it', async () => {
    setup();
    const { root } = await render();
    expect(root.querySelector('table')).toBeNull();
    expect(root.querySelector('a[href="/settings/repositories"]')?.textContent?.trim()).toBe(
      'Repositories',
    );
  });

  it('tells a member who is not an organization admin, and asks the server nothing', async () => {
    const server = setup(false);
    const { root } = await render();
    expect(root.textContent).toContain('Only organization administrators connect GitLab.');
    expect(server.requestsTo('GET', '/api/v0/scm-connections')).toHaveLength(0);
    expect(root.querySelector('form')).toBeNull();
  });

  describe('CI setup (onboarding, "Connections")', () => {
    const LABEL = 'Allow Qualor to set up CI (opens merge requests, writes CI/CD variables)';
    const nameOf = (input: HTMLInputElement | null) =>
      (input?.labels?.[0]?.querySelector('.sw-name')?.textContent ?? '')
        .replace(/\s+/g, ' ')
        .trim();

    it('asks when a connection is added, and sends the answer', async () => {
      const server = setup();
      server.on('POST', '/api/v0/scm-connections', {
        status: 201,
        body: { ...CONNECTION, id: 'c2' },
      });
      const { fixture, root } = await render();
      button(root, 'New connection').click();
      await settle(fixture);
      const allow = root.querySelector<HTMLInputElement>('#gitlab-ci-setup')!;
      expect(allow.getAttribute('role')).toBe('switch');
      expect(nameOf(allow)).toBe(LABEL);
      expect(allow.checked).toBe(true);
      allow.click();
      type(root, '#gitlab-url', 'https://gitlab.acme.test');
      type(root, '#gitlab-token', 'glpat-secret-value');
      root
        .querySelector<HTMLFormElement>('#create-dialog form')!
        .dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(server.requestsTo('POST', '/api/v0/scm-connections')[0]?.body).toMatchObject({
        ciSetupAllowed: false,
      });
      // The next "New connection" asks again, from the default.
      button(root, 'New connection').click();
      await settle(fixture);
      expect(root.querySelector<HTMLInputElement>('#gitlab-ci-setup')!.checked).toBe(true);
    });

    it('turns it on and off on a connection, off by default for an existing one', async () => {
      const server = setup();
      const allowed: Connection = {
        ...CONNECTION,
        gitlab: { ...CONNECTION.gitlab!, ciSetupAllowed: true },
        ciSetup: { available: true, reason: null, missing: [] },
      };
      server.on('PATCH', '/api/v0/scm-connections/c1', (r) =>
        (r.body as { ciSetupAllowed: boolean }).ciSetupAllowed
          ? { body: allowed }
          : { body: CONNECTION },
      );
      const { fixture, root } = await render();
      const toggle = root.querySelector<HTMLInputElement>('#ci-setup-c1')!;
      expect(toggle.getAttribute('role')).toBe('switch');
      expect(nameOf(toggle)).toBe(LABEL);
      expect(toggle.checked).toBe(false);
      toggle.click();
      await settle(fixture);
      expect(server.requestsTo('PATCH', '/api/v0/scm-connections/c1').map((r) => r.body)).toEqual([
        { ciSetupAllowed: true },
      ]);
      expect(root.querySelector<HTMLInputElement>('#ci-setup-c1')!.checked).toBe(true);
      expect(root.querySelector('[role="status"]')?.textContent).toContain(
        'CI setup is on for https://gitlab.example.com.',
      );
      root.querySelector<HTMLInputElement>('#ci-setup-c1')!.click();
      await settle(fixture);
      expect(server.requestsTo('PATCH', '/api/v0/scm-connections/c1').map((r) => r.body)).toEqual([
        { ciSetupAllowed: true },
        { ciSetupAllowed: false },
      ]);
      expect(root.querySelector<HTMLInputElement>('#ci-setup-c1')!.checked).toBe(false);
      expect(root.querySelector('[role="status"]')?.textContent).toContain(
        'CI setup is off for https://gitlab.example.com.',
      );
    });

    it('puts the switch back when the change is refused', async () => {
      const server = setup();
      server.on('PATCH', '/api/v0/scm-connections/c1', {
        status: 403,
        body: problem(403, 'FORBIDDEN'),
      });
      const { fixture, root } = await render();
      root.querySelector<HTMLInputElement>('#ci-setup-c1')!.click();
      await settle(fixture);
      expect(root.querySelector<HTMLInputElement>('#ci-setup-c1')!.checked).toBe(false);
      expect(root.querySelector('[role="alert"]')).not.toBeNull();
    });

    it('says why CI setup still cannot work when the server has no public address', async () => {
      const server = setup();
      server.on('GET', '/api/v0/scm-connections', {
        body: page([
          {
            ...CONNECTION,
            gitlab: { ...CONNECTION.gitlab!, ciSetupAllowed: true },
            ciSetup: { available: false, reason: 'no_public_url', missing: [] },
          },
        ]),
      });
      const { root } = await render();
      const card = root.querySelector('section.card')!;
      expect(card.textContent).toContain(
        'Qualor needs its public address (QUALOR_PUBLIC_URL) to set up CI.',
      );
      expect(card.querySelector('a[href="/docs/install-server#the-settings-file"]')).not.toBeNull();
    });
  });
});

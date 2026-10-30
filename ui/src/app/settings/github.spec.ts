import { noAnswerYet } from '../../testing/pending';
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
import { OrgContext } from '../org/org-context';
import type { Connection } from './gitlab.page';
import { githubProblemText } from './github-text';
import { GitHubPage } from './github.page';

// Assembled at run time, so the repository's own Gitleaks check finds no fake secret here (.gitleaks.toml).
const WEBHOOK_SECRET = ['whsec-', '0123456789abcdef'].join('');
const PEM = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n';
const GITHUB: Connection = {
  id: 'g1',
  organizationId: ORG_ID,
  provider: 'github',
  baseUrl: 'https://api.github.com',
  createdAt: '2026-09-20T10:00:00.000Z',
  github: {
    appId: '123456',
    keyReadable: true,
    webhookSecretSet: true,
    webhookSecretReadable: true,
    webhookUrl: 'https://q.example/api/v0/github/webhooks/g1',
  },
  gitlab: null,
  ciSetup: { available: false, reason: 'missing_permissions', missing: [] },
};
const GITLAB: Connection = {
  ...GITHUB,
  id: 'c1',
  provider: 'gitlab',
  baseUrl: 'https://gitlab.example.com',
  github: null,
  gitlab: {
    webhookSecretSet: false,
    webhookSecretReadable: false,
    webhookUrl: null,
    ciSetupAllowed: false,
  },
};

function setup(admin = true): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
  server.on('GET', '/api/v0/scm-connections', { body: page([GITHUB, GITLAB]) });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin }));
  return server;
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

function button(root: ParentNode, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

async function render() {
  const fixture = TestBed.createComponent(GitHubPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

/**
 * The page's own status region, where its news is said: a child of the page itself, as no App
 * card's is (each card has a region of its own, for what its Test finds missing).
 */
function news(root: HTMLElement): Element | null {
  return root.querySelector(':scope > [role="status"]');
}

/** Puts a file in a file input and fires its `change`, as a browser does after a choice. */
function upload(root: HTMLElement, selector: string, file: File): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  Object.defineProperty(input, 'files', { value: [file], configurable: true });
  input.dispatchEvent(new Event('change'));
}

describe('GitHubPage (github.md §2)', () => {
  // OrgContext keeps the chosen organization in localStorage; the next spec must not inherit it.
  afterEach(() => localStorage.clear());

  it('points to Repositories for the mapping of projects to repositories', async () => {
    setup();
    const { root } = await render();
    const link = root.querySelector('.settings-head a[href="/settings/repositories"]');
    expect(link?.textContent?.trim()).toBe('Repositories');
    expect(root.textContent).not.toContain('Projects list of the');
  });

  it("names the App's five permissions, and what Contents is for", async () => {
    setup();
    const { root } = await render();
    const intro = root.querySelector('.settings-head')?.textContent?.replace(/\s+/g, ' ');
    expect(intro).toContain(
      'Give the App Checks, Contents and Pull requests (read and write), and Issues and Metadata (read-only). Qualor uses Contents only to resolve and reopen its own review conversations.',
    );
  });

  describe('what the App lacks, after a Test with a repository', () => {
    const passed = (missingAccess: string[] | null) => ({
      body: {
        ok: true,
        user: { username: 'qualor-acme[bot]' },
        project: { id: 424242, pathWithNamespace: 'acme/api', accessLevel: null },
        problem: null,
        missingAccess,
      },
    });
    const test = async (
      root: HTMLElement,
      fixture: Awaited<ReturnType<typeof render>>['fixture'],
    ) => {
      type(root, '#test-ref-g1', 'acme/api');
      button(root, 'Test').click();
      await settle(fixture);
    };
    const warning = (root: HTMLElement) => root.querySelector('#missing-g1 .alert-warn');
    const items = (root: HTMLElement) =>
      [...(warning(root)?.querySelectorAll('li') ?? [])].map((li) =>
        li.textContent?.replace(/\s+/g, ' ').trim(),
      );

    it('lists each missing item with its GitHub name, what it costs and what to do, and the Test still passed', async () => {
      const server = setup();
      server.on(
        'POST',
        '/api/v0/scm-connections/g1/test',
        passed(['contents_write', 'event_check_run', 'event_pull_request_review_comment']),
      );
      const { fixture, root } = await render();
      // Before any Test the card's region is there, and empty: it takes no room (scm.page.css).
      expect(root.querySelector('#missing-g1')?.matches(':empty')).toBe(true);
      await test(root, fixture);
      // A warning, not an error: the pill, the green news, and no alert.
      expect(root.querySelector('section .connection-state')?.textContent?.trim()).toBe(
        'Connected',
      );
      expect(root.querySelector('.alert-success')?.textContent).toContain(
        'the repository acme/api is reachable',
      );
      expect(root.querySelector('p[role="alert"]')).toBeNull();
      expect(warning(root)?.textContent?.replace(/\s+/g, ' ')).toContain(
        'The test passed, but the App lacks:',
      );
      expect(items(root)).toEqual([
        "Contents: Read and write: Qualor uses it only to resolve and reopen its own review conversations. Without it they stay open after a fix or a won't fix.",
        'The Check run event: the Re-run button does nothing.',
        "The Pull request review comment event: a reply in Qualor's conversations is answered only at the next analysis.",
      ]);
      // GitHub's own names, as the guide spells them.
      expect(
        [...(warning(root)?.querySelectorAll('li strong') ?? [])].map((s) => s.textContent),
      ).toEqual(['Contents: Read and write', 'Check run', 'Pull request review comment']);
      expect(warning(root)?.textContent?.replace(/\s+/g, ' ')).toContain(
        "Change the App's permissions and events on GitHub, then accept the new permissions on the installation.",
      );
      // Said where a screen reader hears it: the card's region is there before the warning.
      expect(root.querySelector('#missing-g1')?.getAttribute('role')).toBe('status');
    });

    it('has a text of its own for every missing item', async () => {
      const server = setup();
      server.on(
        'POST',
        '/api/v0/scm-connections/g1/test',
        passed([
          'contents_write',
          'issues_read',
          'event_check_run',
          'event_issue_comment',
          'event_pull_request_review_comment',
        ]),
      );
      const { fixture, root } = await render();
      await test(root, fixture);
      const all = items(root);
      expect(all).toHaveLength(5);
      expect(new Set(all).size).toBe(5);
      expect(all[1]).toBe(
        'Issues: Read-only: GitHub sends the Issue comment event only to an App that can read issues, so a qualor review comment is answered only at the next analysis.',
      );
      expect(all[3]).toBe(
        'The Issue comment event: a qualor review comment is answered only at the next analysis.',
      );
    });

    it('shows nothing when the App lacks nothing, or after a Test without a repository, and a later Test takes the warning away', async () => {
      const server = setup();
      let answer: { body: unknown } = passed(['issues_read']);
      server.on('POST', '/api/v0/scm-connections/g1/test', () => answer);
      const { fixture, root } = await render();
      await test(root, fixture);
      expect(items(root)).toHaveLength(1);
      answer = passed([]);
      await test(root, fixture);
      expect(warning(root)).toBeNull();
      expect(root.querySelector('section .connection-state')?.textContent?.trim()).toBe(
        'Connected',
      );
      answer = { body: { ...passed(null).body, project: null } };
      type(root, '#test-ref-g1', '');
      button(root, 'Test').click();
      await settle(fixture);
      expect(warning(root)).toBeNull();
      // A failed Test says its failure, and nothing of what is missing.
      answer = passed(['issues_read']);
      await test(root, fixture);
      expect(items(root)).toHaveLength(1);
      answer = {
        body: {
          ok: false,
          user: null,
          project: null,
          problem: { code: 'not_installed', message: 'x' },
          missingAccess: null,
        },
      };
      await test(root, fixture);
      expect(warning(root)).toBeNull();
    });
  });

  it('lists only GitHub connections, with the App id and the webhook URL', async () => {
    setup();
    const { root } = await render();
    const cards = root.querySelectorAll('section.card');
    expect(cards).toHaveLength(1);
    expect(cards[0]?.textContent).toContain('123456');
    expect(cards[0]?.textContent).toContain('https://q.example/api/v0/github/webhooks/g1');
    expect(root.textContent).not.toContain('gitlab.example.com');
  });

  it('adds an App: the key and the secret are sent once, never shown, and the fields emptied', async () => {
    const server = setup();
    server.on('POST', '/api/v0/scm-connections', { status: 201, body: { ...GITHUB, id: 'g2' } });
    const { fixture, root } = await render();
    const key = root.querySelector<HTMLTextAreaElement>('#github-key')!;
    expect(key.tagName).toBe('TEXTAREA');
    expect(key.getAttribute('autocomplete')).toBe('off');
    expectNoPasswordManager(key);
    const secret = root.querySelector<HTMLInputElement>('#github-secret')!;
    expect(secret.type).toBe('password');
    expect(secret.getAttribute('autocomplete')).toBe('new-password');
    expectNoPasswordManager(secret);
    // The secret serves the Re-run button and the answers to replies and commands.
    expect(root.querySelector('#github-secret-hint')?.textContent?.replace(/\s+/g, ' ')).toContain(
      "The same secret as in the App's webhook settings, for the Re-run button and for answering replies and commands at once.",
    );
    type(root, '#github-url', 'https://api.github.com');
    type(root, '#github-app-id', '123456');
    type(root, '#github-key', PEM);
    type(root, '#github-secret', WEBHOOK_SECRET);
    root.querySelector<HTMLFormElement>('form.card')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections')[0]?.body).toEqual({
      organizationId: ORG_ID,
      provider: 'github',
      baseUrl: 'https://api.github.com',
      appId: '123456',
      privateKey: PEM,
      webhookSecret: WEBHOOK_SECRET,
    });
    expect(root.querySelector<HTMLTextAreaElement>('#github-key')!.value).toBe('');
    expect(root.querySelector<HTMLInputElement>('#github-secret')!.value).toBe('');
    expect(root.textContent).not.toContain('MIIEow');
    expect(root.textContent).not.toContain(WEBHOOK_SECRET);
  });

  it('maps a refused key to its field in the UI’s own words', async () => {
    const server = setup();
    server.on('POST', '/api/v0/scm-connections', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.privateKey', message: 'Use the unencrypted key GitHub generated' },
      ]),
    });
    const { fixture, root } = await render();
    type(root, '#github-url', 'https://api.github.com');
    type(root, '#github-app-id', '1');
    type(root, '#github-key', PEM);
    root.querySelector<HTMLFormElement>('form.card')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#github-key')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#github-key-error')?.textContent).toContain('private key');
    expect(root.textContent).not.toContain('Use the unencrypted key GitHub generated');
  });

  it('refuses a bad App id, a short secret and a missing key before any request', async () => {
    const server = setup();
    const { fixture, root } = await render();
    type(root, '#github-app-id', '0123');
    type(root, '#github-secret', 'short');
    root.querySelector<HTMLFormElement>('form.card')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/scm-connections')).toHaveLength(0);
    expect(root.querySelector('#github-app-id')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#github-key')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#github-secret')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector<HTMLInputElement>('#github-secret')!.value).toBe('');
    expect(document.activeElement).toBe(root.querySelector('#github-app-id'));
  });

  it('reads a .pem file into the key field, and refuses one over 16 KiB before any request', async () => {
    const server = setup();
    const { fixture, root } = await render();
    upload(root, '#github-key-file', new File([PEM], 'app.private-key.pem'));
    await settle(fixture);
    expect(root.querySelector<HTMLTextAreaElement>('#github-key')!.value).toBe(PEM);
    upload(root, '#github-key-file', new File(['x'.repeat(16 * 1024 + 1)], 'big.pem'));
    await settle(fixture);
    expect(root.querySelector('#github-key-error')?.textContent).toContain(
      'The key file is larger than 16 KiB',
    );
    expect(root.querySelector<HTMLTextAreaElement>('#github-key')!.value).toBe('');
    expect(server.requests.filter((r) => r.method !== 'GET')).toHaveLength(0);
  });

  it('tests against owner/repo and explains a missing installation', async () => {
    const server = setup();
    server.on('POST', '/api/v0/scm-connections/g1/test', {
      body: {
        ok: false,
        user: null,
        project: null,
        problem: { code: 'not_installed', message: 'x' },
      },
    });
    const { fixture, root } = await render();
    const state = () => root.querySelector('section .connection-state')?.textContent?.trim();
    expect(state()).toBe('Not tested yet');
    type(root, '#test-ref-g1', 'acme/api');
    button(root, 'Test').click();
    await settle(fixture);
    expect(state()).toBe('Test failed');
    expect(server.requestsTo('POST', '/api/v0/scm-connections/g1/test')[0]?.body).toEqual({
      projectRef: 'acme/api',
    });
    expect(root.textContent).toContain(githubProblemText('not_installed'));
    // A failed test reads as the failure it is, never in the green news of a success.
    expect(news(root)?.textContent?.trim()).toBe('');
    expect(root.querySelector('p[role="alert"]')?.textContent).toContain(
      githubProblemText('not_installed'),
    );
  });

  it('has a sentence of its own for every test code', () => {
    const codes = [
      'undecryptable',
      'url_not_allowed',
      'not_public',
      'unresolved',
      'timeout',
      'unreachable',
      'token_refused',
      'not_found',
      'http_error',
      'bad_answer',
      'not_installed',
      'permission_missing',
    ] as const;
    const texts = codes.map((c) => githubProblemText(c));
    expect(new Set(texts).size).toBe(codes.length);
  });

  it('says when the key or the secret can no longer be read, and when there is no webhook secret', async () => {
    const server = setup();
    server.on('GET', '/api/v0/scm-connections', {
      body: page([
        {
          ...GITHUB,
          github: {
            appId: '123456',
            keyReadable: false,
            webhookSecretSet: true,
            webhookSecretReadable: false,
            webhookUrl: 'https://q.example/api/v0/github/webhooks/g1',
          },
        },
        {
          ...GITHUB,
          id: 'g3',
          github: {
            appId: '777',
            keyReadable: true,
            webhookSecretSet: false,
            webhookSecretReadable: false,
            webhookUrl: null,
          },
        },
      ]),
    });
    const { root } = await render();
    const [first, second] = [...root.querySelectorAll('section.card')];
    expect(first?.textContent).toContain('The private key can no longer be read: set it again');
    expect(first?.textContent).toContain('The webhook secret can no longer be read: set it again');
    expect(second?.textContent).not.toContain('can no longer be read');
    expect(second?.textContent).toContain(
      'No webhook secret: the Re-run button does nothing, and replies and commands are answered at the next analysis.',
    );
  });

  it('replaces the key, asks for the webhook secret again with a new address, and never echoes either', async () => {
    const server = setup();
    server.on('PATCH', '/api/v0/scm-connections/g1', (request) => ({
      body: {
        ...GITHUB,
        baseUrl: (request.body as { baseUrl?: string }).baseUrl ?? GITHUB.baseUrl,
      },
    }));
    const { fixture, root } = await render();
    const key = root.querySelector<HTMLTextAreaElement>('#key-g1')!;
    expect(key.value).toBe('');
    expect(root.querySelector<HTMLInputElement>('#new-secret-g1')!.value).toBe('');
    const form = key.closest('form')!;
    key.value = PEM;
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/g1')[0]?.body).toEqual({
      privateKey: PEM,
    });
    expect(key.value).toBe('');
    // A new address with a stored secret: the secret again, or dropping it, is required.
    type(root, '#url-g1', 'https://ghe.acme.test/api/v3');
    key.value = PEM;
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/g1')).toHaveLength(1);
    expect(key.value).toBe('');
    expect(root.querySelector('#new-secret-g1')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#new-secret-error-g1')?.textContent).toContain('webhook secret');
    key.value = PEM;
    root.querySelector<HTMLInputElement>('#new-secret-g1')!.value = 'whsec-new-0123456789';
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/g1')[1]?.body).toEqual({
      baseUrl: 'https://ghe.acme.test/api/v3',
      privateKey: PEM,
      webhookSecret: 'whsec-new-0123456789',
    });
    expect(root.querySelector<HTMLInputElement>('#new-secret-g1')!.value).toBe('');
    expect(news(root)?.textContent).toContain(
      'The App now uses https://ghe.acme.test/api/v3, and its webhook secret was replaced.',
    );
    expect(root.textContent).not.toContain('MIIEow');
    expect(root.textContent).not.toContain('whsec-new-0123456789');
  });

  it('says that the secret typed with a new key was replaced, or set where none was stored', async () => {
    const server = setup();
    const WITHOUT_SECRET: Connection = {
      ...GITHUB,
      github: {
        ...GITHUB.github!,
        webhookSecretSet: false,
        webhookSecretReadable: false,
        webhookUrl: null,
      },
    };
    let stored = GITHUB;
    server.on('GET', '/api/v0/scm-connections', () => ({ body: page([stored]) }));
    server.on('PATCH', '/api/v0/scm-connections/g1', (request) => ({
      body: {
        ...stored,
        baseUrl: (request.body as { baseUrl?: string }).baseUrl ?? stored.baseUrl,
      },
    }));
    const submit = async (fields: { url?: string }) => {
      const { fixture, root } = await render();
      if (fields.url !== undefined) type(root, '#url-g1', fields.url);
      root.querySelector<HTMLTextAreaElement>('#key-g1')!.value = PEM;
      root.querySelector<HTMLInputElement>('#new-secret-g1')!.value = 'whsec-new-0123456789';
      root.querySelector('#key-g1')!.closest('form')!.dispatchEvent(new Event('submit'));
      await settle(fixture);
      const status = news(root)?.textContent;
      fixture.destroy();
      return status;
    };
    expect(await submit({})).toContain(
      'The private key and the webhook secret of App 123456 were replaced.',
    );
    stored = WITHOUT_SECRET;
    expect(await submit({})).toContain(
      'The private key of App 123456 was replaced, and its webhook secret was set.',
    );
    expect(await submit({ url: 'https://ghe.acme.test/api/v3' })).toContain(
      'The App now uses https://ghe.acme.test/api/v3, and its webhook secret was set.',
    );
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/g1').map((r) => r.body)).toEqual([
      { privateKey: PEM, webhookSecret: 'whsec-new-0123456789' },
      { privateKey: PEM, webhookSecret: 'whsec-new-0123456789' },
      {
        baseUrl: 'https://ghe.acme.test/api/v3',
        privateKey: PEM,
        webhookSecret: 'whsec-new-0123456789',
      },
    ]);
  });

  it("changes the App id, sets and removes the webhook secret, and deletes after the page's own confirmation", async () => {
    const server = setup();
    let connections: Connection[] = [GITHUB];
    server.on('GET', '/api/v0/scm-connections', () => ({ body: page(connections) }));
    server.on('PATCH', '/api/v0/scm-connections/g1', { body: GITHUB });
    server.on('DELETE', '/api/v0/scm-connections/g1', () => {
      connections = [];
      return { status: 204 };
    });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    type(root, '#app-id-g1', '654321');
    root.querySelector('#app-id-g1')!.closest('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const secret = root.querySelector<HTMLInputElement>('#secret-g1')!;
    expect(secret.type).toBe('password');
    expect(secret.getAttribute('autocomplete')).toBe('new-password');
    expectNoPasswordManager(secret);
    expectNoPasswordManager(root.querySelector('#new-secret-g1')!);
    secret.value = WEBHOOK_SECRET;
    secret.closest('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(secret.value).toBe('');
    button(root, 'Remove the webhook secret').click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/scm-connections/g1').map((r) => r.body)).toEqual([
      { appId: '654321' },
      { webhookSecret: WEBHOOK_SECRET },
      { webhookSecret: null },
    ]);
    expect(news(root)?.textContent).toContain(
      'The webhook secret was removed: the Re-run button does nothing now, and replies and commands are answered at the next analysis.',
    );
    button(root, 'Delete').click();
    await settle(fixture);
    const ask = root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!;
    expect(ask.open).toBe(true);
    expect(ask.querySelector('#confirm-text')?.textContent?.trim()).toBe(
      'Delete the GitHub App 123456 at https://api.github.com? Its projects stop being decorated.',
    );
    button(ask, 'Delete').click();
    await settle(fixture);
    expect(confirm).not.toHaveBeenCalled();
    expect(server.requestsTo('DELETE', '/api/v0/scm-connections/g1')).toHaveLength(1);
    expect(root.textContent).toContain('No GitHub App yet.');
    confirm.mockRestore();
  });

  describe('the "Drop the webhook secret" box', () => {
    function patched(server: FakeServer): void {
      server.on('PATCH', '/api/v0/scm-connections/g1', (request) => {
        const body = request.body as { baseUrl?: string; webhookSecret?: string | null };
        return {
          body: {
            ...GITHUB,
            baseUrl: body.baseUrl ?? GITHUB.baseUrl,
            github: {
              ...GITHUB.github!,
              ...(body.webhookSecret === null
                ? {
                    webhookSecretSet: false,
                    webhookSecretReadable: false,
                    webhookUrl: null,
                    ciSetupAllowed: false,
                  }
                : {}),
            },
          },
        };
      });
    }

    it('removes the secret with a new key alone, and says so', async () => {
      const server = setup();
      patched(server);
      const { fixture, root } = await render();
      root.querySelector<HTMLTextAreaElement>('#key-g1')!.value = PEM;
      root.querySelector<HTMLInputElement>('#drop-secret-g1')!.checked = true;
      root.querySelector('#key-g1')!.closest('form')!.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(server.requestsTo('PATCH', '/api/v0/scm-connections/g1').map((r) => r.body)).toEqual([
        { privateKey: PEM, webhookSecret: null },
      ]);
      expect(news(root)?.textContent).toContain(
        'The private key of App 123456 was replaced, and its webhook secret was removed: the Re-run button does nothing now, and replies and commands are answered at the next analysis.',
      );
      expect(root.textContent).toContain(
        'No webhook secret: the Re-run button does nothing, and replies and commands are answered at the next analysis.',
      );
    });

    it('refuses a typed secret with the box ticked, before any request', async () => {
      const server = setup();
      patched(server);
      const { fixture, root } = await render();
      const secret = root.querySelector<HTMLInputElement>('#new-secret-g1')!;
      root.querySelector<HTMLTextAreaElement>('#key-g1')!.value = PEM;
      secret.value = 'whsec-new-0123456789';
      root.querySelector<HTMLInputElement>('#drop-secret-g1')!.checked = true;
      secret.closest('form')!.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(server.requestsTo('PATCH', '/api/v0/scm-connections/g1')).toHaveLength(0);
      expect(secret.getAttribute('aria-invalid')).toBe('true');
      expect(root.querySelector('#new-secret-error-g1')?.textContent).toContain('not both');
      expect(secret.value).toBe('');
      expect(root.querySelector<HTMLTextAreaElement>('#key-g1')!.value).toBe('');
      expect(document.activeElement).toBe(secret);
      expect(news(root)?.textContent?.trim()).toBe('');
    });

    it('removes the secret with a new address, and says so', async () => {
      const server = setup();
      patched(server);
      const { fixture, root } = await render();
      type(root, '#url-g1', 'https://ghe.acme.test/api/v3');
      root.querySelector<HTMLTextAreaElement>('#key-g1')!.value = PEM;
      root.querySelector<HTMLInputElement>('#drop-secret-g1')!.checked = true;
      root.querySelector('#key-g1')!.closest('form')!.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(server.requestsTo('PATCH', '/api/v0/scm-connections/g1').map((r) => r.body)).toEqual([
        { baseUrl: 'https://ghe.acme.test/api/v3', privateKey: PEM, webhookSecret: null },
      ]);
      expect(news(root)?.textContent).toContain(
        'The App now uses https://ghe.acme.test/api/v3, and its webhook secret was removed: the Re-run button does nothing now, and replies and commands are answered at the next analysis.',
      );
    });
  });

  it('refuses a .pem file that cannot be read, in the key field', async () => {
    const server = setup();
    const { fixture, root } = await render();
    const file = new File([PEM], 'app.private-key.pem');
    Object.defineProperty(file, 'text', { value: () => Promise.reject(new Error('NotReadable')) });
    upload(root, '#key-file-g1', file);
    await settle(fixture);
    const key = root.querySelector<HTMLTextAreaElement>('#key-g1')!;
    expect(root.querySelector('#key-error-g1')?.textContent).toContain(
      'The key file could not be read',
    );
    expect(key.getAttribute('aria-invalid')).toBe('true');
    expect(key.value).toBe('');
    expect(document.activeElement).toBe(key);
    expect(server.requests.filter((r) => r.method !== 'GET')).toHaveLength(0);
  });

  it('describes a refused row field by its error and its hint', async () => {
    setup();
    const { fixture, root } = await render();
    const form = root.querySelector('#key-g1')!.closest('form')!;
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#key-g1')?.getAttribute('aria-describedby')).toBe(
      'key-error-g1 key-hint-g1',
    );
    type(root, '#url-g1', 'https://ghe.acme.test/api/v3');
    root.querySelector<HTMLTextAreaElement>('#key-g1')!.value = PEM;
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#new-secret-g1')?.getAttribute('aria-describedby')).toBe(
      'new-secret-error-g1 new-secret-hint-g1',
    );
    expect(root.querySelector('#key-g1')?.getAttribute('aria-describedby')).toBe('key-hint-g1');
  });

  it('empties the secret fields of a submission ignored while a change runs', async () => {
    const server = setup();
    let answer: (reply: { status: number; body: unknown }) => void = noAnswerYet;
    server.on(
      'PATCH',
      '/api/v0/scm-connections/g1',
      () => new Promise((resolve) => (answer = resolve)),
    );
    const { fixture, root } = await render();
    const key = root.querySelector<HTMLTextAreaElement>('#key-g1')!;
    const newSecret = root.querySelector<HTMLInputElement>('#new-secret-g1')!;
    const secret = root.querySelector<HTMLInputElement>('#secret-g1')!;
    key.value = PEM;
    key.closest('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    // A change runs: every further submission is ignored, but its secrets never stay.
    key.value = PEM;
    newSecret.value = 'whsec-new-0123456789';
    key.closest('form')!.dispatchEvent(new Event('submit'));
    secret.value = WEBHOOK_SECRET;
    secret.closest('form')!.dispatchEvent(new Event('submit'));
    type(root, '#github-app-id', '1');
    type(root, '#github-key', PEM);
    type(root, '#github-secret', WEBHOOK_SECRET);
    root.querySelector<HTMLFormElement>('form.card')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(key.value).toBe('');
    expect(newSecret.value).toBe('');
    expect(secret.value).toBe('');
    expect(root.querySelector<HTMLTextAreaElement>('#github-key')!.value).toBe('');
    expect(root.querySelector<HTMLInputElement>('#github-secret')!.value).toBe('');
    expect(server.requests.filter((r) => r.method !== 'GET')).toHaveLength(1);
    answer({ status: 200, body: GITHUB });
    await settle(fixture);
  });

  it('empties every key and secret field when the organization changes, and when the page closes', async () => {
    const OTHER_ORG = '0190a6c2-0000-7000-8000-000000000002';
    const server = setup();
    server.on('GET', '/api/v0/organizations', {
      body: page([
        { id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' },
        { id: OTHER_ORG, key: 'other', name: 'Other', createdAt: '', updatedAt: '' },
      ]),
    });
    const { fixture, root } = await render();
    const fields = () =>
      ['#key-g1', '#new-secret-g1', '#secret-g1', '#github-key', '#github-secret'].map((selector) =>
        root.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!,
      );
    const fill = (all: (HTMLInputElement | HTMLTextAreaElement)[]) => {
      for (const field of all) field.value = WEBHOOK_SECRET;
      root.querySelector<HTMLInputElement>('#drop-secret-g1')!.checked = true;
    };
    const before = fields();
    fill(before);
    TestBed.inject(OrgContext).select(OTHER_ORG);
    await settle(fixture);
    expect(before.map((f) => f.value)).toEqual(['', '', '', '', '']);
    const after = fields();
    expect(after.map((f) => f.value)).toEqual(['', '', '', '', '']);
    expect(root.querySelector<HTMLInputElement>('#drop-secret-g1')!.checked).toBe(false);
    fill(after);
    fixture.destroy();
    expect(after.map((f) => f.value)).toEqual(['', '', '', '', '']);
  });

  it('shows members that only administrators connect GitHub', async () => {
    const server = setup(false);
    const { root } = await render();
    expect(root.textContent).toContain('Only organization administrators connect GitHub.');
    expect(root.querySelector('form')).toBeNull();
    expect(server.requestsTo('GET', '/api/v0/scm-connections')).toHaveLength(0);
  });
});

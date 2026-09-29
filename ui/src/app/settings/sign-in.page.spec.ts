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
import type { SsoSettings } from '../api/ee';
import { SessionStore } from '../auth/session';
import { SignInSettingsPage } from './sign-in.page';

const SETTINGS = '/api/v0/ee/sso/settings';
/** `me()`'s id: the admin who saves. */
const ME = '0190a6c2-0000-7000-8000-00000000000a';
const ROOT = '0190a6c2-0000-7000-8000-0000000000b1';
const SSO_ONLY = '0190a6c2-0000-7000-8000-0000000000b2';
const MEMBER = '0190a6c2-0000-7000-8000-0000000000b3';

function user(id: string, username: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    username,
    displayName: null,
    email: null,
    isInstanceAdmin: true,
    active: true,
    passwordChangeRequired: false,
    hasPassword: true,
    sso: { identities: 0, scim: false },
    lastLoginAt: null,
    createdAt: '2026-09-01T00:00:00.000Z',
    ...overrides,
  };
}

const USERS = [
  user(ME, 'alice'),
  user(ROOT, 'root'),
  user(SSO_ONLY, 'sso-admin', { hasPassword: false, sso: { identities: 1, scim: false } }),
  user(MEMBER, 'bob', { isInstanceAdmin: false }),
];

function settings(overrides: Partial<SsoSettings> = {}): SsoSettings {
  return {
    passwordSignIn: 'everyone',
    breakGlassUserIds: [],
    forced: false,
    breakGlass: [],
    ...overrides,
  };
}

function setup(
  options: { current?: SsoSettings; features?: string[]; users?: ReturnType<typeof user>[] } = {},
): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', { body: page([]) });
  server.on('GET', '/api/v0/system/info', {
    body: {
      version: '0.1.0',
      edition: 'enterprise',
      features: options.features ?? ['sso'],
      extensions: [],
    },
  });
  server.on('GET', SETTINGS, { body: options.current ?? settings() });
  server.on('GET', '/api/v0/users', { body: page(options.users ?? USERS) });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: true }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(SignInSettingsPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

function box(root: HTMLElement, id: string): HTMLInputElement {
  return root.querySelector<HTMLInputElement>(`label[data-key="${id}"] input`)!;
}

async function check(fixture: { whenStable(): Promise<unknown> }, input: HTMLInputElement) {
  input.click();
  await settle(fixture);
}

async function save(fixture: { whenStable(): Promise<unknown> }, root: HTMLElement) {
  root.querySelector('form')!.dispatchEvent(new Event('submit'));
  await settle(fixture);
}

function button(root: ParentNode, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

function asking(root: HTMLElement): boolean {
  return root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')?.open === true;
}

/**
 * Answers the page's confirmation dialog (step 9: it replaces the browser's `confirm()`) with
 * the button `choice`, and returns the question it asked.
 */
async function answer(
  fixture: { whenStable(): Promise<unknown> },
  root: HTMLElement,
  choice: string,
): Promise<string> {
  const ask = root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!;
  expect(ask.open).toBe(true);
  const question = ask.querySelector('#confirm-text')?.textContent?.trim() ?? '';
  button(ask, choice).click();
  await settle(fixture);
  expect(ask.open).toBe(false);
  return question;
}

describe('SignInSettingsPage (sso-scim.md §10, §18)', () => {
  it('offers the two options and explains the lock-out rules', async () => {
    setup();
    const { root } = await render();
    expect(root.querySelector<HTMLInputElement>('#sign-in-everyone')?.checked).toBe(true);
    expect(root.querySelector<HTMLInputElement>('#sign-in-limited')?.checked).toBe(false);
    const rules = root.querySelector('#sign-in-rules')?.textContent ?? '';
    expect(rules).toContain('API and CI tokens keep working');
    expect(rules).toContain('cannot be deactivated or lose the instance administrator role');
    expect(rules).toContain('QUALOR_FORCE_PASSWORD_SIGN_IN=true');
  });

  it('names the choice and the picker as groups, each in its setting row', async () => {
    setup();
    const { root } = await render();
    const name = (el: Element | null) =>
      root.querySelector(`#${el?.getAttribute('aria-labelledby')}`)?.textContent?.trim();
    const policy = root.querySelector('[role="radiogroup"]');
    expect(name(policy)).toBe('Password sign-in');
    expect(policy?.querySelectorAll('input[type="radio"]')).toHaveLength(2);
    const picker = root.querySelector('#sign-in-picker');
    expect(picker?.getAttribute('role')).toBe('group');
    expect(name(picker)).toBe('Break-glass administrators');
    expect(root.querySelectorAll('form .setting-row')).toHaveLength(2);
  });

  it('offers only instance admins, and disables those without a password', async () => {
    setup();
    const { root } = await render();
    expect(box(root, ME).disabled).toBe(false);
    expect(box(root, ROOT).disabled).toBe(false);
    expect(box(root, SSO_ONLY).disabled).toBe(true);
    expect(root.querySelector(`label[data-key="${SSO_ONLY}"]`)?.textContent).toContain(
      'No password',
    );
    expect(root.querySelector(`label[data-key="${MEMBER}"]`)).toBeNull();
  });

  it('saves the limit with the picked administrators', async () => {
    const server = setup();
    server.on('PUT', SETTINGS, {
      body: settings({ passwordSignIn: 'break_glass_only', breakGlassUserIds: [ME, ROOT] }),
    });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    await check(fixture, root.querySelector<HTMLInputElement>('#sign-in-limited')!);
    await check(fixture, box(root, ME));
    await check(fixture, box(root, ROOT));
    await save(fixture, root);
    // Nothing is sent before the page's dialog is answered.
    expect(server.requestsTo('PUT', SETTINGS)).toHaveLength(0);
    expect(await answer(fixture, root, 'Limit password sign-in')).toBe(
      'Limit password sign-in? Only these administrators will be able to sign in with a password: alice, root. Everyone else signs in with single sign-on.',
    );
    expect(confirm).not.toHaveBeenCalled();
    expect(server.requestsTo('PUT', SETTINGS).map((r) => r.body)).toEqual([
      { passwordSignIn: 'break_glass_only', breakGlassUserIds: [ME, ROOT] },
    ]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'only the break-glass administrators',
    );
    confirm.mockRestore();
  });

  it('saves nothing when the limit is not confirmed, and asks nothing for everyone', async () => {
    const server = setup();
    server.on('PUT', SETTINGS, { body: settings() });
    const { fixture, root } = await render();
    await check(fixture, root.querySelector<HTMLInputElement>('#sign-in-limited')!);
    await check(fixture, box(root, ROOT));
    await save(fixture, root);
    await answer(fixture, root, 'Cancel');
    expect(server.requestsTo('PUT', SETTINGS)).toHaveLength(0);
    await check(fixture, root.querySelector<HTMLInputElement>('#sign-in-everyone')!);
    await save(fixture, root);
    expect(asking(root)).toBe(false);
    expect(server.requestsTo('PUT', SETTINGS)).toHaveLength(1);
  });

  it('refuses more than 10 break-glass administrators on the picker, sending nothing', async () => {
    const admins = Array.from({ length: 11 }, (_, i) =>
      user(`0190a6c2-0000-7000-8000-0000000001${String(i).padStart(2, '0')}`, `admin${i}`),
    );
    const server = setup({ users: admins });
    const { fixture, root } = await render();
    for (const a of admins) await check(fixture, box(root, a.id));
    await save(fixture, root);
    expect(server.requestsTo('PUT', SETTINGS)).toHaveLength(0);
    expect(asking(root)).toBe(false);
    expect(root.querySelector('#sign-in-picker')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#sign-in-picker-error')?.textContent).toContain(
      'Pick at most 10 break-glass administrators.',
    );
  });

  it('warns the saving admin who is not listed that they will sign in with SSO', async () => {
    setup();
    const { fixture, root } = await render();
    expect(root.querySelector('#sign-in-self-warning')).toBeNull();
    await check(fixture, root.querySelector<HTMLInputElement>('#sign-in-limited')!);
    await check(fixture, box(root, ROOT));
    expect(root.querySelector('#sign-in-self-warning')?.textContent).toContain(
      'you will sign in with SSO from now on',
    );
    await check(fixture, box(root, ME));
    expect(root.querySelector('#sign-in-self-warning')).toBeNull();
  });

  it("shows the server's 422 on the field it names", async () => {
    const server = setup();
    server.on('PUT', SETTINGS, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.breakGlassUserIds', message: 'List at least one' },
        { path: 'body.passwordSignIn', message: 'Enable a connection' },
      ]),
    });
    const { fixture, root } = await render();
    await check(fixture, root.querySelector<HTMLInputElement>('#sign-in-limited')!);
    await save(fixture, root);
    await answer(fixture, root, 'Limit password sign-in');
    expect(root.querySelector('#sign-in-picker')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#sign-in-picker-error')?.textContent).toContain(
      'List at least one active instance administrator with a password.',
    );
    expect(root.querySelector('#sign-in-policy-error')?.textContent).toContain(
      'Enable a single sign-on connection first',
    );
  });

  it('shows a 409 as a clear message', async () => {
    const server = setup();
    server.on('PUT', SETTINGS, {
      status: 409,
      body: problem(409, 'LAST_BREAK_GLASS_ADMIN'),
    });
    const { fixture, root } = await render();
    await save(fixture, root);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'At least one break-glass administrator must stay usable',
    );
  });

  it('notes that the variable forces password sign-in', async () => {
    setup({ current: settings({ forced: true }) });
    const { root } = await render();
    expect(root.querySelector('#sign-in-forced')?.textContent).toContain(
      'forced on for everyone by QUALOR_FORCE_PASSWORD_SIGN_IN',
    );
  });

  it('asks nothing of the enterprise API while sso is inactive', async () => {
    const server = setup({ features: [] });
    await render();
    expect(server.requestsTo('GET', SETTINGS)).toHaveLength(0);
  });
});

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
import type { LinkedIdentity } from '../api/ee';
import { SessionStore } from '../auth/session';
import { LEAVE_APP, LinkedAccountsPage } from './linked-accounts.page';
import { SettingsPage } from './settings.page';

const C1 = '0190a6c2-0000-7000-8000-0000000000c1';
const C2 = '0190a6c2-0000-7000-8000-0000000000c2';
const I1 = '0190a6c2-0000-7000-8000-0000000000e1';
const IDENTITIES = '/api/v0/ee/sso/me/identities';

function identity(overrides: Partial<LinkedIdentity> = {}): LinkedIdentity {
  return {
    id: I1,
    connectionId: C1,
    connectionName: 'Acme SSO',
    protocol: 'oidc',
    linkedBy: 'user',
    scim: false,
    createdAt: '2026-09-01T10:00:00.000Z',
    lastSignInAt: null,
    ...overrides,
  };
}

const PROVIDERS = [
  { id: C1, name: 'Acme SSO', protocol: 'oidc', startUrl: `/api/v0/ee/sso/${C1}/start` },
  { id: C2, name: 'Partner SAML', protocol: 'saml', startUrl: `/api/v0/ee/sso/${C2}/start` },
];

interface Setup {
  features?: string[];
  identities?: LinkedIdentity[];
  admin?: boolean;
}

function setup(options: Setup = {}): { server: FakeServer; leave: ReturnType<typeof vi.fn> } {
  const server = new FakeServer();
  const leave = vi.fn();
  server.on('GET', '/api/v0/organizations', { body: page([]) });
  server.on('GET', '/api/v0/system/info', {
    body: {
      version: '0.1.0',
      edition: 'enterprise',
      features: options.features ?? ['sso'],
      extensions: [
        {
          point: 'settings.nav',
          id: 'linked-accounts',
          label: 'Linked accounts',
          path: '/settings/ee/linked-accounts',
        },
      ],
    },
  });
  server.on('GET', '/api/v0/auth/methods', {
    body: { password: 'everyone', providers: PROVIDERS },
  });
  server.on('GET', IDENTITIES, { body: options.identities ?? [identity()] });
  TestBed.configureTestingModule({
    providers: [
      provideRouter([{ path: '**', children: [] }]),
      provideFakeServer(server),
      { provide: LEAVE_APP, useValue: leave },
    ],
  });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? false }));
  return { server, leave };
}

async function render(query: { sso_error?: string } = {}) {
  const fixture = TestBed.createComponent(LinkedAccountsPage);
  if (query.sso_error !== undefined) fixture.componentRef.setInput('sso_error', query.sso_error);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

function button(root: HTMLElement, text: string): HTMLButtonElement | undefined {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text);
}

function row(root: HTMLElement, id: string): HTMLElement {
  return root.querySelector<HTMLElement>(`tr[data-key="${id}"]`)!;
}

describe('LinkedAccountsPage (sso-scim.md §18)', () => {
  it('lists your identities and offers Link for each connection you have none on', async () => {
    setup();
    const { root } = await render();
    const linked = row(root, I1);
    expect(linked.textContent).toContain('Acme SSO');
    expect(linked.textContent).toContain('Never');
    expect(button(linked, 'Unlink')).toBeDefined();
    const links = [...root.querySelectorAll<HTMLButtonElement>('[data-test^=link-]')];
    expect(links.map((b) => b.getAttribute('data-test'))).toEqual([`link-${C2}`]);
    expect(links[0]!.textContent).toContain('Partner SAML');
  });

  it('starts a link with POST and follows the answered address', async () => {
    const { server, leave } = setup();
    server.on('POST', `/api/v0/ee/sso/connections/${C2}/link`, {
      body: { url: 'https://idp.example/authorize?state=s' },
    });
    const { fixture, root } = await render();
    root.querySelector<HTMLButtonElement>(`[data-test=link-${C2}]`)!.click();
    await settle(fixture);
    expect(server.requestsTo('POST', `/api/v0/ee/sso/connections/${C2}/link`)).toHaveLength(1);
    expect(leave).toHaveBeenCalledWith('https://idp.example/authorize?state=s');
  });

  it('says so when the identity provider cannot be used now (503 SSO_UNAVAILABLE)', async () => {
    const { server, leave } = setup();
    server.on('POST', `/api/v0/ee/sso/connections/${C2}/link`, {
      status: 503,
      body: problem(503, 'SSO_UNAVAILABLE'),
    });
    const { fixture, root } = await render();
    root.querySelector<HTMLButtonElement>(`[data-test=link-${C2}]`)!.click();
    await settle(fixture);
    expect(leave).not.toHaveBeenCalled();
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'The identity provider cannot be used right now. Try again later.',
    );
  });

  it('unlinks after a confirmation, and sends nothing without one', async () => {
    const { server } = setup();
    server.on('DELETE', `${IDENTITIES}/${I1}`, { status: 204 });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const { fixture, root } = await render();
    button(row(root, I1), 'Unlink')!.click();
    await settle(fixture);
    expect(confirm).toHaveBeenCalledWith(
      'Unlink Acme SSO? You can no longer sign in with it until you link it again.',
    );
    expect(server.requestsTo('DELETE', `${IDENTITIES}/${I1}`)).toHaveLength(0);
    confirm.mockReturnValue(true);
    server.on('GET', IDENTITIES, { body: [] });
    button(row(root, I1), 'Unlink')!.click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', `${IDENTITIES}/${I1}`)).toHaveLength(1);
    expect(root.querySelector(`tr[data-key="${I1}"]`)).toBeNull();
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Acme SSO unlinked.');
    // The connection can be linked again.
    expect(root.querySelector(`[data-test=link-${C1}]`)).not.toBeNull();
    confirm.mockRestore();
  });

  it('explains 409 LAST_SIGN_IN_METHOD and keeps the identity', async () => {
    const { server } = setup();
    server.on('DELETE', `${IDENTITIES}/${I1}`, {
      status: 409,
      body: problem(409, 'LAST_SIGN_IN_METHOD'),
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const { fixture, root } = await render();
    button(row(root, I1), 'Unlink')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This is your only way to sign in. Ask an administrator to set a password first.',
    );
    expect(row(root, I1)).not.toBeNull();
    confirm.mockRestore();
  });

  it('offers no Unlink for an identity your identity provider provisions (SCIM)', async () => {
    setup({ identities: [identity({ scim: true, linkedBy: 'scim' })] });
    const { root } = await render();
    expect(button(row(root, I1), 'Unlink')).toBeUndefined();
    expect(row(root, I1).textContent).toContain(
      'Your identity provider manages this link; only an administrator can remove it.',
    );
  });

  it('explains 409 SCIM_MANAGED_IDENTITY when the identity became managed meanwhile', async () => {
    const { server } = setup();
    server.on('DELETE', `${IDENTITIES}/${I1}`, {
      status: 409,
      body: problem(409, 'SCIM_MANAGED_IDENTITY'),
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const { fixture, root } = await render();
    button(row(root, I1), 'Unlink')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'Your identity provider manages this link; only an administrator can remove it.',
    );
    confirm.mockRestore();
  });

  it('shows why a link failed (?sso_error=), never the raw value', async () => {
    setup();
    const { root } = await render({ sso_error: 'identity_in_use' });
    expect(root.querySelector('[data-test=sso-error]')?.textContent).toContain(
      'already linked to another Qualor account',
    );
    const other = await render({ sso_error: '<b>x</b>' });
    expect(other.root.querySelector('[data-test=sso-error]')?.textContent).toContain(
      'Single sign-on failed',
    );
    expect(other.root.textContent).not.toContain('<b>x</b>');
  });

  it('asks the enterprise API nothing while sso is not active', async () => {
    const { server } = setup({ features: ['audit-log'] });
    const { root } = await render();
    expect(root.textContent).toContain('Linked accounts need an enterprise licence');
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
  });
});

describe('Settings → Linked accounts tab', () => {
  function links(root: HTMLElement): string[] {
    return [...root.querySelectorAll('nav a')].map((a) => a.textContent?.trim() ?? '');
  }

  it('is listed for every user while sso is active, once', async () => {
    setup();
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    expect(links(fixture.nativeElement as HTMLElement)).toContain('Linked accounts');
    TestBed.resetTestingModule();
    setup({ admin: true });
    const admin = TestBed.createComponent(SettingsPage);
    await settle(admin);
    expect(
      links(admin.nativeElement as HTMLElement).filter((l) => l === 'Linked accounts'),
    ).toHaveLength(1);
  });

  it('is not listed while sso is not active', async () => {
    setup({ features: ['audit-log'] });
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    expect(links(fixture.nativeElement as HTMLElement)).not.toContain('Linked accounts');
  });
});

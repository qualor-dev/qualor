import { noAnswerYet } from '../../testing/pending';
import { ErrorHandler } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
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
import { LeaveGuards } from '../shared/unsaved-changes';
import { Shell } from './shell';

describe('Shell', () => {
  let server: FakeServer;
  let errors: unknown[];

  function configure() {
    server = new FakeServer();
    errors = [];
    server.on('GET', '/api/v0/organizations', {
      body: page([
        { id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' },
        { id: 'org-2', key: 'acme', name: 'Acme', createdAt: '', updatedAt: '' },
      ]),
    });
    server.on('GET', '/api/v0/system/info', {
      body: { version: '1.2.3', edition: 'community', features: [], extensions: [] },
    });
    TestBed.configureTestingModule({
      imports: [Shell],
      providers: [
        provideRouter([{ path: '**', children: [] }]),
        provideFakeServer(server),
        {
          provide: ErrorHandler,
          useValue: { handleError: (error: unknown) => errors.push(error) },
        },
      ],
    });
    TestBed.inject(SessionStore).set(me());
  }

  beforeEach(() => configure());

  it('renders a skip link, the labelled main navigation and the user menu', async () => {
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('a.skip-link')?.getAttribute('href')).toBe('#main');
    expect(root.querySelector('main#main')).not.toBeNull();
    const nav = root.querySelector('nav[aria-label="Main"]');
    expect([...(nav?.querySelectorAll('a') ?? [])].map((a) => a.textContent?.trim())).toEqual([
      'Projects',
      'Quality gates',
      'Quality profiles',
      'Rules',
      'Settings',
      'Docs',
    ]);
    expect(root.querySelector('.user-menu')?.textContent).toContain('Alice');
    // The account's links sit in a popover opened by the user button.
    const button = root.querySelector<HTMLButtonElement>('.user-button');
    expect(button?.getAttribute('popovertarget')).toBe('user-menu');
    expect(button?.textContent).toContain('Alice');
    const menu = root.querySelector('#user-menu');
    expect(menu?.hasAttribute('popover')).toBe(true);
    expect(menu?.querySelector('a[href="/change-password"]')?.textContent?.trim()).toBe(
      'Change password',
    );
    expect([...(menu?.querySelectorAll('button') ?? [])].map((b) => b.textContent?.trim())).toEqual(
      ['Sign out'],
    );
    // The server's version and edition at the foot of the menu.
    expect(menu?.querySelector('.menu-version')?.textContent?.trim()).toBe(
      'Qualor 1.2.3 · Community',
    );
    // Two organisations: a labelled switcher.
    const select = root.querySelector<HTMLSelectElement>('#org-switch');
    expect(root.querySelector('label[for="org-switch"]')?.textContent).toContain('Organization');
    expect([...(select?.options ?? [])].map((o) => o.textContent)).toEqual(['Default', 'Acme']);
  });

  it('switches the organization once a page with unsaved changes lets go, and else shows the one in use', async () => {
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    let answer: (leave: boolean) => void = noAnswerYet;
    let asked = 0;
    TestBed.runInInjectionContext(() =>
      TestBed.inject(LeaveGuards).register({
        canLeave: () => {
          asked++;
          return new Promise<boolean>((resolve) => (answer = resolve));
        },
      }),
    );
    const select = root.querySelector<HTMLSelectElement>('#org-switch')!;
    // Stay: nothing switches, and the select shows the organisation still in use.
    select.value = 'org-2';
    select.dispatchEvent(new Event('change'));
    answer(false);
    await settle(fixture);
    expect(asked).toBe(1);
    expect(TestBed.inject(OrgContext).currentId()).toBe(ORG_ID);
    expect(select.value).toBe(ORG_ID);
    // Leave: it switches.
    select.value = 'org-2';
    select.dispatchEvent(new Event('change'));
    answer(true);
    await settle(fixture);
    expect(asked).toBe(2);
    expect(TestBed.inject(OrgContext).currentId()).toBe('org-2');
    expect(select.value).toBe('org-2');
  });

  describe('the main.nav entries (4E-2 §4)', () => {
    const PORTFOLIO = {
      point: 'main.nav',
      id: 'portfolio',
      label: 'Portfolio',
      path: '/portfolio',
    };

    async function navWith(features: string[], extensions: unknown[]) {
      server.on('GET', '/api/v0/system/info', {
        body: { version: '0.8.0', edition: 'enterprise', features, extensions },
      });
      const fixture = TestBed.createComponent(Shell);
      await settle(fixture);
      const nav = (fixture.nativeElement as HTMLElement).querySelector('nav[aria-label="Main"]');
      return [...(nav?.querySelectorAll('a') ?? [])].map((a) => [
        a.textContent?.trim(),
        a.getAttribute('href'),
      ]);
    }

    it('shows Portfolio after Quality gates while the feature and its entry are there', async () => {
      const links = await navWith(['portfolio'], [PORTFOLIO]);
      expect(links.slice(0, 3)).toEqual([
        ['Projects', '/projects'],
        ['Quality gates', '/gates'],
        ['Portfolio', '/portfolio'],
      ]);
      expect(links).toHaveLength(7);
    });

    it('shows no Portfolio without the feature, without the entry, or for an unknown entry', async () => {
      expect((await navWith([], [PORTFOLIO])).map(([name]) => name)).not.toContain('Portfolio');
      TestBed.resetTestingModule();
      configure();
      expect((await navWith(['portfolio'], [])).map(([name]) => name)).not.toContain('Portfolio');
      TestBed.resetTestingModule();
      configure();
      const other = { point: 'main.nav', id: 'other', label: 'Other', path: '/other' };
      const settings = { ...PORTFOLIO, point: 'settings.nav' };
      expect(await navWith(['portfolio'], [other, settings])).toHaveLength(6);
    });
  });

  it('shows the demo banner and no password change to the demo account only', async () => {
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('[data-test=demo-banner]')).toBeNull();
    expect(root.querySelector('a[href="/change-password"]')).not.toBeNull();
    TestBed.inject(SessionStore).set(me({ demo: true }));
    await settle(fixture);
    expect(root.querySelector('[data-test=demo-banner]')?.textContent).toContain('read-only demo');
    expect(root.querySelector('[data-test=demo-banner]')?.getAttribute('role')).toBe('status');
    expect(root.querySelector('a[href="/change-password"]')).toBeNull();
  });

  it('signs out through the API with the CSRF token and opens the login page', async () => {
    server.on('POST', '/api/v0/auth/logout', { status: 204 });
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const signOut = [...root.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Sign out'),
    );
    signOut!.click();
    await settle(fixture);
    await settle();
    expect(server.requestsTo('POST', '/api/v0/auth/logout')[0]?.headers.get('x-qualor-csrf')).toBe(
      'csrf-token',
    );
    expect(TestBed.inject(SessionStore).me()).toBeNull();
    expect(TestBed.inject(Router).url).toBe('/login');
  });

  it('clears the local session and the user data on screen even when sign-out fails', async () => {
    server.on('POST', '/api/v0/auth/logout', { status: 500 });
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('#org-switch')).not.toBeNull();
    [...root.querySelectorAll('button')].find((b) => b.textContent?.includes('Sign out'))!.click();
    await settle(fixture);
    await settle();
    expect(TestBed.inject(SessionStore).me()).toBeNull();
    expect(TestBed.inject(SessionStore).csrfToken()).toBeNull();
    expect(TestBed.inject(Router).url).toBe('/login');
    expect(root.querySelector('.user-menu')).toBeNull();
    expect(root.querySelector('#org-switch')).toBeNull();
  });

  it('moves focus to the main region when the page changes, not when only the query does', async () => {
    const fixture = TestBed.createComponent(Shell);
    const root = fixture.nativeElement as HTMLElement;
    document.body.append(root);
    const input = document.createElement('input');
    document.body.append(input);
    try {
      const router = TestBed.inject(Router);
      await router.navigateByUrl('/one');
      await settle(fixture);
      const main = root.querySelector('main')!;
      // The first page keeps the browser's own focus handling.
      expect(document.activeElement).not.toBe(main);
      await router.navigateByUrl('/two');
      await settle(fixture);
      expect(document.activeElement).toBe(main);
      input.focus();
      await router.navigateByUrl('/two?q=x');
      await settle(fixture);
      expect(document.activeElement).toBe(input);
    } finally {
      root.remove();
      input.remove();
    }
  });

  it('stays usable without errors when the organisations cannot be loaded', async () => {
    server.on('GET', '/api/v0/organizations', {
      status: 500,
      body: problem(500, 'INTERNAL_ERROR'),
    });
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const fixture = TestBed.createComponent(Shell);
      await settle(fixture);
      fixture.detectChanges();
      await settle(fixture);
      const root = fixture.nativeElement as HTMLElement;
      expect(root.querySelector('#org-switch')).toBeNull();
      expect(root.querySelector('.user-menu')?.textContent).toContain('Alice');
      expect(root.querySelectorAll('nav[aria-label="Main"] a')).toHaveLength(6);
      const org = TestBed.inject(OrgContext);
      expect(org.orgs()).toEqual([]);
      expect(org.current()).toBeNull();
      expect(org.currentId()).toBeNull();
      expect(org.isAdmin()).toBe(false);
      expect(errors).toEqual([]);
      expect(consoleError).not.toHaveBeenCalled();
    } finally {
      consoleError.mockRestore();
    }
  });

  it('shows organisation names only in the switcher (enterprise.md §11)', async () => {
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const select = root.querySelector<HTMLSelectElement>('#org-switch');
    expect([...(select?.options ?? [])].map((o) => o.textContent?.trim())).toEqual([
      'Default',
      'Acme',
    ]);
    expect(root.textContent).not.toContain('read-only');
  });

  it('tells an instance admin in the menu and a banner that a newer release exists', async () => {
    TestBed.inject(SessionStore).set(me({ admin: true }));
    server.on('GET', '/api/v0/system/version', { body: { version: '1.2.3', latest: '1.3.0' } });
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.menu-version')?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
      'Qualor 1.2.3 · Community · 1.3.0 available',
    );
    expect(root.querySelector('q-update-banner')?.textContent).toContain(
      'Qualor 1.3.0 is available',
    );
  });

  it('never asks about updates for a user who is not an instance admin', async () => {
    server.on('GET', '/api/v0/system/version', { body: { version: '1.2.3', latest: '1.3.0' } });
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.menu-version')?.textContent?.trim()).toBe(
      'Qualor 1.2.3 · Community',
    );
    expect(server.requestsTo('GET', '/api/v0/system/version')).toHaveLength(0);
  });

  it('shows the licence banner to an instance admin, after the header', async () => {
    TestBed.inject(SessionStore).set(me({ admin: true }));
    server.on('GET', '/api/v0/license', {
      body: {
        edition: 'community',
        state: 'expired',
        reason: null,
        source: 'uploaded',
        license: null,
        expiresSoon: false,
        restartRequired: false,
        activeFeatures: [],
        plugins: [],
      },
    });
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const banner = root.querySelector('header + q-license-banner');
    expect(banner?.textContent).toContain('Enterprise features are off');
  });

  it('shows the setup checklist to an admin, before the page, and asks nothing for others', async () => {
    const path = /^\/api\/v0\/organizations\/[^/]+\/setup-checklist$/;
    const asked = () => server.requests.filter((r) => path.test(r.path));
    server.on('GET', path, {
      body: {
        steps: [
          { id: 'connect', done: true, hint: null, blocking: true },
          { id: 'repositories', done: false, hint: null, blocking: true },
          { id: 'analysis', done: false, hint: null, blocking: true },
          { id: 'ai_review', done: false, hint: null, blocking: true },
          { id: 'team', done: false, hint: null, blocking: true },
        ],
        closed: false,
        allDone: false,
      },
    });
    const member = TestBed.createComponent(Shell);
    await settle(member);
    expect(asked()).toHaveLength(0);
    member.destroy();

    TestBed.inject(SessionStore).set(me({ admin: true }));
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const aside = root.querySelector('q-setup-checklist + main')?.previousElementSibling;
    expect(aside?.querySelector('aside h2')?.textContent).toBe('Set up Qualor');
    expect(aside?.querySelector('.setup-count')?.textContent).toBe('1 of 5 done');
    localStorage.clear();
  });

  it('shows the forced-password banner to an instance admin under the licence banner', async () => {
    TestBed.inject(SessionStore).set(me({ admin: true }));
    server.on('GET', '/api/v0/system/info', {
      body: {
        version: '0.1.0',
        edition: 'enterprise',
        features: ['sso'],
        extensions: [],
      },
    });
    server.on('GET', '/api/v0/ee/sso/settings', {
      body: { passwordSignIn: 'everyone', breakGlassUserIds: [], forced: true, breakGlass: [] },
    });
    const fixture = TestBed.createComponent(Shell);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const banner = root.querySelector('q-license-banner + q-sso-banner');
    expect(banner?.textContent).toContain('forced on by QUALOR_FORCE_PASSWORD_SIGN_IN');
  });
});

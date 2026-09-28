import { TestBed } from '@angular/core/testing';
import { provideRouter, Router, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { routes } from '../app.routes';
import { SessionStore } from './session';

describe('route guards (ruling R7, plan 1F ruling Y4)', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    server.on('GET', '/api/v0/organizations', { body: { items: [], nextCursor: null } });
    TestBed.configureTestingModule({
      providers: [provideRouter(routes, withComponentInputBinding()), provideFakeServer(server)],
    });
  });

  async function open(url: string): Promise<string> {
    const router = TestBed.inject(Router);
    await router.navigateByUrl(url);
    await settle();
    return router.url;
  }

  it('sends a visitor without a session to the login page with a return URL', async () => {
    server.on('GET', '/api/v0/auth/me', { status: 401, body: problem(401, 'UNAUTHENTICATED') });
    expect(await open('/projects?q=pay')).toBe('/login?returnUrl=%2Fprojects%3Fq%3Dpay');
  });

  it('keeps a user who must change the password on the password page', async () => {
    server.on('GET', '/api/v0/auth/me', { body: me({ passwordChangeRequired: true }) });
    expect(await open('/projects')).toBe('/change-password');
    expect(await open('/settings')).toBe('/change-password');
    expect(await open('/login')).toBe('/change-password');
  });

  it('lets a signed-in user in and sends them away from the login page', async () => {
    server.on('GET', '/api/v0/auth/me', { body: me() });
    expect(await open('/projects')).toBe('/projects');
    expect(await open('/login')).toBe('/projects');
    expect(server.requestsTo('GET', '/api/v0/auth/me')).toHaveLength(1);
  });

  it('sends a signed-in user whose link failed (?sso_error=) to linked accounts, with the code', async () => {
    server.on('GET', '/api/v0/auth/me', { body: me() });
    expect(await open('/login?sso_error=identity_in_use')).toBe(
      '/settings/ee/linked-accounts?sso_error=identity_in_use',
    );
    expect(await open('/login?returnUrl=%2Fgates')).toBe('/projects');
  });

  it('shows a retry state when the server cannot be reached, never a signed-out one', async () => {
    let reachable = false;
    server.on('GET', '/api/v0/auth/me', () => {
      if (!reachable) throw new TypeError('Failed to fetch');
      return { body: me() };
    });
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/projects?q=pay');
    await settle(harness.fixture);
    const router = TestBed.inject(Router);
    expect(router.url).toBe('/unavailable?returnUrl=%2Fprojects%3Fq%3Dpay');
    expect(TestBed.inject(SessionStore).me()).toBeUndefined();
    const root = harness.routeNativeElement!;
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('could not be reached');
    reachable = true;
    [...root.querySelectorAll('button')].find((b) => b.textContent?.includes('Try again'))!.click();
    await settle(harness.fixture);
    expect(router.url).toBe('/projects?q=pay');
    expect(TestBed.inject(SessionStore).me()?.user.username).toBe('alice');
  });

  it('treats a failing server as unavailable, not as signed out', async () => {
    server.on('GET', '/api/v0/auth/me', { status: 503, body: problem(503, 'UNAVAILABLE') });
    expect(await open('/login')).toBe('/unavailable?returnUrl=%2Flogin');
    expect(TestBed.inject(SessionStore).me()).toBeUndefined();
    expect(server.requestsTo('GET', '/api/v0/auth/me')).toHaveLength(1);
    expect(await open('/projects')).toBe('/unavailable?returnUrl=%2Fprojects');
    expect(server.requestsTo('GET', '/api/v0/auth/me')).toHaveLength(2);
  });
});

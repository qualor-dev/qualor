import { BrowserPlatformLocation, PlatformLocation } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, provideRouter, Router } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { FakeServer, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { UnsubscribePage } from './unsubscribe.page';

const URL = '/api/v0/notifications/unsubscribe';

const stopButton = (root: HTMLElement) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Stop emails');

describe('UnsubscribePage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [UnsubscribePage],
      providers: [provideRouter([]), provideFakeServer(server)],
    });
  });
  afterEach(() => window.history.replaceState(null, '', '/'));

  async function render(hash: string) {
    window.history.replaceState(null, '', `/unsubscribe${hash}`);
    const fixture = TestBed.createComponent(UnsubscribePage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    return { fixture, root, button: () => stopButton(root) };
  }

  it('asks first, then posts the token from the fragment and names the project', async () => {
    server.on('POST', URL, { body: { project: { name: 'Payments API' } } });
    const { fixture, root, button } = await render('#t=abc.def');
    expect(root.querySelector('h1')?.textContent?.trim()).toBe('Stop emails about this project?');
    // Opening the page changes nothing, and the token leaves the address bar.
    expect(server.requests).toHaveLength(0);
    expect(window.location.hash).toBe('');
    button()!.click();
    await settle(fixture);
    expect(server.requestsTo('POST', URL)[0]?.query.get('t')).toBe('abc.def');
    expect(root.textContent).toContain('You no longer watch Payments API.');
    expect(root.querySelector('a[href="/settings/notifications"]')).not.toBeNull();
    // The button is gone; focus moved to the answer.
    expect(document.activeElement).toBe(root.querySelector('h1'));
  });

  it('says the project is no longer named when it is gone', async () => {
    server.on('POST', URL, { body: { project: null } });
    const { fixture, root, button } = await render('#t=abc.def');
    button()!.click();
    await settle(fixture);
    expect(root.textContent).toContain('You no longer watch this project.');
  });

  it('says a refused link is not valid (400 TOKEN_INVALID)', async () => {
    server.on('POST', URL, { status: 400, body: problem(400, 'TOKEN_INVALID') });
    const { fixture, root, button } = await render('#t=forged.token');
    button()!.click();
    await settle(fixture);
    expect(root.querySelector('h1')?.textContent?.trim()).toBe("This link doesn't work");
    expect(root.textContent).toContain(
      'This link is not valid. Manage your notifications in Settings.',
    );
    expect(button()).toBeUndefined();
    expect(document.activeElement).toBe(root.querySelector('h1'));
  });

  it('keeps the button and shows the problem when the server fails (not a bad link)', async () => {
    server.on('POST', URL, { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root, button } = await render('#t=abc.def');
    button()!.click();
    await settle(fixture);
    expect(root.querySelector('[role=alert]')).not.toBeNull();
    expect(button()).toBeDefined();
  });

  it('offers no button without a token', async () => {
    const { root, button } = await render('');
    expect(root.querySelector('h1')?.textContent?.trim()).toBe('This link is not complete');
    expect(button()).toBeUndefined();
    expect(server.requests).toHaveLength(0);
  });
});

describe('UnsubscribePage opened by the router (as ResetPasswordPage, mail E2 M15)', () => {
  let server: FakeServer;
  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      providers: [
        provideRouter([{ path: 'unsubscribe', component: UnsubscribePage }]),
        provideFakeServer(server),
        // The real address bar, not TestBed's stand-in: the router writes to window.history.
        { provide: PlatformLocation, useClass: BrowserPlatformLocation },
      ],
    });
  });
  afterEach(() => window.history.replaceState(null, '', '/'));

  it('keeps the token out of the address bar and the router URL, and still posts it', async () => {
    server.on('POST', URL, { body: { project: { name: 'Payments API' } } });
    window.history.replaceState(null, '', '/unsubscribe#t=abc.def');
    const harness = await RouterTestingHarness.create();
    const router = TestBed.inject(Router);
    router.initialNavigation();
    await settle(harness.fixture);
    const page = harness.routeNativeElement!;
    expect(window.location.hash).toBe('');
    expect(window.location.href).not.toContain('abc.def');
    expect(router.url).toBe('/unsubscribe');
    await router.navigateByUrl('/nowhere').catch(() => undefined);
    await settle(harness.fixture);
    expect(window.location.href).not.toContain('abc.def');
    expect(harness.routeNativeElement).toBe(page);
    stopButton(page)!.click();
    await settle(harness.fixture);
    expect(server.requestsTo('POST', URL)[0]?.query.get('t')).toBe('abc.def');
    expect(page.textContent).toContain('You no longer watch Payments API.');
  });
});

describe('UnsubscribePage for vulnerability emails (route data kind)', () => {
  const VULN = '/api/v0/notifications/unsubscribe/vulnerabilities';
  let server: FakeServer;
  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [UnsubscribePage],
      providers: [
        provideRouter([]),
        provideFakeServer(server),
        { provide: ActivatedRoute, useValue: { snapshot: { data: { kind: 'vulnerabilities' } } } },
      ],
    });
  });
  afterEach(() => window.history.replaceState(null, '', '/'));

  it('asks first, posts to the vulnerabilities route and confirms', async () => {
    server.on('POST', VULN, { body: {} });
    window.history.replaceState(null, '', '/unsubscribe/vulnerabilities#t=abc.def');
    const fixture = TestBed.createComponent(UnsubscribePage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('h1')?.textContent?.trim()).toBe('Stop vulnerability emails?');
    expect(root.textContent).toContain(
      'You will no longer get emails about new vulnerabilities, in any project. You can turn them back on per project under Settings → Notifications.',
    );
    expect(server.requests).toHaveLength(0);
    stopButton(root)!.click();
    await settle(fixture);
    expect(server.requestsTo('POST', VULN)[0]?.query.get('t')).toBe('abc.def');
    expect(root.textContent).toContain('You no longer get vulnerability emails.');
    expect(root.querySelector('a[href="/settings/notifications"]')).not.toBeNull();
  });

  it('says a refused link is not valid', async () => {
    server.on('POST', VULN, { status: 400, body: problem(400, 'TOKEN_INVALID') });
    window.history.replaceState(null, '', '/unsubscribe/vulnerabilities#t=forged');
    const fixture = TestBed.createComponent(UnsubscribePage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    stopButton(root)!.click();
    await settle(fixture);
    expect(root.querySelector('h1')?.textContent?.trim()).toBe("This link doesn't work");
  });
});

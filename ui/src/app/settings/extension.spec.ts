import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { ExtensionPage } from './extension.page';

function setup(options: { admin?: boolean; fail?: boolean } = {}): FakeServer {
  const server = new FakeServer();
  server.on(
    'GET',
    '/api/v0/system/info',
    options.fail
      ? { status: 500, body: problem(500, 'INTERNAL') }
      : {
          body: {
            version: '0.0.0',
            edition: 'enterprise',
            features: ['audit-log'],
            extensions: [
              {
                point: 'settings.nav',
                id: 'audit',
                label: 'Audit log',
                path: '/settings/ee/audit',
              },
            ],
          },
        },
  );
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? true }));
  return server;
}

async function render(id: string): Promise<HTMLElement> {
  const fixture = TestBed.createComponent(ExtensionPage);
  fixture.componentRef.setInput('id', id);
  await settle(fixture);
  return fixture.nativeElement as HTMLElement;
}

describe('ExtensionPage (enterprise.md §10.4)', () => {
  it('names the extension and says its screen is not in this web UI', async () => {
    setup();
    const root = await render('audit');
    expect(root.querySelector('h2')?.textContent?.trim()).toBe('Audit log');
    expect(root.textContent).toContain(
      "This feature's screen is not available in this version of the web UI.",
    );
  });

  it('says Not found for an id no active feature registered', async () => {
    setup();
    const root = await render('nope');
    expect(root.querySelector('h2')?.textContent?.trim()).toBe('Not found');
  });

  it('tells a person who is not an instance admin that the page is not for them', async () => {
    setup({ admin: false });
    const root = await render('audit');
    expect(root.textContent).toContain('Only instance administrators manage enterprise features.');
    expect(root.textContent).not.toContain('Audit log');
    expect(root.querySelector('h2')).toBeNull();
  });

  it('says so when the system information could not be loaded, instead of an empty page', async () => {
    setup({ fail: true });
    const root = await render('audit');
    const alert = root.querySelector('.alert-error[role="alert"]');
    expect(alert?.textContent).toContain('The request failed (HTTP 500, INTERNAL).');
    expect(root.textContent).not.toContain('Not found');
  });
});

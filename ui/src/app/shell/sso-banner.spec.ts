import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, page, provideFakeServer, settle } from '../../testing/fake-server';
import type { SsoSettings } from '../api/ee';
import { SessionStore } from '../auth/session';
import { SsoBanner } from './sso-banner';

const SETTINGS = '/api/v0/ee/sso/settings';

function settings(forced: boolean): SsoSettings {
  return { passwordSignIn: 'break_glass_only', breakGlassUserIds: [], forced, breakGlass: [] };
}

function setup(options: { forced?: boolean; admin?: boolean; features?: string[] } = {}) {
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
  server.on('GET', SETTINGS, { body: settings(options.forced ?? true) });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? true }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(SsoBanner);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

const TEXT =
  'Password sign-in is forced on by QUALOR_FORCE_PASSWORD_SIGN_IN. Remove it once single sign-on works again.';

describe('SsoBanner (sso-scim.md §10.4)', () => {
  it('tells instance admins that the emergency variable forces password sign-in', async () => {
    const server = setup();
    const { fixture, root } = await render();
    const banner = root.querySelector('[role="status"]');
    expect(banner?.textContent?.replace(/\s+/g, ' ').trim()).toBe(TEXT);
    // Once per session: rendering again asks nothing more.
    fixture.detectChanges();
    await settle(fixture);
    expect(server.requestsTo('GET', SETTINGS)).toHaveLength(1);
  });

  it('shows nothing while the variable is not set', async () => {
    setup({ forced: false });
    const { root } = await render();
    expect(root.querySelector('[role="status"]')).toBeNull();
  });

  it('asks nothing for a user who is not an instance admin', async () => {
    const server = setup({ admin: false });
    const { root } = await render();
    expect(root.querySelector('[role="status"]')).toBeNull();
    expect(server.requestsTo('GET', SETTINGS)).toHaveLength(0);
  });

  it('asks nothing while sso is not active', async () => {
    const server = setup({ features: ['audit-log'] });
    const { root } = await render();
    expect(root.querySelector('[role="status"]')).toBeNull();
    expect(server.requestsTo('GET', SETTINGS)).toHaveLength(0);
  });
});

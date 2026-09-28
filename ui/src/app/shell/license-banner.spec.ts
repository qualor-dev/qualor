import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import type { LicenseStatus } from '../settings/license.page';
import { LicenseBanner } from './license-banner';

const LICENCE = {
  id: 'l1',
  keyId: 'k2026',
  customer: 'Acme Corporation',
  issued: '2026-10-01T00:00:00.000Z',
  expires: '2027-10-01T00:00:00.000Z',
  graceEndsAt: '2027-10-15T00:00:00.000Z',
  features: ['llm.fix-quota'],
  test: false,
};

const ACTIVE: LicenseStatus = {
  edition: 'enterprise',
  state: 'active',
  reason: null,
  source: 'uploaded',
  license: LICENCE,
  expiresSoon: false,
  restartRequired: false,
  activeFeatures: ['llm.fix-quota'],
  plugins: [],
};

function setup(status: LicenseStatus, admin = true): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/license', { body: status });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin }));
  return server;
}

/** The banner's text as it reads: template line breaks collapse to one space, as on screen. */
function text(root: HTMLElement): string {
  return (root.querySelector('[role="status"]')?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

async function render(): Promise<HTMLElement> {
  const fixture = TestBed.createComponent(LicenseBanner);
  await settle(fixture);
  return fixture.nativeElement as HTMLElement;
}

function expectLinkToLicence(root: HTMLElement): void {
  expect(root.querySelector('a')?.getAttribute('href')).toBe('/settings/license');
}

describe('LicenseBanner (enterprise.md §11)', () => {
  it('shows nothing to a user who is not an instance admin, and asks nothing', async () => {
    const server = setup({ ...ACTIVE, edition: 'community', state: 'expired' }, false);
    const root = await render();
    expect(root.textContent?.trim()).toBe('');
    expect(server.requestsTo('GET', '/api/v0/license')).toHaveLength(0);
  });

  it('shows nothing while the licence is active and not about to expire', async () => {
    setup(ACTIVE);
    const root = await render();
    expect(text(root)).toBe('');
    // No empty status region either: the page's own stays the only one.
    expect(root.querySelector('[role="status"]')).toBeNull();
  });

  it('warns an admin when the licence expires soon', async () => {
    setup({ ...ACTIVE, expiresSoon: true });
    const root = await render();
    expect(text(root)).toContain('The Qualor licence expires on Oct 1, 2027');
    expectLinkToLicence(root);
  });

  it('says what the grace period means', async () => {
    setup({ ...ACTIVE, state: 'grace' });
    const root = await render();
    expect(text(root)).toContain('The Qualor licence expired on Oct 1, 2027');
    expect(text(root)).toContain('Enterprise features stop on Oct 15, 2027');
    expectLinkToLicence(root);
  });

  it('tells an admin that an expired licence turned the enterprise features off', async () => {
    setup({ ...ACTIVE, edition: 'community', state: 'expired' });
    const root = await render();
    expect(text(root)).toContain('The Qualor licence has expired. Enterprise features are off');
    expect(text(root)).not.toContain('read-only');
    expect(text(root)).not.toMatch(/organization/i);
    expectLinkToLicence(root);
  });

  it('shows nothing for a community edition without a key', async () => {
    setup({ ...ACTIVE, edition: 'community', state: 'none', source: null, license: null });
    const root = await render();
    expect(text(root)).toBe('');
  });

  it('stays quiet when the licence cannot be read', async () => {
    const server = new FakeServer();
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me({ admin: true }));
    const root = await render();
    expect(text(root)).toBe('');
  });
});

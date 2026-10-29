import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import type { LicenseStatus } from '../settings/license.page';
import { LicenseBanner, TRIAL_DISMISS_KEY } from './license-banner';

const LICENCE = {
  id: 'l1',
  keyId: 'k2026',
  customer: 'Acme Corporation',
  issued: '2026-10-01T00:00:00.000Z',
  expires: '2027-10-01T00:00:00.000Z',
  graceEndsAt: '2027-10-15T00:00:00.000Z',
  features: ['llm.fix-quota'],
  test: false,
  trial: false,
  plan: 'Business' as const,
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

const DAY = 86_400_000;

function localToday(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function trial(daysAhead: number, over: Partial<LicenseStatus> = {}): LicenseStatus {
  return {
    ...ACTIVE,
    license: {
      ...LICENCE,
      trial: true,
      expires: new Date(Date.now() + daysAhead * DAY - 60_000).toISOString(),
    },
    expiresSoon: true,
    ...over,
  };
}

function dismissButton(root: HTMLElement): HTMLButtonElement | null {
  return (
    Array.from(root.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'Dismiss until tomorrow',
    ) ?? null
  );
}

describe('LicenseBanner (enterprise.md §11)', () => {
  afterEach(() => {
    try {
      localStorage.clear();
    } catch {
      // ignore
    }
    vi.restoreAllMocks();
  });

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

  describe('trial', () => {
    it('tells the admin how many days are left, with the e-mail and licence links', async () => {
      setup(trial(5));
      const root = await render();
      expect(text(root)).toMatch(
        /Your Business trial ends in 5 days, on [A-Z][a-z]{2} \d{1,2}, \d{4}\. To buy a licence or extend the trial, email license@qualor\.dev\./,
      );
      expect(root.querySelector('a[href="mailto:license@qualor.dev"]')).not.toBeNull();
      expect(root.querySelector('a[href="/settings/license"]')).not.toBeNull();
      expect(dismissButton(root)).not.toBeNull();
    });

    it('names an Enterprise trial as Enterprise', async () => {
      const t = trial(5);
      setup({ ...t, license: { ...t.license!, plan: 'Enterprise' } });
      const root = await render();
      expect(text(root)).toContain('Your Enterprise trial ends in 5 days');
    });

    it('says 1 day on the last day', async () => {
      setup(trial(0.2));
      const root = await render();
      expect(text(root)).toContain('ends in 1 day, on');
      expect(text(root)).not.toContain('1 days');
    });

    it("hides on Dismiss and remembers today's local date", async () => {
      setup(trial(5));
      const fixture = TestBed.createComponent(LicenseBanner);
      await settle(fixture);
      const root = fixture.nativeElement as HTMLElement;
      dismissButton(root)?.click();
      await settle(fixture);
      expect(root.querySelector('[role="status"]')).toBeNull();
      expect(localStorage.getItem(TRIAL_DISMISS_KEY)).toBe(localToday());
    });

    it('shows again when the stored date is not today', async () => {
      localStorage.setItem(TRIAL_DISMISS_KEY, '2020-01-01');
      setup(trial(5));
      const root = await render();
      expect(text(root)).toContain('Your Business trial ends in 5 days');
    });

    it('stays hidden for today when it was dismissed today', async () => {
      localStorage.setItem(TRIAL_DISMISS_KEY, localToday());
      setup(trial(5));
      const root = await render();
      expect(root.querySelector('[role="status"]')).toBeNull();
    });

    it('still hides for this page load when storage is blocked', async () => {
      setup(trial(5));
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('blocked');
      });
      const fixture = TestBed.createComponent(LicenseBanner);
      await settle(fixture);
      const root = fixture.nativeElement as HTMLElement;
      dismissButton(root)?.click();
      await settle(fixture);
      expect(root.querySelector('[role="status"]')).toBeNull();
    });

    it('shows no banner for an expired trial', async () => {
      setup(trial(-1, { state: 'expired', edition: 'community', expiresSoon: false }));
      const root = await render();
      expect(root.querySelector('[role="status"]')).toBeNull();
    });

    it('shows nothing to a non-admin and asks nothing', async () => {
      const server = setup(trial(5), false);
      const root = await render();
      expect(root.textContent?.trim()).toBe('');
      expect(server.requestsTo('GET', '/api/v0/license')).toHaveLength(0);
    });
  });
});

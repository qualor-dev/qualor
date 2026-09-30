import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  expectNoPasswordManager,
  FakeServer,
  me,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { LicensePage, type LicenseStatus } from './license.page';
import { cleanKey } from './license-text';
import { SettingsPage } from './settings.page';

const COMMUNITY: LicenseStatus = {
  edition: 'community',
  state: 'none',
  reason: null,
  source: null,
  license: null,
  expiresSoon: false,
  restartRequired: false,
  activeFeatures: [],
  plugins: [],
};

const ACME = {
  id: 'l1',
  keyId: 'k2026',
  customer: 'Acme Corporation',
  issued: '2026-10-01T00:00:00.000Z',
  expires: '2027-10-01T00:00:00.000Z',
  graceEndsAt: '2027-10-15T00:00:00.000Z',
  features: ['llm.fix-quota'],
  test: false,
};

const ACTIVE_UPLOADED: LicenseStatus = {
  ...COMMUNITY,
  edition: 'enterprise',
  state: 'active',
  source: 'uploaded',
  license: ACME,
  activeFeatures: ['llm.fix-quota'],
};

const KEY = ['QLK1', 'k', 'p', 's'].join('.');

function setup(status: LicenseStatus, admin = true): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/license', { body: status });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(LicensePage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

function paste(root: HTMLElement, value: string): void {
  const area = root.querySelector<HTMLTextAreaElement>('textarea#license-key')!;
  area.value = value;
  area.dispatchEvent(new Event('input'));
}

function submit(root: HTMLElement): void {
  root.querySelector<HTMLFormElement>('form#license-form')!.dispatchEvent(new Event('submit'));
}

function button(root: HTMLElement, name: string): HTMLButtonElement | undefined {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === name);
}

describe('cleanKey', () => {
  it('drops every kind of whitespace a mail client or a PDF adds, and nothing else', () => {
    const wrapped = `  QLK1.k\n.p\r\n.\u00a0s\u200b\u200c\u200d\u2060\ufeff\u2028\u3000\t `;
    expect(cleanKey(wrapped)).toBe(KEY);
    expect(cleanKey('QLK1.k-_.p.s')).toBe('QLK1.k-_.p.s');
  });
});

describe('LicensePage (enterprise.md §11)', () => {
  it('shows the community edition and a form to paste a key', async () => {
    setup(COMMUNITY);
    const { root } = await render();
    expect(root.textContent).toContain('Community edition');
    const area = root.querySelector('textarea#license-key');
    expect(area).not.toBeNull();
    expect(root.querySelector('label[for="license-key"]')?.textContent).toContain('Licence key');
    // Nothing is saved yet: there is nothing to remove.
    expect(button(root, 'Remove')).toBeUndefined();
  });

  it('keeps password managers and spelling tools away from the key field', async () => {
    setup(COMMUNITY);
    const { root } = await render();
    const area = root.querySelector<HTMLTextAreaElement>('textarea#license-key')!;
    expectNoPasswordManager(area);
    expect(area.getAttribute('autocomplete')).toBe('off');
    expect(area.getAttribute('spellcheck')).toBe('false');
  });

  it('saves a key and says a restart applies it', async () => {
    const server = setup(COMMUNITY);
    server.on('PUT', '/api/v0/license', { body: { ...COMMUNITY, restartRequired: true } });
    const { fixture, root } = await render();
    paste(root, KEY);
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/license')[0]?.body).toEqual({ key: KEY });
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Saved. Restart the server to apply the new key.',
    );
    expect(root.querySelector('#license-restart')?.textContent).toContain('Restart required');
    // The key is sent once and never shown again, not even in the field.
    expect(root.querySelector<HTMLTextAreaElement>('#license-key')!.value).toBe('');
    expect(root.textContent).not.toContain(KEY);
    // A saved key can be removed again.
    expect(button(root, 'Remove')).toBeDefined();
  });

  it('sends a wrapped key without any whitespace', async () => {
    const server = setup(COMMUNITY);
    server.on('PUT', '/api/v0/license', { body: { ...COMMUNITY, restartRequired: true } });
    const { fixture, root } = await render();
    paste(root, '\ufeffQLK1.k\r\n.p.\u00a0s\u200b\n');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/license')[0]?.body).toEqual({ key: KEY });
  });

  it('asks for a key when the field holds only whitespace, without sending', async () => {
    const server = setup(COMMUNITY);
    const { fixture, root } = await render();
    paste(root, ' \n\u200b ');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/license')).toHaveLength(0);
    expect(root.querySelector('#license-key')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#license-key-error')?.textContent).toContain(
      'Paste the licence key you received.',
    );
  });

  it('shows the rejection reason next to the field, from the reason code', async () => {
    const server = setup(COMMUNITY);
    server.on('PUT', '/api/v0/license', {
      status: 422,
      // The UI maps `reason` (enterprise.md §9), never the English message.
      body: {
        ...problem(422, 'LICENSE_INVALID', [{ path: 'body.key', message: 'server words' }]),
        reason: 'bad-signature',
      },
    });
    const { fixture, root } = await render();
    paste(root, KEY);
    submit(root);
    await settle(fixture);
    const error = root.querySelector('#license-key-error');
    expect(error?.getAttribute('role')).toBe('alert');
    expect(error?.textContent).toContain('its signature does not match');
    expect(root.textContent).not.toContain('server words');
    expect(root.querySelector('#license-key')?.getAttribute('aria-describedby')).toContain(
      'license-key-error',
    );
    // The key was sent: it is not kept in the field or echoed anywhere.
    expect(root.querySelector<HTMLTextAreaElement>('#license-key')!.value).toBe('');
    expect(root.textContent).not.toContain(KEY);
  });

  it('says in plain words when the server names no reason, or one this UI does not know', async () => {
    const server = setup(COMMUNITY);
    const answers = [
      problem(422, 'LICENSE_INVALID', [
        // The server's text for bad-signature: without `reason` it is not read either.
        { path: 'body.key', message: 'The key has been changed: its signature does not match' },
      ]),
      {
        ...problem(422, 'LICENSE_INVALID', [{ path: 'body.key', message: 'server words' }]),
        reason: 'a-newer-reason',
      },
    ];
    server.on('PUT', '/api/v0/license', () => ({ status: 422, body: answers.shift() }));
    const { fixture, root } = await render();
    for (let i = 0; i < 2; i++) {
      paste(root, 'hello');
      submit(root);
      await settle(fixture);
      const message = root.querySelector('#license-key-error')?.textContent ?? '';
      expect(message).toContain('The key was not accepted.');
      expect(message).not.toContain('signature');
      expect(message).not.toContain('server words');
    }
  });

  it('maps the malformed reason, a schema refusal and an expired key to their own words', async () => {
    const server = setup(COMMUNITY);
    const answers = [
      {
        ...problem(422, 'LICENSE_INVALID', [{ path: 'body.key', message: 'server words' }]),
        reason: 'malformed',
      },
      problem(422, 'VALIDATION_FAILED', [{ path: 'body.key', message: 'Too big' }]),
      problem(422, 'LICENSE_EXPIRED', [{ path: 'body.key', message: 'This licence has expired' }]),
    ];
    server.on('PUT', '/api/v0/license', () => ({ status: 422, body: answers.shift() }));
    const { fixture, root } = await render();
    const texts: string[] = [];
    for (let i = 0; i < 3; i++) {
      paste(root, KEY);
      submit(root);
      await settle(fixture);
      texts.push(root.querySelector('#license-key-error')?.textContent?.trim() ?? '');
    }
    expect(texts[0]).toContain('This is not a Qualor licence key');
    expect(texts[1]).toContain('This is not a Qualor licence key');
    expect(texts[2]).toContain('past its grace period');
  });

  /** The key form's Remove (the confirmation dialog has a Remove of its own). */
  const formRemove = (root: HTMLElement) =>
    button(root.querySelector<HTMLElement>('form#license-form')!, 'Remove');
  const ask = (root: HTMLElement) =>
    root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')!;

  it("removes a saved key after the page's own confirmation, and says what the restart does", async () => {
    const server = setup({ ...COMMUNITY, restartRequired: true });
    server.on('DELETE', '/api/v0/license', { body: { ...COMMUNITY, restartRequired: false } });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    formRemove(root)!.click();
    await settle(fixture);
    expect(ask(root).open).toBe(true);
    expect(ask(root).querySelector('#confirm-text')?.textContent?.trim()).toBe(
      'Remove the saved licence key? At the next start the server runs as the community edition. Nothing is deleted.',
    );
    button(ask(root), 'Remove')!.click();
    await settle(fixture);
    expect(confirm).not.toHaveBeenCalled();
    // Closed, and gone with the saved key it asked about.
    expect(ask(root)?.open ?? false).toBe(false);
    expect(server.requestsTo('DELETE', '/api/v0/license')).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Removed.');
    confirm.mockRestore();
  });

  it('hides Remove once the running key was removed, until a key is saved again', async () => {
    // The server still runs with the uploaded key it booted with: the status stays `uploaded`
    // with restartRequired, whether the row was removed or replaced.
    const server = setup({ ...ACTIVE_UPLOADED });
    server.on('DELETE', '/api/v0/license', { body: { ...ACTIVE_UPLOADED, restartRequired: true } });
    server.on('PUT', '/api/v0/license', { body: { ...ACTIVE_UPLOADED, restartRequired: true } });
    const { fixture, root } = await render();
    formRemove(root)!.click();
    await settle(fixture);
    button(ask(root), 'Remove')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Removed.');
    expect(formRemove(root)).toBeUndefined();
    paste(root, KEY);
    submit(root);
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Saved.');
    expect(formRemove(root)).toBeDefined();
  });

  it('keeps the key when the removal is cancelled', async () => {
    const server = setup({ ...ACTIVE_UPLOADED });
    const { fixture, root } = await render();
    formRemove(root)!.click();
    await settle(fixture);
    button(ask(root), 'Cancel')!.click();
    await settle(fixture);
    expect(ask(root).open).toBe(false);
    expect(server.requestsTo('DELETE', '/api/v0/license')).toHaveLength(0);
  });

  describe('the plan panel (step 9)', () => {
    const DAY = 86_400_000;
    /** A licence issued `since` days ago, `left` days before it expires, with 14 days of grace. */
    function licence(since: number, left: number, overrides: Partial<typeof ACME> = {}) {
      const now = Date.now();
      return {
        ...ACME,
        issued: new Date(now - since * DAY).toISOString(),
        expires: new Date(now + left * DAY).toISOString(),
        graceEndsAt: new Date(now + (left + 14) * DAY).toISOString(),
        ...overrides,
      };
    }
    const meter = (root: HTMLElement) => root.querySelector('#license-plan q-meter');
    const words = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

    it('shows the time left as a meter, and each licensed feature as a check with its state', async () => {
      setup({
        ...ACTIVE_UPLOADED,
        license: licence(100, 265, { features: ['audit-log', 'llm.fix-quota'] }),
        activeFeatures: ['llm.fix-quota'],
      });
      const { root } = await render();
      const plan = root.querySelector('#license-plan')!;
      expect(plan.textContent).toContain('Acme Corporation');
      expect(words(meter(root)?.querySelector('.meter-value'))).toBe('265 days left');
      const track = meter(root)?.querySelector('[role="meter"]');
      expect(track?.getAttribute('aria-valuenow')).toBe('265');
      expect(track?.getAttribute('aria-valuemax')).toBe('365');
      const features = [...plan.querySelectorAll('.feature-checks li')].map((li) => words(li));
      expect(features).toEqual(['audit-log Not active', 'llm.fix-quota Active']);
    });

    it('says when the licence expires soon, runs on grace, or has expired, in words', async () => {
      setup({ ...ACTIVE_UPLOADED, license: licence(340, 25), expiresSoon: true });
      const soon = await render();
      expect(words(meter(soon.root)?.querySelector('.meter-note'))).toContain('Renew soon');
      // Attention, not failure: amber until the licence has expired (step 11).
      expect(meter(soon.root)?.querySelector('.meter')?.classList).toContain('attention');
      expect(meter(soon.root)?.querySelector('.meter')?.classList).not.toContain('reached');
      TestBed.resetTestingModule();
      setup({ ...ACTIVE_UPLOADED, state: 'grace', license: licence(370, -5) });
      const grace = await render();
      expect(words(meter(grace.root)?.querySelector('.meter-value'))).toBe('9 days of grace left');
      expect(meter(grace.root)?.querySelector('.meter')?.classList).toContain('attention');
      expect(meter(grace.root)?.querySelector('.meter')?.classList).not.toContain('reached');
      expect(words(meter(grace.root)?.querySelector('.meter-note'))).toContain(
        'Enterprise features stop on',
      );
      TestBed.resetTestingModule();
      setup({
        ...COMMUNITY,
        state: 'expired',
        source: 'uploaded',
        license: licence(400, -35, { expires: '2027-10-01T00:00:00.000Z' }),
      });
      const expired = await render();
      expect(words(meter(expired.root)?.querySelector('.meter-value'))).toBe(
        'Expired on Oct 1, 2027',
      );
      expect(meter(expired.root)?.querySelector('.meter')?.classList).toContain('reached');
    });

    it('claims no time for a key the server rejected (revoked, not yet valid)', async () => {
      for (const reason of ['revoked', 'not-yet-valid'] as const) {
        setup({
          ...COMMUNITY,
          state: 'invalid',
          reason,
          source: 'uploaded',
          license: licence(100, 265),
        });
        const { root } = await render();
        expect(meter(root), reason).toBeNull();
        expect(root.textContent, reason).not.toContain('days left');
        TestBed.resetTestingModule();
      }
    });

    it('draws no meter without a licence', async () => {
      setup(COMMUNITY);
      const { root } = await render();
      expect(meter(root)).toBeNull();
      expect(root.querySelector('#license-plan')?.textContent).toContain('Community edition');
    });
  });

  it('shows an active licence with its customer, dates, features and plugins', async () => {
    setup({
      ...ACTIVE_UPLOADED,
      plugins: [
        { name: 'qualor-enterprise', state: 'loaded', features: ['llm.fix-quota'], error: null },
        { name: 'broken', state: 'failed', features: [], error: 'register timed out' },
      ],
    });
    const { root } = await render();
    const text = root.textContent ?? '';
    expect(text).toContain('Enterprise edition, active until Oct 1, 2027');
    expect(text).toContain('Acme Corporation');
    expect(text).toContain('l1');
    expect(text).toContain('k2026');
    expect(text).toContain('llm.fix-quota');
    expect(text).toContain('register timed out');
    expect(text).toContain('Saved in Qualor');
    expect(root.querySelector('#license-restart')).toBeNull();
  });

  it('marks a test key', async () => {
    setup({ ...ACTIVE_UPLOADED, license: { ...ACME, keyId: 'test-e2e', test: true } });
    const { root } = await render();
    expect(root.textContent).toContain('test key');
  });

  it('shows the grace period', async () => {
    setup({
      ...COMMUNITY,
      edition: 'enterprise',
      state: 'grace',
      source: 'environment',
      license: ACME,
      activeFeatures: ['llm.fix-quota'],
    });
    const { root } = await render();
    expect(root.textContent).toContain('Grace period');
    expect(root.textContent).toContain('Oct 15, 2027');
    expect(root.textContent).toContain('Acme Corporation');
    // The key comes from the environment: no form, the variable is named instead.
    expect(root.querySelector('textarea#license-key')).toBeNull();
    expect(button(root, 'Remove')).toBeUndefined();
    expect(root.textContent).toContain('QUALOR_LICENSE');
  });

  it('names QUALOR_LICENSE_FILE for a key from a file', async () => {
    setup({ ...COMMUNITY, state: 'expired', source: 'file', license: ACME });
    const { root } = await render();
    expect(root.textContent).toContain('Expired: running as the community edition');
    expect(root.textContent).toContain('QUALOR_LICENSE_FILE');
    expect(root.querySelector('textarea#license-key')).toBeNull();
  });

  it('shows no organisation count or limit (enterprise.md §11)', async () => {
    for (const status of [COMMUNITY, ACTIVE_UPLOADED]) {
      TestBed.resetTestingModule();
      setup(status);
      const { root } = await render();
      expect(root.textContent).toContain(
        status === COMMUNITY ? 'Community edition' : 'Acme Corporation',
      );
      expect(root.querySelector('dl.facts')?.textContent ?? '').not.toMatch(/organization/i);
      expect(root.textContent).not.toContain('read-only');
    }
  });

  it('gives the reason a boot key was rejected in the UI own words', async () => {
    setup({ ...COMMUNITY, state: 'invalid', reason: 'unknown-key', source: 'environment' });
    const { root } = await render();
    expect(root.textContent).toContain(
      'The key was rejected: This key was signed with a key this version of Qualor does not accept',
    );
  });

  it('says the boot key was rejected in general words when no known reason is given', async () => {
    setup({ ...COMMUNITY, state: 'invalid', reason: null, source: 'environment' });
    const { root } = await render();
    const text = root.querySelector('.license-state')?.textContent?.trim() ?? '';
    expect(text).toBe(
      'The key was rejected. Check that it was copied completely, or ask for a new one.',
    );
    expect(text).not.toContain(':');
  });

  it('tells a person who is not an instance admin that the page is not for them', async () => {
    const server = setup(COMMUNITY, false);
    const { root } = await render();
    expect(root.textContent).toContain('Only instance administrators manage the licence.');
    expect(server.requestsTo('GET', '/api/v0/license')).toHaveLength(0);
  });
});

describe('SettingsPage navigation (enterprise.md §10.4, §11)', () => {
  function setupNav(admin: boolean): FakeServer {
    const server = new FakeServer();
    server.on('GET', '/api/v0/organizations', { body: page([]) });
    server.on('GET', '/api/v0/system/info', {
      body: {
        version: '0.0.0',
        edition: 'enterprise',
        features: ['audit-log'],
        extensions: [
          { point: 'settings.nav', id: 'audit', label: 'Audit log', path: '/settings/ee/audit' },
        ],
      },
    });
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me({ admin }));
    return server;
  }

  it('lists the licence and each extension point for an instance admin', async () => {
    setupNav(true);
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const links = [...root.querySelectorAll('nav a')].map((a) => a.textContent?.trim());
    expect(links).toContain('Licence');
    expect(links).toContain('Audit log');
    expect(root.querySelector('a[href="/ee/audit"], a[href$="ee/audit"]')).not.toBeNull();
  });

  it('shows neither to other users', async () => {
    setupNav(false);
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const links = [...root.querySelectorAll('nav a')].map((a) => a.textContent?.trim());
    expect(links).not.toContain('Licence');
    expect(links).not.toContain('Audit log');
  });
});

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
import type { AuditSettings } from '../api/ee';
import { SessionStore } from '../auth/session';
import { AuditSettingsPage } from './audit-settings.page';

const SETTINGS = '/api/v0/ee/audit/settings';
const SECRET = 'whsec_' + 'A1b2C3d4'.repeat(4);

const STATUS = {
  cursorSeq: '40',
  pending: 3,
  lastSuccessAt: '2026-09-20T10:00:00.000Z',
  lastError: 'HTTP 503: receiver busy',
  failingSince: '2026-09-21T08:00:00.000Z',
  nextAttemptAt: '2026-09-21T08:04:00.000Z',
  skipped: 2,
};

function settings(stream: AuditSettings['stream'] = null, retentionDays = 365): AuditSettings {
  return { retentionDays, stream };
}

function setup(
  options: { admin?: boolean; features?: string[]; current?: AuditSettings } = {},
): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', { body: page([]) });
  server.on('GET', '/api/v0/system/info', {
    body: {
      version: '0.1.0',
      edition: 'enterprise',
      features: options.features ?? ['audit-log', 'audit-log.stream'],
      extensions: [],
    },
  });
  server.on('GET', SETTINGS, { body: options.current ?? settings() });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? true }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(AuditSettingsPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

function button(root: HTMLElement, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

async function click(fixture: { whenStable(): Promise<unknown> }, target: HTMLElement) {
  target.click();
  await settle(fixture);
}

async function save(fixture: { whenStable(): Promise<unknown> }, root: HTMLElement) {
  root.querySelector('form')!.dispatchEvent(new Event('submit'));
  await settle(fixture);
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
  await click(fixture, button(ask, choice));
  expect(ask.open).toBe(false);
  return question;
}

describe('AuditSettingsPage (rbac-audit.md §11, §14, §17)', () => {
  it('saves the retention in days', async () => {
    const server = setup();
    server.on('PUT', SETTINGS, { body: settings(null, 90) });
    const { fixture, root } = await render();
    expect(root.querySelector<HTMLInputElement>('#audit-retention')?.value).toBe('365');
    type(root, '#audit-retention', '90');
    await save(fixture, root);
    expect(server.requestsTo('PUT', SETTINGS).map((r) => r.body)).toEqual([
      { retentionDays: 90, stream: null },
    ]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Audit settings saved.');
  });

  it("shows the server's 422 on the retention field", async () => {
    const server = setup();
    server.on('PUT', SETTINGS, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.retentionDays', message: 'Too small: expected number to be >=30' },
      ]),
    });
    const { fixture, root } = await render();
    // 40 passes the page's own check, so the refusal is the server's.
    type(root, '#audit-retention', '40');
    await save(fixture, root);
    expect(server.requestsTo('PUT', SETTINGS).map((r) => r.body)).toEqual([
      { retentionDays: 40, stream: null },
    ]);
    const field = root.querySelector('#audit-retention')!;
    expect(field.getAttribute('aria-invalid')).toBe('true');
    expect(field.getAttribute('aria-describedby')).toBe(
      'audit-retention-hint audit-retention-error',
    );
    expect(root.querySelector('#audit-retention-error')?.textContent).toContain(
      'Keep events between 30 and 36 500 days.',
    );
  });

  it('points the retention field at its hint only while it is valid', async () => {
    setup();
    const { root } = await render();
    expect(root.querySelector('#audit-retention')?.getAttribute('aria-describedby')).toBe(
      'audit-retention-hint',
    );
  });

  it('says so when the server information cannot be loaded, instead of an empty page', async () => {
    const server = setup();
    server.on('GET', '/api/v0/system/info', { status: 500, body: problem(500, 'INTERNAL') });
    const { root } = await render();
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
    expect(root.querySelector('form')).toBeNull();
  });

  it('adds a stream and shows its generated secret once', async () => {
    const server = setup();
    server.on('PUT', SETTINGS, {
      body: {
        retentionDays: 365,
        stream: {
          url: 'https://siem.example.com/qualor',
          active: true,
          secretSet: true,
          status: { ...STATUS, lastError: null, failingSince: null, nextAttemptAt: null },
          secret: SECRET,
        },
      },
    });
    const { fixture, root } = await render();
    type(root, '#audit-stream-url', 'https://siem.example.com/qualor');
    await save(fixture, root);
    expect(server.requestsTo('PUT', SETTINGS).map((r) => r.body)).toEqual([
      { retentionDays: 365, stream: { url: 'https://siem.example.com/qualor', active: true } },
    ]);
    const field = root.querySelector<HTMLInputElement>('#secret-once')!;
    expect(field.value).toBe(SECRET);
    const done = button(root, 'Done');
    done.focus();
    done.click();
    await settle(fixture);
    expect(root.querySelector('#secret-once')).toBeNull();
    expect(root.textContent).not.toContain(SECRET);
    // The button went with the secret: focus stays in the page, on its heading.
    expect(document.activeElement).toBe(root.querySelector('h2'));
  });

  it("shows the server's 422 on the stream URL field", async () => {
    const server = setup();
    server.on('PUT', SETTINGS, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.stream.url', message: 'private address' },
      ]),
    });
    const { fixture, root } = await render();
    type(root, '#audit-stream-url', 'https://10.0.0.1/siem');
    await save(fixture, root);
    expect(root.querySelector('#audit-stream-url')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#audit-stream-url-error')?.textContent).toContain(
      'Use an https URL of a public host',
    );
  });

  it('shows the stream, its status and whether a secret is set, never the secret', async () => {
    setup({
      current: settings({
        url: 'https://siem.example.com/qualor',
        active: true,
        secretSet: true,
        status: STATUS,
      }),
    });
    const { root } = await render();
    expect(root.querySelector<HTMLInputElement>('#audit-stream-url')?.value).toBe(
      'https://siem.example.com/qualor',
    );
    expect(root.querySelector<HTMLInputElement>('#audit-stream-active')?.checked).toBe(true);
    const status = root.querySelector('#audit-stream-status')!.textContent ?? '';
    expect(status).toContain('Sep 20, 2026, 10:00 AM UTC');
    expect(status).toContain('HTTP 503: receiver busy');
    expect(status).toContain('Sep 21, 2026, 8:00 AM UTC');
    expect(status).toContain('Sep 21, 2026, 8:04 AM UTC');
    expect(status).toContain('3 events');
    expect(status).toContain('2 events');
    expect(root.querySelector('#secret-once')).toBeNull();
  });

  it('regenerates the secret after a confirmation and shows it once', async () => {
    const server = setup({
      current: settings({
        url: 'https://siem.example.com/q',
        active: true,
        secretSet: true,
        status: STATUS,
      }),
    });
    server.on('POST', `${SETTINGS}/stream/regenerate-secret`, { body: { secret: SECRET } });
    const confirm = vi.spyOn(window, 'confirm');
    const { fixture, root } = await render();
    button(root, 'Regenerate the secret').click();
    await settle(fixture);
    expect(await answer(fixture, root, 'Regenerate the secret')).toBe(
      'Regenerate the stream secret? The receiver must be given the new secret: batches signed with it fail the old check.',
    );
    expect(confirm).not.toHaveBeenCalled();
    expect(server.requestsTo('POST', `${SETTINGS}/stream/regenerate-secret`)).toHaveLength(1);
    expect(root.querySelector<HTMLInputElement>('#secret-once')?.value).toBe(SECRET);
    confirm.mockRestore();
  });

  it('sends a test batch and shows its result', async () => {
    const server = setup({
      current: settings({
        url: 'https://siem.example.com/q',
        active: true,
        secretSet: true,
        status: STATUS,
      }),
    });
    server.on('POST', `${SETTINGS}/stream/test`, {
      body: { ok: false, status: 500, excerpt: 'boom' },
    });
    const { fixture, root } = await render();
    button(root, 'Send test').click();
    await settle(fixture);
    const result = root.querySelector('#audit-stream-test')!.textContent ?? '';
    expect(result).toContain('The receiver answered HTTP 500, so the test failed.');
    expect(result).toContain('boom');
  });

  it('removes the stream after a confirmation when the URL is emptied', async () => {
    const server = setup({
      current: settings({
        url: 'https://siem.example.com/q',
        active: true,
        secretSet: true,
        status: STATUS,
      }),
    });
    server.on('PUT', SETTINGS, { body: settings(null) });
    const { fixture, root } = await render();
    type(root, '#audit-stream-url', '');
    await save(fixture, root);
    expect(server.requestsTo('PUT', SETTINGS)).toHaveLength(0);
    expect(await answer(fixture, root, 'Remove')).toBe(
      'Remove the SIEM stream? Events are no longer sent; they stay in the audit log.',
    );
    expect(server.requestsTo('PUT', SETTINGS).map((r) => r.body)).toEqual([
      { retentionDays: 365, stream: null },
    ]);
  });

  it('disables the stream card with a licence note without audit-log.stream', async () => {
    const server = setup({ features: ['audit-log'] });
    const { root } = await render();
    expect(root.querySelector('#audit-stream-not-licensed')?.textContent).toContain(
      'Streaming the audit log to a SIEM needs the Enterprise plan.',
    );
    expect(root.querySelector<HTMLInputElement>('#audit-stream-url')?.disabled).toBe(true);
    expect(root.querySelector('#audit-stream-url')?.getAttribute('aria-describedby')).toBe(
      'audit-stream-not-licensed',
    );
    expect(root.querySelector<HTMLInputElement>('#audit-stream-active')?.disabled).toBe(true);
    // Retention stays editable, and nothing but the settings was asked of the stream.
    expect(root.querySelector<HTMLInputElement>('#audit-retention')?.disabled).toBe(false);
    expect(root.querySelector('#audit-stream-status')).toBeNull();
    expect(server.requests.filter((r) => r.path.includes('/stream/'))).toEqual([]);
  });

  it('saves retention without a stream object on a Business licence', async () => {
    const server = setup({ features: ['sso', 'audit-log', 'llm.fix-quota'] });
    server.on('PUT', SETTINGS, { body: settings(null, 90) });
    const { fixture, root } = await render();
    type(root, '#audit-retention', '90');
    await save(fixture, root);
    expect(server.requestsTo('PUT', SETTINGS).map((r) => r.body)).toEqual([{ retentionDays: 90 }]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Audit settings saved.');
  });

  it('removes a kept stream without audit-log.stream', async () => {
    const kept = {
      url: 'https://siem.example.com/q',
      active: true,
      secretSet: true,
      status: STATUS,
    };
    const server = setup({ features: ['audit-log'], current: settings(kept) });
    server.on('PUT', SETTINGS, (request) => ({
      body: settings((request.body as { stream?: unknown }).stream === null ? null : kept),
    }));
    const { fixture, root } = await render();
    // Read-only: the address, whether it is active and its status, without the stream's buttons.
    const url = root.querySelector<HTMLInputElement>('#audit-stream-url')!;
    expect(url.value).toBe('https://siem.example.com/q');
    expect(url.disabled).toBe(true);
    expect(root.querySelector<HTMLInputElement>('#audit-stream-active')?.disabled).toBe(true);
    expect(root.querySelector('#audit-stream-status')?.textContent).toContain('3 events');
    expect(button(root, 'Send test').disabled).toBe(true);
    expect(button(root, 'Regenerate the secret').disabled).toBe(true);
    // The reason is in the status card, next to the disabled buttons.
    expect(root.querySelector('#audit-stream-paused')?.textContent).toContain(
      'The stream is paused: streaming the audit log to a SIEM needs the Enterprise plan.',
    );
    expect(button(root, 'Send test').getAttribute('aria-describedby')).toBe('audit-stream-paused');
    expect(button(root, 'Regenerate the secret').getAttribute('aria-describedby')).toBe(
      'audit-stream-paused',
    );
    button(root, 'Send test').click();
    button(root, 'Regenerate the secret').click();
    await settle(fixture);
    expect(server.requests.filter((r) => r.path.includes('/stream/'))).toEqual([]);

    // Save keeps the stream: retention alone, without asking.
    await save(fixture, root);
    expect(server.requestsTo('PUT', SETTINGS).map((r) => r.body)).toEqual([{ retentionDays: 365 }]);
    expect(root.querySelector<HTMLDialogElement>('dialog#confirm-dialog')?.open).toBe(false);

    await click(fixture, button(root, 'Remove'));
    expect(await answer(fixture, root, 'Remove')).toBe(
      'Remove the SIEM stream? Events are no longer sent; they stay in the audit log.',
    );
    expect(server.requestsTo('PUT', SETTINGS).map((r) => r.body)).toEqual([
      { retentionDays: 365 },
      { stream: null },
    ]);
    expect(root.querySelector('#audit-stream-status')).toBeNull();
    expect(root.querySelector<HTMLInputElement>('#audit-stream-url')?.value).toBe('');
  });

  it('removes nothing when the removal is cancelled', async () => {
    const server = setup({
      features: ['audit-log'],
      current: settings({
        url: 'https://siem.example.com/q',
        active: true,
        secretSet: true,
        status: STATUS,
      }),
    });
    const { fixture, root } = await render();
    await click(fixture, button(root, 'Remove'));
    await answer(fixture, root, 'Cancel');
    expect(server.requestsTo('PUT', SETTINGS)).toHaveLength(0);
  });

  it('offers no Remove button while audit-log.stream is active', async () => {
    setup({
      current: settings({
        url: 'https://siem.example.com/q',
        active: true,
        secretSet: true,
        status: STATUS,
      }),
    });
    const { root } = await render();
    expect(button(root, 'Remove')).toBeUndefined();
    expect(root.querySelector('#audit-stream-not-licensed')).toBeNull();
    expect(root.querySelector('#audit-stream-paused')).toBeNull();
    expect(button(root, 'Send test').disabled).toBe(false);
    expect(button(root, 'Send test').getAttribute('aria-describedby')).toBeNull();
  });

  it('asks nothing of the enterprise API without audit-log, or for someone who is not an instance admin', async () => {
    const server = setup({ features: [] });
    const { root } = await render();
    expect(root.textContent).toContain('The audit log needs an enterprise licence');
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
    TestBed.resetTestingModule();
    const other = setup({ admin: false });
    const second = await render();
    expect(second.root.textContent).toContain(
      'Only instance administrators change the audit settings.',
    );
    expect(other.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
  });
});

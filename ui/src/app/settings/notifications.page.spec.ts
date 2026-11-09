import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { NotificationsPage } from './notifications.page';

const A = '0190a6c2-0000-7000-8000-0000000000a1';
const Z = '0190a6c2-0000-7000-8000-0000000000a2';
const ALL = {
  gateFailed: true,
  gateRecovered: true,
  analysisFailed: true,
  newVulnerabilities: true,
};
const DATA = {
  preferences: { email: true, orgWebhookFailures: true },
  isOrgAdmin: true,
  emailAddress: 'alice@example.com',
  mailConfigured: true,
  vulnerabilityAlerts: true,
  watches: [
    { project: { id: A, key: 'acme/a', name: 'Alpha' }, branches: 'main', events: ALL },
    {
      project: { id: Z, key: 'acme/z', name: 'Zeta' },
      branches: 'all',
      events: { ...ALL, gateRecovered: false },
    },
  ],
};
const WATCH_A = `/api/v0/projects/${A}/watch`;
const READY = { emailReady: true, emailBlocker: null, vulnerabilityAlerts: true };

describe('NotificationsPage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [NotificationsPage],
      providers: [provideRouter([]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render() {
    const fixture = TestBed.createComponent(NotificationsPage);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }
  const label = (root: HTMLElement, text: string) =>
    [...root.querySelectorAll('label')].find((l) => l.textContent?.includes(text));
  const rowOf = (root: HTMLElement, i: number) => root.querySelectorAll('tbody tr')[i]!;
  const boxes = (row: Element) => [
    ...row.querySelectorAll<HTMLInputElement>('input[type=checkbox]'),
  ];
  const names = (root: HTMLElement) =>
    [...root.querySelectorAll('tbody tr')].map((r) => r.querySelector('a')?.textContent?.trim());
  const alert = (root: HTMLElement) => root.querySelector('[role="alert"]');
  const stopAlpha = (root: HTMLElement) =>
    root.querySelector<HTMLButtonElement>('button[aria-label="Stop watching Alpha"]')!;

  /** Answers every PUT of the watch like the server, but only when the test releases it. */
  function holdWatchPuts(): { release: () => void } {
    const gates: (() => void)[] = [];
    server.on('PUT', WATCH_A, async (r) => {
      await new Promise<void>((resolve) => gates.push(resolve));
      return { body: { watching: true, ...(r.body as object), ...READY } };
    });
    return { release: () => gates.shift()?.() };
  }

  it('shows the address switch, the org-admin switch and every watched project with its choices', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    const { root } = await render();
    expect(label(root, 'Email me at alice@example.com')?.querySelector('input')?.checked).toBe(
      true,
    );
    expect(label(root, 'Failing webhooks in organisations I administer')).toBeDefined();
    expect(names(root)).toEqual(['Alpha', 'Zeta']);
    expect(rowOf(root, 0).querySelector('a')?.getAttribute('href')).toBe(`/projects/${A}`);
    expect(rowOf(root, 1).querySelector('select')?.value).toBe('all');
    expect(boxes(rowOf(root, 1)).map((c) => c.checked)).toEqual([true, false, true, true]);
  });

  it('saves the email switch, and a project scope and event', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    server.on('PUT', '/api/v0/me/notifications', {
      body: { preferences: { email: false, orgWebhookFailures: true } },
    });
    server.on('PUT', WATCH_A, (r) => ({
      body: { watching: true, ...(r.body as object), ...READY },
    }));
    const { fixture, root } = await render();
    label(root, 'Email me at')!.querySelector('input')!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/me/notifications')[0]?.body).toEqual({
      email: false,
    });
    const select = root.querySelector<HTMLSelectElement>('tbody tr select')!;
    select.value = 'all';
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    expect(server.requestsTo('PUT', WATCH_A).at(-1)?.body).toEqual({
      branches: 'all',
      events: ALL,
    });
    boxes(rowOf(root, 0))[0]!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', WATCH_A).at(-1)?.body).toEqual({
      branches: 'all',
      events: { ...ALL, gateFailed: false },
    });
  });

  it('sends quick changes one at a time, each on top of the last, and only the latest of several', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    const put = holdWatchPuts();
    const { fixture, root } = await render();
    const [failed, recovered, analysis] = boxes(rowOf(root, 0)) as [
      HTMLInputElement,
      HTMLInputElement,
      HTMLInputElement,
    ];
    failed.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', WATCH_A)).toHaveLength(1);
    // Two more while the first is on its way: nothing is sent yet.
    recovered.click();
    analysis.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', WATCH_A)).toHaveLength(1);
    expect(boxes(rowOf(root, 0)).map((c) => c.checked)).toEqual([false, false, false, true]);
    put.release();
    await settle(fixture);
    // One PUT with both later changes on top of the first, not two stale ones.
    expect(server.requestsTo('PUT', WATCH_A)).toHaveLength(2);
    expect(server.requestsTo('PUT', WATCH_A)[1]?.body).toEqual({
      branches: 'main',
      events: { ...ALL, gateFailed: false, gateRecovered: false, analysisFailed: false },
    });
    put.release();
    await settle(fixture);
    expect(boxes(rowOf(root, 0)).map((c) => c.checked)).toEqual([false, false, false, true]);
    expect(alert(root)).toBeNull();
  });

  it('puts a refused box back, says so, and drops the changes queued behind it', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    let first = true;
    const gates: (() => void)[] = [];
    server.on('PUT', WATCH_A, async (r) => {
      await new Promise<void>((resolve) => gates.push(resolve));
      if (first) {
        first = false;
        return { status: 500, body: problem(500, 'INTERNAL') };
      }
      return { body: { watching: true, ...(r.body as object), ...READY } };
    });
    const { fixture, root } = await render();
    const [failed, recovered] = boxes(rowOf(root, 0)) as [HTMLInputElement, HTMLInputElement];
    failed.click();
    await settle(fixture);
    recovered.click();
    await settle(fixture);
    gates.shift()?.();
    await settle(fixture);
    // The refused change and the one queued behind it are gone; the boxes show the server's state.
    expect(server.requestsTo('PUT', WATCH_A)).toHaveLength(1);
    expect(boxes(rowOf(root, 0)).map((c) => c.checked)).toEqual([true, true, true, true]);
    expect(alert(root)).not.toBeNull();
    // The next change builds on the server's state.
    recovered.click();
    await settle(fixture);
    gates.shift()?.();
    await settle(fixture);
    expect(server.requestsTo('PUT', WATCH_A)[1]?.body).toEqual({
      branches: 'main',
      events: { ...ALL, gateRecovered: false },
    });
    expect(alert(root)).toBeNull();
  });

  it('puts a refused scope, box and switch back', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    server.on('PUT', WATCH_A, { status: 500, body: problem(500, 'INTERNAL') });
    server.on('PUT', '/api/v0/me/notifications', { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root } = await render();
    const select = root.querySelector<HTMLSelectElement>('tbody tr select')!;
    select.value = 'all';
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    expect(select.value).toBe('main');
    const box = boxes(rowOf(root, 0))[1]!;
    box.click();
    await settle(fixture);
    expect(box.checked).toBe(true);
    const email = label(root, 'Email me at')!.querySelector('input')!;
    email.click();
    await settle(fixture);
    expect(email.checked).toBe(true);
    expect(alert(root)).not.toBeNull();
  });

  it('stops watching a project and says so', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    server.on('DELETE', WATCH_A, { status: 204 });
    const { fixture, root } = await render();
    stopAlpha(root).click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', WATCH_A)).toHaveLength(1);
    expect(names(root)).toEqual(['Zeta']);
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      'You no longer watch Alpha.',
    );
  });

  it('lets a change on its way finish before it stops, and shows nothing of its answer once the row is gone', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    server.on('DELETE', WATCH_A, { status: 204 });
    const put = holdWatchPuts();
    const { fixture, root } = await render();
    boxes(rowOf(root, 0))[0]!.click();
    await settle(fixture);
    stopAlpha(root).click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', WATCH_A)).toHaveLength(0);
    put.release();
    await settle(fixture);
    expect(server.requestsTo('DELETE', WATCH_A)).toHaveLength(1);
    expect(names(root)).toEqual(['Zeta']);
    expect(alert(root)).toBeNull();
  });

  it('clears the error of a change refused on its way once the stop it waited for succeeds', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    server.on('DELETE', WATCH_A, { status: 204 });
    const gates: (() => void)[] = [];
    server.on('PUT', WATCH_A, async () => {
      await new Promise<void>((resolve) => gates.push(resolve));
      return { status: 500, body: problem(500, 'INTERNAL') };
    });
    const { fixture, root } = await render();
    boxes(rowOf(root, 0))[0]!.click();
    await settle(fixture);
    stopAlpha(root).click();
    await settle(fixture);
    gates.shift()?.();
    await settle(fixture);
    expect(server.requestsTo('DELETE', WATCH_A)).toHaveLength(1);
    expect(names(root)).toEqual(['Zeta']);
    expect(alert(root)).toBeNull();
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      'You no longer watch Alpha.',
    );
  });

  it('keeps the row and says why when stopping fails', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    server.on('DELETE', WATCH_A, { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root } = await render();
    stopAlpha(root).click();
    await settle(fixture);
    expect(names(root)).toEqual(['Alpha', 'Zeta']);
    expect(alert(root)).not.toBeNull();
    expect(stopAlpha(root).disabled).toBe(false);
  });

  it('shows the empty list, no org switch for others, the missing address and a server without email', async () => {
    server.on('GET', '/api/v0/me/notifications', {
      body: { ...DATA, isOrgAdmin: false, emailAddress: null, mailConfigured: false, watches: [] },
    });
    const { root } = await render();
    expect(root.textContent).toContain(
      "You don't watch any project yet. Use Watch on a project page.",
    );
    expect(root.textContent).toContain(
      'You have no email address: ask an administrator to add one.',
    );
    expect(root.textContent).toContain(
      "Email isn't set up on this server, so Qualor sends no notifications yet.",
    );
    expect(label(root, 'Failing webhooks')).toBeUndefined();
    expect(root.querySelector('table')).toBeNull();
  });

  it('adds a New vulnerabilities column, one box per watch', async () => {
    server.on('GET', '/api/v0/me/notifications', { body: DATA });
    const { root } = await render();
    const heads = [...root.querySelectorAll('thead th')].map((h) => h.textContent?.trim());
    expect(heads).toContain('New vulnerabilities');
    expect(boxes(rowOf(root, 0))).toHaveLength(4);
    expect(boxes(rowOf(root, 0))[3]!.getAttribute('aria-label')).toBe('New vulnerabilities: Alpha');
    expect(root.querySelector('tbody .badge')).toBeNull();
  });

  it('disables the column with a Business pill outside Business, and keeps the stored value', async () => {
    const stored = { ...ALL, newVulnerabilities: false };
    server.on('GET', '/api/v0/me/notifications', {
      body: {
        ...DATA,
        vulnerabilityAlerts: false,
        watches: [{ ...DATA.watches[0]!, events: stored }],
      },
    });
    server.on('PUT', WATCH_A, (r) => ({
      body: { watching: true, ...(r.body as object), ...READY, vulnerabilityAlerts: false },
    }));
    const { fixture, root } = await render();
    const box = boxes(rowOf(root, 0))[3]!;
    expect(box.disabled).toBe(true);
    expect(box.checked).toBe(false);
    expect(rowOf(root, 0).querySelector('.badge')?.textContent?.trim()).toBe('Business');
    boxes(rowOf(root, 0))[0]!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', WATCH_A).at(-1)?.body).toEqual({
      branches: 'main',
      events: { ...stored, gateFailed: false },
    });
  });

  it('keeps sending a stored false when another event changes', async () => {
    const stored = { ...ALL, newVulnerabilities: false };
    server.on('GET', '/api/v0/me/notifications', {
      body: { ...DATA, watches: [{ ...DATA.watches[0]!, events: stored }] },
    });
    server.on('PUT', WATCH_A, (r) => ({
      body: { watching: true, ...(r.body as object), ...READY },
    }));
    const { fixture, root } = await render();
    boxes(rowOf(root, 0))[1]!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', WATCH_A).at(-1)?.body).toEqual({
      branches: 'main',
      events: { ...stored, gateRecovered: false },
    });
  });
});

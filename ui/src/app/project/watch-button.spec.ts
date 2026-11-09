import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { WatchButton } from './watch-button';

const ID = '0190a6c2-0000-7000-8000-0000000000p1';
const URL = `/api/v0/projects/${ID}/watch`;
const READY = { emailReady: true, emailBlocker: null };
const ALL_EVENTS = { gateFailed: true, gateRecovered: true, analysisFailed: true };
const WATCHING = { watching: true, branches: 'main', events: ALL_EVENTS, ...READY };

describe('WatchButton', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [WatchButton],
      providers: [provideRouter([]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render() {
    const fixture = TestBed.createComponent(WatchButton);
    fixture.componentRef.setInput('projectId', ID);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const toggle = () => root.querySelector<HTMLButtonElement>('button.watch-toggle')!;
    const menu = () => root.querySelector<HTMLElement>('#watch-menu');
    return { fixture, root, toggle, menu };
  }
  const echo = () =>
    server.on('PUT', URL, (r) => ({ body: { watching: true, ...(r.body as object), ...READY } }));

  it('starts watching with the main branch and every event, and opens its menu', async () => {
    server.on('GET', URL, { body: { watching: false, ...READY } });
    echo();
    const { fixture, toggle, menu } = await render();
    expect(toggle().textContent?.trim()).toBe('Watch');
    expect(toggle().getAttribute('aria-expanded')).toBe('false');
    toggle().click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)[0]?.body).toEqual({
      branches: 'main',
      events: { ...ALL_EVENTS, newVulnerabilities: true },
    });
    expect(toggle().textContent?.trim()).toBe('Watching');
    expect(toggle().getAttribute('aria-expanded')).toBe('true');
    const radios = menu()!.querySelectorAll<HTMLInputElement>('input[type=radio]');
    expect([...radios].map((r) => r.checked)).toEqual([true, false]);
    const boxes = menu()!.querySelectorAll<HTMLInputElement>('input[type=checkbox]');
    expect([...boxes].map((b) => b.checked)).toEqual([true, true, true]);
  });

  it('opens the menu of an existing watch without saving, then saves each change', async () => {
    server.on('GET', URL, { body: WATCHING });
    echo();
    const { fixture, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)).toHaveLength(0);
    menu()!.querySelectorAll<HTMLInputElement>('input[type=radio]')[1]!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL).at(-1)?.body).toEqual({
      branches: 'all',
      events: ALL_EVENTS,
    });
    menu()!.querySelectorAll<HTMLInputElement>('input[type=checkbox]')[1]!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL).at(-1)?.body).toEqual({
      branches: 'all',
      events: { gateFailed: true, gateRecovered: false, analysisFailed: true },
    });
    // A click on a box inside the menu keeps it open.
    expect(menu()).not.toBeNull();
  });

  it('stops watching, closes the menu and gives the focus back to the button', async () => {
    server.on('GET', URL, { body: WATCHING });
    server.on('DELETE', URL, { status: 204 });
    const { fixture, root, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    const stop = [...root.querySelectorAll('button')].find(
      (b) => b.textContent?.trim() === 'Stop watching',
    )!;
    stop.click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', URL)).toHaveLength(1);
    expect(toggle().textContent?.trim()).toBe('Watch');
    expect(menu()).toBeNull();
    expect(document.activeElement).toBe(toggle());
  });

  it('closes on Escape', async () => {
    server.on('GET', URL, { body: WATCHING });
    const { fixture, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    menu()!.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await settle(fixture);
    expect(menu()).toBeNull();
    expect(toggle().getAttribute('aria-expanded')).toBe('false');
  });

  it('closes on a click outside it, leaving the focus where it went', async () => {
    server.on('GET', URL, { body: WATCHING });
    const outside = document.body.appendChild(document.createElement('button'));
    try {
      const { fixture, toggle, menu } = await render();
      toggle().click();
      await settle(fixture);
      menu()!.querySelector('legend')!.click();
      await settle(fixture);
      expect(menu()).not.toBeNull();
      outside.focus();
      outside.click();
      await settle(fixture);
      expect(menu()).toBeNull();
      expect(document.activeElement).toBe(outside);
    } finally {
      outside.remove();
    }
  });

  /** A reply held back until the test calls the returned `release`. */
  function holdPut(): { release: () => void } {
    const gates: (() => void)[] = [];
    server.on('PUT', URL, async (r) => {
      await new Promise<void>((resolve) => gates.push(resolve));
      return { body: { watching: true, ...(r.body as object), ...READY } };
    });
    return { release: () => gates.shift()?.() };
  }
  const radios = (menu: HTMLElement) => [
    ...menu.querySelectorAll<HTMLInputElement>('input[type=radio]'),
  ];
  const boxes = (menu: HTMLElement) => [
    ...menu.querySelectorAll<HTMLInputElement>('input[type=checkbox]'),
  ];
  const stopButton = (root: HTMLElement) =>
    [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Stop watching')!;

  it('puts a refused change back to the saved value and says why', async () => {
    server.on('GET', URL, { body: WATCHING });
    server.on('PUT', URL, { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    boxes(menu()!)[1]!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)).toHaveLength(1);
    expect(menu()!.querySelector('[role="alert"]')).not.toBeNull();
    expect(boxes(menu()!).map((b) => b.checked)).toEqual([true, true, true]);
    radios(menu()!)[1]!.click();
    await settle(fixture);
    expect(radios(menu()!).map((r) => r.checked)).toEqual([true, false]);
  });

  it('sends quick changes one after the other, the second building on the first', async () => {
    server.on('GET', URL, { body: WATCHING });
    const put = holdPut();
    const { fixture, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    radios(menu()!)[1]!.click();
    await settle(fixture);
    boxes(menu()!)[1]!.click();
    await settle(fixture);
    boxes(menu()!)[2]!.click();
    await settle(fixture);
    // One PUT at a time; the changes made meanwhile wait, and only the latest is sent.
    expect(server.requestsTo('PUT', URL)).toHaveLength(1);
    expect(radios(menu()!).map((r) => r.checked)).toEqual([false, true]);
    expect(boxes(menu()!).map((b) => b.checked)).toEqual([true, false, false]);
    put.release();
    await settle(fixture);
    const puts = server.requestsTo('PUT', URL);
    expect(puts).toHaveLength(2);
    expect(puts[1]?.body).toEqual({
      branches: 'all',
      events: { gateFailed: true, gateRecovered: false, analysisFailed: false },
    });
    put.release();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)).toHaveLength(2);
    expect(radios(menu()!).map((r) => r.checked)).toEqual([false, true]);
    expect(boxes(menu()!).map((b) => b.checked)).toEqual([true, false, false]);
    expect(toggle().getAttribute('aria-disabled')).toBeNull();
  });

  it('drops an answer about the project it showed before', async () => {
    const OTHER = '0190a6c2-0000-7000-8000-0000000000p2';
    server.on('GET', URL, { body: WATCHING });
    server.on('GET', `/api/v0/projects/${OTHER}/watch`, { body: { watching: false, ...READY } });
    const put = holdPut();
    const { fixture, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    radios(menu()!)[1]!.click();
    await settle(fixture);
    fixture.componentRef.setInput('projectId', OTHER);
    await settle(fixture);
    put.release();
    await settle(fixture);
    expect(toggle().textContent?.trim()).toBe('Watch');
    expect(menu()).toBeNull();
    expect(toggle().getAttribute('aria-disabled')).toBeNull();
  });

  it('opens nothing before the first answer, and asks again after a failed one', async () => {
    let answer: () => void = () => undefined;
    server.on('GET', URL, async () => {
      await new Promise<void>((resolve) => (answer = resolve));
      return { status: 500, body: problem(500, 'INTERNAL') };
    });
    const { fixture, toggle, menu } = await render();
    expect(toggle().getAttribute('aria-disabled')).toBe('true');
    toggle().click();
    await settle(fixture);
    expect(menu()).toBeNull();
    answer();
    await settle(fixture);
    expect(toggle().getAttribute('aria-disabled')).toBeNull();
    server.on('GET', URL, { body: WATCHING });
    toggle().click();
    await settle(fixture);
    expect(server.requestsTo('GET', URL)).toHaveLength(2);
    expect(radios(menu()!).map((r) => r.checked)).toEqual([true, false]);
    expect(menu()!.querySelector('[role="alert"]')).toBeNull();
  });

  it('marks the buttons busy while a change is on its way, and still closes the menu', async () => {
    server.on('GET', URL, { body: { watching: false, ...READY } });
    const put = holdPut();
    const { fixture, root, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    expect(toggle().getAttribute('aria-disabled')).toBe('true');
    expect(menu()).toBeNull();
    put.release();
    await settle(fixture);
    expect(toggle().getAttribute('aria-disabled')).toBeNull();
    boxes(menu()!)[0]!.click();
    await settle(fixture);
    expect(stopButton(root).getAttribute('aria-disabled')).toBe('true');
    stopButton(root).click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', URL)).toHaveLength(0);
    toggle().click();
    await settle(fixture);
    expect(menu()).toBeNull();
    put.release();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)).toHaveLength(2);
  });

  it('keeps the watch and says why when stopping fails', async () => {
    server.on('GET', URL, { body: WATCHING });
    server.on('DELETE', URL, { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    stopButton(root).click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', URL)).toHaveLength(1);
    expect(menu()!.querySelector('[role="alert"]')).not.toBeNull();
    expect(toggle().textContent?.trim()).toBe('Watching');
    expect(stopButton(root).getAttribute('aria-disabled')).toBeNull();
  });

  it.each([
    ['no_address', 'You have no email address: ask an administrator to add one.'],
    ['not_configured', "Email isn't set up on this server."],
    ['preference_off', 'Notification email is off in your settings.'],
  ])('says why no email would arrive (%s)', async (blocker, text) => {
    server.on('GET', URL, { body: { ...WATCHING, emailReady: false, emailBlocker: blocker } });
    const { fixture, toggle, menu } = await render();
    toggle().click();
    await settle(fixture);
    const hint = menu()!.querySelector('.hint');
    expect(hint?.textContent).toContain(text);
    expect(hint?.querySelector('a')?.getAttribute('href') ?? null).toBe(
      blocker === 'preference_off' ? '/settings/notifications' : null,
    );
  });
});

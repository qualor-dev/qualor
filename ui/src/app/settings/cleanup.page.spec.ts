import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  type CleanupDefaults,
  cleanupDefaults,
  FakeServer,
  me,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { CleanupPage } from './cleanup.page';

const URL = '/api/v0/system/cleanup';

function setup(answer: CleanupDefaults = cleanupDefaults(), admin = true): FakeServer {
  const server = new FakeServer();
  server.on('GET', URL, { body: answer });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(CleanupPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

const branches = (root: HTMLElement) => root.querySelector<HTMLSelectElement>('#cleanup-branches')!;
const mergeRequests = (root: HTMLElement) =>
  root.querySelector<HTMLSelectElement>('#cleanup-merge-requests')!;
const options = (select: HTMLSelectElement) =>
  [...select.options].map((o) => o.textContent?.trim());
const saveButton = (root: HTMLElement) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Save') ?? null;

function choose(select: HTMLSelectElement, value: string): void {
  select.value = value;
  select.dispatchEvent(new Event('change'));
}

async function save(fixture: { whenStable(): Promise<unknown> }, root: HTMLElement) {
  root.querySelector('form')!.dispatchEvent(new Event('submit'));
  await settle(fixture);
}

describe('CleanupPage', () => {
  it('offers off and 30 to 365 days for each rule, from the stored defaults', async () => {
    setup(cleanupDefaults({ mergeRequestsDays: 90 }));
    const { root } = await render();
    expect(root.querySelector('h2')?.textContent?.trim()).toBe('Cleanup');
    expect(root.querySelector('label[for="cleanup-branches"]')?.textContent?.trim()).toBe(
      'Branches not analysed for',
    );
    expect(root.querySelector('label[for="cleanup-merge-requests"]')?.textContent?.trim()).toBe(
      'Merge requests not analysed for',
    );
    const choices = ['Off', '30 days', '60 days', '90 days', '180 days', '365 days'];
    expect(options(branches(root))).toEqual(choices);
    expect(options(mergeRequests(root))).toEqual(choices);
    expect(branches(root).value).toBe('off');
    expect(mergeRequests(root).value).toBe('90');
    expect(saveButton(root)?.disabled).toBe(true);
  });

  it('keeps a stored number of days that is not in the list as its own choice', async () => {
    setup(cleanupDefaults({ branchesDays: 400 }));
    const { root } = await render();
    expect(options(branches(root))).toEqual([
      'Off',
      '30 days',
      '60 days',
      '90 days',
      '180 days',
      '365 days',
      '400 days',
    ]);
    expect(branches(root).value).toBe('400');
  });

  it('saves the rules: days, or null for off', async () => {
    const server = setup(cleanupDefaults({ mergeRequestsDays: 90 }));
    server.on('PUT', URL, (request) => ({ body: request.body }));
    const { fixture, root } = await render();
    choose(branches(root), '30');
    choose(mergeRequests(root), 'off');
    await settle(fixture);
    expect(saveButton(root)?.disabled).toBe(false);
    await save(fixture, root);
    expect(server.requestsTo('PUT', URL).map((r) => r.body)).toEqual([
      { branchesDays: 30, mergeRequestsDays: null },
    ]);
    expect(root.querySelector('[role=status]')?.textContent?.trim()).toBe(
      'The cleanup settings were saved.',
    );
    expect(branches(root).value).toBe('30');
    expect(saveButton(root)?.disabled).toBe(true);
  });

  it('says why a save failed by its code', async () => {
    const server = setup();
    server.on('PUT', URL, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.branchesDays', message: 'x' }]),
    });
    const { fixture, root } = await render();
    choose(branches(root), '60');
    await settle(fixture);
    await save(fixture, root);
    expect(root.querySelector('[role=alert]')?.textContent?.trim()).toBe(
      'Some values are not valid. Check the highlighted fields.',
    );
  });

  it('warns next to Save that deleted analyses cannot be recovered', async () => {
    setup();
    const { root } = await render();
    const actions = root.querySelector('.setting-actions')!;
    expect(actions.querySelector('#cleanup-warning')?.textContent?.trim()).toBe(
      'Deleted analyses cannot be recovered.',
    );
    expect(saveButton(root)?.closest('.setting-actions')).toBe(actions);
    expect(saveButton(root)?.getAttribute('aria-describedby')).toBe('cleanup-warning');
  });

  it('says what is always kept and that projects can set their own rules', async () => {
    setup();
    const { root } = await render();
    expect(root.querySelector('[data-line="kept"]')?.textContent?.replace(/\s+/g, ' ')).toContain(
      'The main branch of each project, and the branches its vulnerability monitoring tracks.',
    );
    expect(root.textContent).toContain('A project admin can set other rules for one project.');
  });

  it('asks the server nothing for someone who is not an instance admin', async () => {
    const server = setup(cleanupDefaults(), false);
    const { root } = await render();
    expect(root.textContent).toContain('Only instance administrators change the cleanup settings.');
    expect(server.requestsTo('GET', URL)).toEqual([]);
    expect(root.querySelector('select')).toBeNull();
  });

  it('says so when the read fails', async () => {
    const server = setup();
    server.on('GET', URL, { status: 403, body: problem(403, 'FORBIDDEN') });
    const { root } = await render();
    expect(root.querySelector('[role=alert]')?.textContent?.trim()).toBe(
      'You are not allowed to do this.',
    );
  });
});

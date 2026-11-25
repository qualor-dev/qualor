import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  ORG_ID,
  problem,
  type ProjectCleanup,
  projectCleanup,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import type { ProjectDto } from '../current-project';
import { CleanupPanel } from './cleanup-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const URL = `/api/v0/projects/${PROJECT}/cleanup`;

function project(permissions = ['project.read', 'project.settings']): ProjectDto {
  return {
    id: PROJECT,
    organizationId: ORG_ID,
    key: 'acme/payments',
    name: 'Payments',
    mainBranchName: 'main',
    qualityGateId: null,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    permissions,
  } as ProjectDto;
}

function setup(body: ProjectCleanup = projectCleanup()): FakeServer {
  const server = new FakeServer();
  server.on('GET', URL, { body });
  TestBed.configureTestingModule({ providers: [provideRouter([]), provideFakeServer(server)] });
  return server;
}

/** Answers a save with what it sent, over the stored state `base`. */
function answerSaves(server: FakeServer, base: ProjectCleanup = projectCleanup()): void {
  server.on('PUT', URL, (request) => ({
    body: projectCleanup({
      ...(request.body as Pick<ProjectCleanup, 'branchesDays' | 'mergeRequestsDays'>),
      keepBranches: (request.body as ProjectCleanup).keepBranches,
      serverDefaults: base.serverDefaults,
      alwaysKept: base.alwaysKept,
    }),
  }));
}

async function render(permissions?: string[]) {
  const fixture = TestBed.createComponent(CleanupPanel);
  fixture.componentRef.setInput('project', project(permissions));
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
const keepField = (root: HTMLElement) => root.querySelector<HTMLInputElement>('#cleanup-keep');
const keepChips = (root: HTMLElement) =>
  [...root.querySelectorAll('.keep-list .keep-text')].map((c) => c.textContent?.trim());
const keepError = (root: HTMLElement) =>
  root.querySelector('#cleanup-keep-error')?.textContent?.trim() ?? '';

function choose(select: HTMLSelectElement, value: string): void {
  select.value = value;
  select.dispatchEvent(new Event('change'));
}

/** Types `text` into the keep-pattern field and presses Enter. */
function addPattern(root: HTMLElement, text: string): void {
  const input = keepField(root)!;
  input.value = text;
  input.dispatchEvent(new Event('input'));
  input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', cancelable: true }));
}

describe('CleanupPanel', () => {
  it('offers the server default, off and 30 to 365 days for each rule', async () => {
    setup(projectCleanup({ serverDefaults: { branchesDays: null, mergeRequestsDays: 90 } }));
    const { root } = await render();
    const section = root.querySelector('section.card.panel')!;
    expect(section.id).toBe('cleanup');
    expect(section.querySelector('h2')?.textContent?.trim()).toBe('Cleanup');
    expect(root.querySelector('label[for="cleanup-branches"]')?.textContent?.trim()).toBe(
      'Branches not analysed for',
    );
    expect(root.querySelector('label[for="cleanup-merge-requests"]')?.textContent?.trim()).toBe(
      'Merge requests not analysed for',
    );
    const days = ['30 days', '60 days', '90 days', '180 days', '365 days'];
    expect(options(branches(root))).toEqual(['Server default (off)', 'Off', ...days]);
    expect(options(mergeRequests(root))).toEqual(['Server default (90 days)', 'Off', ...days]);
    expect(branches(root).value).toBe('default');
    expect(mergeRequests(root).value).toBe('default');
    expect(saveButton(root)?.disabled).toBe(true);
  });

  it("starts from the project's own values: off, a number of days, one outside the list", async () => {
    setup(projectCleanup({ branchesDays: 0, mergeRequestsDays: 45 }));
    const { root } = await render();
    expect(branches(root).value).toBe('off');
    expect(mergeRequests(root).value).toBe('45');
    // A value set through the API keeps its own choice, in order.
    expect(options(mergeRequests(root))).toEqual([
      'Server default (off)',
      'Off',
      '30 days',
      '45 days',
      '60 days',
      '90 days',
      '180 days',
      '365 days',
    ]);
  });

  it('lists what is always kept: the main branch and the tracked patterns', async () => {
    setup(
      projectCleanup({
        alwaysKept: { mainBranch: 'trunk', trackedPatterns: ['release/*', 'hotfix/*'] },
      }),
    );
    const { root } = await render();
    const kept = root.querySelector('[data-line="kept"]')!;
    expect(kept.querySelector('.setting-name')?.textContent?.trim()).toBe('Always kept');
    const lines = [...kept.querySelectorAll('.kept-list > li')];
    expect(lines.map((l) => l.textContent?.replace(/\s+/g, ' ').trim())).toEqual([
      'trunk the main branch',
      'release/* hotfix/* branches matching the vulnerability-monitoring branch patterns, even while monitoring is off',
    ]);
  });

  it('names the main branch of the project while it has no analysis, and no tracked line without patterns', async () => {
    setup(projectCleanup({ alwaysKept: { mainBranch: null, trackedPatterns: [] } }));
    const { root } = await render();
    const lines = [...root.querySelectorAll('[data-line="kept"] .kept-list > li')];
    expect(lines.map((l) => l.textContent?.replace(/\s+/g, ' ').trim())).toEqual([
      'main the main branch',
    ]);
  });

  it('saves the rules and the keep patterns', async () => {
    const server = setup(projectCleanup({ keepBranches: ['keep/*'] }));
    answerSaves(server);
    const { fixture, root } = await render();
    expect(keepChips(root)).toEqual(['keep/*']);
    choose(branches(root), '90');
    choose(mergeRequests(root), 'off');
    addPattern(root, '  demo/** ');
    await settle(fixture);
    expect(keepChips(root)).toEqual(['keep/*', 'demo/**']);
    expect(keepField(root)!.value).toBe('');
    expect(saveButton(root)?.disabled).toBe(false);
    saveButton(root)!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL).map((r) => r.body)).toEqual([
      { branchesDays: 90, mergeRequestsDays: 0, keepBranches: ['keep/*', 'demo/**'] },
    ]);
    expect(root.querySelector('[role=status]')?.textContent?.trim()).toBe(
      'The cleanup settings were saved.',
    );
    expect(branches(root).value).toBe('90');
    expect(saveButton(root)?.disabled).toBe(true);
  });

  it('sends null for the server default, and the pattern still in the field', async () => {
    const server = setup(projectCleanup({ branchesDays: 30, mergeRequestsDays: 0 }));
    answerSaves(server);
    const { fixture, root } = await render();
    choose(branches(root), 'default');
    choose(mergeRequests(root), 'default');
    const input = keepField(root)!;
    input.value = 'release/*';
    input.dispatchEvent(new Event('input'));
    await settle(fixture);
    saveButton(root)!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)[0]?.body).toEqual({
      branchesDays: null,
      mergeRequestsDays: null,
      keepBranches: ['release/*'],
    });
  });

  it('removes a keep pattern with its button', async () => {
    setup(projectCleanup({ keepBranches: ['keep/*', 'demo/**'] }));
    const { fixture, root } = await render();
    root
      .querySelector<HTMLButtonElement>('button[aria-label="Remove the pattern keep/*"]')!
      .click();
    await settle(fixture);
    expect(keepChips(root)).toEqual(['demo/**']);
    expect(saveButton(root)?.disabled).toBe(false);
  });

  it('refuses a pattern twice, one of 256 characters, a control character and a 21st', async () => {
    const server = setup();
    const { fixture, root } = await render();
    addPattern(root, 'keep/*');
    await settle(fixture);
    addPattern(root, 'keep/*');
    await settle(fixture);
    expect(keepError(root)).toBe('This pattern is already in the list.');
    expect(keepField(root)!.getAttribute('aria-invalid')).toBe('true');
    addPattern(root, 'a'.repeat(256));
    await settle(fixture);
    expect(keepError(root)).toBe('A pattern can have at most 255 characters.');
    addPattern(root, 'bad\u0007');
    await settle(fixture);
    expect(keepError(root)).toBe('A pattern cannot contain a control character.');
    for (let i = 2; i <= 20; i++) {
      addPattern(root, `p${i}/*`);
      await settle(fixture);
    }
    expect(keepChips(root)).toHaveLength(20);
    expect(keepError(root)).toBe('');
    addPattern(root, 'p21/*');
    await settle(fixture);
    expect(keepError(root)).toBe('Use at most 20 patterns.');
    expect(keepChips(root)).toHaveLength(20);
    // A refused pattern in the field stops Save before it sends anything.
    saveButton(root)!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)).toEqual([]);
  });

  it('shows a pattern the server refuses on the field, in its own words', async () => {
    const server = setup();
    server.on('PUT', URL, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.keepBranches', message: 'A pattern is not a valid branch glob' },
      ]),
    });
    const { fixture, root } = await render();
    addPattern(root, 'release/[');
    await settle(fixture);
    saveButton(root)!.click();
    await settle(fixture);
    expect(keepError(root)).toBe('One of the patterns is not a valid branch pattern.');
    expect(root.textContent).not.toContain('valid branch glob');
    expect(root.querySelector('.alert-error')).toBeNull();
  });

  it('says why a save failed by its code', async () => {
    const server = setup();
    server.on('PUT', URL, { status: 403, body: problem(403, 'FORBIDDEN') });
    const { fixture, root } = await render();
    choose(branches(root), '30');
    await settle(fixture);
    saveButton(root)!.click();
    await settle(fixture);
    expect(root.querySelector('[role=alert]')?.textContent?.trim()).toBe(
      'You are not allowed to do this.',
    );
  });

  it('warns next to Save that deleted analyses cannot be recovered', async () => {
    setup();
    const { root } = await render();
    const actions = root.querySelector('.setting-actions')!;
    const warning = actions.querySelector('#cleanup-warning');
    expect(warning?.textContent?.trim()).toBe('Deleted analyses cannot be recovered.');
    expect(saveButton(root)?.closest('.setting-actions')).toBe(actions);
    expect(saveButton(root)?.getAttribute('aria-describedby')).toBe('cleanup-warning');
  });

  it('is read-only without project.settings', async () => {
    const server = setup(
      projectCleanup({ branchesDays: 60, keepBranches: ['keep/*'], serverDefaults: {} }),
    );
    const { root } = await render(['project.read']);
    expect(server.requestsTo('GET', URL)).toHaveLength(1);
    expect(branches(root).disabled).toBe(true);
    expect(branches(root).value).toBe('60');
    expect(mergeRequests(root).disabled).toBe(true);
    expect(keepChips(root)).toEqual(['keep/*']);
    expect(keepField(root)).toBeNull();
    expect(root.querySelector('.keep-remove')).toBeNull();
    expect(saveButton(root)).toBeNull();
    expect(root.textContent).toContain('Only project admins change these settings.');
  });

  it('says so when the read fails, and reads again on Try again', async () => {
    const server = setup();
    server.on('GET', URL, { status: 503, body: problem(503, 'UNAVAILABLE') });
    const { fixture, root } = await render();
    expect(root.querySelector('[role=alert]')?.textContent).toContain('HTTP 503');
    server.on('GET', URL, { body: projectCleanup() });
    [...root.querySelectorAll('button')]
      .find((b) => b.textContent?.trim() === 'Try again')!
      .click();
    await settle(fixture);
    expect(root.querySelector('[role=alert]')).toBeNull();
    expect(branches(root).value).toBe('default');
  });
});

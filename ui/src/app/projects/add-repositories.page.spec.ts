import { type ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  type FakeReply,
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  type RecordedRequest,
} from '../../testing/fake-server';
import type { ItemOf, ResponseBody } from '../api/types';
import { SessionStore } from '../auth/session';
import { AddRepositoriesPage, type SetupRun } from './add-repositories.page';

type Connection = ItemOf<'/api/v0/scm-connections'>;
type Repository = ResponseBody<'/api/v0/scm-connections/{id}/repositories', 'get'>['items'][number];
type RunItem = SetupRun['items'][number];

const GITHUB_ID = '0190a6c2-0000-7000-8000-0000000000c1';
const GITLAB_ID = '0190a6c2-0000-7000-8000-0000000000c2';
const GHES_ID = '0190a6c2-0000-7000-8000-0000000000c3';
const RUN_ID = '0190a6c2-0000-7000-8000-0000000000e1';

function connection(
  id: string,
  provider: 'github' | 'gitlab',
  baseUrl: string,
  ciSetup: Connection['ciSetup'],
): Connection {
  return {
    id,
    organizationId: ORG_ID,
    provider,
    baseUrl,
    createdAt: '2026-10-01T00:00:00.000Z',
    github:
      provider === 'github'
        ? {
            appId: '12345',
            keyReadable: true,
            webhookSecretSet: false,
            webhookSecretReadable: false,
            webhookUrl: null,
          }
        : null,
    gitlab:
      provider === 'gitlab'
        ? {
            webhookSecretSet: false,
            webhookSecretReadable: false,
            webhookUrl: null,
            ciSetupAllowed: ciSetup.available,
          }
        : null,
    ciSetup,
  };
}

const GITHUB = connection(GITHUB_ID, 'github', 'https://api.github.com', {
  available: true,
  reason: null,
  missing: [],
});
const GITLAB = connection(GITLAB_ID, 'gitlab', 'https://gitlab.acme.example', {
  available: false,
  reason: 'not_allowed',
  missing: [],
});
const GHES = connection(GHES_ID, 'github', 'https://github.acme.example/api/v3', {
  available: false,
  reason: 'missing_permissions',
  missing: ['workflows_write', 'secrets_write'],
});

function repo(name: string, over: Partial<Repository> = {}): Repository {
  return {
    ref: name,
    name,
    defaultBranch: 'main',
    language: 'TypeScript',
    archived: false,
    project: null,
    ...over,
  };
}

const REPOS = [
  repo('acme/billing', { language: 'C#' }),
  repo('acme/legacy-portal', { language: 'Java', defaultBranch: 'master', archived: true }),
  repo('acme/payments-api', {
    project: { id: 'p-pay', key: 'acme/payments-api', state: 'mapped' },
  }),
  repo('acme/website', {
    language: 'Astro',
    project: { id: 'p-web', key: 'acme/website', state: 'adoptable' },
  }),
];

function item(ref: string, over: Partial<RunItem> = {}): RunItem {
  return {
    ref,
    name: ref,
    project: null,
    projectOutcome: 'pending',
    ciOutcome: 'pending',
    ciUrl: null,
    ciReason: null,
    snippet: null,
    token: null,
    error: null,
    ...over,
  };
}

function run(status: SetupRun['status'], items: RunItem[], ciSetup = true): SetupRun {
  return { id: RUN_ID, status, ciSetup, items };
}

const WORKFLOW = "name: qualor\non:\n  push:\njobs:\n  qualor:\n    if: a == 'b' || c\n";

/** Answers each reply once, in order, then the last one again and again. */
function sequence(replies: FakeReply[]): () => FakeReply {
  return () => (replies.length > 1 ? replies.shift()! : replies[0]!);
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

describe('AddRepositoriesPage', () => {
  let server: FakeServer;
  let current: ComponentFixture<AddRepositoriesPage> | null = null;

  beforeEach(() => {
    // Only the timers: the fake fetch and Angular's scheduling still run; polls wait for them.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    server = new FakeServer();
    server.on('GET', '/api/v0/organizations', {
      body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
    });
    server.on('GET', '/api/v0/scm-connections', { body: page([GITHUB, GITLAB, GHES]) });
    server.on('GET', /^\/api\/v0\/scm-connections\/[^/]+\/repositories$/, {
      body: { items: REPOS, hasMore: false },
    });
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me({ admin: true }));
  });

  afterEach(() => {
    current?.destroy();
    current = null;
    vi.useRealTimers();
    Reflect.deleteProperty(navigator, 'clipboard');
  });

  /** Lets the fake fetch answer and Angular render, without reaching the next poll. */
  async function flush(): Promise<void> {
    for (let i = 0; i < 12; i++) {
      await vi.advanceTimersByTimeAsync(0);
      current?.detectChanges();
    }
  }

  async function advance(ms: number): Promise<void> {
    await vi.advanceTimersByTimeAsync(ms);
    await flush();
  }

  async function render(inputs: { runId?: string; connection?: string } = {}) {
    const fixture = TestBed.createComponent(AddRepositoriesPage);
    current = fixture;
    if (inputs.runId !== undefined) fixture.componentRef.setInput('runId', inputs.runId);
    if (inputs.connection !== undefined) {
      fixture.componentRef.setInput('connection', inputs.connection);
    }
    await flush();
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  const repoRequests = (id: string): RecordedRequest[] =>
    server.requestsTo('GET', `/api/v0/scm-connections/${id}/repositories`);
  const radios = (root: HTMLElement) => [
    ...root.querySelectorAll<HTMLInputElement>('input[type="radio"][name="connection"]'),
  ];
  const rowOf = (root: HTMLElement, name: string) =>
    [...root.querySelectorAll<HTMLTableRowElement>('.repo-table tbody tr')].find(
      (tr) => text(tr.querySelector('.repo-name')) === name,
    );
  const boxOf = (root: HTMLElement, name: string) =>
    rowOf(root, name)?.querySelector<HTMLInputElement>('input[type="checkbox"]');
  const button = (root: HTMLElement, name: string) =>
    [...root.querySelectorAll<HTMLButtonElement>('button')].find((b) => text(b) === name);
  const tick = (box: HTMLInputElement | null | undefined) => {
    box!.click();
  };

  describe('picking', () => {
    it('lists the connections with their CI-setup state and why one is read only', async () => {
      const { root } = await render();
      expect(
        server.requestsTo('GET', '/api/v0/scm-connections')[0]?.query.get('organizationId'),
      ).toBe(ORG_ID);
      const rows = [...root.querySelectorAll('.conn')];
      expect(rows.map((r) => text(r.querySelector('.conn-name')))).toEqual([
        'GitHub',
        'GitLab',
        'GitHub Enterprise',
      ]);
      expect(rows.map((r) => text(r.querySelector('.conn-meta')))).toEqual([
        'github.com, App 12345',
        'gitlab.acme.example',
        'github.acme.example, App 12345',
      ]);
      expect(rows.map((r) => text(r.querySelector('.badge')))).toEqual([
        'CI setup available',
        'Read only',
        'Read only',
      ]);
      // The first connection is chosen; its repositories load.
      expect(radios(root)[0]?.checked).toBe(true);
      expect(repoRequests(GITHUB_ID)).toHaveLength(1);
      expect(repoRequests(GITHUB_ID)[0]?.query.get('page')).toBe('1');
      // A read-only connection says why, and its radio points at the note.
      const gitlabWhy = rows[1]?.querySelector('.req');
      expect(text(gitlabWhy)).toBe(
        'CI setup is off for this connection. Turn it on in Settings → GitLab.',
      );
      expect(gitlabWhy?.querySelector('a')?.getAttribute('href')).toBe('/settings/gitlab');
      expect(radios(root)[1]?.getAttribute('aria-describedby')).toBe(gitlabWhy?.id);
      const ghesWhy = rows[2]?.querySelector('.req');
      expect(text(ghesWhy)).toBe(
        'The GitHub App lacks the Workflows and Secrets permissions. How to grant them',
      );
      expect(ghesWhy?.querySelector('a')?.getAttribute('href')).toBe(
        '/docs/github#update-an-app-you-created-before',
      );
      expect(radios(root)[0]?.hasAttribute('aria-describedby')).toBe(false);
    });

    it('names only the missing permission, and the public address when it is missing', async () => {
      server.on('GET', '/api/v0/scm-connections', {
        body: page([
          connection(GITHUB_ID, 'github', 'https://api.github.com', {
            available: false,
            reason: 'missing_permissions',
            missing: ['secrets_write'],
          }),
          connection(GITLAB_ID, 'gitlab', 'https://gitlab.com', {
            available: false,
            reason: 'no_public_url',
            missing: [],
          }),
        ]),
      });
      const { root } = await render();
      const notes = [...root.querySelectorAll('.conn .req')].map(text);
      expect(notes[0]).toContain('The GitHub App lacks the Secrets permission.');
      expect(notes[1]).toContain(
        'Qualor needs its public address (QUALOR_PUBLIC_URL) to set up CI.',
      );
    });

    it('turns CI setup on where the connection allows it, and explains it per provider', async () => {
      const { root } = await render();
      const ci = root.querySelector<HTMLInputElement>('#ci-setup')!;
      expect(ci.getAttribute('role')).toBe('switch');
      expect(ci.checked).toBe(true);
      expect(ci.disabled).toBe(false);
      expect(text(root.querySelector('#ci-setup-help'))).toBe(
        "Qualor opens a merge request that adds the Qualor job, and stores the project's token as the Actions secret QUALOR_TOKEN. Nothing changes until you merge it.",
      );
      // GitLab, read only: the switch is off and disabled, and says what happens instead.
      radios(root)[1]!.click();
      await flush();
      expect(repoRequests(GITLAB_ID)).toHaveLength(1);
      expect(ci.checked).toBe(false);
      expect(ci.disabled).toBe(true);
      expect(text(root.querySelector('#ci-setup-help'))).toBe(
        'Not available for this connection. You get the CI job and a token to copy for each project.',
      );
    });

    it('marks mapped, adoptable and archived repositories, and only offers the selectable ones', async () => {
      const { root } = await render();
      expect(text(root.querySelector('.repo-table caption'))).toContain('Repositories of the');
      // Mapped: a disabled box, the project it was added as, tied to the box.
      const mapped = rowOf(root, 'acme/payments-api')!;
      const mappedBox = boxOf(root, 'acme/payments-api')!;
      expect(mappedBox.disabled).toBe(true);
      const state = mapped.querySelector('.state-cell')!;
      expect(text(state)).toBe('Added as acme/payments-api');
      expect(state.querySelector('a')?.getAttribute('href')).toBe('/projects/p-pay');
      expect(mappedBox.getAttribute('aria-describedby')).toBe(state.id);
      // Adoptable: selectable, labelled.
      expect(boxOf(root, 'acme/website')!.disabled).toBe(false);
      expect(text(rowOf(root, 'acme/website')!.querySelector('.state-cell'))).toBe(
        'Existing project Keeps its key and history',
      );
      // Archived: tagged, and not offered (an archived repository runs no CI).
      const archived = boxOf(root, 'acme/legacy-portal')!;
      expect(archived.disabled).toBe(true);
      expect(text(rowOf(root, 'acme/legacy-portal')!.querySelector('.state-cell'))).toContain(
        'Archived',
      );
      // Each box is labelled by its repository.
      const label = root.querySelector(`label[for="${boxOf(root, 'acme/billing')!.id}"]`);
      expect(text(label)).toBe('acme/billing');
      // The page's box selects the selectable rows only.
      tick(root.querySelector<HTMLInputElement>('#select-page'));
      await flush();
      expect(text(root.querySelector('.bar-count strong'))).toBe('2 selected');
      expect(boxOf(root, 'acme/billing')!.checked).toBe(true);
      expect(boxOf(root, 'acme/website')!.checked).toBe(true);
      expect(mappedBox.checked).toBe(false);
      expect(archived.checked).toBe(false);
      expect(rowOf(root, 'acme/billing')!.classList).toContain('is-selected');
    });

    it('keeps the count in a live region, and the page box indeterminate when some are selected', async () => {
      const { root } = await render();
      const count = root.querySelector('.bar-count')!;
      expect(count.getAttribute('role')).toBe('status');
      expect(text(count)).toBe('0 selected Up to 50 at a time');
      const add = root.querySelector<HTMLButtonElement>('.add-bar .btn-primary')!;
      expect(add.disabled).toBe(true);
      tick(boxOf(root, 'acme/billing'));
      await flush();
      expect(text(count)).toBe('1 selected Up to 50 at a time');
      expect(text(add)).toBe('Add 1 repository');
      expect(add.disabled).toBe(false);
      expect(root.querySelector<HTMLInputElement>('#select-page')!.indeterminate).toBe(true);
      button(root, 'Clear')!.click();
      await flush();
      expect(text(count)).toBe('0 selected Up to 50 at a time');
    });

    it('selects at most 50 repositories', async () => {
      const many = Array.from({ length: 60 }, (_, i) =>
        repo(`acme/r${String(i).padStart(2, '0')}`),
      );
      server.on('GET', /^\/api\/v0\/scm-connections\/[^/]+\/repositories$/, {
        body: { items: many, hasMore: false },
      });
      const { root } = await render();
      tick(root.querySelector<HTMLInputElement>('#select-page'));
      await flush();
      const boxes = [...root.querySelectorAll<HTMLInputElement>('.repo-table tbody input')];
      expect(boxes.filter((b) => b.checked)).toHaveLength(50);
      // The others cannot be ticked, and the bar says why.
      expect(boxes.slice(50).every((b) => b.disabled && !b.checked)).toBe(true);
      expect(text(root.querySelector('.bar-count'))).toBe(
        '50 selected: the most for one run. Add the rest in another run.',
      );
      // Unticking one frees a place.
      tick(boxes[0]);
      await flush();
      expect(boxes[55]!.disabled).toBe(false);
      expect(text(root.querySelector('.bar-count strong'))).toBe('49 selected');
    });

    it('filters on the server, keeps loading past empty filtered pages, and loads more', async () => {
      let calls = 0;
      server.on('GET', /^\/api\/v0\/scm-connections\/[^/]+\/repositories$/, (request) => {
        calls++;
        const filter = request.query.get('filter');
        const n = Number(request.query.get('page'));
        if (filter === null) return { body: { items: REPOS, hasMore: true } };
        // GitHub filters each page: pages 1 and 2 hold no match.
        if (n < 3) return { body: { items: [], hasMore: true } };
        return { body: { items: n === 3 ? [repo('acme/billing')] : [], hasMore: n < 4 } };
      });
      const { root } = await render();
      expect(calls).toBe(1);
      const filter = root.querySelector<HTMLInputElement>('#repo-filter')!;
      filter.value = 'bill';
      filter.dispatchEvent(new Event('input'));
      await flush();
      // The filter waits for typing to pause.
      expect(calls).toBe(1);
      await advance(300);
      const filtered = repoRequests(GITHUB_ID).slice(1);
      expect(filtered.map((r) => [r.query.get('filter'), r.query.get('page')])).toEqual([
        ['bill', '1'],
        ['bill', '2'],
        ['bill', '3'],
      ]);
      expect([...root.querySelectorAll('.repo-table tbody .repo-name')].map(text)).toEqual([
        'acme/billing',
      ]);
      button(root, 'Load more')!.click();
      await flush();
      expect(repoRequests(GITHUB_ID).at(-1)?.query.get('page')).toBe('4');
      expect(button(root, 'Load more')).toBeUndefined();
    });

    it('keeps the selection across filters, and drops it with another connection', async () => {
      const { root } = await render();
      tick(boxOf(root, 'acme/billing'));
      await flush();
      const filter = root.querySelector<HTMLInputElement>('#repo-filter')!;
      filter.value = 'web';
      filter.dispatchEvent(new Event('input'));
      await advance(300);
      expect(text(root.querySelector('.bar-count strong'))).toBe('1 selected');
      radios(root)[1]!.click();
      await flush();
      expect(text(root.querySelector('.bar-count strong'))).toBe('0 selected');
      expect(root.querySelector<HTMLInputElement>('#repo-filter')!.value).toBe('');
    });

    it('starts a run with the selected repositories and opens its progress', async () => {
      server.on('POST', '/api/v0/repository-setups', { status: 202, body: { id: RUN_ID } });
      const { root } = await render();
      tick(boxOf(root, 'acme/billing'));
      tick(boxOf(root, 'acme/website'));
      await flush();
      const add = root.querySelector<HTMLButtonElement>('.add-bar .btn-primary')!;
      expect(text(add)).toBe('Add 2 repositories');
      add.click();
      await flush();
      expect(server.requestsTo('POST', '/api/v0/repository-setups')[0]?.body).toEqual({
        organizationId: ORG_ID,
        connectionId: GITHUB_ID,
        repositories: ['acme/billing', 'acme/website'],
        ciSetup: true,
      });
      expect(TestBed.inject(Router).url).toBe(`/projects/add/${RUN_ID}?connection=${GITHUB_ID}`);
    });

    it('starts without CI setup when the switch is turned off', async () => {
      server.on('POST', '/api/v0/repository-setups', { status: 202, body: { id: RUN_ID } });
      const { root } = await render();
      root.querySelector<HTMLInputElement>('#ci-setup')!.click();
      tick(boxOf(root, 'acme/billing'));
      await flush();
      root.querySelector<HTMLButtonElement>('.add-bar .btn-primary')!.click();
      await flush();
      expect(server.requestsTo('POST', '/api/v0/repository-setups')[0]?.body).toMatchObject({
        ciSetup: false,
      });
    });

    it('reads the connection again and explains when CI setup became unavailable', async () => {
      server.on('POST', '/api/v0/repository-setups', {
        status: 422,
        body: problem(422, 'VALIDATION_FAILED', [
          { path: 'body.ciSetup', message: 'The GitHub App lacks the Workflows and Secrets' },
        ]),
      });
      const { root } = await render();
      tick(boxOf(root, 'acme/billing'));
      await flush();
      server.on('GET', '/api/v0/scm-connections', {
        body: page([
          connection(GITHUB_ID, 'github', 'https://api.github.com', {
            available: false,
            reason: 'missing_permissions',
            missing: ['workflows_write'],
          }),
        ]),
      });
      root.querySelector<HTMLButtonElement>('.add-bar .btn-primary')!.click();
      await flush();
      expect(server.requestsTo('GET', '/api/v0/scm-connections')).toHaveLength(2);
      const alert = root.querySelector('[role="alert"]');
      expect(text(alert)).toBe(
        'CI setup is no longer available for this connection, so nothing was started. The connection says why. Add the repositories without CI setup, or fix it and try again.',
      );
      const ci = root.querySelector<HTMLInputElement>('#ci-setup')!;
      expect(ci.checked).toBe(false);
      expect(ci.disabled).toBe(true);
      expect(text(root.querySelector('.conn .req'))).toContain('lacks the Workflows permission');
      // The selection stays, so the run can start again at once.
      expect(text(root.querySelector('.bar-count strong'))).toBe('1 selected');
      expect(TestBed.inject(Router).url).toBe('/');
    });

    it('says when the organization has no connection yet', async () => {
      server.on('GET', '/api/v0/scm-connections', { body: page([]) });
      const { root } = await render();
      expect(text(root.querySelector('.no-connection'))).toContain(
        'Connect GitHub or GitLab first',
      );
      expect(root.querySelector('.repo-table')).toBeNull();
    });
  });

  describe('a run', () => {
    const done = (ref: string, over: Partial<RunItem>) =>
      item(ref, {
        projectOutcome: 'created',
        project: { id: `p-${ref.replace('/', '-')}`, key: ref },
        ...over,
      });

    it('polls every 2 s while queued or running, honours Retry-After and stops when done', async () => {
      const answers = [
        { body: run('queued', [item('acme/billing'), item('acme/website')]) },
        {
          body: run('running', [
            done('acme/billing', {
              ciOutcome: 'merge_request',
              ciUrl: 'https://github.com/acme/billing/pull/7',
            }),
            item('acme/website'),
          ]),
          headers: { 'retry-after': '5' },
        },
        {
          body: run('done', [
            done('acme/billing', {
              ciOutcome: 'merge_request',
              ciUrl: 'https://github.com/acme/billing/pull/7',
            }),
            done('acme/website', {
              ciOutcome: 'merge_request',
              ciUrl: 'https://github.com/acme/website/pull/8',
            }),
          ]),
        },
      ];
      server.on('GET', `/api/v0/repository-setups/${RUN_ID}`, sequence(answers));
      const reads = () => server.requestsTo('GET', `/api/v0/repository-setups/${RUN_ID}`).length;
      const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
      expect(reads()).toBe(1);
      expect(text(root.querySelector('h1'))).toBe('Adding 2 repositories');
      expect(text(root.querySelector('.page-meta'))).toBe(
        'From GitHub, github.com CI setup with a merge request',
      );
      expect(text(root.querySelector('.panel-sub'))).toBe(
        'The run goes on if you leave this page.',
      );
      const list = root.querySelector('.run-list')!;
      expect(list.getAttribute('aria-busy')).toBe('true');
      expect(list.getAttribute('aria-live')).toBe('polite');
      expect(
        [...list.querySelectorAll('li')].map((li) => text(li.querySelector('.badge'))),
      ).toEqual(['Waiting', 'Waiting']);
      await advance(1999);
      expect(reads()).toBe(1);
      await advance(1);
      expect(reads()).toBe(2);
      const meter = root.querySelector('[role="progressbar"]')!;
      expect(meter.getAttribute('aria-valuenow')).toBe('1');
      expect(meter.getAttribute('aria-valuemax')).toBe('2');
      expect(meter.getAttribute('aria-valuetext')).toBe('1 of 2');
      expect(
        [...list.querySelectorAll('li')].map((li) => text(li.querySelector('.badge'))),
      ).toEqual(['Merge request opened', 'Setting up CI']);
      // Retry-After: 5 asks for a longer wait than the 2 s poll.
      await advance(4999);
      expect(reads()).toBe(2);
      await advance(1);
      expect(reads()).toBe(3);
      expect(text(root.querySelector('h1'))).toBe('2 repositories added');
      // Done: no more reads, and focus is on the results' heading.
      await advance(20_000);
      expect(reads()).toBe(3);
      expect(document.activeElement).toBe(root.querySelector('h1'));
    });

    it('backs off when a read fails, and offers to check again after four failures', async () => {
      let failing = true;
      server.on('GET', `/api/v0/repository-setups/${RUN_ID}`, () =>
        failing
          ? { status: 500, body: problem(500, 'INTERNAL') }
          : { body: run('running', [item('acme/billing')]) },
      );
      const reads = () => server.requestsTo('GET', `/api/v0/repository-setups/${RUN_ID}`).length;
      const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
      expect(reads()).toBe(1);
      // 2, 4 and 8 poll intervals after the 1st, 2nd and 3rd failure.
      await advance(3999);
      expect(reads()).toBe(1);
      await advance(1);
      expect(reads()).toBe(2);
      await advance(8000);
      expect(reads()).toBe(3);
      await advance(16_000);
      expect(reads()).toBe(4);
      await advance(60_000);
      expect(reads()).toBe(4);
      const alert = root.querySelector('[role="alert"]');
      expect(text(alert)).toContain('The progress could not be read.');
      failing = false;
      button(root, 'Check again')!.click();
      await flush();
      expect(reads()).toBe(5);
      expect(root.querySelector('[role="alert"]')).toBeNull();
      await advance(2000);
      expect(reads()).toBe(6);
    });

    it('stops polling when the page is left', async () => {
      server.on('GET', `/api/v0/repository-setups/${RUN_ID}`, {
        body: run('running', [item('acme/billing')]),
      });
      const { fixture } = await render({ runId: RUN_ID });
      fixture.destroy();
      current = null;
      await vi.advanceTimersByTimeAsync(10_000);
      expect(server.requestsTo('GET', `/api/v0/repository-setups/${RUN_ID}`)).toHaveLength(1);
    });

    it('shows each outcome: a merge request, a snippet with its one-time token, a failure', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined);
      Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
      const first = run('done', [
        done('acme/billing', {
          ciOutcome: 'merge_request',
          ciUrl: 'https://github.com/acme/billing/pull/7',
        }),
        done('acme/mobile-app', {
          ciOutcome: 'failed',
          error: { code: 'refused', message: 'The provider refused the change' },
        }),
        item('acme/website', {
          projectOutcome: 'adopted',
          project: { id: 'p-web', key: 'acme/website' },
          ciOutcome: 'snippet',
          ciReason: 'empty_repository',
          snippet: WORKFLOW,
          token: 'qlr_prj_secret',
        }),
        item('acme/gone', {
          projectOutcome: 'failed',
          ciOutcome: 'failed',
          error: { code: 'not_found', message: 'The repository was not found' },
        }),
      ]);
      server.on('GET', `/api/v0/repository-setups/${RUN_ID}`, { body: first });
      const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
      expect(text(root.querySelector('h1'))).toBe('3 repositories added');
      expect(text(root.querySelector('.page-meta'))).toBe(
        '1 merge request to merge 1 CI job to add 2 failed',
      );
      const cards = [...root.querySelectorAll('article.result')];
      expect(cards.map((c) => text(c.querySelector('h2')))).toEqual([
        'acme/billing',
        'acme/mobile-app',
        'acme/website',
        'acme/gone',
      ]);
      expect(cards[0]?.getAttribute('aria-labelledby')).toBe(cards[0]?.querySelector('h2')?.id);

      // The merge request: its link, opening the provider in a new tab.
      const [mr, failed, snippet, gone] = cards as HTMLElement[];
      expect(text(mr!.querySelector('.badge'))).toBe('Merge request opened');
      expect(text(mr!.querySelector('.result-sub'))).toBe('Project acme/billing created');
      expect(mr!.querySelector('.result-sub a')?.getAttribute('href')).toBe(
        '/projects/p-acme-billing',
      );
      const link = mr!.querySelector<HTMLAnchorElement>('a.mr-link')!;
      expect(link.getAttribute('href')).toBe('https://github.com/acme/billing/pull/7');
      expect(link.getAttribute('target')).toBe('_blank');
      expect(link.getAttribute('rel')).toBe('noopener noreferrer');
      expect(text(link)).toBe('Add Qualor code analysis #7');

      // A CI failure: its message, the project is ready, and a new run for it.
      expect(text(failed!.querySelector('.badge'))).toBe('CI setup failed');
      expect(text(failed!.querySelector('.fail-reason'))).toBe('GitHub refused the change.');
      expect(text(failed)).toContain('The project is ready.');
      expect(button(failed!, 'Try again')).toBeDefined();

      // The snippet: why, the token once with Copy, and the file with Copy.
      expect(text(snippet!.querySelector('.badge'))).toBe('CI job to add');
      expect(text(snippet!.querySelector('.result-sub'))).toBe(
        'Mapped to the existing project acme/website',
      );
      expect(text(snippet)).toContain('The repository has no commits yet');
      const token = snippet!.querySelector<HTMLInputElement>('q-secret-once input')!;
      expect(token.value).toBe('qlr_prj_secret');
      expect(token.readOnly).toBe(true);
      expect(text(snippet!.querySelector('q-secret-once'))).toContain(
        'Copy it now: it is shown only this once.',
      );
      expect(text(snippet!.querySelector('.code-head code'))).toBe('.github/workflows/qualor.yml');
      expect(snippet!.querySelector('pre.snippet')?.textContent).toBe(WORKFLOW);
      button(snippet!.querySelector('.code-head')!, 'Copy')!.click();
      await flush();
      expect(writeText).toHaveBeenCalledWith(WORKFLOW);
      expect(text(snippet!.querySelector('.code-head'))).toContain('Copied.');
      button(snippet!.querySelector('q-secret-once')!, 'Copy')!.click();
      await flush();
      expect(writeText).toHaveBeenCalledWith('qlr_prj_secret');

      // A repository without a project: why, and nothing to link.
      expect(text(gone!.querySelector('.badge'))).toBe('Failed');
      expect(text(gone!.querySelector('.result-sub'))).toBe('No project was created.');
      expect(text(gone!.querySelector('.fail-reason'))).toBe(
        'The repository was not found, or the connection cannot reach it.',
      );

      // Two secrets on one page never share an id; none takes the focus from the heading.
      const ids = [...root.querySelectorAll('[id]')].map((e) => e.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it('names the three GitHub permissions a refused change needs', async () => {
      server.on('GET', `/api/v0/repository-setups/${RUN_ID}`, {
        body: run('done', [
          done('acme/billing', {
            ciOutcome: 'failed',
            error: {
              code: 'permission',
              message: 'The GitHub App needs Contents, Workflows and Secrets write',
            },
          }),
        ]),
      });
      const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
      expect(text(root.querySelector('article.result .fail-reason'))).toBe(
        'The GitHub App needs the Contents, Workflows and Secrets permissions, read and write.',
      );
    });

    it('keeps a token it was given once, and points to the token settings when it has none', async () => {
      const answers = [
        run(
          'running',
          [
            done('acme/website', {
              ciOutcome: 'skipped',
              snippet: WORKFLOW,
              token: 'qlr_prj_once',
            }),
            item('acme/api'),
          ],
          false,
        ),
        run(
          'done',
          [
            done('acme/website', { ciOutcome: 'skipped', snippet: WORKFLOW, token: null }),
            done('acme/api', { ciOutcome: 'skipped', snippet: WORKFLOW, token: null }),
          ],
          false,
        ),
      ];
      server.on(
        'GET',
        `/api/v0/repository-setups/${RUN_ID}`,
        sequence(answers.map((body) => ({ body }))),
      );
      const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
      await advance(2000);
      const [website, api] = [...root.querySelectorAll<HTMLElement>('article.result')];
      expect(website!.querySelector<HTMLInputElement>('q-secret-once input')?.value).toBe(
        'qlr_prj_once',
      );
      expect(api!.querySelector('q-secret-once')).toBeNull();
      const pointer = api!.querySelector('.token-gone');
      expect(text(pointer)).toContain('The token is shown only once');
      expect(pointer?.querySelector('a')?.getAttribute('href')).toBe(
        '/projects/p-acme-api/settings#tokens',
      );
      expect(text(root.querySelector('.page-meta'))).toBe('2 CI jobs to add');
      // Nothing of the token reaches the browser's storage.
      expect(JSON.stringify({ ...localStorage })).not.toContain('qlr_prj_once');
    });

    it('starts a new run for a failed repository with Try again', async () => {
      server.on('GET', `/api/v0/repository-setups/${RUN_ID}`, {
        body: run('done', [
          done('acme/mobile-app', {
            ciOutcome: 'failed',
            error: { code: 'unavailable', message: 'The provider could not be reached' },
          }),
        ]),
      });
      server.on('POST', '/api/v0/repository-setups', {
        status: 202,
        body: { id: '0190a6c2-0000-7000-8000-0000000000e2' },
      });
      const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
      button(root, 'Try again')!.click();
      await flush();
      expect(server.requestsTo('POST', '/api/v0/repository-setups')[0]?.body).toEqual({
        organizationId: ORG_ID,
        connectionId: GITHUB_ID,
        repositories: ['acme/mobile-app'],
        ciSetup: true,
      });
      expect(TestBed.inject(Router).url).toBe(
        `/projects/add/0190a6c2-0000-7000-8000-0000000000e2?connection=${GITHUB_ID}`,
      );
    });

    describe('one-time tokens across runs', () => {
      const RUN_B = '0190a6c2-0000-7000-8000-0000000000e2';
      const TOKEN = 'qlr_prj_only_once';
      /** Run A: a snippet whose token the first read reveals (later reads have none), and a failure. */
      function runA(token: string | null) {
        return run('done', [
          done('acme/website', { ciOutcome: 'snippet', snippet: WORKFLOW, token }),
          done('acme/mobile-app', {
            ciOutcome: 'failed',
            error: { code: 'unavailable', message: 'The provider could not be reached' },
          }),
        ]);
      }
      beforeEach(() => {
        server.on(
          'GET',
          `/api/v0/repository-setups/${RUN_ID}`,
          sequence([{ body: runA(TOKEN) }, { body: runA(null) }]),
        );
        server.on('GET', `/api/v0/repository-setups/${RUN_B}`, {
          body: run('done', [done('acme/mobile-app', { ciOutcome: 'merge_request', ciUrl: null })]),
        });
        server.on('POST', '/api/v0/repository-setups', { status: 202, body: { id: RUN_B } });
      });
      const posts = () => server.requestsTo('POST', '/api/v0/repository-setups');
      const tokenField = (root: HTMLElement) =>
        root.querySelector<HTMLInputElement>('q-secret-once input');

      it('asks before Try again while a token of the run is not copied, and Stay keeps the page', async () => {
        const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
        const retry = button(root, 'Try again')!;
        retry.click();
        await flush();
        expect(posts()).toHaveLength(0);
        const ask = root.querySelector('.retry-ask');
        expect(text(ask?.querySelector('p'))).toBe(
          'Copy the tokens on this page first: they are shown only once.',
        );
        expect(document.activeElement).toBe(ask?.querySelector('p'));
        button(root, 'Stay')!.click();
        await flush();
        expect(root.querySelector('.retry-ask')).toBeNull();
        expect(posts()).toHaveLength(0);
        expect(document.activeElement).toBe(button(root, 'Try again'));
        expect(tokenField(root)?.value).toBe(TOKEN);
        // Asked again, the person goes on anyway.
        button(root, 'Try again')!.click();
        await flush();
        button(root, 'Try again anyway')!.click();
        await flush();
        expect(posts()[0]?.body).toMatchObject({ repositories: ['acme/mobile-app'] });
        expect(TestBed.inject(Router).url).toBe(`/projects/add/${RUN_B}?connection=${GITHUB_ID}`);
      });

      it('does not ask once the token was copied with Copy', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
        const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
        button(root.querySelector('q-secret-once')!, 'Copy')!.click();
        await flush();
        button(root, 'Try again')!.click();
        await flush();
        expect(root.querySelector('.retry-ask')).toBeNull();
        expect(posts()).toHaveLength(1);
      });

      it('does not ask once the token was copied from its field (selected and copied)', async () => {
        const { root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
        tokenField(root)!.dispatchEvent(new Event('copy', { bubbles: true }));
        await flush();
        button(root, 'Try again')!.click();
        await flush();
        expect(root.querySelector('.retry-ask')).toBeNull();
        expect(posts()).toHaveLength(1);
      });

      it('shows a run its tokens again after another run and on a new page, and stores none', async () => {
        const { fixture, root } = await render({ runId: RUN_ID, connection: GITHUB_ID });
        expect(tokenField(root)?.value).toBe(TOKEN);
        // Try again's run, on the same page (the router reuses it for /projects/add/<run>).
        fixture.componentRef.setInput('runId', RUN_B);
        await flush();
        expect(text(root.querySelector('h1'))).toBe('1 repository added');
        // Back to the first run: the server reveals the token no more, the page still has it.
        fixture.componentRef.setInput('runId', RUN_ID);
        await flush();
        expect(server.requestsTo('GET', `/api/v0/repository-setups/${RUN_ID}`)).toHaveLength(2);
        expect(tokenField(root)?.value).toBe(TOKEN);
        expect(root.querySelector('.token-gone')).toBeNull();
        // Another visit in the same browser page (left and opened again): still there.
        fixture.destroy();
        current = null;
        const again = await render({ runId: RUN_ID, connection: GITHUB_ID });
        expect(tokenField(again.root)?.value).toBe(TOKEN);
        // Kept in memory only.
        const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage });
        expect(stored).not.toContain(TOKEN);
      });

      it('shows another user signed in on the same page none of the tokens', async () => {
        const first = await render({ runId: RUN_ID, connection: GITHUB_ID });
        expect(tokenField(first.root)?.value).toBe(TOKEN);
        first.fixture.destroy();
        current = null;
        TestBed.inject(SessionStore).set({
          ...me({ admin: true }),
          user: { ...me({ admin: true }).user, id: '0190a6c2-0000-7000-8000-00000000000b' },
        });
        const second = await render({ runId: RUN_ID, connection: GITHUB_ID });
        expect(tokenField(second.root)).toBeNull();
        expect(second.root.querySelector('.token-gone')).not.toBeNull();
      });
    });

    it('says the C# repository needs its build command checked', async () => {
      server.on('GET', `/api/v0/repository-setups/${RUN_ID}`, {
        body: run('done', [
          done('acme/billing', {
            ciOutcome: 'merge_request',
            ciUrl: 'https://gitlab.acme.example/acme/billing/-/merge_requests/3',
          }),
        ]),
      });
      // The navigation that started the run hands over the repositories GitHub calls C#.
      const navigated = TestBed.inject(Router).navigate(['/projects/add', RUN_ID], {
        state: { csharp: ['acme/billing'] },
      });
      await flush();
      await navigated;
      const { root } = await render({ runId: RUN_ID, connection: GITLAB_ID });
      expect(text(root.querySelector('a.mr-link'))).toBe('Add Qualor code analysis !3');
      expect(text(root.querySelector('.result .note'))).toContain(
        'check the build command in the merge request before you merge it',
      );
    });
  });
});

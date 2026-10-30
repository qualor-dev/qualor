import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  dependency,
  FakeDependencies,
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
  VIEWER_PROJECT_PERMISSIONS,
} from '../../../testing/fake-server';
import { SessionStore } from '../../auth/session';
import type { Branch } from '../branches';
import { DependenciesPage } from './dependencies.page';

const PROJECT = 'p1';
const ROUTE = `/api/v0/projects/${PROJECT}/dependencies`;
const MAIN_ID = '0190a6c2-0000-7000-8000-0000000000b1';
const DEV_ID = '0190a6c2-0000-7000-8000-0000000000b2';
const MR_ID = '0190a6c2-0000-7000-8000-0000000000b3';
const MAIN: Branch = {
  id: MAIN_ID,
  projectId: PROJECT,
  kind: 'branch',
  name: 'main',
  isMain: true,
  mrSourceBranch: null,
  mrTargetBranch: null,
  mrTitle: null,
  mrUrl: null,
  lastAnalysisId: 'a1',
  lastAnalyzedAt: '2026-09-15T09:00:00.000Z',
  gateStatus: 'failed',
  measures: {},
};
const DEVELOP: Branch = { ...MAIN, id: DEV_ID, name: 'develop', isMain: false };
const MR: Branch = {
  ...MAIN,
  id: MR_ID,
  kind: 'merge_request',
  name: '42',
  isMain: false,
  mrSourceBranch: 'feature/refund-limits',
  mrTargetBranch: 'main',
};

const VERSION_ID = '0190a6c2-0000-7000-8000-0000000000c1';
const OLD_VERSION_ID = '0190a6c2-0000-7000-8000-0000000000c2';
const VERSIONS = [
  version({ id: VERSION_ID, label: '2.1.0', tracked: true }),
  version({ id: OLD_VERSION_ID, label: '1.9.0', tracked: false }),
];

function version(over: { id: string; label: string; tracked: boolean }) {
  return {
    source: 'tag' as const,
    tag: `v${over.label}`,
    analyzedAt: '2026-09-10T09:00:00.000Z',
    tracking: 'auto' as const,
    trackingReason: 'newest_in_line' as const,
    prerelease: false,
    packages: 7,
    ...over,
  };
}

const XSS = 'left-pad<img src=x onerror="alert(1)">';
const ROWS = [
  dependency({ verdict: 'allowed' }),
  dependency({
    name: 'gpl-money',
    version: '2.1.0',
    line: 40,
    licenses: ['GPL-3.0-only'],
    direct: false,
    verdict: 'forbidden',
  }),
  dependency({
    name: 'dual-lib',
    version: '1.0.0',
    line: 57,
    licenses: ['MIT OR GPL-2.0-or-later', 'ISC'],
    direct: null,
    verdict: 'allowed',
  }),
  dependency({
    ecosystem: 'pnpm',
    path: 'web/pnpm-lock.yaml',
    line: null,
    name: XSS,
    version: '0.3.1',
    licenses: [],
    direct: true,
    verdict: 'unknown',
  }),
];

describe('DependenciesPage (6M §8)', () => {
  let server: FakeServer;
  let fake: FakeDependencies;

  beforeEach(() => {
    server = new FakeServer();
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([MAIN, DEVELOP, MR]) });
    server.on('GET', `/api/v0/projects/${PROJECT}/versions`, { body: page(VERSIONS) });
    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: { id: PROJECT, organizationId: ORG_ID, permissions: [...VIEWER_PROJECT_PERMISSIONS] },
    });
    fake = FakeDependencies.install(server, { rows: ROWS });
    TestBed.configureTestingModule({
      imports: [DependenciesPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render(url = '/') {
    await TestBed.inject(Router).navigateByUrl(url);
    const fixture = TestBed.createComponent(DependenciesPage);
    fixture.componentRef.setInput('projectId', PROJECT);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();
  const lastQuery = () => server.requestsTo('GET', ROUTE).at(-1)?.query;
  const headers = (root: HTMLElement) => [...root.querySelectorAll('thead th')].map(text);
  const cells = (root: HTMLElement, row: number) =>
    [...(root.querySelectorAll('tbody tr')[row]?.querySelectorAll('td, th') ?? [])].map(text);

  function choose(root: HTMLElement, id: string, value: string): void {
    const select = root.querySelector<HTMLSelectElement>(`#${id}`)!;
    select.value = value;
    select.dispatchEvent(new Event('change'));
  }

  it("lists the main branch's inventory with its summary, and shows server text as text", async () => {
    const { root } = await render();
    const query = lastQuery();
    expect(query?.has('branch')).toBe(false);
    expect(query?.has('mr')).toBe(false);
    expect(query?.get('page')).toBe('1');
    expect(query?.get('pageSize')).toBe('50');
    expect(root.querySelector<HTMLSelectElement>('#deps-branch')?.value).toBe(MAIN_ID);

    const summary = root.querySelector('.deps-summary');
    expect(text(summary)).toContain('3 of 4 packages have a known licence');
    expect(summary?.querySelector('a')?.getAttribute('href')).toBe('/docs/dependency-licenses');

    expect(headers(root)).toEqual([
      'Package',
      'Version',
      'Ecosystem',
      'Lockfile',
      'Licences',
      'Dependency',
    ]);
    expect(cells(root, 0)).toEqual([
      'express',
      '4.19.2',
      'npm',
      'package-lock.json:12',
      'MIT',
      'Direct',
    ]);
    expect(cells(root, 1)).toEqual([
      'gpl-money',
      '2.1.0',
      'npm',
      'package-lock.json:40',
      'GPL-3.0-only',
      'Transitive',
    ]);
    // Each licence string is a chip of its own.
    expect(
      [...(root.querySelectorAll('tbody tr')[2]?.querySelectorAll('.chip') ?? [])].map(text),
    ).toEqual(['MIT OR GPL-2.0-or-later', 'ISC']);
    expect(cells(root, 2)?.[5]).toBe('–');
    expect(cells(root, 3)?.slice(3, 5)).toEqual(['web/pnpm-lock.yaml', 'Unknown']);
    // One page: its range, and no Previous or Next.
    expect(text(root.querySelector('.pager-range'))).toBe('1–4 of 4');
    expect(root.querySelector('.pager-buttons')).toBeNull();
    // The package name carries HTML: it stays text.
    expect(text(root.querySelectorAll('tbody tr')[3]?.querySelector('th'))).toBe(XSS);
    expect(root.querySelector('tbody img')).toBeNull();
  });

  it('links each lockfile to the Code tab at its line, or at the file when it has none', async () => {
    const { root } = await render();
    const links = [...root.querySelectorAll<HTMLAnchorElement>('tbody td a')];
    expect(links[0]?.getAttribute('href')).toBe(
      `/projects/${PROJECT}/code/file?branch=${MAIN_ID}&path=package-lock.json#L12`,
    );
    expect(links[3]?.getAttribute('href')).toBe(
      `/projects/${PROJECT}/code/file?branch=${MAIN_ID}&path=web%2Fpnpm-lock.yaml`,
    );
  });

  it('shows no Policy column and no Forbidden filter without verdicts', async () => {
    const { root } = await render();
    expect(headers(root)).not.toContain('Policy');
    expect(root.querySelector('#deps-forbidden')).toBeNull();
    expect(root.querySelector('.badge-failed')).toBeNull();
  });

  it('adds the Policy column and the Forbidden filter with verdicts, and links a forbidden row to its issue', async () => {
    fake.verdicts = true;
    const { fixture, root } = await render();
    expect(headers(root).at(-1)).toBe('Policy');
    expect(cells(root, 0)?.at(-1)).toBe('Allowed');
    expect(cells(root, 3)?.at(-1)).toBe('Unknown');
    const forbidden = root.querySelectorAll('tbody tr')[1]!;
    expect(text(forbidden.querySelector('.badge-failed'))).toBe('Forbidden');
    const issues = forbidden.querySelector<HTMLAnchorElement>('a[href*="/issues"]');
    expect(issues?.getAttribute('aria-label')).toBe('Issues of gpl-money 2.1.0');
    expect(issues?.getAttribute('href')).toBe(
      `/projects/${PROJECT}/issues?branch=${MAIN_ID}&rule=license:forbidden&q=gpl-money`,
    );

    root.querySelector<HTMLInputElement>('#deps-forbidden')!.click();
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?verdict=forbidden');
    expect(lastQuery()?.get('verdict')).toBe('forbidden');
    expect([...root.querySelectorAll('tbody th')].map(text)).toEqual(['gpl-money']);
  });

  it('offers no Forbidden filter, and lists every row, while the answer has no verdicts', async () => {
    const { root } = await render('/?verdict=forbidden');
    expect(root.querySelector('#deps-forbidden')).toBeNull();
    expect(root.querySelectorAll('tbody tr')).toHaveLength(4);
  });

  it('filters by licence, group, unknown and direct through the URL', async () => {
    const { fixture, root } = await render();
    const licenses = [...root.querySelectorAll<HTMLOptionElement>('#deps-license option')];
    expect(licenses.map((o) => text(o))).toEqual([
      'All licences',
      'GPL-3.0-only (1)',
      'ISC (1)',
      'MIT (1)',
      'MIT OR GPL-2.0-or-later (1)',
    ]);
    choose(root, 'deps-license', 'MIT');
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?license=MIT');
    expect(lastQuery()?.get('license')).toBe('MIT');
    expect([...root.querySelectorAll('tbody th')].map(text)).toEqual(['express']);

    choose(root, 'deps-license', '');
    await settle(fixture);
    choose(root, 'deps-group', 'strong-copyleft');
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?group=strong-copyleft');
    expect(lastQuery()?.get('group')).toBe('strong-copyleft');
    expect(
      [...root.querySelectorAll<HTMLOptionElement>('#deps-group option')].map((o) => text(o)),
    ).toEqual([
      'All groups',
      'Network copyleft',
      'Strong copyleft',
      'Weak copyleft',
      'Non-commercial or source-available',
    ]);

    choose(root, 'deps-group', '');
    await settle(fixture);
    root.querySelector<HTMLInputElement>('#deps-unknown')!.click();
    await settle(fixture);
    expect(lastQuery()?.get('unknown')).toBe('true');
    expect([...root.querySelectorAll('tbody th')].map(text)).toEqual([XSS]);

    root.querySelector<HTMLInputElement>('#deps-unknown')!.click();
    await settle(fixture);
    root.querySelector<HTMLInputElement>('#deps-direct')!.click();
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?direct=true');
    expect(lastQuery()?.get('direct')).toBe('true');
    expect(lastQuery()?.has('unknown')).toBe(false);
  });

  it('keeps a licence the URL names in the list when it is not among the most frequent', async () => {
    const { root } = await render('/?license=WTFPL');
    const select = root.querySelector<HTMLSelectElement>('#deps-license')!;
    expect(select.value).toBe('WTFPL');
    expect(lastQuery()?.get('license')).toBe('WTFPL');
    expect(text(root.querySelector('tbody'))).toContain('No package matches.');
  });

  it('searches by package name and ecosystem on submit, and refuses an ecosystem the API would', async () => {
    const { fixture, root } = await render();
    const search = root.querySelector<HTMLInputElement>('#deps-search')!;
    const ecosystem = root.querySelector<HTMLInputElement>('#deps-ecosystem')!;
    // The ecosystems seen in this branch's rows are suggested.
    expect(
      [...root.querySelectorAll<HTMLOptionElement>('#deps-ecosystems option')].map((o) => o.value),
    ).toEqual(expect.arrayContaining(['npm', 'pnpm']));
    search.value = 'gpl';
    search.dispatchEvent(new Event('input'));
    ecosystem.value = 'npm';
    ecosystem.dispatchEvent(new Event('input'));
    root.querySelector('form[role="search"]')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?q=gpl&ecosystem=npm');
    expect(lastQuery()?.get('q')).toBe('gpl');
    expect(lastQuery()?.get('ecosystem')).toBe('npm');

    const sent = server.requestsTo('GET', ROUTE).length;
    ecosystem.value = 'Not An Ecosystem';
    ecosystem.dispatchEvent(new Event('input'));
    root.querySelector('form[role="search"]')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('GET', ROUTE)).toHaveLength(sent);
    expect(ecosystem.getAttribute('aria-invalid')).toBe('true');
    expect(text(root.querySelector('#deps-ecosystem-error'))).toBe(
      'An ecosystem is a lowercase name such as npm or gomod.',
    );
  });

  it('asks for a merge request by its number and a branch by its name', async () => {
    const { fixture, root } = await render();
    expect(
      [...root.querySelectorAll<HTMLOptionElement>('#deps-branch > option')].map((o) => text(o)),
    ).toEqual(['main', 'develop', '!42 feature/refund-limits → main']);
    choose(root, 'deps-branch', MR_ID);
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe(`/?branch=${MR_ID}`);
    expect(lastQuery()?.get('mr')).toBe('42');
    expect(lastQuery()?.has('branch')).toBe(false);
    expect(root.querySelector('tbody a')?.getAttribute('href')).toContain(`branch=${MR_ID}`);

    choose(root, 'deps-branch', DEV_ID);
    await settle(fixture);
    expect(lastQuery()?.get('branch')).toBe('develop');
    expect(lastQuery()?.has('mr')).toBe(false);
  });

  it('lists the released versions after the branches, tracked ones marked', async () => {
    const { root } = await render();
    const group = root.querySelector<HTMLOptGroupElement>('#deps-branch optgroup');
    expect(group?.label).toBe('Versions');
    expect([...group!.querySelectorAll('option')].map((o) => text(o))).toEqual([
      '2.1.0 (tracked)',
      '1.9.0',
    ]);
    expect(
      server.requestsTo('GET', `/api/v0/projects/${PROJECT}/versions`).at(-1)?.query.get('limit'),
    ).toBe('100');
  });

  it('shows no Versions group when the project has no versions', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/versions`, { body: page([]) });
    const { root } = await render();
    expect(root.querySelector('#deps-branch optgroup')).toBeNull();
  });

  it('asks for a version by its id, keeps the filters and clears the branch', async () => {
    const { fixture, root } = await render(`/?branch=${DEV_ID}`);
    choose(root, 'deps-branch', `version:${VERSION_ID}`);
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe(`/?version=${VERSION_ID}`);
    expect(lastQuery()?.get('version')).toBe(VERSION_ID);
    expect(lastQuery()?.has('branch')).toBe(false);
    expect(lastQuery()?.has('mr')).toBe(false);
    expect(root.querySelector<HTMLSelectElement>('#deps-branch')?.value).toBe(
      `version:${VERSION_ID}`,
    );

    choose(root, 'deps-group', 'weak-copyleft');
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe(`/?version=${VERSION_ID}&group=weak-copyleft`);
    expect(lastQuery()?.get('version')).toBe(VERSION_ID);

    choose(root, 'deps-branch', DEV_ID);
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe(`/?branch=${DEV_ID}&group=weak-copyleft`);
    expect(lastQuery()?.has('version')).toBe(false);
    expect(lastQuery()?.get('branch')).toBe('develop');
  });

  it('falls back to the main branch for a version that is not a UUID', async () => {
    const { root } = await render('/?version=not-a-uuid');
    expect(lastQuery()?.has('version')).toBe(false);
    expect(root.querySelector<HTMLSelectElement>('#deps-branch')?.value).toBe(MAIN_ID);
  });

  it('still asks for a version past the first page, and says when it is not found', async () => {
    const unknown = '0190a6c2-0000-7000-8000-0000000000c9';
    server.on('GET', ROUTE, { status: 404, body: problem(404, 'NOT_FOUND') });
    const { root } = await render(`/?version=${unknown}`);
    expect(lastQuery()?.get('version')).toBe(unknown);
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'This item does not exist, or you cannot see it.',
    );
  });

  it('pages through a long inventory', async () => {
    fake.rows = Array.from({ length: 120 }, (_, i) =>
      dependency({ name: `pkg-${String(i).padStart(3, '0')}`, line: i + 1 }),
    );
    const { fixture, root } = await render();
    const pager = root.querySelector('nav[aria-label="Pages"]')!;
    expect(text(pager.querySelector('.pager-range'))).toBe('1–50 of 120');
    const button = (name: string) =>
      [...pager.querySelectorAll<HTMLButtonElement>('button')].find((b) => text(b) === name)!;
    expect(button('Previous').disabled).toBe(true);
    button('Next').click();
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?page=2');
    expect(lastQuery()?.get('page')).toBe('2');
    expect(text(root.querySelector('tbody th'))).toBe('pkg-050');
    expect(text(root.querySelector('.pager-range'))).toBe('51–100 of 120');
    button('Next').click();
    await settle(fixture);
    expect(text(root.querySelector('.pager-range'))).toBe('101–120 of 120');
    expect(button('Next').disabled).toBe(true);
  });

  it('goes back to the first page when a filter changes', async () => {
    const { fixture, root } = await render('/?page=3');
    choose(root, 'deps-group', 'weak-copyleft');
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?group=weak-copyleft');
  });

  it('says when no scan has recorded an inventory yet, with no table', async () => {
    fake.inventory = false;
    const { root } = await render();
    expect(text(root.querySelector('.empty-state'))).toBe(
      'No dependency inventory yet. Scans with Qualor 0.9 or later record one.',
    );
    expect(root.querySelector('table')).toBeNull();
    expect(root.querySelector('.deps-summary')).toBeNull();
  });

  it('says why a version has no dependency list, with no table', async () => {
    fake.inventory = false;
    const { root } = await render(`/?version=${VERSION_ID}`);
    expect(lastQuery()?.get('version')).toBe(VERSION_ID);
    expect(text(root.querySelector('.empty-state'))).toBe(
      'No dependency list for this version. The tag scan found no lockfile Trivy reads, or Trivy did not run.',
    );
    expect(root.querySelector('table')).toBeNull();
  });

  it('asks for the main branch at once, and a project never analysed says it has no inventory', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([]) });
    fake.inventory = false;
    const { root } = await render();
    expect(server.requestsTo('GET', ROUTE)).toHaveLength(1);
    expect(root.querySelector('[role="alert"]')).toBeNull();
    expect(text(root.querySelector('.empty-state'))).toBe(
      'No dependency inventory yet. Scans with Qualor 0.9 or later record one.',
    );
  });

  it('says why the inventory could not be loaded', async () => {
    server.on('GET', ROUTE, { status: 404, body: problem(404, 'NOT_FOUND') });
    const { root } = await render();
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'This item does not exist, or you cannot see it.',
    );
  });
});

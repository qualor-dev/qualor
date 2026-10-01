import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  FakeServer,
  me,
  MEMBER_PROJECT_PERMISSIONS,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import { SessionStore } from '../../auth/session';
import { CodePage } from './code.page';
import type { TreeItem } from './tree';

const PROJECT = 'p1';
const MAIN = 'b-main';
const OTHER = 'b-other';
const FILES = (b: string) => `/api/v0/branches/${b}/files`;

const dir = (name: string, path: string, m: Record<string, number | null> = {}) =>
  ({ type: 'dir', name, path, language: null, kind: null, measures: m }) as TreeItem;
const file = (
  name: string,
  path: string,
  m: Record<string, number | null> = {},
  kind: 'main' | 'test' = 'main',
) => ({ type: 'file', name, path, language: 'typescript', kind, measures: m }) as TreeItem;

function setup(items: TreeItem[], nextCursor: string | null = null): FakeServer {
  const server = new FakeServer();
  server.on('GET', `/api/v0/projects/${PROJECT}`, {
    body: {
      id: PROJECT,
      organizationId: ORG_ID,
      key: 'acme/payments',
      name: 'Payments',
      mainBranchName: 'main',
      mainBranch: {
        id: MAIN,
        name: 'main',
        gateStatus: 'passed',
        lastAnalysisId: 'a1',
        lastAnalyzedAt: null,
        measures: {},
      },
      permissions: [...MEMBER_PROJECT_PERMISSIONS],
    },
  });
  server.on('GET', `/api/v0/projects/${PROJECT}/branches`, {
    body: page([
      { id: MAIN, name: 'main', kind: 'branch', isMain: true },
      { id: OTHER, name: 'dev', kind: 'branch', isMain: false },
    ]),
  });
  server.on('GET', FILES(MAIN), { body: page(items, nextCursor) });
  server.on('GET', FILES(OTHER), { body: page([file('o.ts', 'o.ts')]) });
  server.on('GET', `/api/v0/branches/${MAIN}/measures`, {
    body: [
      { metric: 'files', overall: 42, new: null },
      { metric: 'ncloc', overall: 12345, new: null },
      { metric: 'coverage', overall: 81.5, new: null },
      { metric: 'issues', overall: 7, new: null },
    ],
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me());
  return server;
}

async function render(url = '/') {
  await TestBed.inject(Router).navigateByUrl(url);
  const fixture = TestBed.createComponent(CodePage);
  fixture.componentRef.setInput('projectId', PROJECT);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

const names = (root: HTMLElement) =>
  [...root.querySelectorAll('tbody tr')].map((r) =>
    r.querySelector('.entry-name')?.textContent?.trim(),
  );

const flat = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

describe('CodePage (spec §4.2)', () => {
  it("uses the project's main branch without ?branch, and asks for the root in pages of 200", async () => {
    const server = setup([file('a.ts', 'a.ts')]);
    await render();
    const requests = server.requestsTo('GET', FILES(MAIN));
    expect(requests).toHaveLength(1);
    expect(requests[0]?.query.get('dir')).toBe('');
    expect(requests[0]?.query.get('limit')).toBe('200');
  });

  it('shows a row per entry with its measures, a coverage bar, a test tag and links', async () => {
    setup([
      dir('src', 'src', {
        ncloc: 1200,
        complexity: 80,
        coverage: 75,
        duplicated_lines_density: 3.2,
        issues: 4,
      }),
      file('a.ts', 'a.ts', {
        ncloc: 10,
        complexity: 2,
        coverage: null,
        duplicated_lines_density: 0,
        issues: 0,
      }),
      file('z.spec.ts', 'z.spec.ts', { ncloc: 5 }, 'test'),
    ]);
    const { root } = await render();
    const rows = [...root.querySelectorAll('tbody tr')];
    const d = rows[0]!;
    expect(d.querySelector('.entry-name')?.textContent?.trim()).toBe('src');
    expect(d.querySelector('a.entry-name')?.getAttribute('href')).toBe('/?dir=src');
    expect([...d.querySelectorAll('td')].map(flat).slice(1)).toEqual([
      '1,200',
      '80',
      '75.0%',
      '3.2%',
      '4',
    ]);
    expect(d.querySelector<HTMLElement>('.cov-bar')?.style.width).toBe('75%');
    expect(d.querySelector('td a[href^="/projects/p1/issues"]')?.getAttribute('href')).toBe(
      '/projects/p1/issues?branch=b-main&path=src%2F',
    );
    const f = rows[1]!;
    expect(f.querySelector('a.entry-name')?.getAttribute('href')).toBe(
      '/projects/p1/code/file?branch=b-main&path=a.ts',
    );
    expect(f.querySelector('.cov-bar')).toBeNull();
    expect([...f.querySelectorAll('td')].map(flat)[3]).toBe('—');
    expect(f.querySelector('.badge')).toBeNull();
    expect(rows[2]!.querySelector('.badge.badge-tag')?.textContent?.trim()).toBe('test');
  });

  it('links a directory count to its path with a trailing slash, a file count to its exact path', async () => {
    setup([dir('util', 'util', { issues: 2 }), file('a.ts', 'a.ts', { issues: 3 })]);
    const { root } = await render();
    const links = [...root.querySelectorAll('td a[href^="/projects/p1/issues"]')].map((a) =>
      a.getAttribute('href'),
    );
    expect(links).toEqual([
      '/projects/p1/issues?branch=b-main&path=util%2F',
      '/projects/p1/issues?branch=b-main&path=a.ts',
    ]);
  });

  it('keeps odd characters in a directory name out of the path, and navigates with them as a query param', async () => {
    const server = setup([dir('my dir', 'src/my dir/#x')]);
    const { fixture, root } = await render('/?dir=src');
    root.querySelector<HTMLAnchorElement>('a.entry-name')!.click();
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?dir=src%2Fmy%20dir%2F%23x');
    const last = server.requestsTo('GET', FILES(MAIN)).at(-1);
    expect(last?.query.get('dir')).toBe('src/my dir/#x');
  });

  it('sorts descending first on a header click, then ascending, with aria-sort', async () => {
    setup([
      file('a.ts', 'a.ts', { coverage: 10 }),
      file('b.ts', 'b.ts', { coverage: 90 }),
      file('c.ts', 'c.ts', { coverage: null }),
    ]);
    const { fixture, root } = await render();
    const th = () =>
      [...root.querySelectorAll('thead th')].find((h) => h.textContent?.trim() === 'Coverage')!;
    expect(th().getAttribute('aria-sort')).toBe('none');
    expect(root.querySelector('thead th[aria-sort="ascending"]')?.textContent?.trim()).toBe('Name');
    th().querySelector('button')!.click();
    await settle(fixture);
    expect(names(root)).toEqual(['b.ts', 'a.ts', 'c.ts']);
    expect(th().getAttribute('aria-sort')).toBe('descending');
    th().querySelector('button')!.click();
    await settle(fixture);
    expect(names(root)).toEqual(['a.ts', 'b.ts', 'c.ts']);
    expect(th().getAttribute('aria-sort')).toBe('ascending');
  });

  it('says the sort is within the loaded entries while more exist, and loads the next page', async () => {
    const server = setup([file('a.ts', 'a.ts')], 'cur1');
    const { fixture, root } = await render();
    expect(root.textContent).toContain('Sorted within the 1 loaded entries');
    server.on('GET', FILES(MAIN), { body: page([file('z.ts', 'z.ts')]) });
    [...root.querySelectorAll('button')]
      .find((b) => b.textContent?.trim() === 'Show more')!
      .click();
    await settle(fixture);
    expect(server.requestsTo('GET', FILES(MAIN)).at(-1)?.query.get('cursor')).toBe('cur1');
    expect(names(root)).toEqual(['a.ts', 'z.ts']);
    expect(root.textContent).not.toContain('Sorted within');
  });

  it('switches branch from the picker and goes back to the root', async () => {
    const server = setup([file('a.ts', 'a.ts')]);
    const { fixture, root } = await render('/?dir=src');
    const select = root.querySelector<HTMLSelectElement>('q-branch-picker select')!;
    select.value = OTHER;
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe(`/?branch=${OTHER}`);
    const last = server.requestsTo('GET', FILES(OTHER)).at(-1);
    expect(last?.query.get('dir')).toBe('');
    expect(names(root)).toEqual(['o.ts']);
  });

  it('shows the root crumb as the project name, then each segment as a link', async () => {
    setup([]);
    const { root } = await render('/?dir=src%2Fmy%20dir');
    const links = [...root.querySelectorAll('nav.crumbs a')];
    expect(links.map((a) => a.textContent?.trim())).toEqual(['Payments', 'src']);
    expect(links[1]?.getAttribute('href')).toBe('/?dir=src');
    expect(root.querySelector('nav.crumbs [aria-current="page"]')?.textContent?.trim()).toBe(
      'my dir',
    );
  });

  it('summarises the root from the branch measures', async () => {
    setup([file('a.ts', 'a.ts')]);
    const { root } = await render();
    const text = flat(root.querySelector('.code-summary'));
    expect(text).toContain('42 files');
    expect(text).toContain('12,345 lines of code');
    expect(text).toContain('81.5% coverage');
    expect(text).toContain('7 open issues');
  });

  it('sums a complete sub-directory listing', async () => {
    setup([
      file('a.ts', 'src/a.ts', { ncloc: 10, issues: 1 }),
      file('b.ts', 'src/b.ts', { ncloc: 5, issues: 2 }),
    ]);
    const { root } = await render('/?dir=src');
    const text = flat(root.querySelector('.code-summary'));
    expect(text).toContain('2 files');
    expect(text).toContain('15 lines of code');
    expect(text).toContain('3 open issues');
  });

  it('has no summary for a partial sub-directory listing', async () => {
    setup([file('a.ts', 'src/a.ts', { ncloc: 10 })], 'more');
    const { root } = await render('/?dir=src');
    expect(root.querySelector('.code-summary')).toBeNull();
  });

  it('shows an empty state with a link to the quick start for a branch without files', async () => {
    setup([]);
    const { root } = await render();
    expect(root.querySelector('.empty-state')?.textContent).toContain(
      'No files analysed on this branch yet.',
    );
    expect(root.querySelector('.empty-state a')?.getAttribute('href')).toBe('/docs/quick-start');
  });

  it('shows an error as an alert in the panel', async () => {
    const server = setup([]);
    server.on('GET', FILES(MAIN), { status: 500, body: problem(500, 'INTERNAL') });
    const { root } = await render();
    expect(root.querySelector('.panel [role="alert"]')).not.toBeNull();
    expect(root.querySelector('.empty-state')).toBeNull();
  });
});

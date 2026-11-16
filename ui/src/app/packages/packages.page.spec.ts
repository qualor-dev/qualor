import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { FakeServer, me, problem, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { isUuid } from '../shared/ids';
import { PackagesPage } from './packages.page';

const USAGES = '/api/v0/packages/usages';
const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

const PROJECT = { id: '11111111-1111-4111-8111-111111111111', key: 'shop', name: 'Shop <b>x</b>' };
/** A branch that is not the main one: the Dependencies tab reads `?branch=` as its id. */
const RELEASE = {
  kind: 'branch',
  id: '22222222-2222-4222-8222-222222222222',
  name: 'release/1',
  main: false,
  source: null,
};

/** Stands in for the Dependencies tab: only the URL it is opened with matters here. */
@Component({ template: '' })
class DependenciesTab {}

function row(over: Record<string, unknown> = {}) {
  return {
    project: PROJECT,
    target: { kind: 'branch', id: 'b1', name: 'main', main: true, source: null },
    ecosystem: 'npm',
    purlType: 'npm',
    name: 'lodash',
    version: '4.17.21',
    path: 'pnpm-lock.yaml',
    direct: true,
    distribution: null,
    vulnerabilities: 2,
    ...over,
  };
}

function answer(rows: unknown[], over: Record<string, unknown> = {}) {
  return { rows, page: 1, pageSize: 50, total: rows.length, totalCapped: false, ...over };
}

describe('PackagesPage (0.16 SBOM §6.9)', () => {
  let server: FakeServer;
  let harness: RouterTestingHarness;

  async function setup(reply: Parameters<FakeServer['on']>[2]): Promise<void> {
    server = new FakeServer();
    server.on('GET', USAGES, reply);
    TestBed.configureTestingModule({
      providers: [
        provideRouter(
          [
            { path: 'packages', component: PackagesPage },
            { path: 'projects/:projectId/dependencies', component: DependenciesTab },
          ],
          withComponentInputBinding(),
        ),
        provideFakeServer(server),
      ],
    });
    TestBed.inject(SessionStore).set(me());
    harness = await RouterTestingHarness.create();
  }

  async function open(url = '/packages'): Promise<HTMLElement> {
    await harness.navigateByUrl(url);
    return refresh();
  }

  async function refresh(): Promise<HTMLElement> {
    await settle(harness.fixture);
    harness.detectChanges();
    await settle(harness.fixture);
    return harness.fixture.nativeElement as HTMLElement;
  }

  const calls = () => server.requestsTo('GET', USAGES);

  function type(root: HTMLElement, id: string, value: string) {
    const field = root.querySelector<HTMLInputElement | HTMLSelectElement>(`#${id}`)!;
    field.value = value;
    field.dispatchEvent(new Event(field instanceof HTMLSelectElement ? 'change' : 'input'));
  }

  it('offers one labelled search field, an ecosystem select and a version field', async () => {
    await setup({ body: answer([row()]) });
    const root = await open();
    expect(text(root.querySelector('label[for="packages-q"]'))).toBe('Package name or purl');
    expect(text(root.querySelector('label[for="packages-version"]'))).toBe('Version');
    const select = root.querySelector<HTMLSelectElement>('#packages-ecosystem')!;
    expect(text(root.querySelector('label[for="packages-ecosystem"]'))).toBe('Ecosystem');
    const options = [...select.options].map((o) => o.textContent?.trim());
    expect(options[0]).toBe('Any');
    expect(options).toEqual(expect.arrayContaining(['npm', 'pypi', 'maven', 'deb', 'rpm', 'apk']));
  });

  it('says what to do before a search, and sends nothing', async () => {
    await setup({ body: answer([row()]) });
    const root = await open();
    expect(text(root)).toContain('Search a package by name or purl');
    expect(root.querySelector('table')).toBeNull();
    expect(calls()).toHaveLength(0);
  });

  it('refuses an empty submit with a message and sends nothing', async () => {
    await setup({ body: answer([row()]) });
    const root = await open();
    type(root, 'packages-q', '   ');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await refresh();
    expect(text(root.querySelector('#packages-q-error'))).toBe(
      'Search needs at least one character',
    );
    expect(root.querySelector('#packages-q')?.getAttribute('aria-invalid')).toBe('true');
    expect(calls()).toHaveLength(0);
  });

  it('writes the search to the URL and calls the route with it', async () => {
    await setup({ body: answer([row()]) });
    const root = await open();
    type(root, 'packages-q', ' lodash ');
    type(root, 'packages-ecosystem', 'npm');
    type(root, 'packages-version', '4.17.21');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await refresh();
    const query = calls()[0]!.query;
    expect(query.get('q')).toBe('lodash');
    expect(query.get('ecosystem')).toBe('npm');
    expect(query.get('version')).toBe('4.17.21');
    expect(query.get('page')).toBe('1');
  });

  it('reads the search from the URL and fills the fields', async () => {
    await setup({ body: answer([row()]) });
    const root = await open('/packages?q=lodash&ecosystem=npm&version=4.17.21&page=2');
    expect(root.querySelector<HTMLInputElement>('#packages-q')!.value).toBe('lodash');
    expect(root.querySelector<HTMLSelectElement>('#packages-ecosystem')!.value).toBe('npm');
    expect(root.querySelector<HTMLInputElement>('#packages-version')!.value).toBe('4.17.21');
    expect(calls()[0]!.query.get('page')).toBe('2');
  });

  it('shows the columns, the main mark and a link to the Dependencies tab', async () => {
    await setup({
      body: answer([
        row(),
        row({
          target: RELEASE,
          path: '',
          direct: false,
          vulnerabilities: null,
        }),
        row({
          target: { kind: 'version', id: 'v1', name: '9.9.9', main: false, source: 'sbom' },
          distribution: { family: 'debian', version: '12.15' },
          direct: null,
          vulnerabilities: 0,
        }),
      ]),
    });
    const root = await open('/packages?q=lodash');
    const headers = [...root.querySelectorAll('thead th')].map((h) => text(h));
    expect(headers).toEqual([
      'Project',
      'Branch or version',
      'Package',
      'Version',
      'Path',
      'Dependency',
      'Distribution',
      'Vulnerabilities',
    ]);
    const rows = [...root.querySelectorAll('tbody tr')];
    expect(rows).toHaveLength(3);
    // User data is text: the project name's markup is not parsed.
    expect(text(rows[0]!.children[0])).toBe('Shop <b>x</b>');
    expect(root.querySelector('tbody b')).toBeNull();
    expect(text(rows[0]!.children[1])).toBe('main main');
    expect(text(rows[0]!.children[7])).toBe('2');
    expect(text(rows[1]!.children[4])).toBe('—');
    expect(text(rows[1]!.children[5])).toBe('Transitive');
    expect(text(rows[1]!.children[7])).toBe('not checked');
    expect(text(rows[2]!.children[1])).toBe('9.9.9 SBOM');
    expect(text(rows[2]!.children[6])).toBe('debian 12.15');
    expect(text(rows[2]!.children[7])).toBe('0');

    const href = (i: number) => rows[i]!.querySelector('a')!.getAttribute('href');
    const base = `/projects/${PROJECT.id}/dependencies`;
    expect(href(0)).toBe(`${base}?q=lodash`);
    expect(href(1)).toBe(`${base}?branch=${RELEASE.id}&q=lodash`);
    expect(href(2)).toBe(`${base}?version=v1&q=lodash`);
  });

  it('follows a branch row to the Dependencies tab with that branch asked for by its id', async () => {
    await setup({ body: answer([row({ target: RELEASE })]) });
    const root = await open('/packages?q=lodash');
    root.querySelector<HTMLAnchorElement>('tbody a')!.click();
    await refresh();
    const router = TestBed.inject(Router);
    const url = router.parseUrl(router.url);
    expect(url.root.children['primary']?.segments.map((s) => s.path)).toEqual([
      'projects',
      PROJECT.id,
      'dependencies',
    ]);
    expect(url.queryParams).toEqual({ branch: RELEASE.id, q: 'lodash' });
    // The Dependencies tab takes `?branch=` only as an id (dependencies.page.ts): a name would
    // open the main branch.
    expect(isUuid(url.queryParams['branch'])).toBe(true);
  });

  it('marks a version SBOM by its source, not by its distribution', async () => {
    await setup({
      body: answer([
        row({
          target: { kind: 'version', id: 'v1', name: '9.9.9', main: false, source: 'sbom' },
          distribution: null,
        }),
        row({
          target: { kind: 'version', id: 'v2', name: '1.0.0', main: false, source: 'tag' },
          distribution: { family: 'debian', version: '12.15' },
        }),
      ]),
    });
    const root = await open('/packages?q=lodash');
    const rows = [...root.querySelectorAll('tbody tr')];
    expect(text(rows[0]!.children[1])).toBe('9.9.9 SBOM');
    expect(text(rows[1]!.children[1])).toBe('1.0.0');
  });

  it('says so when nothing matches', async () => {
    await setup({ body: answer([]) });
    const root = await open('/packages?q=nothing');
    expect(text(root)).toContain('No package matches.');
    expect(root.querySelector('.pager')).toBeNull();
  });

  it('shows "10 000+" when the total is capped', async () => {
    await setup({ body: answer([row()], { total: 10_000, totalCapped: true }) });
    const root = await open('/packages?q=lodash');
    expect(text(root.querySelector('.pager-range'))).toBe('1–50 of 10 000+');
  });

  it('walks the pages through the URL', async () => {
    await setup((req) => ({
      body: answer([row()], { page: Number(req.query.get('page')), total: 120 }),
    }));
    const root = await open('/packages?q=lodash');
    expect(text(root.querySelector('.pager-range'))).toBe('1–50 of 120');
    const [previous, next] = [...root.querySelectorAll<HTMLButtonElement>('.pager button')];
    expect(previous!.disabled).toBe(true);
    next!.click();
    await refresh();
    expect(calls().at(-1)!.query.get('page')).toBe('2');
    expect(text(root.querySelector('.pager-range'))).toBe('51–100 of 120');
    expect(harness.fixture.nativeElement.querySelector('.pager button')!.disabled).toBe(false);
  });

  /** The server's answer to a page of `total` rows: rows only on the pages that have some. */
  const pages =
    (total: number, capped = false) =>
    (req: { query: URLSearchParams }) => {
      const page = Number(req.query.get('page'));
      const size = Number(req.query.get('pageSize'));
      const rows = (page - 1) * size < total ? [row()] : [];
      return { body: answer(rows, { page, pageSize: size, total, totalCapped: capped }) };
    };

  it('never offers a page past 100, which the server refuses', async () => {
    await setup(pages(10_000, true));
    const root = await open('/packages?q=lodash&page=100');
    expect(calls().at(-1)!.query.get('page')).toBe('100');
    expect(text(root.querySelector('.pager-range'))).toBe('4951–5000 of 10 000+');
    const [previous, next] = [...root.querySelectorAll<HTMLButtonElement>('.pager button')];
    expect(previous!.disabled).toBe(false);
    expect(next!.disabled).toBe(true);
    expect(text(root.querySelector('.pager-more'))).toBe('Narrow the search to see the rest.');
  });

  it('asks for page 100 at most, whatever the URL says', async () => {
    await setup(pages(10_000, true));
    await open('/packages?q=lodash&page=150');
    expect(calls().map((c) => c.query.get('page'))).toEqual(['100']);
  });

  it('opens the last page for a page past the last one, never "201–120 of 120"', async () => {
    await setup(pages(120));
    const root = await open('/packages?q=lodash&page=5');
    await refresh();
    expect(calls().map((c) => c.query.get('page'))).toEqual(['5', '3']);
    expect(TestBed.inject(Router).url).toBe('/packages?q=lodash&page=3');
    expect(text(root.querySelector('.pager-range'))).toBe('101–120 of 120');
    expect(text(root)).not.toContain('201–120');
    expect(root.querySelector('.pager-more')).toBeNull();
  });

  it('shows the problem of a refused query', async () => {
    await setup({ status: 422, body: problem(422, 'VALIDATION_FAILED') });
    const root = await open('/packages?q=pkg:bad');
    expect(root.querySelector('.alert-error')).not.toBeNull();
    expect(root.querySelector('table')).toBeNull();
  });
});

import { TestBed } from '@angular/core/testing';
import { provideRouter, Router, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import {
  FakePortfolio,
  FakeServer,
  me,
  ORG_ID,
  page,
  portfolioAggregate,
  portfolioOverview,
  portfolioRow,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { PortfolioPage } from './portfolio.page';

const OVERVIEW = '/api/v0/ee/portfolio';
const PROJECTS = '/api/v0/ee/portfolio/projects';
const NAV = { point: 'main.nav', id: 'portfolio', label: 'Portfolio', path: '/portfolio' };

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

describe('PortfolioPage (4E-2 §4)', () => {
  let server: FakeServer;
  let harness: RouterTestingHarness;

  async function setup(features = ['portfolio']): Promise<void> {
    server = new FakeServer();
    server.on('GET', '/api/v0/organizations', {
      body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
    });
    server.on('GET', '/api/v0/system/info', {
      body: {
        version: '0.8.0',
        edition: 'enterprise',
        features,
        extensions: features.includes('portfolio') ? [NAV] : [],
      },
    });
    TestBed.configureTestingModule({
      providers: [
        provideRouter(
          [
            { path: 'portfolio', component: PortfolioPage },
            { path: 'projects/:projectId', children: [] },
          ],
          withComponentInputBinding(),
        ),
        provideFakeServer(server),
      ],
    });
    TestBed.inject(SessionStore).set(me());
    harness = await RouterTestingHarness.create();
  }

  async function open(url = '/portfolio'): Promise<HTMLElement> {
    await harness.navigateByUrl(url);
    return refresh();
  }

  async function refresh(): Promise<HTMLElement> {
    await settle(harness.fixture);
    harness.detectChanges();
    await settle(harness.fixture);
    return harness.fixture.nativeElement as HTMLElement;
  }

  const button = (root: HTMLElement, name: string) =>
    [...root.querySelectorAll('button')].find((b) => text(b) === name);
  const card = (root: HTMLElement, name: string) => text(root.querySelector(`[data-card=${name}]`));

  it('loads the current organisation by week and shows the totals as cards', async () => {
    await setup();
    FakePortfolio.install(server);
    const root = await open();
    expect(text(root.querySelector('h1'))).toBe('Portfolio');
    const request = server.requestsTo('GET', OVERVIEW)[0];
    expect(request?.query.get('scope')).toBe('organization');
    expect(request?.query.get('organizationId')).toBe(ORG_ID);
    expect(request?.query.get('granularity')).toBe('week');
    expect(card(root, 'projects')).toContain('3');
    expect(card(root, 'projects')).toContain('2 analyzed');
    expect(card(root, 'projects')).toContain('1 abandoned');
    expect(card(root, 'gate')).toContain('50 %');
    expect(card(root, 'security')).toContain('A 1');
    expect(card(root, 'security')).toContain('C 1');
    expect(card(root, 'reliability')).toContain('A 2');
    expect(card(root, 'ncloc')).toContain('12,345');
    expect(card(root, 'coverage')).toContain('72.5 %');
    expect(card(root, 'coverage')).toContain('3.3 %');
    expect(card(root, 'issues')).toContain('42');
    expect(card(root, 'issues')).toContain('Blocker 2');
    expect(card(root, 'issues')).toContain('High 5');
    const terms = [...root.querySelectorAll('[data-card=findings] dl > div')].map((d) => [
      text(d.querySelector('dt')),
      text(d.querySelector('dd')),
    ]);
    expect(terms).toEqual([
      ['Secrets', '1'],
      ['Vulnerable dependencies', '4'],
      ['Vulnerable releases', '3'],
      ['Exploited', '2'],
    ]);
    // The organisation scope has no organisations table.
    expect(root.querySelector('[data-test=organizations]')).toBeNull();
  });

  it('groups the counts in the notes as the measures are', async () => {
    await setup();
    FakePortfolio.install(
      server,
      portfolioOverview({
        totals: {
          ...portfolioAggregate({
            projects: 4000,
            analysed: 2500,
            abandoned: 1500,
            gate: { passed: 1200, failed: 1300, error: 0, none: 0 },
            passedShare: 0.48,
          }),
          secrets: 0,
          vulnerableDependencies: 0,
          vulnerableReleases: 0,
          exploited: 0,
        },
        attention: {
          ...portfolioOverview().attention,
          mostSevere: [
            portfolioRow('severe', {
              bySeverity: { blocker: 1000, high: 2345, medium: 0, low: 0, info: 0 },
            }),
          ],
        },
      }),
    );
    const root = await open();
    expect(text(root.querySelector('[data-card=projects] .kpi-note'))).toBe(
      '2,500 analyzed · 1,500 abandoned',
    );
    expect(card(root, 'gate')).toContain('1,200 of 2,500 analyzed projects passed');
    expect(text(root.querySelector('[data-attention=mostSevere]'))).toContain(
      '3,345 blocker and high',
    );
  });

  it('shows a dash for the gate pass share when nothing was analyzed', async () => {
    await setup();
    FakePortfolio.install(
      server,
      portfolioOverview({
        totals: {
          ...portfolioAggregate({ analysed: 0, passedShare: null }),
          secrets: 0,
          vulnerableDependencies: 0,
          vulnerableReleases: 0,
          exploited: 0,
        },
      }),
    );
    const root = await open();
    expect(text(root.querySelector('[data-card=gate] .meter-value'))).toBe('–');
    expect(card(root, 'gate')).toContain('No project analyzed yet');
    expect(root.querySelector('[data-card=gate] [role=meter]')).toBeNull();
  });

  it('gives every trend chart a table of its values', async () => {
    await setup();
    FakePortfolio.install(server);
    const root = await open();
    const charts = [...root.querySelectorAll('[data-trend]')].map((c) =>
      c.getAttribute('data-trend'),
    );
    expect(charts).toEqual(['gate', 'coverage', 'ncloc', 'issues', 'analyses', 'triage']);
    const column = (trend: string) =>
      [...root.querySelectorAll(`[data-trend=${trend}] .chart-table tbody tr`)].map((tr) =>
        text(tr.querySelector('td.num')),
      );
    expect(column('coverage')).toEqual([
      '61 %',
      '62 %',
      '63 %',
      '64 %',
      '65 %',
      '66 %',
      '67 %',
      '68 %',
      '69 %',
      '70 %',
      '71 %',
      '72 %',
    ]);
    expect(column('gate')[0]).toBe('–');
    expect(column('gate')[1]).toBe('50 %');
    expect(column('ncloc')[11]).toBe('12,000');
    expect(column('issues')[11]).toBe('41');
    expect(column('analyses')[11]).toBe('21');
    expect(column('triage')[11]).toBe('11');
    // Each point is its period, by its start; the line under the heading says what it holds.
    expect(text(root.querySelector('[data-trend=coverage] .chart-table tbody td'))).toBe(
      'Jul 20, 2026',
    );
    expect(text(root.querySelector('.portfolio-note'))).toBe(
      'Each point is the state at the end of its week; the last one is the current week, up to now.',
    );
    expect(root.querySelector('[data-trend=gate] svg')?.getAttribute('aria-label')).toContain(
      'Gate pass share',
    );
  });

  it('switches scope and granularity through the query and asks for them', async () => {
    await setup();
    const portfolio = FakePortfolio.install(server);
    let root = await open();
    expect(button(root, 'This organisation')?.getAttribute('aria-pressed')).toBe('true');
    expect(button(root, 'Weeks')?.getAttribute('aria-pressed')).toBe('true');
    portfolio.overview = portfolioOverview({
      scope: { kind: 'all', organization: null },
      organizations: [
        { id: ORG_ID, key: 'default', name: 'Default', ...portfolioAggregate() },
        {
          id: '0190a6c2-0000-7000-8000-000000000002',
          key: 'north',
          name: 'North',
          ...portfolioAggregate({ projects: 5, passedShare: null, coverage: null }),
        },
      ],
    });
    button(root, 'All organisations')!.click();
    root = await refresh();
    const router = TestBed.inject(Router);
    expect(router.url).toBe('/portfolio?scope=all&granularity=week');
    const all = server.requestsTo('GET', OVERVIEW).at(-1);
    expect(all?.query.get('scope')).toBe('all');
    expect(all?.query.has('organizationId')).toBe(false);
    expect(server.requestsTo('GET', PROJECTS).at(-1)?.query.get('scope')).toBe('all');
    expect(button(root, 'All organisations')?.getAttribute('aria-pressed')).toBe('true');
    const rows = [...root.querySelectorAll('[data-test=organizations] tbody tr')];
    expect(rows.map((tr) => text(tr.querySelector('th')))).toEqual([
      'Default default',
      'North north',
    ]);
    expect(text(rows[1])).toContain('–');
    expect(text(rows[1])).not.toContain('—');

    button(root, 'Months')!.click();
    root = await refresh();
    expect(router.url).toBe('/portfolio?scope=all&granularity=month');
    expect(server.requestsTo('GET', OVERVIEW).at(-1)?.query.get('granularity')).toBe('month');
    expect(button(root, 'Months')?.getAttribute('aria-pressed')).toBe('true');
    expect(text(root.querySelector('.portfolio-note'))).toBe(
      'Each point is the state at the end of its month; the last one is the current month, up to now.',
    );
  });

  it('reads the scope and granularity from the URL', async () => {
    await setup();
    FakePortfolio.install(server);
    await open('/portfolio?scope=all&granularity=month');
    const request = server.requestsTo('GET', OVERVIEW)[0];
    expect(request?.query.get('scope')).toBe('all');
    expect(request?.query.get('granularity')).toBe('month');
  });

  it('lists the attention lists with links to the projects', async () => {
    await setup();
    FakePortfolio.install(server);
    const root = await open();
    const lists = [...root.querySelectorAll('[data-attention]')];
    expect(lists.map((l) => l.getAttribute('data-attention'))).toEqual([
      'exploited',
      'failingGates',
      'worstSecurity',
      'mostSevere',
      'abandoned',
    ]);
    expect(text(lists[0])).toContain('Exploited vulnerabilities');
    expect(text(lists[0])).toContain('2 exploited');
    const link = lists[1]?.querySelector('a');
    expect(link?.getAttribute('href')).toBe(`/projects/${portfolioRow('fail').project.id}`);
    expect(text(lists[1])).toContain('3 blocker and high');
    expect(text(lists[2])).toContain('E');
    expect(text(lists[3])).toContain('7 blocker and high');
    expect(text(lists[4])).toContain('Never analyzed');
  });

  it('shows no Exploited text without vuln.priority, and a dash for a null count', async () => {
    await setup();
    const base = portfolioOverview();
    FakePortfolio.install(
      server,
      portfolioOverview({
        totals: { ...base.totals, vulnerableReleases: null, exploited: null },
        attention: { ...base.attention, exploited: null },
      }),
      [portfolioRow('a', { vulnerableReleases: null, exploited: null })],
    );
    const root = await open();
    expect(root.textContent).not.toContain('Exploited');
    expect(root.textContent).not.toContain('exploited');
    const terms = [...root.querySelectorAll('[data-card=findings] dl > div')].map((d) => [
      text(d.querySelector('dt')),
      text(d.querySelector('dd')),
    ]);
    expect(terms.at(-1)).toEqual(['Vulnerable releases', '–']);
    const cells = [...root.querySelectorAll('[data-test=projects] tbody tr td')].map((c) =>
      text(c),
    );
    expect(cells.at(-2)).toBe('–');
  });

  it('sorts on the new vulnerability columns', async () => {
    await setup();
    FakePortfolio.install(server);
    const root = await open();
    const header = (name: string) =>
      [...root.querySelectorAll('[data-test=projects] th')].find(
        (th) => text(th.querySelector('button')) === name,
      );
    header('Vulnerable releases')!.querySelector('button')!.click();
    await refresh();
    expect(server.requestsTo('GET', PROJECTS).at(-1)?.query.get('sort')).toBe('vulnerableReleases');
    header('Exploited')!.querySelector('button')!.click();
    await refresh();
    expect(server.requestsTo('GET', PROJECTS).at(-1)?.query.get('sort')).toBe('exploited');
  });

  it('shows a dash, not 0 blocker and high, for a listed project with no measures', async () => {
    await setup();
    FakePortfolio.install(
      server,
      portfolioOverview({
        attention: {
          ...portfolioOverview().attention,
          failingGates: [portfolioRow('bare', { bySeverity: null })],
        },
      }),
    );
    const root = await open();
    const note = root.querySelector('[data-attention=failingGates] li .muted');
    expect(text(note)).toBe('–');
  });

  it('sorts the projects on the server and appends the next page', async () => {
    await setup();
    const rows = Array.from({ length: 3 }, (_, i) => portfolioRow(`p${i}`));
    FakePortfolio.install(server, portfolioOverview(), rows);
    server.on('GET', PROJECTS, (r) => {
      const cursor = r.query.get('cursor');
      return { body: cursor ? page([rows[2]!]) : page(rows.slice(0, 2), 'next-page') };
    });
    const root = await open();
    expect(server.requestsTo('GET', PROJECTS)[0]?.query.get('sort')).toBe('gate');
    const table = () => root.querySelector('[data-test=projects]')!;
    const keys = () =>
      [...table().querySelectorAll('tbody tr')].map((tr) => tr.querySelector('a')?.textContent);
    expect(keys()).toEqual(['Project p0', 'Project p1']);
    expect(table().querySelector('tbody a')?.getAttribute('href')).toBe(
      `/projects/${rows[0]!.project.id}`,
    );
    const header = (name: string) =>
      [...table().querySelectorAll('th')].find((th) => text(th.querySelector('button')) === name);
    expect(header('Quality gate')?.getAttribute('aria-sort')).toBe('ascending');
    expect(header('Lines of code')?.getAttribute('aria-sort')).toBe('none');

    button(root, 'Load more')!.click();
    await refresh();
    expect(server.requestsTo('GET', PROJECTS).at(-1)?.query.get('cursor')).toBe('next-page');
    expect(keys()).toEqual(['Project p0', 'Project p1', 'Project p2']);
    expect(button(root, 'Load more')).toBeUndefined();

    header('Lines of code')!.querySelector('button')!.click();
    await refresh();
    const sorted = server.requestsTo('GET', PROJECTS).at(-1);
    expect(sorted?.query.get('sort')).toBe('ncloc');
    expect(sorted?.query.has('cursor')).toBe(false);
    expect(header('Lines of code')?.getAttribute('aria-sort')).toBe('descending');
    expect(header('Quality gate')?.getAttribute('aria-sort')).toBe('none');
    expect(keys()).toEqual(['Project p0', 'Project p1']);

    // R12: coverage runs the lowest first.
    header('Coverage')!.querySelector('button')!.click();
    await refresh();
    expect(server.requestsTo('GET', PROJECTS).at(-1)?.query.get('sort')).toBe('coverage');
    expect(header('Coverage')?.getAttribute('aria-sort')).toBe('ascending');
  });

  it('links the CSV and PDF downloads to the export of the scope shown', async () => {
    await setup();
    FakePortfolio.install(server);
    const root = await open();
    const links = () =>
      [...root.querySelectorAll<HTMLAnchorElement>('a[download]')].map((a) => [
        text(a),
        a.getAttribute('href'),
      ]);
    expect(links()).toEqual([
      [
        'CSV',
        `/api/v0/ee/portfolio/export?scope=organization&organizationId=${ORG_ID}&granularity=week&format=csv`,
      ],
      [
        'PDF',
        `/api/v0/ee/portfolio/export?scope=organization&organizationId=${ORG_ID}&granularity=week&format=pdf`,
      ],
    ]);
    await harness.navigateByUrl('/portfolio?scope=all&granularity=month');
    await refresh();
    expect(links()).toEqual([
      ['CSV', '/api/v0/ee/portfolio/export?scope=all&granularity=month&format=csv'],
      ['PDF', '/api/v0/ee/portfolio/export?scope=all&granularity=month&format=pdf'],
    ]);
  });

  it('says when there is no project to read, and asks for no projects page', async () => {
    await setup();
    FakePortfolio.install(
      server,
      portfolioOverview({
        totals: {
          ...portfolioAggregate({ projects: 0, analysed: 0, abandoned: 0, passedShare: null }),
          secrets: 0,
          vulnerableDependencies: 0,
          vulnerableReleases: 0,
          exploited: 0,
        },
      }),
      [],
    );
    const root = await open();
    expect(text(root.querySelector('.empty-state'))).toBe('No projects you can read yet.');
    expect(root.querySelector('[data-card]')).toBeNull();
    expect(server.requestsTo('GET', PROJECTS)).toHaveLength(0);
  });

  it('says when the portfolio took too long, and when it failed', async () => {
    await setup();
    server.on('GET', OVERVIEW, { status: 503, body: problem(503, 'PORTFOLIO_TIMEOUT') });
    let root = await open();
    expect(text(root.querySelector('[role=alert]'))).toBe(
      'The portfolio took too long to compute; try one organisation.',
    );
    expect(root.querySelector('[data-card]')).toBeNull();
    expect(server.requestsTo('GET', PROJECTS)).toHaveLength(0);

    server.on('GET', OVERVIEW, { status: 500, body: problem(500, 'INTERNAL_ERROR') });
    await harness.navigateByUrl('/portfolio?scope=all');
    root = await refresh();
    expect(root.querySelector('[role=alert]')).not.toBeNull();
    expect(text(root.querySelector('[role=alert]'))).not.toContain('too long');
  });

  it('shows the error, not an empty portfolio, when the organisations fail to load', async () => {
    await setup();
    FakePortfolio.install(server);
    server.on('GET', '/api/v0/organizations', {
      status: 500,
      body: problem(500, 'INTERNAL_ERROR'),
    });
    const root = await open();
    expect(root.querySelector('[role=alert]')).not.toBeNull();
    expect(root.querySelector('.empty-state')).toBeNull();
    expect(text(root)).not.toContain('No projects you can read yet.');
    expect(server.requestsTo('GET', OVERVIEW)).toHaveLength(0);
  });

  it('says the feature is not licensed and sends no enterprise request', async () => {
    await setup([]);
    const root = await open();
    expect(text(root.querySelector('h1'))).toBe('Portfolio');
    expect(text(root)).toContain(
      'Portfolio reports need an enterprise licence with the portfolio feature.',
    );
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
    expect(root.querySelector('a[download]')).toBeNull();
  });
});

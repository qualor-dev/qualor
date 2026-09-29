import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { BranchOverviewPage } from './branch-overview.page';
import type { Branch } from './branches';

const PROJECT = 'p1';
const MAIN: Branch = {
  id: 'b-main',
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
const MR: Branch = {
  ...MAIN,
  id: 'b-mr',
  kind: 'merge_request',
  name: '42',
  isMain: false,
  mrSourceBranch: 'feature/refund-limits',
  mrTargetBranch: 'main',
  mrTitle: 'Refund <b>limits</b>',
  mrUrl: 'https://gitlab.example.com/acme/p1/-/merge_requests/42',
  lastAnalysisId: null,
  lastAnalyzedAt: null,
  gateStatus: null,
};

function projectWithMain(overrides: Record<string, unknown> = {}) {
  return {
    id: PROJECT,
    organizationId: ORG_ID,
    key: 'acme/p1',
    name: 'P1',
    mainBranchName: 'main',
    qualityGateId: null,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    mainBranch: {
      id: 'b-main',
      name: 'main',
      gateStatus: 'failed',
      lastAnalysisId: 'a1',
      lastAnalyzedAt: '2026-09-15T09:00:00.000Z',
      measures: {},
      ...overrides,
    },
  };
}

function analysis(gateResult: Record<string, unknown> = {}) {
  return {
    id: 'a1',
    projectId: PROJECT,
    status: 'succeeded',
    branch: { id: 'b-main', kind: 'branch', name: 'main' },
    revision: 'cccccccccccccccccccccccccccccccccccccccc',
    analysisDate: '2026-09-15T09:00:00.000Z',
    gateStatus: 'failed',
    gateResult: {
      gate: { id: 'g', name: 'Qualor way' },
      status: 'failed',
      warnings: [],
      conditions: [
        { value: 2, metric: 'new_issues', status: 'failed', operator: 'gt', threshold: 0 },
      ],
      ignoredConditions: [{ metric: 'new_coverage', reason: 'small_changeset' }],
      ...gateResult,
    },
    error: null,
    warnings: [],
    engines: [],
    queuedAt: '',
    startedAt: null,
    finishedAt: null,
  };
}

/** A later upload of an older revision: failed with STALE_ANALYSIS, newest in the history. */
const STALE = {
  ...analysis(),
  id: 'a2',
  status: 'failed',
  revision: 'dddddddddddddddddddddddddddddddddddddddd',
  analysisDate: '2026-09-10T09:00:00.000Z',
  gateStatus: null,
  gateResult: null,
  error: { code: 'STALE_ANALYSIS', message: 'stale' },
};

/** A point of a history series, on analysis a0 (Sep 1) or a1 (Sep 15). */
const series = (metric: string, a0: number, a1: number) => ({
  metric,
  points: [
    { analysisId: 'a0', date: '2026-09-01T09:00:00.000Z', value: a0 },
    { analysisId: 'a1', date: '2026-09-15T09:00:00.000Z', value: a1 },
  ],
});

/** The branch's whole history (the server keeps at most 1 000 points, evenly spread). */
const MAIN_HISTORY = [
  series('coverage', 60.8, 65.7),
  series('issues', 7, 9),
  series('blocker_issues', 1, 1),
  series('high_issues', 1, 2),
  series('medium_issues', 3, 4),
  series('low_issues', 1, 1),
  series('info_issues', 1, 1),
];

describe('BranchOverviewPage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    server.on('GET', `/api/v0/projects/${PROJECT}`, { body: projectWithMain() });
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([MAIN, MR]) });
    server.on('GET', '/api/v0/analyses/a1', { body: analysis() });
    server.on('GET', '/api/v0/branches/b-main/analyses', { body: page([STALE, analysis()]) });
    server.on('GET', '/api/v0/branches/b-main/measures', {
      body: [
        { metric: 'issues', overall: 9, new: 2 },
        { metric: 'coverage', overall: 65.7, new: 100 },
        { metric: 'security_rating', overall: 5, new: 1 },
        { metric: 'blocker_issues', overall: 1, new: null },
        { metric: 'high_issues', overall: 2, new: null },
        { metric: 'medium_issues', overall: 4, new: null },
        { metric: 'low_issues', overall: 1, new: null },
        { metric: 'info_issues', overall: 1, new: null },
        { metric: 'security_issues', overall: 3, new: null },
        { metric: 'reliability_issues', overall: 2, new: null },
        { metric: 'maintainability_issues', overall: 4, new: null },
        { metric: 'duplicated_lines_density', overall: 0, new: 0 },
        { metric: 'ncloc', overall: 654, new: null },
        { metric: 'lines', overall: 800, new: 19 },
      ],
    });
    server.on('GET', '/api/v0/branches/b-main/measures/history', { body: MAIN_HISTORY });
    server.on('GET', '/api/v0/issues', {
      body: {
        items: [],
        nextCursor: null,
        facets: {
          engine: [
            { value: 'eslint', count: 5 },
            { value: '<b>semgrep</b>', count: 1 },
          ],
          rule: [{ value: 'eslint:eqeqeq', count: 2 }],
        },
      },
    });
    server.on('GET', '/api/v0/branches/b-mr/measures', { body: [] });
    server.on('GET', '/api/v0/branches/b-mr/measures/history', { body: [] });
    server.on('GET', '/api/v0/branches/b-mr/analyses', { body: page([]) });
    TestBed.configureTestingModule({
      imports: [BranchOverviewPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render(branchId?: string) {
    const fixture = TestBed.createComponent(BranchOverviewPage);
    fixture.componentRef.setInput('projectId', PROJECT);
    if (branchId) fixture.componentRef.setInput('branchId', branchId);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

  it('shows the gate verdict with its conditions, the KPIs and the charts', async () => {
    const { root } = await render();
    // The main branch is the project's overview: no branch strip.
    expect(root.querySelector('.branch-context')).toBeNull();
    expect(text(root.querySelector('#gate-heading'))).toBe('Quality gate Qualor way');
    expect(text(root.querySelector('.gate-word'))).toBe('Failed');
    const gate = root.querySelector('[aria-labelledby="gate-heading"]');
    expect([...(gate?.querySelectorAll('tbody td') ?? [])].map(text)).toEqual([
      'Issues on new code is greater than 0',
      '2',
      'Failed',
    ]);
    expect(root.textContent).toContain('Coverage on new code: Skipped for a small change');
    expect(root.textContent).toContain('Analyzed Sep 15, 2026, 9:00 AM UTC, revision cccccccc');
    const kpi = (name: string) => text(root.querySelector(`[data-kpi="${name}"] .kpi-value`));
    expect([kpi('coverage'), kpi('issues'), kpi('ncloc')]).toEqual(['65.7 %', '9', '654']);
    expect(text(root.querySelector('[data-kpi="issues"] q-delta'))).toBe('+2 since Sep 1, 2026');
    expect([...root.querySelectorAll('q-rating .rating-letter')].map(text)).toEqual(['E', '–']);
    const newCode = root.querySelector('[aria-labelledby="new-code-heading"]');
    expect([...(newCode?.querySelectorAll('dt') ?? [])].map(text)).toEqual([
      'Coverage on new code',
      'Issues on new code',
      'Duplicated lines (%) on new code',
      'Lines on new code',
    ]);
    expect([...(newCode?.querySelectorAll('dd') ?? [])].map(text)).toEqual([
      '100 %',
      '2',
      '0 %',
      '19',
    ]);
    const issues = root.querySelector('[aria-labelledby="open-issues-heading"]');
    const [bySeverity, byQuality] = [...(issues?.querySelectorAll('q-distribution') ?? [])];
    expect([...(bySeverity?.querySelectorAll('li') ?? [])].map(text)).toEqual([
      'Blocker 1',
      'High 2',
      'Medium 4',
      'Low 1',
      'Info 1',
    ]);
    expect([...(byQuality?.querySelectorAll('li') ?? [])].map(text)).toEqual([
      'Security 3',
      'Reliability 2',
      'Maintainability 4',
    ]);
    expect(root.querySelector('q-line-chart svg')?.getAttribute('aria-label')).toBe(
      'Issues went from 7 on Sep 1, 2026 to 9 on Sep 15, 2026',
    );
    const sources = root.querySelector('[aria-labelledby="sources-heading"]');
    expect(sources?.textContent).toContain('<b>semgrep</b>');
    expect(sources?.querySelector('b')).toBeNull();
    expect(text(sources?.querySelector('.rule-list li'))).toBe('eslint:eqeqeq 2');
  });

  it('switches the history to one metric', async () => {
    const { fixture, root } = await render();
    const buttons = [...root.querySelectorAll<HTMLButtonElement>('.segmented button')];
    expect(buttons.map((b) => [text(b), b.getAttribute('aria-pressed')])).toEqual([
      ['Issues by severity', 'true'],
      ['Coverage', 'false'],
      ['Duplications', 'false'],
      ['Lines of code', 'false'],
    ]);
    buttons[1]?.click();
    await settle(fixture);
    expect(buttons[1]?.getAttribute('aria-pressed')).toBe('true');
    expect(root.querySelector('q-line-chart svg')?.getAttribute('aria-label')).toBe(
      'Coverage went from 60.8 % on Sep 1, 2026 to 65.7 % on Sep 15, 2026',
    );
  });

  it('lists the recent succeeded analyses with their gate, leaving failed uploads out', async () => {
    const { root } = await render();
    const rows = [...root.querySelectorAll('[aria-labelledby="recent-heading"] tbody tr')];
    expect(rows).toHaveLength(1);
    expect(text(rows[0])).toContain('cccccccc');
    expect(text(rows[0]?.querySelector('q-gate-badge'))).toBe('Failed');
    expect(text(rows[0])).not.toContain('dddddddd');
  });

  it("reads the main branch from the project and the gate from the branch's last analysis", async () => {
    // The history's newest entry is a stale upload that failed; the gate is still a1's.
    const { root } = await render();
    expect(text(root.querySelector('#gate-heading'))).toBe('Quality gate Qualor way');
    expect(text(root.querySelector('.gate-meta'))).toContain('revision cccccccc');
    expect(text(root.querySelector('.gate-meta'))).not.toContain('dddddddd');
    expect(root.querySelectorAll('[aria-labelledby="gate-heading"] tbody tr')).toHaveLength(1);
    expect(server.requestsTo('GET', '/api/v0/analyses/a1')).toHaveLength(1);
    // The list feeds only the recent-analyses panel.
    expect(server.requestsTo('GET', '/api/v0/branches/b-main/analyses')).toHaveLength(1);
    expect(server.requestsTo('GET', `/api/v0/projects/${PROJECT}/branches`)).toHaveLength(0);
  });

  it('titles a merge request by its number and branches, and says when nothing ran', async () => {
    const { root } = await render('b-mr');
    expect(text(root.querySelector('.branch-name'))).toBe('!42 feature/refund-limits → main');
    // The strip above the overview names the merge request, as text, and links to GitLab.
    const strip = root.querySelector('.branch-context');
    expect(text(strip?.querySelector('.branch-context-title'))).toBe(
      '!42 feature/refund-limits → main',
    );
    expect(strip?.textContent).toContain('Refund <b>limits</b>');
    expect(strip?.querySelector('b')).toBeNull();
    const gitlab = [...(strip?.querySelectorAll('a') ?? [])].find(
      (a) => text(a) === 'Open in GitLab',
    );
    expect(gitlab?.getAttribute('href')).toBe(
      'https://gitlab.example.com/acme/p1/-/merge_requests/42',
    );
    expect(gitlab?.getAttribute('rel')).toBe('noopener noreferrer');
    const back = [...(strip?.querySelectorAll('a') ?? [])].find((a) =>
      text(a)?.startsWith('All branches'),
    );
    expect(back?.getAttribute('href')).toBe(`/projects/${PROJECT}/branches`);
    expect(root.textContent).toContain('This branch has no analysis yet.');
    expect(root.querySelector('[role="alert"]')).toBeNull();
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/analyses'))).toHaveLength(0);
    expect(root.querySelector('q-line-chart svg')?.getAttribute('aria-label')).toBe(
      'Issues: no values yet',
    );
  });

  it('reports a branch that does not exist', async () => {
    const { root } = await render('nope');
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'This item does not exist, or you cannot see it.',
    );
  });

  it('shows the gate warnings, known ones in words and unknown ones as their code', async () => {
    server.on('GET', '/api/v0/analyses/a1', {
      body: analysis({ warnings: ['NEW_CODE_BASELINE_MISSING', '<b>FUTURE_CODE</b>'] }),
    });
    const { root } = await render();
    const warnings = [...root.querySelectorAll('#gate-warnings + ul li')].map(text);
    expect(warnings).toEqual([
      'The fixed new-code baseline no longer exists; the last 30 days are new code instead.',
      '<b>FUTURE_CODE</b>',
    ]);
    expect(root.querySelector('li b')).toBeNull();
  });

  it('explains a gate that did not apply or could not be evaluated', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: projectWithMain({ gateStatus: 'none' }),
    });
    server.on('GET', '/api/v0/analyses/a1', {
      body: analysis({ status: 'none', gate: null, conditions: [], ignoredConditions: [] }),
    });
    let { root } = await render();
    expect(text(root.querySelector('.gate-explanation'))).toBe(
      'No quality gate applies to this project, so nothing was checked.',
    );

    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: projectWithMain({ gateStatus: 'error' }),
    });
    server.on('GET', '/api/v0/analyses/a1', {
      body: analysis({ status: 'error', warnings: ['NEW_CODE_UNAVAILABLE'] }),
    });
    ({ root } = await render());
    expect(text(root.querySelector('.gate-explanation'))).toBe(
      'The gate could not be evaluated, so it does not pass. The warnings below say why.',
    );
    expect(text(root.querySelector('#gate-warnings + ul li'))).toContain('GIT_DEPTH: 0');
  });

  it('shows a gate name that carries markup as text', async () => {
    server.on('GET', '/api/v0/analyses/a1', {
      body: analysis({ gate: { id: 'g', name: '<img src=x onerror="alert(1)">' } }),
    });
    const { root } = await render();
    expect(text(root.querySelector('#gate-heading'))).toBe(
      'Quality gate <img src=x onerror="alert(1)">',
    );
    expect(root.querySelector('img')).toBeNull();
  });

  it('keeps the gate when the measures cannot be loaded, and says so', async () => {
    server.on('GET', '/api/v0/branches/b-main/measures', {
      status: 500,
      body: problem(500, 'INTERNAL'),
    });
    const { root } = await render();
    expect(text(root.querySelector('.gate-word'))).toBe('Failed');
    expect(text(root.querySelector('[role="alert"]'))).toContain('HTTP 500');
    expect([...root.querySelectorAll('.kpi-value')].map(text)).toEqual(['–', '–', '–', '–']);
    expect([...root.querySelectorAll('q-rating .rating-letter')].map(text)).toEqual(['–', '–']);
  });

  it('keeps the gate and the measures when the analyses list and the facets fail', async () => {
    server.on('GET', '/api/v0/branches/b-main/analyses', {
      status: 500,
      body: problem(500, 'INTERNAL'),
    });
    server.on('GET', '/api/v0/issues', { status: 500, body: problem(500, 'INTERNAL') });
    const { root } = await render();
    expect(text(root.querySelector('.gate-word'))).toBe('Failed');
    expect(text(root.querySelector('[data-kpi="issues"] .kpi-value'))).toBe('9');
    expect(text(root.querySelector('[aria-labelledby="recent-heading"] [role="alert"]'))).toContain(
      'HTTP 500',
    );
    expect(
      text(root.querySelector('[aria-labelledby="sources-heading"] [role="alert"]')),
    ).toContain('HTTP 500');
  });

  it('shows no empty states or zero counts while the figures are still loading', async () => {
    const pending = () => new Promise<never>(() => undefined);
    server.on('GET', '/api/v0/branches/b-main/measures', pending);
    server.on('GET', '/api/v0/branches/b-main/analyses', pending);
    server.on('GET', '/api/v0/issues', pending);
    // Pending requests keep the app unstable, so `settle` would wait forever: tick instead.
    const fixture = TestBed.createComponent(BranchOverviewPage);
    fixture.componentRef.setInput('projectId', PROJECT);
    for (let i = 0; i < 5; i++) {
      await new Promise((resolve) => setTimeout(resolve));
      fixture.detectChanges();
    }
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('#gate-heading')).not.toBeNull();
    expect(root.textContent).not.toContain('No analysis yet.');
    expect(root.textContent).not.toContain('No open issues.');
    expect(
      root.querySelectorAll('[aria-labelledby="open-issues-heading"] q-distribution li'),
    ).toHaveLength(0);
  });

  it('shows no zero counts when the measures fail, and a failed history in its own panel', async () => {
    server.on('GET', '/api/v0/branches/b-main/measures', {
      status: 500,
      body: problem(500, 'INTERNAL'),
    });
    server.on('GET', '/api/v0/branches/b-main/measures/history', {
      status: 500,
      body: problem(500, 'INTERNAL'),
    });
    const { root } = await render();
    expect(
      root.querySelectorAll('[aria-labelledby="open-issues-heading"] q-distribution li'),
    ).toHaveLength(0);
    const history = root.querySelector('[aria-labelledby="history-heading"]');
    expect(text(history?.querySelector('[role="alert"]'))).toContain('HTTP 500');
    expect(history?.querySelector('q-line-chart')).toBeNull();
  });

  it('reads the recent analyses from their own history, which a long branch never thins out', async () => {
    const older = {
      ...analysis(),
      id: 'a0b',
      revision: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      analysisDate: '2026-09-08T09:00:00.000Z',
      gateStatus: 'passed',
    };
    server.on('GET', '/api/v0/branches/b-main/analyses', {
      body: page([STALE, analysis(), older]),
    });
    // The whole history skipped a0b (downsampled); the recent one, from a0b on, has it.
    const exact = (metric: string, a0b: number, a1: number) => ({
      metric,
      points: [
        { analysisId: 'a0b', date: older.analysisDate, value: a0b },
        { analysisId: 'a1', date: '2026-09-15T09:00:00.000Z', value: a1 },
      ],
    });
    server.on('GET', '/api/v0/branches/b-main/measures/history', (request) =>
      request.query.get('from') === older.analysisDate
        ? { body: [exact('issues', 8, 9), exact('coverage', 64, 65.7)] }
        : { body: MAIN_HISTORY },
    );
    const { root } = await render();
    const rows = [...root.querySelectorAll('[aria-labelledby="recent-heading"] tbody tr')];
    expect(rows).toHaveLength(2);
    expect(text(rows[1])).toContain('64 %');
    expect(text(rows[0]?.querySelector('td.num q-delta'))).toBe('+1');
    expect(text(root.querySelector('[data-kpi="issues"] q-delta'))).toBe('+1 since Sep 8, 2026');
  });
});

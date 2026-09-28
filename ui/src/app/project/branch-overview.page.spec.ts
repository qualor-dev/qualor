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
      ],
    });
    server.on('GET', '/api/v0/branches/b-main/measures/history', {
      body: [
        {
          metric: 'coverage',
          points: [
            { analysisId: 'a0', date: '2026-09-01T09:00:00.000Z', value: 60.8 },
            { analysisId: 'a1', date: '2026-09-15T09:00:00.000Z', value: 65.7 },
          ],
        },
      ],
    });
    server.on('GET', '/api/v0/branches/b-mr/measures', { body: [] });
    server.on('GET', '/api/v0/branches/b-mr/measures/history', { body: [] });
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
    return fixture.nativeElement as HTMLElement;
  }

  const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

  it('shows the main branch gate with its conditions, measures and trends', async () => {
    const root = await render();
    expect(text(root.querySelector('#gate-heading'))).toBe('Quality gate · Qualor way');
    expect(text(root.querySelector('q-gate-badge'))).toBe('Failed');
    const gate = root.querySelector('[aria-labelledby="gate-heading"]');
    expect([...(gate?.querySelectorAll('tbody td') ?? [])].map(text)).toEqual([
      'Issues on new code is greater than 0',
      '2',
      'Failed',
    ]);
    expect(root.textContent).toContain('Coverage on new code: Skipped for a small change');
    expect(root.textContent).toContain('Analyzed Sep 15, 2026, 9:00 AM UTC, revision cccccccc');
    const overall = [...root.querySelectorAll('[aria-labelledby="overall-heading"] .metric')];
    expect(overall.slice(0, 2).map((m) => [...m.children].map(text))).toEqual([
      ['9', 'Issues'],
      ['E', 'Security rating'],
    ]);
    const newCode = [...root.querySelectorAll('[aria-labelledby="new-code-heading"] .metric')];
    expect(newCode.slice(0, 2).map((m) => [...m.children].map(text))).toEqual([
      ['2', 'Issues on new code'],
      ['100 %', 'Coverage on new code'],
    ]);
    expect(root.querySelectorAll('q-trend-chart')).toHaveLength(4);
    expect(
      root.querySelector('q-trend-chart svg[aria-label^="Coverage went from 60.8 %"]'),
    ).not.toBeNull();
  });

  it("reads the main branch from the project and the gate from the branch's last analysis", async () => {
    // The history's newest entry is a stale upload that failed; the gate is still a1's.
    const root = await render();
    expect(text(root.querySelector('#gate-heading'))).toBe('Quality gate · Qualor way');
    expect(root.textContent).toContain('revision cccccccc');
    expect(root.textContent).not.toContain('dddddddd');
    expect(root.querySelectorAll('[aria-labelledby="gate-heading"] tbody tr')).toHaveLength(1);
    expect(server.requestsTo('GET', '/api/v0/analyses/a1')).toHaveLength(1);
    expect(server.requestsTo('GET', '/api/v0/branches/b-main/analyses')).toHaveLength(0);
    expect(server.requestsTo('GET', `/api/v0/projects/${PROJECT}/branches`)).toHaveLength(0);
  });

  it('titles a merge request by its number and branches, and says when nothing ran', async () => {
    const root = await render('b-mr');
    expect(text(root.querySelector('.branch-name'))).toBe('!42 feature/refund-limits → main');
    expect(root.textContent).toContain('This branch has no analysis yet.');
    expect(root.querySelector('[role="alert"]')).toBeNull();
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/analyses'))).toHaveLength(0);
  });

  it('reports a branch that does not exist', async () => {
    const root = await render('nope');
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'This item does not exist, or you cannot see it.',
    );
  });

  it('shows the gate warnings, known ones in words and unknown ones as their code', async () => {
    server.on('GET', '/api/v0/analyses/a1', {
      body: analysis({ warnings: ['NEW_CODE_BASELINE_MISSING', '<b>FUTURE_CODE</b>'] }),
    });
    const root = await render();
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
    let root = await render();
    expect(text(root.querySelector('.gate-explanation'))).toBe(
      'No quality gate applies to this project, so nothing was checked.',
    );

    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: projectWithMain({ gateStatus: 'error' }),
    });
    server.on('GET', '/api/v0/analyses/a1', {
      body: analysis({ status: 'error', warnings: ['NEW_CODE_UNAVAILABLE'] }),
    });
    root = await render();
    expect(text(root.querySelector('.gate-explanation'))).toBe(
      'The gate could not be evaluated, so it does not pass. The warnings below say why.',
    );
    expect(text(root.querySelector('#gate-warnings + ul li'))).toContain('GIT_DEPTH: 0');
  });

  it('shows a gate name that carries markup as text', async () => {
    server.on('GET', '/api/v0/analyses/a1', {
      body: analysis({ gate: { id: 'g', name: '<img src=x onerror="alert(1)">' } }),
    });
    const root = await render();
    expect(text(root.querySelector('#gate-heading'))).toBe(
      'Quality gate · <img src=x onerror="alert(1)">',
    );
    expect(root.querySelector('img')).toBeNull();
  });

  it('keeps the gate when the measures cannot be loaded, and says so', async () => {
    server.on('GET', '/api/v0/branches/b-main/measures', {
      status: 500,
      body: problem(500, 'INTERNAL'),
    });
    const root = await render();
    expect(text(root.querySelector('q-gate-badge'))).toBe('Failed');
    expect(text(root.querySelector('[role="alert"]'))).toContain('HTTP 500');
    const overall = [...root.querySelectorAll('[aria-labelledby="overall-heading"] .metric-value')];
    expect(overall.map(text)).toEqual(['–', '–', '–', '–', '–', '–']);
  });
});

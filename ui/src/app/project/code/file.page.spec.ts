import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  FakeServer,
  me,
  MEMBER_PROJECT_PERMISSIONS,
  ORG_ID,
  problem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import { SessionStore } from '../../auth/session';
import { FilePage } from './file.page';
import type { FileDetail } from './line-map';

const PROJECT = 'p1';
const MAIN = 'b-main';
const PATH = 'src/my dir/#x?.ts';
const FILE = (b: string) => `/api/v0/branches/${b}/file`;
const URL_OF = (path = PATH, branch = MAIN, fragment = '') =>
  `/?branch=${branch}&path=${encodeURIComponent(path)}${fragment}`;

type Issue = FileDetail['issues'][number];
const issue = (id: string, startLine: number | null, over: Partial<Issue> = {}): Issue => ({
  id,
  ruleKey: 'ts:no-eval',
  message: `Message ${id}`,
  severity: 'high',
  quality: 'security',
  kind: 'issue',
  status: 'open',
  inNewCode: false,
  duplicateOfIssueId: null,
  startLine,
  startColumn: null,
  endLine: null,
  endColumn: null,
  ...over,
});

const DETAIL: FileDetail = {
  path: PATH,
  language: 'typescript',
  kind: 'main',
  analysisId: 'a1',
  measures: {
    lines: 20,
    ncloc: 1500,
    complexity: 12,
    cognitive_complexity: 9,
    coverage: 75,
    duplicated_lines: 4,
    issues: 3,
  },
  coverage: {
    covered: [[1, 10]],
    uncovered: [[11, 12]],
    branches: [
      [3, 2, 1],
      [4, 2, 2],
    ],
  },
  newLines: [[5, 8]],
  duplications: [
    {
      startLine: 2,
      endLine: 5,
      others: [{ path: 'src/b.ts', startLine: 10, endLine: 13 }],
      othersTotal: 1,
    },
    {
      startLine: 14,
      endLine: 18,
      others: [
        { path: 'src/c.ts', startLine: 1, endLine: 5 },
        { path: 'src/d.ts', startLine: 30, endLine: 34 },
      ],
      othersTotal: 5,
    },
  ],
  duplicationsTruncated: false,
  issues: [
    issue('i9', 9, { severity: 'low', status: 'confirmed' }),
    issue('inull', null, { severity: 'info' }),
    issue('i7', 7, { severity: 'blocker', ruleKey: 'ts:sql' }),
  ],
  issuesTruncated: false,
};

function setup(detail: FileDetail | null = DETAIL): FakeServer {
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
  server.on(
    'GET',
    FILE(MAIN),
    detail ? { body: detail } : { status: 404, body: problem(404, 'NOT_FOUND') },
  );
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me());
  return server;
}

async function render(url = URL_OF()) {
  await TestBed.inject(Router).navigateByUrl(url);
  const fixture = TestBed.createComponent(FilePage);
  fixture.componentRef.setInput('projectId', PROJECT);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

const flat = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

describe('FilePage (spec §4.3)', () => {
  it('asks for the file by its path as a query param, odd characters intact', async () => {
    const server = setup();
    await render();
    const requests = server.requestsTo('GET', FILE(MAIN));
    expect(requests).toHaveLength(1);
    expect(requests[0]?.query.get('path')).toBe(PATH);
  });

  it('uses the main branch when the link names none', async () => {
    const server = setup();
    await render(`/?path=${encodeURIComponent(PATH)}`);
    expect(server.requestsTo('GET', FILE(MAIN))).toHaveLength(1);
  });

  it('shows the path with crumbs back to each directory, the language, the kind and the issues link', async () => {
    setup();
    const { root } = await render();
    const crumbs = [...root.querySelectorAll('nav.crumbs a')];
    expect(crumbs.map((a) => [flat(a), a.getAttribute('href')])).toEqual([
      ['Payments', '/projects/p1/code?branch=b-main'],
      ['src', '/projects/p1/code?branch=b-main&dir=src'],
      ['my dir', '/projects/p1/code?branch=b-main&dir=src%2Fmy%20dir'],
    ]);
    expect(flat(root.querySelector('nav.crumbs [aria-current="page"]'))).toBe('#x?.ts');
    expect(flat(root.querySelector('.file-meta'))).toContain('typescript');
    expect(flat(root.querySelector('.file-meta .badge'))).toBe('main');
    expect(root.querySelector('a.issues-in-file')?.getAttribute('href')).toBe(
      `/projects/p1/issues?branch=b-main&path=${encodeURIComponent(PATH)}`,
    );
  });

  it('shows the tiles: lines of code, complexities, coverage with conditions, duplicated lines, issues', async () => {
    setup();
    const { root } = await render();
    const tile = (name: string) => flat(root.querySelector(`[data-tile="${name}"] .kpi-value`));
    expect(tile('ncloc')).toBe('1,500');
    expect(tile('complexity')).toBe('12');
    expect(tile('cognitive_complexity')).toBe('9');
    expect(tile('coverage')).toBe('75.0% · 3 of 4 conditions');
    expect(tile('duplicated_lines')).toBe('4');
    expect(tile('issues')).toBe('3');
    expect(flat(root.querySelector('[data-tile="cognitive_complexity"] .kpi-label'))).toBe(
      'Cognitive complexity',
    );
  });

  it('shows coverage without conditions, and a dash without coverage', async () => {
    setup({
      ...DETAIL,
      measures: { ...DETAIL.measures, coverage: null },
      coverage: null,
    });
    const { root } = await render();
    expect(flat(root.querySelector('[data-tile="coverage"] .kpi-value'))).toBe('—');
  });

  it('says the source stays in the repository, next to the line map', async () => {
    setup();
    const { root } = await render();
    expect(root.querySelector('q-line-map svg[role="img"]')).not.toBeNull();
    expect(root.textContent).toContain('Source code stays in your repository.');
  });

  it('lists duplicated blocks with links to the other side at its first line, and how many more', async () => {
    setup();
    const { root } = await render();
    const items = [...root.querySelectorAll('.dups li')];
    expect(items.map(flat)).toEqual([
      'Lines 2–5 ↔ src/b.ts 10–13',
      'Lines 14–18 ↔ src/c.ts 1–5, src/d.ts 30–34 +3 more',
    ]);
    const other = items[0]!.querySelector('a.dup-other');
    expect(other?.getAttribute('href')).toBe(
      '/projects/p1/code/file?branch=b-main&path=src%2Fb.ts#L10',
    );
    expect(root.textContent).not.toContain('Only the first blocks are listed.');
  });

  it('notes a truncated duplication list', async () => {
    setup({ ...DETAIL, duplicationsTruncated: true });
    const { root } = await render();
    expect(root.textContent).toContain('Only the first blocks are listed.');
  });

  it('lists the issues by line, each linking to its page', async () => {
    setup();
    const { root } = await render();
    const rows = [...root.querySelectorAll('.issues-table tbody tr')];
    expect(rows.map((r) => flat(r.querySelector('td')))).toEqual(['7', '9', '—']);
    expect(rows.map((r) => r.querySelector('a.issue-link')?.getAttribute('href'))).toEqual([
      '/projects/p1/issues/i7',
      '/projects/p1/issues/i9',
      '/projects/p1/issues/inull',
    ]);
    const first = [...rows[0]!.querySelectorAll('td')].map(flat);
    expect(first).toEqual(['7', 'Blocker', 'Message i7', 'ts:sql', 'Open']);
    expect(rows[0]!.querySelector('.badge-blocker')).not.toBeNull();
    expect(root.textContent).not.toContain('Only the first 500 issues are listed.');
  });

  it('notes a truncated issue list', async () => {
    setup({ ...DETAIL, issuesTruncated: true });
    const { root } = await render();
    expect(root.textContent).toContain('Only the first 500 issues are listed.');
  });

  it('highlights the line the fragment names', async () => {
    setup();
    const { root } = await render(URL_OF(PATH, MAIN, '#L7'));
    const hl = root.querySelector('q-line-map rect.hl');
    expect(hl?.getAttribute('y')).toBe('6');
  });

  it('opens an issue from its marker on the map', async () => {
    setup();
    const { fixture, root } = await render();
    root
      .querySelector('q-line-map rect.marker[data-issue="i9"]')!
      .dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/projects/p1/issues/i9');
  });

  it('shows an empty state with a link back to the directory for a file not in the analysis', async () => {
    setup(null);
    const { root } = await render();
    expect(root.textContent).toContain("This file is not in the branch's latest analysis.");
    expect(root.querySelector('.empty-state a')?.getAttribute('href')).toBe(
      '/projects/p1/code?branch=b-main&dir=src%2Fmy%20dir',
    );
    expect(root.querySelector('q-line-map')).toBeNull();
  });

  it('shows the not-found empty state without a path, and asks for nothing', async () => {
    const server = setup();
    const { root } = await render('/?branch=b-main');
    expect(root.textContent).toContain("This file is not in the branch's latest analysis.");
    expect(root.querySelector('.empty-state a')?.getAttribute('href')).toBe(
      '/projects/p1/code?branch=b-main',
    );
    expect(server.requestsTo('GET', FILE(MAIN))).toHaveLength(0);
  });

  it('shows the not-found empty state when no branch can be resolved', async () => {
    const server = setup();
    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: {
        id: PROJECT,
        organizationId: ORG_ID,
        key: 'acme/payments',
        name: 'Payments',
        mainBranchName: 'main',
        mainBranch: null,
        permissions: [...MEMBER_PROJECT_PERMISSIONS],
      },
    });
    const { root } = await render('/?path=src%2Fa.ts');
    expect(root.textContent).toContain("This file is not in the branch's latest analysis.");
    expect(server.requestsTo('GET', FILE(MAIN))).toHaveLength(0);
  });

  it('shows another error as an alert', async () => {
    const server = setup();
    server.on('GET', FILE(MAIN), { status: 500, body: problem(500, 'INTERNAL') });
    const { root } = await render();
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
    expect(root.querySelector('q-line-map')).toBeNull();
  });
});

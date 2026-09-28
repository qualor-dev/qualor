import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, page, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import type { Branch } from './branches';
import { BranchesPage } from './branches.page';

const PROJECT = 'p1';
const branch = (id: string, overrides: Partial<Branch> = {}): Branch => ({
  id,
  projectId: PROJECT,
  kind: 'branch',
  name: id,
  isMain: false,
  mrSourceBranch: null,
  mrTargetBranch: null,
  mrTitle: null,
  mrUrl: null,
  lastAnalysisId: null,
  lastAnalyzedAt: null,
  gateStatus: null,
  measures: {},
  ...overrides,
});

describe('BranchesPage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [BranchesPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render() {
    const fixture = TestBed.createComponent(BranchesPage);
    fixture.componentRef.setInput('projectId', PROJECT);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();
  const rows = (root: HTMLElement) =>
    [...root.querySelectorAll('tbody tr')].map((tr) => [...tr.querySelectorAll('td')].map(text));

  it('lists branches and merge requests with gate, new-code measures and a UTC date', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, {
      body: page([
        branch('main', {
          isMain: true,
          gateStatus: 'failed',
          lastAnalyzedAt: '2026-09-15T09:00:00.000Z',
          measures: { new_issues: 2, new_coverage: 81.25 },
        }),
        branch('mr', {
          kind: 'merge_request',
          name: '42',
          mrSourceBranch: 'feature/x',
          mrTargetBranch: 'main',
        }),
      ]),
    });
    const { root } = await render();
    expect(rows(root)).toEqual([
      ['mainMain branch', 'Failed', '2', '81.3 %', 'Sep 15, 2026, 9:00 AM UTC'],
      ['!42 feature/x → main', 'Not analyzed', '–', '–', 'Never'],
    ]);
    expect(root.querySelector('tbody a')?.getAttribute('href')).toBe('/projects/p1/branches/main');
    const query = server.requestsTo('GET', `/api/v0/projects/${PROJECT}/branches`)[0]!.query;
    expect([...query.keys()]).toEqual(['limit']);
    expect(query.get('limit')).toBe('50');
  });

  it("shows a merge request's GitLab title, and links to GitLab only over http(s) (scm.md §8)", async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, {
      body: page([
        branch('mr1', {
          kind: 'merge_request',
          name: '12',
          mrTitle: 'Refund <b>limits</b>',
          mrUrl: 'https://gitlab.example.com/acme/api/-/merge_requests/12',
        }),
        branch('mr2', {
          kind: 'merge_request',
          name: '13',
          mrTitle: null,
          mrUrl: 'javascript:alert(1)',
        }),
      ]),
    });
    const { root } = await render();
    const [first, second] = [...root.querySelectorAll('tbody tr')];
    expect(first?.textContent).toContain('Refund <b>limits</b>');
    expect(first?.querySelector('b')).toBeNull();
    const link = [...(first?.querySelectorAll('a') ?? [])].find(
      (a) => text(a) === 'Open in GitLab',
    );
    expect(link?.getAttribute('href')).toBe(
      'https://gitlab.example.com/acme/api/-/merge_requests/12',
    );
    expect(link?.getAttribute('rel')).toBe('noopener noreferrer');
    // Each link names its merge request, and keeps the visible words in its name.
    expect(link?.getAttribute('aria-label')).toBe('Open in GitLab: Refund <b>limits</b>');
    expect(second?.textContent).not.toContain('Open in GitLab');
  });

  it('shows every kind again when the route reuses the page for another project', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([branch('a')]) });
    server.on('GET', '/api/v0/projects/p2/branches', {
      body: page([branch('x', { projectId: 'p2' })]),
    });
    const { fixture, root } = await render();
    const select = root.querySelector<HTMLSelectElement>('#branch-kind')!;
    select.value = 'merge_request';
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    fixture.componentRef.setInput('projectId', 'p2');
    await settle(fixture);
    const requests = server.requestsTo('GET', '/api/v0/projects/p2/branches');
    expect(requests).toHaveLength(1);
    expect(requests[0]?.query.get('kind')).toBeNull();
    expect(select.value).toBe('');
  });

  it('filters by kind, pages with "Load more", and says what is missing for the filter', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, (request) => {
      const kind = request.query.get('kind');
      if (kind === 'merge_request') return { body: page([]) };
      if (kind === 'branch') return { body: page([]) };
      return request.query.get('cursor') === 'c2'
        ? { body: page([branch('b')]) }
        : { body: page([branch('a')], 'c2') };
    });
    const { fixture, root } = await render();
    [...root.querySelectorAll('button')].find((b) => text(b) === 'Load more')!.click();
    await settle(fixture);
    expect(rows(root).map((r) => r[0])).toEqual(['a', 'b']);

    const select = root.querySelector<HTMLSelectElement>('#branch-kind')!;
    const choose = async (value: string) => {
      select.value = value;
      select.dispatchEvent(new Event('change'));
      await settle(fixture);
    };
    await choose('merge_request');
    expect(
      server.requestsTo('GET', `/api/v0/projects/${PROJECT}/branches`).at(-1)?.query.get('kind'),
    ).toBe('merge_request');
    expect(text(root.querySelector('tbody td'))).toBe('No merge requests.');
    await choose('branch');
    expect(text(root.querySelector('tbody td'))).toBe('No branches.');
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([]) });
    await choose('');
    expect(text(root.querySelector('tbody td'))).toBe('Nothing analyzed yet.');
  });
});

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
  VIEWER_PROJECT_PERMISSIONS,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { type Issue, IssuesPage } from './issues.page';

/** The project, with a maintainer's permissions on it (rbac-audit.md §16). */
const PROJECT = { id: 'p1', organizationId: ORG_ID, permissions: [...MEMBER_PROJECT_PERMISSIONS] };

const XSS = 'Avoid <img src=x onerror="alert(1)"> here';

function issue(id: string, overrides: Partial<Issue> = {}): Issue {
  return {
    id,
    projectId: 'p1',
    branchId: 'b-main',
    rule: { key: 'eslint:eqeqeq', name: 'Require ===', engine: 'eslint' },
    severity: 'high',
    severityOverridden: false,
    quality: 'reliability',
    kind: 'issue',
    status: 'open',
    message: `Message ${id}`,
    path: 'src/a.ts',
    startLine: 12,
    startColumn: null,
    endLine: null,
    endColumn: null,
    inNewCode: false,
    duplicateOfIssueId: null,
    firstSeenAt: '2026-09-15T09:00:00.000Z',
    resolvedAt: null,
    closedAt: null,
    createdAt: '2026-09-15T09:00:00.000Z',
    updatedAt: '2026-09-15T09:00:00.000Z',
    ...overrides,
  };
}

describe('IssuesPage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    server.on('GET', '/api/v0/projects/p1/branches', {
      body: page([
        {
          id: 'b-main',
          projectId: 'p1',
          kind: 'branch',
          name: 'main',
          isMain: true,
          mrSourceBranch: null,
          mrTargetBranch: null,
          mrTitle: null,
          mrUrl: null,
          lastAnalysisId: null,
          lastAnalyzedAt: null,
          gateStatus: null,
          measures: {},
        },
      ]),
    });
    server.on('GET', '/api/v0/issues', {
      body: {
        items: [issue('i1', { message: XSS, inNewCode: true }), issue('i2')],
        nextCursor: null,
        facets: {
          severity: [{ value: 'high', count: 2 }],
          status: [{ value: 'open', count: 2 }],
          rule: [{ value: 'eslint:eqeqeq', count: 2 }],
        },
      },
    });
    server.on('GET', '/api/v0/projects/p1', { body: PROJECT });
    TestBed.configureTestingModule({
      imports: [IssuesPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render() {
    const fixture = TestBed.createComponent(IssuesPage);
    fixture.componentRef.setInput('projectId', 'p1');
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  const facet = (root: HTMLElement, legend: string) =>
    root.querySelector(`fieldset[data-facet="${legend}"]`)?.querySelectorAll('label') ?? [];
  const facetText = (root: HTMLElement, legend: string) =>
    [...facet(root, legend)].map((l) =>
      [...l.querySelectorAll('span')].map((s) => s.textContent?.trim()).join(' '),
    );

  async function chooseTarget(root: HTMLElement, fixture: { whenStable(): Promise<unknown> }) {
    const target = root.querySelector<HTMLSelectElement>('#bulk-target')!;
    target.value = 'resolved';
    target.dispatchEvent(new Event('change'));
    await settle(fixture);
  }

  it('lists the main branch open issues with facets, and shows server text as text', async () => {
    const { root } = await render();
    const query = server.requestsTo('GET', '/api/v0/issues')[0]?.query;
    expect(query?.get('branchId')).toBe('b-main');
    expect(query?.getAll('status')).toEqual(['open']);
    expect(query?.get('facets')).toBe('severity,quality,status,rule,engine');
    const links = [...root.querySelectorAll('tbody a')];
    expect(links[0]?.textContent).toBe(XSS);
    expect(root.querySelector('tbody img')).toBeNull();
    expect(facetText(root, 'severity')).toEqual([
      'Blocker 0',
      'High 2',
      'Medium 0',
      'Low 0',
      'Info 0',
    ]);
    // The status filter is active (open): only the selected value shows a count.
    expect(facetText(root, 'status').slice(0, 2)).toEqual(['Open 2', 'Resolved']);
  });

  it('puts a facet choice in the URL', async () => {
    const { fixture, root } = await render();
    const high = [...facet(root, 'severity')][1]?.querySelector('input');
    high!.click();
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?severity=high');
  });

  it('clamps a crafted URL instead of sending a query the server rejects', async () => {
    await TestBed.inject(Router).navigateByUrl(
      `/?branch=not-a-uuid&severity=nope&rule=${'r'.repeat(600)}&q=${'x'.repeat(300)}&includeDuplicates=true`,
    );
    const { root } = await render();
    const query = server.requestsTo('GET', '/api/v0/issues')[0]?.query;
    expect(query?.get('branchId')).toBe('b-main');
    expect(query?.getAll('severity')).toEqual([]);
    expect(query?.getAll('rule')).toEqual([]);
    expect(query?.get('q')).toHaveLength(200);
    expect(query?.get('includeDuplicates')).toBe('true');
    expect(root.querySelector<HTMLInputElement>('#issues-duplicates')?.checked).toBe(true);
  });

  it('changes the status of the selected issues and reports partial failures', async () => {
    server.on('POST', '/api/v0/issues/bulk-transition', {
      body: { succeeded: ['i1'], failed: [{ id: 'i2', code: 'INVALID_TRANSITION' }] },
    });
    const { fixture, root } = await render();
    root.querySelector<HTMLInputElement>('thead input[type="checkbox"]')!.click();
    const target = root.querySelector<HTMLSelectElement>('#bulk-target')!;
    target.value = 'false_positive';
    target.dispatchEvent(new Event('change'));
    await settle(fixture);
    const submit = root.querySelector<HTMLButtonElement>('form.bulk button[type="submit"]')!;
    expect(submit.disabled).toBe(true); // a false positive needs a comment
    const comment = root.querySelector<HTMLInputElement>('#bulk-comment')!;
    comment.value = 'Test data';
    comment.dispatchEvent(new Event('input'));
    await settle(fixture);
    expect(root.querySelector('form.bulk .label')?.textContent?.trim()).toBe('2 issues selected');
    submit.click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/issues/bulk-transition')[0]?.body).toEqual({
      ids: ['i1', 'i2'],
      to: 'false_positive',
      comment: 'Test data',
    });
    // Intended text change (fix round 1): plural forms, and why the rest did not change.
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      '1 issue changed. 1 issue cannot change to this status; it stays selected.',
    );
    expect(root.querySelector('form.bulk .label')?.textContent?.trim()).toBe('1 issue selected');
    // The submit button is disabled now; focus is on the result, not lost to the body.
    expect(document.activeElement).toBe(root.querySelector('[role="status"]'));
  });

  it('refuses a selection over the 500 ids a bulk change takes', async () => {
    server.on('GET', '/api/v0/issues', {
      body: {
        items: Array.from({ length: 501 }, (_, i) => issue(`i${i}`)),
        nextCursor: null,
        facets: {},
      },
    });
    const { fixture, root } = await render();
    root.querySelector<HTMLInputElement>('thead input[type="checkbox"]')!.click();
    await chooseTarget(root, fixture);
    const submit = root.querySelector<HTMLButtonElement>('form.bulk button[type="submit"]')!;
    expect(root.querySelector('form.bulk .label')?.textContent?.trim()).toBe('501 issues selected');
    expect(submit.disabled).toBe(true);
    expect(root.querySelector('#bulk-limit')?.textContent).toContain(
      'At most 500 issues change status at once',
    );
    submit.closest('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/issues/bulk-transition')).toHaveLength(0);
  });

  it('offers a retry after 503 CONCURRENCY_CONFLICT, which sends the same change again', async () => {
    let calls = 0;
    server.on('POST', '/api/v0/issues/bulk-transition', () =>
      ++calls === 1
        ? {
            status: 503,
            headers: { 'retry-after': '1' },
            body: problem(503, 'CONCURRENCY_CONFLICT'),
          }
        : { body: { succeeded: ['i1', 'i2'], failed: [] } },
    );
    const { fixture, root } = await render();
    root.querySelector<HTMLInputElement>('thead input[type="checkbox"]')!.click();
    await chooseTarget(root, fixture);
    root.querySelector<HTMLButtonElement>('form.bulk button[type="submit"]')!.click();
    await settle(fixture);
    expect(root.querySelector('form.bulk [role="status"]')?.textContent).toContain(
      'Try again in 1 s.',
    );
    const retry = root.querySelector<HTMLButtonElement>('form.bulk button.retry')!;
    expect(retry.textContent?.trim()).toBe('Try again');
    // Not before Retry-After has passed.
    expect(retry.disabled).toBe(true);
    retry.click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/issues/bulk-transition')).toHaveLength(1);
    await new Promise((resolve) => setTimeout(resolve, 1_050));
    await settle(fixture);
    expect(retry.disabled).toBe(false);
    retry.click();
    await settle(fixture);
    const sent = server.requestsTo('POST', '/api/v0/issues/bulk-transition');
    expect(sent).toHaveLength(2);
    expect(sent[1]?.body).toEqual(sent[0]?.body);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('2 issues changed.');
    expect(root.querySelector('form.bulk button.retry')).toBeNull();
  });

  it('takes the facets from the latest query, never from an older answer that arrives late', async () => {
    let release: () => void = () => undefined;
    server.on('GET', '/api/v0/issues', (request) => {
      const high = request.query.getAll('severity').includes('high');
      const reply = {
        body: {
          items: [issue('i1')],
          nextCursor: null,
          facets: { severity: [{ value: 'high', count: high ? 5 : 2 }] },
        },
      };
      return high ? reply : new Promise((resolve) => (release = () => resolve(reply)));
    });
    const { fixture, root } = await render();
    [...facet(root, 'severity')][1]!.querySelector('input')!.click();
    await settle(fixture);
    release();
    await settle(fixture);
    expect(facetText(root, 'severity')[1]).toBe('High 5');
  });

  it('keeps search text that was typed but not sent when another filter changes', async () => {
    const { fixture, root } = await render();
    const search = root.querySelector<HTMLInputElement>('#issues-search')!;
    search.value = 'refund';
    search.dispatchEvent(new Event('input'));
    [...facet(root, 'severity')][1]!.querySelector('input')!.click();
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?severity=high');
    expect(search.value).toBe('refund');
    // What the box shows is what a search then sends.
    search.closest('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?severity=high&q=refund');
  });

  it('offers only the statuses the listed issues can go to', async () => {
    const { fixture, root } = await render();
    const options = () =>
      [...root.querySelectorAll('#bulk-target option')].map((o) => o.textContent?.trim());
    expect(options()).toEqual(['Resolve', "Won't fix", 'False positive']);
    await TestBed.inject(Router).navigateByUrl('/?status=resolved');
    await settle(fixture);
    expect(options()).toEqual(['Reopen']);
    await TestBed.inject(Router).navigateByUrl('/?status=closed');
    await settle(fixture);
    expect(root.querySelector('#bulk-target')).toBeNull();
    expect(root.querySelector('form.bulk')?.textContent).toContain(
      'Issues with these statuses cannot change status.',
    );
  });

  it('says which issues no longer exist, apart from those that cannot change', async () => {
    server.on('POST', '/api/v0/issues/bulk-transition', {
      body: {
        succeeded: [],
        failed: [
          { id: 'i1', code: 'NOT_FOUND' },
          { id: 'i2', code: 'NOT_FOUND' },
        ],
      },
    });
    const { fixture, root } = await render();
    root.querySelector<HTMLInputElement>('thead input[type="checkbox"]')!.click();
    await chooseTarget(root, fixture);
    root.querySelector<HTMLButtonElement>('form.bulk button[type="submit"]')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      '0 issues changed. 2 issues no longer exist or are no longer visible to you.',
    );
    expect(root.querySelector('form.bulk .label')?.textContent?.trim()).toBe('No issue selected');
  });

  it("names issues the caller's role may not change (FORBIDDEN)", async () => {
    server.on('POST', '/api/v0/issues/bulk-transition', {
      body: {
        succeeded: [],
        failed: [
          { id: 'i1', code: 'FORBIDDEN' },
          { id: 'i2', code: 'FORBIDDEN' },
        ],
      },
    });
    const { fixture, root } = await render();
    root.querySelector<HTMLInputElement>('thead input[type="checkbox"]')!.click();
    await chooseTarget(root, fixture);
    root.querySelector<HTMLButtonElement>('form.bulk button[type="submit"]')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      '0 issues changed. 2 issues cannot be changed with your role in their project.',
    );
  });

  it('offers no selection and no bulk change to a viewer (rbac-audit.md §17)', async () => {
    server.on('GET', '/api/v0/projects/p1', {
      body: { ...PROJECT, permissions: [...VIEWER_PROJECT_PERMISSIONS] },
    });
    const { root } = await render();
    expect(root.textContent).toContain('Avoid');
    expect(root.querySelector('form.bulk')).toBeNull();
    expect(root.querySelectorAll('input[type="checkbox"][aria-label]')).toHaveLength(0);
  });

  it('finds the main branch when it is not on the first page of branches', async () => {
    server.on('GET', '/api/v0/projects/p1/branches', {
      body: page([], 'more'),
    });
    server.on('GET', '/api/v0/projects/p1', {
      body: {
        ...PROJECT,
        mainBranch: { id: 'b-far', name: 'trunk', gateStatus: null, lastAnalysisId: null },
      },
    });
    const { root } = await render();
    expect(server.requestsTo('GET', '/api/v0/issues')[0]?.query.get('branchId')).toBe('b-far');
    const select = root.querySelector<HTMLSelectElement>('#issues-branch')!;
    expect([...select.options].map((o) => [o.value, o.textContent, o.selected])).toEqual([
      ['b-far', 'trunk', true],
    ]);
  });

  it('looks up a branch the URL names past the first page of branches', async () => {
    const far = '0190a6c2-0000-7000-8000-0000000000f1';
    server.on('GET', '/api/v0/projects/p1/branches', (request) => ({
      body: request.query.get('cursor')
        ? page([
            {
              id: far,
              projectId: 'p1',
              kind: 'merge_request',
              name: '7',
              isMain: false,
              mrSourceBranch: 'feature/x',
              mrTargetBranch: 'main',
              mrTitle: null,
              mrUrl: null,
              lastAnalysisId: null,
              lastAnalyzedAt: null,
              gateStatus: null,
              measures: {},
            },
          ])
        : page([], 'next'),
    }));
    await TestBed.inject(Router).navigateByUrl(`/?branch=${far}`);
    const { root } = await render();
    expect(server.requestsTo('GET', '/api/v0/issues')[0]?.query.get('branchId')).toBe(far);
    const select = root.querySelector<HTMLSelectElement>('#issues-branch')!;
    expect(select.selectedOptions[0]?.textContent).toBe('!7 feature/x → main');
  });
});

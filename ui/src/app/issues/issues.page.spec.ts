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

  async function selectAll(root: HTMLElement, fixture: { whenStable(): Promise<unknown> }) {
    root.querySelector<HTMLInputElement>('thead input[type="checkbox"]')!.click();
    await settle(fixture);
  }

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
    await selectAll(root, fixture);
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
    await selectAll(root, fixture);
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
    await selectAll(root, fixture);
    await chooseTarget(root, fixture);
    root.querySelector<HTMLButtonElement>('form.bulk button[type="submit"]')!.click();
    await settle(fixture);
    // Intended change (step 4): the live region sits outside the bar, which shows on selection.
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Try again in 1 s.');
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
    // The bar shows on selection, and a new query clears the selection.
    await selectAll(root, fixture);
    expect(options()).toEqual(['Resolve', "Won't fix", 'False positive']);
    await TestBed.inject(Router).navigateByUrl('/?status=resolved');
    await settle(fixture);
    await selectAll(root, fixture);
    expect(options()).toEqual(['Reopen']);
    await TestBed.inject(Router).navigateByUrl('/?status=closed');
    await settle(fixture);
    await selectAll(root, fixture);
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
    await selectAll(root, fixture);
    await chooseTarget(root, fixture);
    root.querySelector<HTMLButtonElement>('form.bulk button[type="submit"]')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      '0 issues changed. 2 issues no longer exist or are no longer visible to you.',
    );
    // Intended change (step 4): nothing stays selected, so the bar goes; the result keeps focus.
    expect(root.querySelector('form.bulk')).toBeNull();
    expect(document.activeElement).toBe(root.querySelector('[role="status"]'));
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
    await selectAll(root, fixture);
    await chooseTarget(root, fixture);
    root.querySelector<HTMLButtonElement>('form.bulk button[type="submit"]')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      '0 issues changed. 2 issues cannot be changed with your role in their project.',
    );
  });

  it('shows the bulk bar only while issues are selected', async () => {
    const { fixture, root } = await render();
    expect(root.querySelector('form.bulk')).toBeNull();
    const row = root.querySelector<HTMLInputElement>('tbody input[type="checkbox"]')!;
    row.click();
    await settle(fixture);
    expect(root.querySelector('form.bulk .label')?.textContent?.trim()).toBe('1 issue selected');
    row.click();
    await settle(fixture);
    expect(root.querySelector('form.bulk')).toBeNull();
  });

  it('heads the list with the number of matching issues and their severities', async () => {
    const { root } = await render();
    expect(root.querySelector('#issues-heading')?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
      'Issues 2',
    );
    const legend = [...root.querySelectorAll('.dist-legend li')].map((li) =>
      li.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(legend).toEqual(['High 2']);
  });

  it('shows when each issue was first seen as the day, the full time in its title', async () => {
    const { root } = await render();
    const seen = root.querySelector('tbody tr td:last-child span');
    expect(seen?.textContent?.trim()).toBe('Sep 15, 2026');
    expect(seen?.getAttribute('title')).toBe('Sep 15, 2026, 9:00 AM UTC');
  });

  it('clears a facet group back to its default, offered only while the group is filtered', async () => {
    await TestBed.inject(Router).navigateByUrl('/?severity=high&status=resolved');
    const { fixture, root } = await render();
    const clear = (group: string) =>
      root.querySelector<HTMLButtonElement>(`[data-group="${group}"] .facet-clear`);
    expect(clear('quality')).toBeNull();
    expect(clear('severity')?.getAttribute('aria-label')).toBe('Clear the Severity filter');
    clear('severity')!.click();
    await settle(fixture);
    expect(TestBed.inject(Router).url).toBe('/?status=resolved');
    clear('status')!.click();
    await settle(fixture);
    // Open is the status filter's default: nothing to clear then.
    expect(TestBed.inject(Router).url).toBe('/');
    expect(clear('status')).toBeNull();
  });

  it('collapses and expands a facet group', async () => {
    const { fixture, root } = await render();
    const toggle = root.querySelector<HTMLButtonElement>('[data-group="rule"] .facet-toggle')!;
    const fieldset = root.querySelector<HTMLFieldSetElement>('fieldset[data-facet="rule"]')!;
    expect(toggle.textContent?.trim()).toBe('Rule');
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(toggle.getAttribute('aria-controls')).toBe(fieldset.id);
    toggle.click();
    await settle(fixture);
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(fieldset.hidden).toBe(true);
    toggle.click();
    await settle(fixture);
    expect(fieldset.hidden).toBe(false);
  });

  it('floats the bulk bar over the page, so checking an issue never moves the list', async () => {
    const { fixture, root } = await render();
    root.querySelector<HTMLInputElement>('tbody input[type="checkbox"]')!.click();
    await settle(fixture);
    // styles.css .float-bar floats it over the page's bottom edge; the e2e checks the list stays put.
    expect(root.querySelector('form.bulk')?.classList).toContain('float-bar');
  });

  it('keeps focus on a group after Clear, or on the filters when the group goes', async () => {
    await TestBed.inject(Router).navigateByUrl('/?severity=high&path=src%2F');
    const { fixture, root } = await render();
    root.querySelector<HTMLButtonElement>('[data-group="severity"] .facet-clear')!.click();
    await settle(fixture);
    expect(document.activeElement).toBe(
      root.querySelector('[data-group="severity"] .facet-toggle'),
    );
    root.querySelector<HTMLButtonElement>('[data-group="path"] .facet-clear')!.click();
    await settle(fixture);
    expect(root.querySelector('[data-group="path"]')).toBeNull();
    expect(document.activeElement).toBe(root.querySelector('#filters-heading'));
  });

  it('lets a long unbroken word in a message wrap instead of widening the table', async () => {
    const { root } = await render();
    expect(getComputedStyle(root.querySelector('.issue-message')!).overflowWrap).toBe('anywhere');
  });

  it('draws each facet count as a bar scaled to the largest count of its group', async () => {
    const { root } = await render();
    const fills = (group: string) =>
      [...root.querySelectorAll<HTMLElement>(`fieldset[data-facet="${group}"] .facet-fill`)].map(
        (f) => f.style.width,
      );
    expect(fills('severity')).toEqual(['0%', '100%', '0%', '0%', '0%']);
    // The status filter is active: only its chosen value has a count, so only it has a bar.
    expect(fills('status')).toEqual(['100%']);
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

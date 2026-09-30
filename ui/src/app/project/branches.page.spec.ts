import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  MEMBER_PROJECT_PERMISSIONS,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
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
  const kindButton = (root: HTMLElement, name: string) =>
    [...root.querySelectorAll<HTMLButtonElement>('.segmented button')].find(
      (b) => text(b) === name,
    )!;
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
      ['main Main branch', 'Failed', '2', '81.3 %', 'Sep 15, 2026'],
      ['!42 feature/x → main', 'Not analyzed', '–', '–', 'Never'],
    ]);
    // The day in the table, the full time on hover.
    expect(root.querySelector('tbody tr td:last-child span')?.getAttribute('title')).toBe(
      'Sep 15, 2026, 9:00 AM UTC',
    );
    expect(root.querySelector('tbody a')?.getAttribute('href')).toBe('/projects/p1/branches/main');
    const query = server.requestsTo('GET', `/api/v0/projects/${PROJECT}/branches`)[0]!.query;
    expect([...query.keys()]).toEqual(['limit']);
    expect(query.get('limit')).toBe('50');
  });

  it('draws the new-code coverage bar at 0 %, and none without a value', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, {
      body: page([branch('zero', { measures: { new_coverage: 0 } }), branch('none')]),
    });
    const { root } = await render();
    const [first, second] = [...root.querySelectorAll('tbody tr')];
    expect(first?.querySelector<HTMLElement>('.cov-bar > span')?.style.width).toBe('0%');
    expect(second?.querySelector('.cov-bar')).toBeNull();
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
    // Intended change (maintainer, 2026-09-29): the link names the host it leads to, which is
    // right for a GitLab merge request and a GitHub pull request alike.
    const link = [...(first?.querySelectorAll('a') ?? [])].find(
      (a) => text(a) === 'Open on gitlab.example.com',
    );
    expect(link?.getAttribute('href')).toBe(
      'https://gitlab.example.com/acme/api/-/merge_requests/12',
    );
    expect(link?.getAttribute('rel')).toBe('noopener noreferrer');
    // Each link names its merge request, and keeps the visible words in its name.
    expect(link?.getAttribute('aria-label')).toBe(
      'Open on gitlab.example.com: Refund <b>limits</b>',
    );
    expect(second?.textContent).not.toContain('Open on');
  });

  it('names a GitHub pull request link by its host too', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, {
      body: page([
        branch('pr7', {
          kind: 'merge_request',
          name: '7',
          mrTitle: 'Bump dependencies',
          mrUrl: 'https://github.com/acme/api/pull/7',
        }),
      ]),
    });
    const { root } = await render();
    const link = root.querySelector('tbody a.external-link');
    expect(text(link)).toBe('Open on github.com');
    expect(link?.getAttribute('aria-label')).toBe('Open on github.com: Bump dependencies');
  });

  describe('deleting a branch or merge request', () => {
    const MAIN = branch('b-main', { name: 'main', isMain: true });
    const FEATURE = branch('b-x', { name: 'feature/x' });
    const MR = branch('b-mr', {
      kind: 'merge_request',
      name: '42',
      mrSourceBranch: 'feature/x',
      mrTargetBranch: 'main',
    });
    const project = (permissions: string[]) => ({
      body: { id: PROJECT, organizationId: ORG_ID, permissions },
    });
    const MAY_DELETE = [...MEMBER_PROJECT_PERMISSIONS, 'project.branches.delete'];
    const buttonIn = (root: Element, name: string) =>
      [...root.querySelectorAll<HTMLButtonElement>('button')].find((b) => text(b) === name)!;

    it('is offered on every branch but the main one, to those who may delete branches', async () => {
      server.on('GET', `/api/v0/projects/${PROJECT}`, project(MAY_DELETE));
      server.on('GET', `/api/v0/projects/${PROJECT}/branches`, {
        body: page([MAIN, FEATURE, MR]),
      });
      const { root } = await render();
      const deletes = [...root.querySelectorAll('tbody button.row-delete')];
      expect(deletes.map(text)).toEqual(['Delete', 'Delete']);
      expect(deletes.map((b) => b.getAttribute('aria-label'))).toEqual([
        'Delete feature/x',
        'Delete !42 feature/x → main',
      ]);
    });

    it('is not offered to a member who may not delete branches', async () => {
      server.on('GET', `/api/v0/projects/${PROJECT}`, project([...MEMBER_PROJECT_PERMISSIONS]));
      server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([MAIN, FEATURE]) });
      const { root } = await render();
      expect(root.querySelector('tbody button.row-delete')).toBeNull();
      expect(root.querySelector('dialog')).toBeNull();
    });

    it('asks first, deletes on confirmation, then says so and lists the rest', async () => {
      let deleted = false;
      server.on('GET', `/api/v0/projects/${PROJECT}`, project(MAY_DELETE));
      server.on('GET', `/api/v0/projects/${PROJECT}/branches`, () => ({
        body: page(deleted ? [MAIN] : [MAIN, FEATURE]),
      }));
      server.on('DELETE', '/api/v0/branches/b-x', () => {
        deleted = true;
        return { status: 204 };
      });
      const { fixture, root } = await render();
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      root.querySelector<HTMLButtonElement>('tbody button.row-delete')!.click();
      await settle(fixture);
      expect(dialog.open).toBe(true);
      expect(text(dialog.querySelector('h2'))).toBe('Delete this branch?');
      expect(text(dialog.querySelector('.dialog-body'))).toContain('feature/x');
      // Cancel sends nothing.
      buttonIn(dialog, 'Cancel').click();
      await settle(fixture);
      expect(dialog.open).toBe(false);
      expect(server.requestsTo('DELETE', '/api/v0/branches/b-x')).toHaveLength(0);
      root.querySelector<HTMLButtonElement>('tbody button.row-delete')!.click();
      await settle(fixture);
      buttonIn(dialog, 'Delete').click();
      await settle(fixture);
      expect(server.requestsTo('DELETE', '/api/v0/branches/b-x')).toHaveLength(1);
      expect(dialog.open).toBe(false);
      expect(rows(root)).toHaveLength(1);
      // The button used is gone with its row: focus moves to the result.
      const status = root.querySelector('[role="status"]');
      expect(text(status)).toBe('Deleted feature/x.');
      expect(document.activeElement).toBe(status);
      // Another kind of list is another view: the news of the delete stays with the one it was in.
      [...root.querySelectorAll<HTMLButtonElement>('.segmented button')]
        .find((b) => text(b) === 'Branches')!
        .click();
      await settle(fixture);
      expect(text(root.querySelector('[role="status"]'))).toBe('');
    });

    it('opens its dialog again on a refusal that came after it was closed', async () => {
      server.on('GET', `/api/v0/projects/${PROJECT}`, project(MAY_DELETE));
      server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([MAIN, FEATURE]) });
      let answer = (): void => undefined;
      server.on(
        'DELETE',
        '/api/v0/branches/b-x',
        () =>
          new Promise((resolve) => {
            answer = () => resolve({ status: 403, body: problem(403, 'FORBIDDEN') });
          }),
      );
      const { fixture, root } = await render();
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      root.querySelector<HTMLButtonElement>('tbody button.row-delete')!.click();
      await settle(fixture);
      buttonIn(dialog, 'Delete').click();
      await settle(fixture);
      // Escape while the server answers.
      dialog.removeAttribute('open');
      dialog.dispatchEvent(new Event('close'));
      await settle(fixture);
      answer();
      await settle(fixture);
      expect(dialog.open).toBe(true);
      expect(text(dialog.querySelector('[role="alert"]'))).toBeTruthy();
    });

    it('says in words that the branch became the main one (409 MAIN_BRANCH), and refreshes', async () => {
      server.on('GET', `/api/v0/projects/${PROJECT}`, project(MAY_DELETE));
      server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([MAIN, FEATURE]) });
      server.on('DELETE', '/api/v0/branches/b-x', {
        status: 409,
        body: problem(409, 'MAIN_BRANCH'),
      });
      const { fixture, root } = await render();
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      const reads = server.requestsTo('GET', `/api/v0/projects/${PROJECT}/branches`).length;
      root.querySelector<HTMLButtonElement>('tbody button.row-delete')!.click();
      await settle(fixture);
      buttonIn(dialog, 'Delete').click();
      await settle(fixture);
      expect(text(dialog.querySelector('[role="alert"]'))).toBe(
        "It is now the project's main branch, which cannot be deleted.",
      );
      expect(server.requestsTo('GET', `/api/v0/projects/${PROJECT}/branches`).length).toBe(
        reads + 1,
      );
    });

    it('treats a branch someone else deleted meanwhile (404) as deleted', async () => {
      let deleted = false;
      server.on('GET', `/api/v0/projects/${PROJECT}`, project(MAY_DELETE));
      server.on('GET', `/api/v0/projects/${PROJECT}/branches`, () => ({
        body: page(deleted ? [MAIN] : [MAIN, FEATURE]),
      }));
      server.on('DELETE', '/api/v0/branches/b-x', () => {
        deleted = true;
        return { status: 404, body: problem(404, 'NOT_FOUND') };
      });
      const { fixture, root } = await render();
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      root.querySelector<HTMLButtonElement>('tbody button.row-delete')!.click();
      await settle(fixture);
      buttonIn(dialog, 'Delete').click();
      await settle(fixture);
      expect(dialog.open).toBe(false);
      expect(text(root.querySelector('[role="status"]'))).toBe('feature/x was already deleted.');
      expect(rows(root)).toHaveLength(1);
    });

    it('keeps the pages loaded with Load more after a delete', async () => {
      const more = branch('b-y', { name: 'feature/y' });
      server.on('GET', `/api/v0/projects/${PROJECT}`, project(MAY_DELETE));
      server.on('GET', `/api/v0/projects/${PROJECT}/branches`, (request) => {
        const cursor = request.query.get('cursor');
        return { body: cursor ? page([more]) : page([MAIN, FEATURE], 'next') };
      });
      server.on('DELETE', '/api/v0/branches/b-x', { status: 204 });
      const { fixture, root } = await render();
      buttonIn(root, 'Load more').click();
      await settle(fixture);
      expect(rows(root)).toHaveLength(3);
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      root.querySelector<HTMLButtonElement>('tbody button.row-delete')!.click();
      await settle(fixture);
      buttonIn(dialog, 'Delete').click();
      await settle(fixture);
      // Both pages were read again: feature/y, from the second page, is still listed.
      expect(text(root.querySelector('tbody'))).toContain('feature/y');
    });

    it('keeps the dialog open with the reason when the server refuses', async () => {
      server.on('GET', `/api/v0/projects/${PROJECT}`, project(MAY_DELETE));
      server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([MAIN, MR]) });
      server.on('DELETE', '/api/v0/branches/b-mr', {
        status: 403,
        body: problem(403, 'FORBIDDEN'),
      });
      const { fixture, root } = await render();
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      root.querySelector<HTMLButtonElement>('tbody button.row-delete')!.click();
      await settle(fixture);
      expect(text(dialog.querySelector('h2'))).toBe('Delete this merge request?');
      buttonIn(dialog, 'Delete').click();
      await settle(fixture);
      expect(dialog.open).toBe(true);
      expect(text(dialog.querySelector('[role="alert"]'))).toBeTruthy();
      expect(rows(root)).toHaveLength(2);
    });
  });

  it('shows every kind again when the route reuses the page for another project', async () => {
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([branch('a')]) });
    server.on('GET', '/api/v0/projects/p2/branches', {
      body: page([branch('x', { projectId: 'p2' })]),
    });
    const { fixture, root } = await render();
    kindButton(root, 'Merge requests').click();
    await settle(fixture);
    expect(kindButton(root, 'Merge requests').getAttribute('aria-pressed')).toBe('true');
    fixture.componentRef.setInput('projectId', 'p2');
    await settle(fixture);
    const requests = server.requestsTo('GET', '/api/v0/projects/p2/branches');
    expect(requests).toHaveLength(1);
    expect(requests[0]?.query.get('kind')).toBeNull();
    expect(kindButton(root, 'All').getAttribute('aria-pressed')).toBe('true');
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

    const choose = async (name: string) => {
      kindButton(root, name).click();
      await settle(fixture);
    };
    expect(root.querySelector('[role="group"][aria-label="Show"]')).not.toBeNull();
    await choose('Merge requests');
    expect(
      server.requestsTo('GET', `/api/v0/projects/${PROJECT}/branches`).at(-1)?.query.get('kind'),
    ).toBe('merge_request');
    expect(text(root.querySelector('tbody td'))).toBe('No merge requests.');
    await choose('Branches');
    expect(text(root.querySelector('tbody td'))).toBe('No branches.');
    server.on('GET', `/api/v0/projects/${PROJECT}/branches`, { body: page([]) });
    await choose('All');
    expect(text(root.querySelector('tbody td'))).toBe('Nothing analyzed yet.');
  });
});

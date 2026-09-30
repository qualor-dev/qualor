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
import type { BranchView } from './branches';
import { CurrentProject } from './current-project';
import { ProjectPage } from './project.page';

const ID = '0190a6c2-0000-7000-8000-0000000000p1';

const PROJECT = {
  id: ID,
  organizationId: ORG_ID,
  key: 'acme/x',
  name: 'X',
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
    measures: { issues: 7 },
  },
};

const MR: BranchView = {
  id: 'b-mr',
  title: '!42 feature/x → main',
  isMain: false,
  kind: 'merge_request',
  mrTitle: 'Refund <b>limits</b>',
  mrUrl: 'https://gitlab.example.com/acme/x/-/merge_requests/42',
  gateStatus: 'passed',
  lastAnalysisId: null,
};

describe('ProjectPage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [ProjectPage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render(id: string) {
    const fixture = TestBed.createComponent(ProjectPage);
    fixture.componentRef.setInput('projectId', id);
    await settle(fixture);
    return fixture.nativeElement as HTMLElement;
  }

  it('shows the project name as text, its key, and labelled tabs', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, {
      body: {
        id: ID,
        organizationId: ORG_ID,
        key: 'acme/x',
        name: '<script>alert(1)</script>',
        mainBranchName: 'main',
        qualityGateId: null,
        newCodeDefinition: null,
        scmConnectionId: null,
        scmProjectRef: null,
        createdAt: '',
        updatedAt: '',
      },
    });
    const root = await render(ID);
    expect(root.querySelector('h1')?.textContent).toBe('<script>alert(1)</script>');
    expect(root.querySelector('script')).toBeNull();
    expect(root.querySelector('code')?.textContent).toBe('acme/x');
    const tabs = root.querySelector('nav[aria-label="Project"]');
    expect([...(tabs?.querySelectorAll('a') ?? [])].map((a) => a.textContent?.trim())).toEqual([
      'Overview',
      'Branches and merge requests',
      'Issues',
    ]);
  });

  it('treats a malformed or unknown project id as a project that does not exist', async () => {
    server.on('GET', '/api/v0/projects/not-a-uuid', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'params.id', message: 'uuid' }]),
    });
    for (const id of ['not-a-uuid', ID]) {
      const root = await render(id);
      expect(root.querySelector('h1')?.textContent).toBe('Project unavailable');
      expect(root.querySelector('[role="alert"]')?.textContent).toBe(
        'This item does not exist, or you cannot see it.',
      );
      // No project tabs, only the way back to the list.
      expect(root.querySelector('nav[aria-label="Project"]')).toBeNull();
      expect(root.querySelector('nav[aria-label="Breadcrumb"] a')?.getAttribute('href')).toBe(
        '/projects',
      );
    }
  });

  it('never shows a read-only line (enterprise.md §11)', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, {
      body: {
        id: ID,
        organizationId: ORG_ID,
        key: 'acme/x',
        name: 'X',
        mainBranchName: 'main',
        qualityGateId: null,
        newCodeDefinition: null,
        scmConnectionId: null,
        scmProjectRef: null,
        createdAt: '',
        updatedAt: '',
      },
    });
    // A server from before 5A still sends readOnly: it no longer brings the line back.
    server.on('GET', '/api/v0/organizations', {
      body: page([
        {
          id: ORG_ID,
          key: 'default',
          name: 'Default',
          readOnly: true,
          createdAt: '',
          updatedAt: '',
        },
      ]),
    });
    const root = await render(ID);
    expect(root.textContent).toContain('X');
    expect(root.querySelector('#project-read-only')).toBeNull();
    expect(root.textContent).not.toContain('read-only');
  });

  it('shows the main branch gate, the branch and the open issues on the band', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, {
      body: {
        id: ID,
        organizationId: ORG_ID,
        key: 'acme/x',
        name: 'X',
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
          measures: { issues: 7 },
        },
      },
    });
    const root = await render(ID);
    expect(root.querySelector('nav[aria-label="Breadcrumb"] a')?.textContent?.trim()).toBe(
      'Projects',
    );
    expect(root.querySelector('q-gate-badge')?.textContent?.trim()).toBe('Failed');
    expect(root.querySelector('.branch-chip')?.textContent?.trim()).toBe('main');
    expect(root.querySelector('.tab-count')?.textContent?.trim()).toBe('7');
    expect(root.querySelector('.tab-count')?.getAttribute('aria-hidden')).toBe('true');
  });

  it('names the branch or merge request an overview shows, with its own gate and link', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, { body: PROJECT });
    const fixture = TestBed.createComponent(ProjectPage);
    fixture.componentRef.setInput('projectId', ID);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const store = TestBed.inject(CurrentProject);
    store.showBranch(MR);
    await settle(fixture);
    expect(root.querySelector('q-gate-badge')?.textContent?.trim()).toBe('Passed');
    expect(root.querySelector('.branch-chip')?.textContent?.trim()).toBe('!42 feature/x → main');
    const meta = root.querySelector('.page-meta');
    expect(meta?.textContent).toContain('Refund <b>limits</b>');
    expect(meta?.querySelector('b')).toBeNull();
    const link = meta?.querySelector('a.external-link');
    expect(link?.getAttribute('href')).toBe(MR.mrUrl);
    expect(link?.getAttribute('rel')).toBe('noopener noreferrer');
    // The link names the host it leads to (GitLab or GitHub alike), then the merge request.
    expect(link?.textContent?.trim()).toBe('Open on gitlab.example.com');
    expect(link?.getAttribute('aria-label')).toBe(
      'Open on gitlab.example.com: Refund <b>limits</b>',
    );
    // Once the overview goes, the band names the main branch again.
    store.showBranch(null);
    await settle(fixture);
    expect(root.querySelector('q-gate-badge')?.textContent?.trim()).toBe('Failed');
    expect(root.querySelector('.branch-chip')?.textContent?.trim()).toBe('main');
    expect(root.querySelector('a.external-link')).toBeNull();
  });

  it('names a plain branch other than main with its own gate, and no merge request words', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, { body: PROJECT });
    const fixture = TestBed.createComponent(ProjectPage);
    fixture.componentRef.setInput('projectId', ID);
    await settle(fixture);
    TestBed.inject(CurrentProject).showBranch({
      id: 'b-release',
      title: 'release/2.0',
      isMain: false,
      kind: 'branch',
      mrTitle: null,
      mrUrl: null,
      gateStatus: 'failed',
      lastAnalysisId: null,
    });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.branch-chip')?.textContent?.trim()).toBe('release/2.0');
    expect(root.querySelector('q-gate-badge')?.textContent?.trim()).toBe('Failed');
    expect(root.querySelector('.page-meta-title')).toBeNull();
    expect(root.querySelector('a.external-link')).toBeNull();
  });

  it('shows no empty title and no link for a merge request without a title or an http(s) page', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, { body: PROJECT });
    const fixture = TestBed.createComponent(ProjectPage);
    fixture.componentRef.setInput('projectId', ID);
    await settle(fixture);
    TestBed.inject(CurrentProject).showBranch({
      ...MR,
      mrTitle: null,
      mrUrl: 'javascript:alert(1)',
    });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.branch-chip')?.textContent?.trim()).toBe('!42 feature/x → main');
    expect(root.querySelector('.page-meta-title')).toBeNull();
    expect(root.querySelector('a.external-link')).toBeNull();
    expect(root.querySelector('a[href^="javascript"]')).toBeNull();
  });
});

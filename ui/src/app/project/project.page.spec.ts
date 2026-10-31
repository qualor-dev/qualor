import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
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
import { type BranchView, branchView } from './branches';
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
  issues: 3,
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
    // The band's Watch button (mail E3) asks for the caller's watch of the project.
    server.on('GET', `/api/v0/projects/${ID}/watch`, {
      body: { watching: false, emailReady: true, emailBlocker: null },
    });
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
      'Dependencies',
      'Code',
    ]);
    // 6M §8: the Dependencies tab, in every edition, between Issues and Code.
    expect(tabs?.querySelector('a[href$="/dependencies"]')).not.toBeNull();
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

  it('counts the issues of the branch it shows, and the main branch again after', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, {
      body: { ...PROJECT, mainBranch: { ...PROJECT.mainBranch, measures: { issues: 7 } } },
    });
    const fixture = TestBed.createComponent(ProjectPage);
    fixture.componentRef.setInput('projectId', ID);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const store = TestBed.inject(CurrentProject);
    expect(root.querySelector('.tab-count')?.textContent?.trim()).toBe('7');
    store.showBranch(MR);
    await settle(fixture);
    expect(root.querySelector('.tab-count')?.textContent?.trim()).toBe('3');
    store.showBranch(null);
    await settle(fixture);
    expect(root.querySelector('.tab-count')?.textContent?.trim()).toBe('7');
  });

  it('links the Issues tab to the list of the branch it shows, and to the main branch’s without one', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, { body: PROJECT });
    // On a merge request's issue page, which shows that merge request.
    await TestBed.inject(Router).navigateByUrl('/issues/0190a6c2-0000-7000-8000-0000000000e1');
    const fixture = TestBed.createComponent(ProjectPage);
    fixture.componentRef.setInput('projectId', ID);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const link = () =>
      [...root.querySelectorAll('nav[aria-label="Project"] a')].find((a) =>
        a.textContent?.trim().startsWith('Issues'),
      )!;
    expect(link().getAttribute('href')).toBe('/issues');
    TestBed.inject(CurrentProject).showBranch(MR);
    await settle(fixture);
    expect(link().getAttribute('href')).toBe('/issues?branch=b-mr');
    // The issue page is still under the Issues tab.
    expect(link().classList).toContain('active');
    expect(link().getAttribute('aria-current')).toBe('page');
    TestBed.inject(CurrentProject).showBranch(null);
    await settle(fixture);
    expect(link().getAttribute('href')).toBe('/issues');
  });

  it('shows no count for a merge request without an issues measure', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, { body: PROJECT });
    const fixture = TestBed.createComponent(ProjectPage);
    fixture.componentRef.setInput('projectId', ID);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('.tab-count')?.textContent?.trim()).toBe('7');
    TestBed.inject(CurrentProject).showBranch(
      branchView({
        id: 'b-mr',
        projectId: ID,
        kind: 'merge_request',
        name: '42',
        isMain: false,
        mrSourceBranch: 'feature/x',
        mrTargetBranch: 'main',
        mrTitle: null,
        mrUrl: null,
        lastAnalysisId: null,
        lastAnalyzedAt: null,
        gateStatus: null,
        measures: {},
      }),
    );
    await settle(fixture);
    expect(root.querySelector('.tab-count')).toBeNull();
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
      issues: null,
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

  it('offers Watch in the band', async () => {
    server.on('GET', `/api/v0/projects/${ID}`, { body: PROJECT });
    const root = await render(ID);
    expect(root.querySelector('q-watch-button button')?.textContent?.trim()).toBe('Watch');
  });

  it('shows no Watch button to the demo account', async () => {
    TestBed.inject(SessionStore).set(me({ demo: true }));
    server.on('GET', `/api/v0/projects/${ID}`, { body: PROJECT });
    const root = await render(ID);
    expect(root.querySelector('q-watch-button')).toBeNull();
  });

  describe('Settings tab', () => {
    const tabs = (root: HTMLElement) =>
      [...root.querySelectorAll('nav[aria-label="Project"] a')].map((a) => a.textContent?.trim());

    function asRole(role: 'admin' | 'member', projectPermissions: string[]): void {
      server.on('GET', `/api/v0/projects/${ID}`, {
        body: { ...PROJECT, permissions: projectPermissions },
      });
      const base = me();
      TestBed.inject(SessionStore).set({
        ...base,
        memberships: [
          {
            ...base.memberships[0]!,
            role,
            permissions: role === 'admin' ? ['org.read', 'org.webhooks.manage'] : ['org.read'],
          },
        ],
      });
    }

    it('is a tab, after Access, for a holder of project.settings', async () => {
      asRole('member', ['project.read', 'project.settings']);
      expect(tabs(await render(ID))).toContain('Settings');
    });

    it('is a tab for an org admin who holds org.webhooks.manage', async () => {
      asRole('admin', ['project.read']);
      expect(tabs(await render(ID))).toContain('Settings');
    });

    it('is no tab for a viewer', async () => {
      asRole('member', ['project.read']);
      expect(tabs(await render(ID))).not.toContain('Settings');
    });
  });

  describe('Compliance tab (4E-1 §4)', () => {
    const tabs = (root: HTMLElement) =>
      [...root.querySelectorAll('nav[aria-label="Project"] a')].map((a) => a.textContent?.trim());
    const TAB = { point: 'project.tab', id: 'compliance', label: 'Compliance', path: 'compliance' };
    const NAV = {
      point: 'settings.nav',
      id: 'compliance',
      label: 'Compliance reports',
      path: '/settings/ee/compliance',
    };

    function info(features: string[], extensions: object[]): void {
      server.on('GET', `/api/v0/projects/${ID}`, { body: PROJECT });
      server.on('GET', '/api/v0/system/info', {
        body: { version: '0.8.0', edition: 'enterprise', features, extensions },
      });
    }

    it('is a tab, after Code, while the plugin lists it and compliance-export is active', async () => {
      info(['compliance-export'], [NAV, TAB]);
      const root = await render(ID);
      expect(tabs(root).slice(-2)).toEqual(['Code', 'Compliance']);
      expect(root.querySelector('nav[aria-label="Project"] a[href$="/compliance"]')).not.toBeNull();
    });

    it('is no tab without the feature (a lapsed licence)', async () => {
      info([], [NAV, TAB]);
      expect(tabs(await render(ID))).not.toContain('Compliance');
    });

    it('is no tab when the plugin lists only the settings entry', async () => {
      info(['compliance-export'], [NAV]);
      expect(tabs(await render(ID))).not.toContain('Compliance');
    });
  });

  describe('the Vulnerabilities tab and its marker (vuln 2b)', () => {
    const tabs = (root: HTMLElement) =>
      [...root.querySelectorAll('nav[aria-label="Project"] a')].map((a) => a.textContent?.trim());
    const withVulns = (vulnerabilities: object | null) =>
      server.on('GET', `/api/v0/projects/${ID}`, { body: { ...PROJECT, vulnerabilities } });

    it('is hidden while monitoring is off for the project', async () => {
      withVulns(null);
      const root = await render(ID);
      expect(tabs(root)).not.toContain('Vulnerabilities');
      expect(root.querySelector('.new-vulns')).toBeNull();
    });

    it('is a tab between Issues and Dependencies while monitoring is on', async () => {
      withVulns({ newIn: { main: false, branches: 0, versions: 0 } });
      const root = await render(ID);
      const names = tabs(root);
      expect(names.indexOf('Vulnerabilities')).toBe(
        names.findIndex((n) => n?.startsWith('Issues')) + 1,
      );
      expect(names.indexOf('Dependencies')).toBe(names.indexOf('Vulnerabilities') + 1);
      expect(root.querySelector('.new-vulns')).toBeNull();
    });

    it('shows a badge in the header that links to the tab when something is new', async () => {
      withVulns({ newIn: { main: true, branches: 0, versions: 2 } });
      const root = await render(ID);
      const badge = root.querySelector('.new-vulns');
      expect(badge?.textContent.trim()).toBe('New vulnerabilities in main and 2 versions');
      expect(badge?.tagName).toBe('A');
      expect(badge?.getAttribute('href')).toMatch(/\/vulnerabilities$/);
      expect(badge?.classList.contains('badge-high')).toBe(true);
    });
  });
});

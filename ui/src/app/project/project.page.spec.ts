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
import { ProjectPage } from './project.page';

const ID = '0190a6c2-0000-7000-8000-0000000000p1';

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

  it('shows the main branch gate, the branch, the last analysis and the open issues on the band', async () => {
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
    expect(root.textContent).toContain('Analyzed Sep 15, 2026, 9:00 AM UTC');
    expect(root.querySelector('.tab-count')?.textContent?.trim()).toBe('7');
    expect(root.querySelector('.tab-count')?.getAttribute('aria-hidden')).toBe('true');
  });
});

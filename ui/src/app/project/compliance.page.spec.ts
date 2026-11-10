import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeCompliance,
  FakeServer,
  me,
  ORG_ID,
  page,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { ProjectCompliancePage } from './compliance.page';

const ID = '0190a6c2-0000-7000-8000-0000000000f1';
const MAIN = '0190a6c2-0000-7000-8000-0000000000b1';
const DEV = '0190a6c2-0000-7000-8000-0000000000b2';
const VERSION = '0190a6c2-0000-7000-8000-0000000000a1';

function branch(id: string, name: string, isMain: boolean) {
  return {
    id,
    name,
    isMain,
    kind: 'branch',
    mrKey: null,
    mrTitle: null,
    mrUrl: null,
    targetBranch: null,
    gateStatus: null,
    lastAnalysisId: null,
    lastAnalyzedAt: null,
    measures: {},
  };
}

function setup(permissions: string[], features = ['compliance-export']): FakeServer {
  const server = new FakeServer();
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
      permissions,
    },
  });
  server.on('GET', `/api/v0/projects/${ID}/branches`, {
    body: page([branch(DEV, 'develop', false), branch(MAIN, 'main', true)]),
  });
  server.on('GET', `/api/v0/projects/${ID}/versions`, {
    body: page([{ id: VERSION, label: '1.2.0', tracked: true }]),
  });
  server.on('GET', '/api/v0/system/info', {
    body: { version: '0.8.0', edition: 'enterprise', features, extensions: [] },
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me());
  return server;
}

async function render(): Promise<HTMLElement> {
  const fixture = TestBed.createComponent(ProjectCompliancePage);
  fixture.componentRef.setInput('projectId', ID);
  await settle(fixture);
  return fixture.nativeElement as HTMLElement;
}

describe('ProjectCompliancePage (4E-1 §4)', () => {
  it("offers the project's branches for a new report to a holder of project.compliance.create", async () => {
    const server = setup(['project.read', 'project.compliance.create']);
    FakeCompliance.install(server, []);
    const root = await render();
    const branches = server.requestsTo('GET', `/api/v0/projects/${ID}/branches`);
    expect(branches[0]?.query.get('kind')).toBe('branch');
    const versions = server.requestsTo('GET', `/api/v0/projects/${ID}/versions`);
    expect(versions[0]?.query.get('limit')).toBe('100');
    const select = root.querySelector<HTMLSelectElement>('#compliance-target');
    expect([...(select?.options ?? [])].map((o) => o.textContent?.trim())).toEqual([
      'develop',
      'main',
      '1.2.0',
    ]);
    expect(select?.selectedOptions[0]?.textContent?.trim()).toBe('main');
    expect(
      server.requestsTo('GET', '/api/v0/ee/compliance/reports')[0]?.query.get('projectId'),
    ).toBe(ID);
  });

  it('shows a reader the list without Create report', async () => {
    const server = setup(['project.read']);
    FakeCompliance.install(server, []);
    const root = await render();
    expect(root.querySelector('.empty-state')?.textContent?.trim()).toBe(
      'No compliance reports yet.',
    );
    expect(root.textContent).not.toContain('Create report');
  });

  it('says the feature is inactive at a direct address, and asks the enterprise API nothing', async () => {
    const server = setup(['project.read', 'project.compliance.create'], []);
    const root = await render();
    expect(root.textContent).toContain(
      'Compliance reports need an enterprise licence with the compliance-export feature.',
    );
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
  });
});

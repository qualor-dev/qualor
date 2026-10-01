import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ADMIN_PERMISSIONS,
  ORG_ID,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import { SessionStore } from '../../auth/session';
import { ProjectSettingsPage } from './project-settings.page';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';

interface Setup {
  projectPermissions: string[];
  orgRole: 'admin' | 'member';
}

function setup(options: Setup): FakeServer {
  const server = new FakeServer();
  server.on('GET', `/api/v0/projects/${PROJECT}`, {
    body: {
      id: PROJECT,
      organizationId: ORG_ID,
      key: 'acme/payments',
      name: 'Payments',
      mainBranchName: 'main',
      qualityGateId: null,
      newCodeDefinition: null,
      scmConnectionId: null,
      scmProjectRef: null,
      createdAt: '',
      updatedAt: '',
      permissions: options.projectPermissions,
    },
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  const base = me();
  TestBed.inject(SessionStore).set({
    ...base,
    memberships: [
      {
        ...base.memberships[0]!,
        role: options.orgRole,
        permissions: options.orgRole === 'admin' ? [...ORG_ADMIN_PERMISSIONS] : ['org.read'],
      },
    ],
  });
  return server;
}

async function render() {
  const router = TestBed.inject(Router);
  const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
  const fixture = TestBed.createComponent(ProjectSettingsPage);
  fixture.componentRef.setInput('projectId', PROJECT);
  await settle(fixture);
  return { fixture, navigate, root: fixture.nativeElement as HTMLElement };
}

const texts = (root: HTMLElement, selector: string) =>
  [...root.querySelectorAll(selector)].map((e) => e.textContent?.trim());

describe('ProjectSettingsPage', () => {
  it('is shown to a project admin: the panels of their permissions, no webhooks', async () => {
    setup({
      projectPermissions: [
        'project.read',
        'project.settings',
        'project.tokens.manage',
        'project.delete',
      ],
      orgRole: 'member',
    });
    const { root, navigate } = await render();
    const headings = texts(root, '.card.panel h2');
    expect(headings).toEqual([
      'New code',
      'Quality gate and profiles',
      'Main branch',
      'Analysis tokens',
      'Danger zone',
    ]);
    expect(texts(root, 'nav.settings-index a')).toEqual(headings);
    expect([...root.querySelectorAll('.card.panel')].map((p) => p.id)).toEqual([
      'new-code',
      'gate',
      'main-branch',
      'tokens',
      'danger',
    ]);
    expect(navigate).not.toHaveBeenCalled();
  });

  it('shows only Webhooks to a caller who holds org.webhooks.manage and no project setting', async () => {
    setup({ projectPermissions: ['project.read'], orgRole: 'admin' });
    const { root, navigate } = await render();
    expect(texts(root, '.card.panel > .panel-head h2')).toEqual(['Webhooks']);
    expect(root.querySelector('.card.panel')?.id).toBe('webhooks');
    expect(navigate).not.toHaveBeenCalled();
  });

  it('redirects a caller without any settings permission to the overview', async () => {
    setup({ projectPermissions: ['project.read'], orgRole: 'member' });
    const { root, navigate } = await render();
    expect(navigate).toHaveBeenCalledWith(['/projects', PROJECT], { replaceUrl: true });
    expect(root.querySelector('.card.panel')).toBeNull();
  });
});

describe('ProjectSettingsPage index', () => {
  it('scrolls to the panel and focuses its heading when an index link is clicked', async () => {
    setup({
      projectPermissions: ['project.read', 'project.settings', 'project.delete'],
      orgRole: 'member',
    });
    const scroll = vi.fn();
    const original = Element.prototype.scrollIntoView;
    Element.prototype.scrollIntoView = scroll;
    onTestFinished(() => {
      Element.prototype.scrollIntoView = original;
    });
    const { root, navigate, fixture } = await render();
    document.body.appendChild(root);
    root.querySelector<HTMLAnchorElement>('nav.settings-index a[href="#danger"]')!.click();
    expect(scroll).toHaveBeenCalledTimes(1);
    expect(scroll.mock.contexts[0]).toBe(root.querySelector('#danger'));
    expect(document.activeElement).toBe(root.querySelector('#danger h2'));
    expect(navigate).toHaveBeenCalledWith([], { fragment: 'danger', replaceUrl: true });
    fixture.destroy();
  });
});

describe('ProjectSettingsPage saves', () => {
  it('reads the project again after the main branch panel saved', async () => {
    const server = setup({
      projectPermissions: ['project.read', 'project.settings'],
      orgRole: 'member',
    });
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, { body: {} });
    const { root, fixture } = await render();
    expect(server.requestsTo('GET', `/api/v0/projects/${PROJECT}`)).toHaveLength(1);
    const input = root.querySelector<HTMLInputElement>('#main-branch-name')!;
    input.value = 'trunk';
    input.dispatchEvent(new Event('input'));
    await settle(fixture);
    [...root.querySelectorAll('#main-branch button')]
      .find((b) => b.textContent?.trim() === 'Save')!
      .dispatchEvent(new Event('click'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', `/api/v0/projects/${PROJECT}`)).toHaveLength(1);
    expect(server.requestsTo('GET', `/api/v0/projects/${PROJECT}`)).toHaveLength(2);
  });
});

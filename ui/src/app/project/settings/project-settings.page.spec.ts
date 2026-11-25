import { TestBed } from '@angular/core/testing';
import { provideRouter, Router, type Routes, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { orgAi } from '../../../testing/ai-settings';
import {
  boardsProjectSettings,
  FakeServer,
  fixSettings,
  me,
  ORG_ADMIN_PERMISSIONS,
  ORG_ID,
  projectCleanup,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import { SessionStore } from '../../auth/session';
import { ProjectSettingsPage } from './project-settings.page';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';

interface Setup {
  /** Whether the organisation has a Jira connection (the Jira panel shows for a project admin). */
  jira?: boolean;
  /** Whether the organisation has an Azure DevOps connection (the Boards panel shows). */
  boards?: boolean;
  projectPermissions: string[];
  orgRole: 'admin' | 'member';
  /** The app's routes; by default the page is rendered outside any. */
  routes?: Routes;
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
      autoFix: { available: true, enabled: true, organizationEnabled: true, excludedFromAi: false },
      aiReview: { enabled: false, organizationEnabled: false, reason: 'review_disabled' },
    },
  });
  server.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, { body: orgAi() });
  server.on('GET', `/api/v0/projects/${PROJECT}/vulnerability-monitoring`, {
    body: {
      enabled: true,
      branchPatterns: [],
      versionRule: { kind: 'lines', lines: 5 },
      labelVersions: false,
      mainBranchName: 'main',
      matchingBranches: [],
      trackedVersions: [],
      versionCount: 1,
    },
  });
  server.on('GET', `/api/v0/projects/${PROJECT}/jira`, {
    body: {
      mapping: null,
      connection:
        options.jira === false
          ? null
          : { deployment: 'data_center', siteUrl: 'https://jira.example.com', problem: null },
      monitoringOn: true,
      exploitedAvailable: true,
    },
  });
  server.on('GET', `/api/v0/projects/${PROJECT}/boards`, {
    body: boardsProjectSettings({ connected: options.boards ?? false, mapped: false }),
  });
  server.on('GET', `/api/v0/projects/${PROJECT}/fixes/settings`, { body: fixSettings() });
  server.on('GET', `/api/v0/projects/${PROJECT}/cleanup`, { body: projectCleanup() });
  TestBed.configureTestingModule({
    providers: [
      provideRouter(options.routes ?? [{ path: '**', children: [] }], withComponentInputBinding()),
      provideFakeServer(server),
    ],
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
      'Vulnerability monitoring',
      'Jira',
      'Fix MRs',
      'AI',
      'Cleanup',
      'Analysis tokens',
      'Danger zone',
    ]);
    expect(texts(root, 'nav.settings-index a')).toEqual(headings);
    expect(root.querySelector('q-vulnerability-panel .alert-error')).toBeNull();
    expect(root.querySelector('q-cleanup-panel .alert-error')).toBeNull();
    expect([...root.querySelectorAll('.card.panel')].map((p) => p.id)).toEqual([
      'new-code',
      'gate',
      'main-branch',
      'vulnerabilities',
      'jira',
      'fixes',
      'ai',
      'cleanup',
      'tokens',
      'danger',
    ]);
    expect(navigate).not.toHaveBeenCalled();
  });

  it('hides the Jira panel and its index link from a member when the organisation has no connection', async () => {
    setup({
      projectPermissions: ['project.read', 'project.settings'],
      orgRole: 'member',
      jira: false,
    });
    const { root } = await render();
    expect(texts(root, '.card.panel h2')).not.toContain('Jira');
    expect(texts(root, 'nav.settings-index a')).not.toContain('Jira');
  });

  it('shows the Azure Boards panel and its index link after Jira when the organisation has an Azure DevOps connection', async () => {
    setup({
      projectPermissions: ['project.read', 'project.settings'],
      orgRole: 'member',
      boards: true,
    });
    const { root } = await render();
    const headings = texts(root, '.card.panel h2');
    expect(headings.slice(4, 7)).toEqual(['Jira', 'Azure Boards', 'Fix MRs']);
    expect(texts(root, 'nav.settings-index a')).toEqual(headings);
    expect(root.querySelector('section#boards')).not.toBeNull();
  });

  it('hides the Azure Boards panel and its index link from a member without an Azure DevOps connection', async () => {
    setup({ projectPermissions: ['project.read', 'project.settings'], orgRole: 'member' });
    const { root } = await render();
    expect(texts(root, '.card.panel h2')).not.toContain('Azure Boards');
    expect(texts(root, 'nav.settings-index a')).not.toContain('Azure Boards');
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

function catchScrolls() {
  const scroll = vi.fn();
  const original = Element.prototype.scrollIntoView;
  Element.prototype.scrollIntoView = scroll;
  onTestFinished(() => {
    Element.prototype.scrollIntoView = original;
  });
  return scroll;
}

/** The page at its own address, `/projects/<id>/settings` with `fragment`, as the app routes it. */
async function open(fragment: string | null, boards = false) {
  setup({
    projectPermissions: ['project.read', 'project.settings', 'project.delete'],
    orgRole: 'member',
    boards,
    routes: [{ path: 'projects/:projectId/settings', component: ProjectSettingsPage }],
  });
  const harness = await RouterTestingHarness.create();
  const hash = fragment === null ? '' : `#${fragment}`;
  const url = `/projects/${PROJECT}/settings${hash}`;
  await harness.navigateByUrl(url, ProjectSettingsPage);
  await settle(harness.fixture);
  return { harness, root: harness.routeNativeElement! };
}

describe('ProjectSettingsPage index', () => {
  it('has one AI entry, and its links are addresses of the page', async () => {
    catchScrolls();
    const { root } = await open(null);
    const links = [...root.querySelectorAll('nav.settings-index a')];
    expect(links.map((a) => a.textContent?.trim())).toEqual([
      'New code',
      'Quality gate and profiles',
      'Main branch',
      'Vulnerability monitoring',
      'Jira',
      'Fix MRs',
      'AI',
      'Cleanup',
      'Danger zone',
    ]);
    // To open in a new tab or copy: the page's own address, with the panel.
    expect(links.map((a) => a.getAttribute('href'))).toEqual(
      [
        'new-code',
        'gate',
        'main-branch',
        'vulnerabilities',
        'jira',
        'fixes',
        'ai',
        'cleanup',
        'danger',
      ].map((id) => `/projects/${PROJECT}/settings#${id}`),
    );
  });

  it('goes to a panel from the index, and keeps it in the address', async () => {
    const scroll = catchScrolls();
    const { harness, root } = await open(null);
    const link = root.querySelector<HTMLAnchorElement>('nav.settings-index a[href$="#danger"]')!;
    // Whether the page took the click over, as the browser would see it after every handler.
    let taken: boolean | null = null;
    const seen = (event: Event) => {
      taken = event.defaultPrevented;
      // The test DOM would try to follow the link otherwise.
      event.preventDefault();
    };
    document.addEventListener('click', seen);
    onTestFinished(() => document.removeEventListener('click', seen));

    // Ctrl-click (or ⌘, Shift or the middle button) opens it elsewhere: the page stays as it is.
    link.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, ctrlKey: true }));
    await settle(harness.fixture);
    expect(taken).toBe(false);
    expect(scroll).not.toHaveBeenCalled();

    link.click();
    await settle(harness.fixture);
    expect(taken).toBe(true);
    expect(scroll).toHaveBeenCalledTimes(1);
    expect(scroll.mock.contexts[0]).toBe(root.querySelector('#danger'));
    expect(document.activeElement).toBe(root.querySelector('#danger h2'));
    expect(TestBed.inject(Router).url).toBe(`/projects/${PROJECT}/settings#danger`);
  });

  it('reveals the Jira panel for the address #jira once the panel has loaded', async () => {
    const scroll = catchScrolls();
    const { root } = await open('jira');
    expect(scroll).toHaveBeenCalledTimes(1);
    expect(scroll.mock.contexts[0]).toBe(root.querySelector('section#jira'));
    expect(document.activeElement).toBe(root.querySelector('section#jira h2'));
  });

  it('reveals the Azure Boards panel for the address #boards once the panel has loaded', async () => {
    const scroll = catchScrolls();
    const { root } = await open('boards', true);
    expect(scroll).toHaveBeenCalledTimes(1);
    expect(scroll.mock.contexts[0]).toBe(root.querySelector('section#boards'));
    expect(document.activeElement).toBe(root.querySelector('section#boards h2'));
  });

  it('reveals the Fix MRs panel for the address #fixes', async () => {
    const scroll = catchScrolls();
    const { root } = await open('fixes');
    expect(scroll).toHaveBeenCalledTimes(1);
    expect(scroll.mock.contexts[0]).toBe(root.querySelector('section#fixes'));
    expect(document.activeElement).toBe(root.querySelector('section#fixes h2'));
  });

  it.each(['ai', 'auto-fix', 'ai-review'])(
    'reveals the AI panel for the address #%s',
    async (fragment) => {
      const scroll = catchScrolls();
      const { root } = await open(fragment);
      expect(scroll).toHaveBeenCalledTimes(1);
      expect(scroll.mock.contexts[0]).toBe(root.querySelector('section#ai'));
      expect(document.activeElement).toBe(root.querySelector('section#ai h2'));
    },
  );
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

  it('reads the project again after the AI panel saved its fix suggestions switch', async () => {
    const server = setup({
      projectPermissions: ['project.read', 'project.settings'],
      orgRole: 'member',
    });
    server.on('PUT', `/api/v0/projects/${PROJECT}/ai/auto-fix`, {
      body: { available: true, enabled: false },
    });
    const { root, fixture } = await render();
    root.querySelector<HTMLInputElement>('#project-ai-fix')!.click();
    await settle(fixture);
    expect(server.requestsTo('PUT', `/api/v0/projects/${PROJECT}/ai/auto-fix`)).toHaveLength(1);
    expect(server.requestsTo('GET', `/api/v0/projects/${PROJECT}`)).toHaveLength(2);
  });
});

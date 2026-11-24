import { type ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  fixSettings,
  me,
  ORG_ID,
  problem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import type { FixSettingsAnswer } from '../../api/types';
import { SessionStore } from '../../auth/session';
import type { ProjectDto } from '../current-project';
import { ProjectFixesPanel } from './fixes-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const URL = `/api/v0/projects/${PROJECT}/fixes/settings`;
const GUIDE = 'https://qualor.dev/docs/fix-merge-requests#the-fix-job';

function project(permissions = ['project.read', 'project.settings']): ProjectDto {
  return {
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
    permissions,
  } as ProjectDto;
}

let fixture: ComponentFixture<ProjectFixesPanel>;

function setup(body: FixSettingsAnswer = fixSettings()): FakeServer {
  const server = new FakeServer();
  server.on('GET', URL, { body });
  TestBed.configureTestingModule({ providers: [provideRouter([]), provideFakeServer(server)] });
  TestBed.inject(SessionStore).set(me());
  return server;
}

async function render(permissions?: string[]) {
  fixture = TestBed.createComponent(ProjectFixesPanel);
  fixture.componentRef.setInput('project', project(permissions));
  await settle(fixture);
  return fixture.nativeElement as HTMLElement;
}

const button = (root: ParentNode, text: string) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;

const field = <T extends HTMLElement>(root: ParentNode, selector: string) =>
  root.querySelector<T>(selector)!;

function choose(root: ParentNode, selector: string, value: string): void {
  const select = field<HTMLSelectElement>(root, selector);
  select.value = value;
  select.dispatchEvent(new Event('change'));
}

const optionTexts = (root: ParentNode, selector: string) =>
  [...root.querySelectorAll<HTMLOptionElement>(`${selector} option`)].map((o) =>
    o.textContent?.replace(/\s+/g, ' ').trim(),
  );

describe('ProjectFixesPanel', () => {
  it('is the section #fixes, with an Enabled switch that follows the saved setting', async () => {
    setup();
    const root = await render();
    expect(root.querySelector('section#fixes h2')?.textContent?.trim()).toBe('Fix MRs');
    const enabled = field<HTMLInputElement>(root, '#fixes-enabled');
    expect(enabled.getAttribute('role')).toBe('switch');
    expect(enabled.checked).toBe(false);
    expect(root.querySelector(`label[for="fixes-enabled"]`)?.textContent).toContain('Enabled');
  });

  it('lists the automatic modes, and the exploited option, and the cap 1 to 20', async () => {
    setup();
    const root = await render();
    expect(optionTexts(root, '#fixes-auto')).toEqual([
      'Off',
      'Critical',
      'High and above',
      'Medium and above',
      'Low and above',
    ]);
    expect(root.querySelector('label[for="fixes-exploited"]')?.textContent).toContain(
      'Exploited vulnerabilities (CISA KEV)',
    );
    const max = optionTexts(root, '#fixes-max');
    expect(max).toHaveLength(20);
    expect(max[0]).toBe('1');
    expect(max[19]).toBe('20');
    expect(root.querySelector('label[for="fixes-max"]')?.textContent).toContain(
      'Fix MRs in progress at most',
    );
    expect(field<HTMLSelectElement>(root, '#fixes-max').value).toBe('5');
  });

  it('disables the exploited option when it is not licensed, unless it is already on', async () => {
    setup(fixSettings({ exploitedAvailable: false }));
    expect(field<HTMLInputElement>(await render(), '#fixes-exploited').disabled).toBe(true);
    TestBed.resetTestingModule();
    setup(
      fixSettings({
        exploitedAvailable: false,
        settings: { autoCreate: { minSeverity: 'high', exploited: true, since: null } },
      }),
    );
    expect(field<HTMLInputElement>(await render(), '#fixes-exploited').disabled).toBe(false);
  });

  it('saves the switch, the rule and the cap, and says so', async () => {
    const server = setup();
    server.on('PUT', URL, (r) => {
      const body = r.body as {
        enabled: boolean;
        autoCreate: { minSeverity: 'high'; exploited: boolean };
        maxOpen: number;
      };
      return {
        body: fixSettings({
          settings: {
            enabled: body.enabled,
            autoCreate: { ...body.autoCreate, since: '2026-11-18T10:00:00.000Z' },
            maxOpen: body.maxOpen,
          },
        }),
      };
    });
    const root = await render();
    expect(button(root, 'Save').disabled).toBe(true);
    field<HTMLInputElement>(root, '#fixes-enabled').click();
    choose(root, '#fixes-auto', 'high');
    field<HTMLInputElement>(root, '#fixes-exploited').click();
    choose(root, '#fixes-max', '8');
    await settle(fixture);
    expect(button(root, 'Save').disabled).toBe(false);
    button(root, 'Save').click();
    await settle(fixture);
    expect(server.requestsTo('PUT', URL).map((r) => r.body)).toEqual([
      { enabled: true, autoCreate: { minSeverity: 'high', exploited: true }, maxOpen: 8 },
    ]);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Saved.');
    expect(button(root, 'Save').disabled).toBe(true);
    expect(field<HTMLInputElement>(root, '#fixes-enabled').checked).toBe(true);
  });

  it('shows a refused save and keeps the form', async () => {
    const server = setup();
    server.on('PUT', URL, { status: 403, body: problem(403, 'FEATURE_NOT_LICENSED') });
    const root = await render();
    field<HTMLInputElement>(root, '#fixes-exploited').click();
    await settle(fixture);
    button(root, 'Save').click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
    expect(field<HTMLInputElement>(root, '#fixes-exploited').checked).toBe(true);
    expect(button(root, 'Save').disabled).toBe(false);
  });

  describe('the preconditions', () => {
    it('says nothing when all are met', async () => {
      setup(
        fixSettings({
          settings: { enabled: true },
          preconditions: { lastClaimAt: '2026-11-18T10:00:00.000Z' },
        }),
      );
      const root = await render();
      expect(root.querySelector('.req')).toBeNull();
    });

    it('says the project is not mapped to a repository', async () => {
      setup(fixSettings({ preconditions: { scmBound: false, provider: null } }));
      const root = await render();
      expect(root.querySelector('.req')?.textContent).toContain(
        'The project is not mapped to a repository.',
      );
    });

    it('says an organization admin must allow fix MRs on the connection (ruling T17a)', async () => {
      setup(fixSettings({ preconditions: { fixMrsAllowed: false } }));
      const root = await render();
      expect(root.querySelector('.req')?.textContent).toContain(
        'An organization admin must allow fix MRs on the connection.',
      );
    });

    it('says vulnerability monitoring is off', async () => {
      setup(fixSettings({ preconditions: { monitoringOn: false } }));
      const root = await render();
      expect(root.querySelector('.req')?.textContent).toContain(
        'Vulnerability monitoring is off for this project.',
      );
    });
  });

  describe('the fix job', () => {
    it('waits for it, with a link to the guide, while switched on and never claimed', async () => {
      setup(fixSettings({ settings: { enabled: true } }));
      const root = await render();
      const link = root.querySelector<HTMLAnchorElement>(`a[href="${GUIDE}"]`)!;
      expect(link.textContent?.trim()).toBe('Waiting for the fix job');
      expect(link.getAttribute('target')).toBe('_blank');
      expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    });

    it('does not wait while switched off, or once it has run', async () => {
      setup();
      const off = await render();
      expect(off.textContent).not.toContain('Waiting for the fix job');
      TestBed.resetTestingModule();
      setup(
        fixSettings({
          settings: { enabled: true },
          preconditions: { lastClaimAt: '2026-11-18T10:00:00.000Z' },
        }),
      );
      const done = await render();
      expect(done.textContent).not.toContain('Waiting for the fix job');
      expect(done.textContent).toContain('The fix job last ran');
    });
  });

  it('shows how many fix MRs are open, and how many of the cap are in progress (ruling FW10)', async () => {
    setup(
      fixSettings({
        settings: { enabled: true, maxOpen: 5 },
        counts: { open: 3, requested: 1, preparing: 1 },
        preconditions: { lastClaimAt: '2026-11-18T10:00:00.000Z' },
      }),
    );
    const text = (await render()).textContent ?? '';
    expect(text).toContain('3 open, 5 of 5 in progress');
    expect(text).not.toContain('on the way');
  });

  it("with needs() of 'github' only the GitHub text shows, with 'gitlab' only the GitLab text, with null neither", async () => {
    setup();
    const gitlab = (await render()).textContent ?? '';
    expect(gitlab).toContain('api scope');
    expect(gitlab).toContain('Developer');
    expect(gitlab).not.toContain('pull_requests: write');
    TestBed.resetTestingModule();
    setup(fixSettings({ preconditions: { provider: 'github' } }));
    const github = (await render()).textContent ?? '';
    expect(github).toContain('contents: write');
    expect(github).toContain('pull_requests: write');
    expect(github).not.toContain('api scope');
    TestBed.resetTestingModule();
    setup(fixSettings({ preconditions: { scmBound: false, provider: null } }));
    const neither = (await render()).textContent ?? '';
    expect(neither).not.toContain('api scope');
    expect(neither).not.toContain('contents: write');
    expect(neither).not.toContain("What the connection's token needs");
  });

  it("an Azure connection shows the identity's four permissions", async () => {
    setup(fixSettings({ preconditions: { provider: 'azure' } }));
    const azure = await render();
    const line = azure.querySelector('[data-line="token"]')?.textContent ?? '';
    expect(line).toContain("What the connection's token needs");
    for (const permission of [
      'Contribute',
      'Create branch',
      'Force push',
      'Contribute to pull requests',
    ]) {
      expect(line).toContain(permission);
    }
    expect(line).not.toContain('api scope');
    expect(line).not.toContain('contents: write');
  });

  it('shows a viewer the settings read-only', async () => {
    const server = setup(fixSettings({ settings: { enabled: true, maxOpen: 7 } }));
    const root = await render(['project.read']);
    expect(field<HTMLInputElement>(root, '#fixes-enabled').checked).toBe(true);
    expect(field<HTMLInputElement>(root, '#fixes-enabled').disabled).toBe(true);
    expect(field<HTMLSelectElement>(root, '#fixes-auto').disabled).toBe(true);
    expect(field<HTMLInputElement>(root, '#fixes-exploited').disabled).toBe(true);
    expect(field<HTMLSelectElement>(root, '#fixes-max').disabled).toBe(true);
    expect(field<HTMLSelectElement>(root, '#fixes-max').value).toBe('7');
    expect(button(root, 'Save')).toBeUndefined();
    expect(server.requestsTo('PUT', URL)).toHaveLength(0);
  });

  it('after a failed load shows only the error and Try again, never the form', async () => {
    const server = setup();
    server.on('GET', URL, { status: 500, body: problem(500, 'INTERNAL') });
    const root = await render();
    expect(root.querySelector('.alert-error')).not.toBeNull();
    expect(root.querySelector('#fixes-enabled')).toBeNull();
    server.on('GET', URL, { body: fixSettings() });
    button(root, 'Try again').click();
    await settle(fixture);
    expect(root.querySelector('#fixes-enabled')).not.toBeNull();
  });
});

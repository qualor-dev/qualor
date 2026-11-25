import { type ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  boardsProjectSettings,
  FakeServer,
  me,
  ORG_ID,
  problem,
  provideFakeServer,
} from '../../../testing/fake-server';
import type {
  BoardsProjectSettings,
  JiraIssueType,
  JiraMapping,
  JiraProjectSettings,
} from '../../api/types';
import { SessionStore } from '../../auth/session';
import type { ProjectDto } from '../current-project';
import { ProjectJiraPanel } from './jira-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const URL = `/api/v0/projects/${PROJECT}/jira`;
const PICKER = `${URL}/projects`;
const TYPES = `${URL}/issue-types`;
const BOARDS = `/api/v0/projects/${PROJECT}/boards`;

function project(): ProjectDto {
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
    permissions: ['project.read', 'project.settings'],
  } as ProjectDto;
}

function issueType(over: Partial<JiraIssueType> = {}): JiraIssueType {
  return {
    id: '10001',
    name: 'Bug',
    supported: true,
    missingFields: [],
    labels: true,
    priority: null,
    ...over,
  };
}

const PRIORITIES = [
  { id: '1', name: 'Highest' },
  { id: '2', name: 'High' },
  { id: '3', name: 'Medium' },
];

function mapping(over: Partial<JiraMapping> = {}): JiraMapping {
  return {
    jiraProject: { id: '10000', key: 'QUAL', name: 'Qualor' },
    issueType: { id: '10001', name: 'Bug' },
    labels: ['team-a'],
    priorities: null,
    labelsAvailable: true,
    priorityAvailable: false,
    autoCreate: { minSeverity: null, exploited: false, since: null },
    updatedAt: '2026-11-17T10:00:00.000Z',
    ...over,
  };
}

function settings(over: Partial<JiraProjectSettings> = {}): JiraProjectSettings {
  return {
    mapping: null,
    connection: { deployment: 'data_center', siteUrl: 'https://jira.example.com', problem: null },
    monitoringOn: true,
    exploitedAvailable: true,
    ...over,
  };
}

interface Options {
  admin?: boolean;
  types?: JiraIssueType[];
  /** The project's Azure Boards state; unmapped by default. */
  boards?: BoardsProjectSettings;
}

let fixture: ComponentFixture<ProjectJiraPanel>;

function setup(body: JiraProjectSettings = settings(), options: Options = {}): FakeServer {
  const server = new FakeServer();
  server.on('GET', URL, { body });
  server.on('GET', PICKER, (r) => ({
    body: {
      items: [
        { id: '10000', key: 'QUAL', name: 'Qualor' },
        { id: '10002', key: 'QX', name: 'Other' },
      ].filter((p) => (p.key + p.name).toLowerCase().includes(r.query.get('query') ?? '')),
    },
  }));
  server.on('GET', TYPES, { body: { items: options.types ?? [issueType()] } });
  server.on('GET', BOARDS, { body: options.boards ?? boardsProjectSettings({ mapped: false }) });
  TestBed.configureTestingModule({ providers: [provideRouter([]), provideFakeServer(server)] });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? false }));
  return server;
}

/** Runs the timers due in `ms`, then lets the fake server answer and the view render. */
async function flush(ms = 0): Promise<void> {
  await vi.advanceTimersByTimeAsync(ms);
  for (let i = 0; i < 6; i++) {
    await vi.advanceTimersByTimeAsync(0);
    fixture.detectChanges();
    await fixture.whenStable();
  }
}

async function render() {
  fixture = TestBed.createComponent(ProjectJiraPanel);
  fixture.componentRef.setInput('project', project());
  await flush();
  return { root: fixture.nativeElement as HTMLElement };
}

const button = (root: ParentNode, text: string) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

function choose(root: HTMLElement, selector: string, value: string): void {
  const select = root.querySelector<HTMLSelectElement>(selector)!;
  select.value = value;
  select.dispatchEvent(new Event('change'));
}

const optionTexts = (root: HTMLElement, selector: string) =>
  [...root.querySelectorAll<HTMLOptionElement>(`${selector} option`)].map((o) =>
    o.textContent?.replace(/\s+/g, ' ').trim(),
  );

/** Maps a new project: search, choose QUAL, choose the issue type. */
async function pick(root: HTMLElement, typeId = '10001'): Promise<void> {
  type(root, '#jira-project-search', 'qual');
  await flush(300);
  button(root, 'QUAL · Qualor').click();
  await flush();
  choose(root, '#jira-issue-type', typeId);
  await flush();
}

describe('ProjectJiraPanel', () => {
  beforeEach(() => {
    // Only the timers: Angular's scheduling and the promises still run, the debounce waits.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  describe('without a connection', () => {
    it('shows an organisation admin a link to Settings → Jira', async () => {
      setup(settings({ connection: null }), { admin: true });
      const { root } = await render();
      const link = root.querySelector('a')!;
      expect(link.getAttribute('href')).toBe('/settings/jira');
      expect(link.textContent?.trim()).toBe('Settings → Jira');
      expect(root.querySelector('#jira-project-search')).toBeNull();
    });

    it('shows nobody else anything, and tells the page', async () => {
      setup(settings({ connection: null }));
      fixture = TestBed.createComponent(ProjectJiraPanel);
      fixture.componentRef.setInput('project', project());
      const shown: boolean[] = [];
      fixture.componentInstance.shown.subscribe((s) => shown.push(s));
      await flush();
      const root = fixture.nativeElement as HTMLElement;
      expect(root.querySelector('section')).toBeNull();
      expect(shown.at(-1)).toBe(false);
    });
  });

  describe('one tracker', () => {
    it('shows only "This project uses Azure Boards." while Boards is mapped', async () => {
      const server = setup(settings(), { boards: boardsProjectSettings() });
      const { root } = await render();
      expect(root.querySelector('section#jira')!.textContent).toContain(
        'This project uses Azure Boards.',
      );
      expect(root.querySelector('#jira-project-search')).toBeNull();
      expect(root.querySelector('#jira-auto')).toBeNull();
      expect(button(root, 'Save')).toBeUndefined();
      expect(server.requestsTo('GET', TYPES)).toHaveLength(0);
    });

    it('shows the form when the Boards state cannot be read: the server still refuses both', async () => {
      const server = setup();
      server.on('GET', BOARDS, { status: 500, body: problem(500, 'INTERNAL') });
      const { root } = await render();
      expect(root.textContent).not.toContain('This project uses Azure Boards.');
      expect(root.querySelector('#jira-project-search')).not.toBeNull();
    });

    it('reads the Boards mapping again when the page says it changed', async () => {
      const server = setup(settings(), { boards: boardsProjectSettings() });
      const { root } = await render();
      server.on('GET', BOARDS, { body: boardsProjectSettings({ mapped: false }) });
      fixture.componentRef.setInput('otherTrackerVersion', 1);
      await flush();
      expect(root.textContent).not.toContain('This project uses Azure Boards.');
      expect(root.querySelector('#jira-project-search')).not.toBeNull();
      expect(server.requestsTo('GET', URL)).toHaveLength(1);
    });

    it('tells the page after a save and after a remove', async () => {
      const server = setup();
      server.on('PUT', URL, { body: settings({ mapping: mapping() }) });
      server.on('DELETE', URL, { status: 204 });
      const { root } = await render();
      const changed: unknown[] = [];
      fixture.componentInstance.mappingChanged.subscribe((v) => changed.push(v));
      await pick(root);
      button(root, 'Save').click();
      await flush();
      expect(changed).toHaveLength(1);
      button(root, 'Remove mapping').click();
      await flush();
      server.on('GET', URL, { body: settings() });
      button(root.querySelector('dialog')!, 'Remove mapping').click();
      await flush();
      expect(changed).toHaveLength(2);
    });
  });

  it('shows the stored connection problem as a banner', async () => {
    setup(
      settings({
        connection: {
          deployment: 'data_center',
          siteUrl: 'https://jira.example.com',
          problem: { code: 'token_refused', message: 'x', at: '2026-11-17T10:00:00.000Z' },
        },
      }),
    );
    const { root } = await render();
    const banner = root.querySelector('.alert-error')!;
    expect(banner.textContent).toContain('Jira refused the token or the email.');
    expect(banner.textContent).toContain('Check the token');
  });

  it('after a failed load shows only the error and Try again, never the form', async () => {
    const server = setup();
    server.on('GET', URL, { status: 500, body: problem(500, 'INTERNAL') });
    const { root } = await render();
    expect(root.querySelector('.alert-error')).not.toBeNull();
    expect(button(root, 'Try again')).toBeDefined();
    expect(button(root, 'Save')).toBeUndefined();
    expect(root.querySelector('#jira-project-search')).toBeNull();
    server.on('GET', URL, { body: settings() });
    button(root, 'Try again').click();
    await flush();
    expect(root.querySelector('#jira-project-search')).not.toBeNull();
  });

  describe('the Jira project and issue type', () => {
    it('searches 300 ms after typing, and choosing a project loads its issue types', async () => {
      const server = setup();
      const { root } = await render();
      type(root, '#jira-project-search', 'qu');
      type(root, '#jira-project-search', 'qual');
      await flush(299);
      expect(server.requestsTo('GET', PICKER)).toHaveLength(0);
      await flush(1);
      const sent = server.requestsTo('GET', PICKER);
      expect(sent).toHaveLength(1);
      expect(sent[0]!.query.get('query')).toBe('qual');
      button(root, 'QUAL · Qualor').click();
      await flush();
      const types = server.requestsTo('GET', TYPES);
      expect(types).toHaveLength(1);
      expect(types[0]!.query.get('jiraProject')).toBe('QUAL');
      expect(root.querySelector('#jira-issue-type')).not.toBeNull();
    });

    it('shows an unsupported type as a disabled option naming its missing fields', async () => {
      setup(settings(), {
        types: [
          issueType(),
          issueType({
            id: '10002',
            name: 'Story',
            supported: false,
            missingFields: ['Components', 'Epic Link'],
          }),
        ],
      });
      const { root } = await render();
      type(root, '#jira-project-search', 'qual');
      await flush(300);
      button(root, 'QUAL · Qualor').click();
      await flush();
      const options = [...root.querySelectorAll<HTMLOptionElement>('#jira-issue-type option')];
      const story = options.find((o) => o.textContent?.includes('Story'))!;
      expect(story.textContent?.trim()).toBe('Story — needs: Components, Epic Link');
      expect(story.disabled).toBe(true);
      expect(options.find((o) => o.textContent?.trim() === 'Bug')!.disabled).toBe(false);
    });

    it('starts from the stored mapping: its project, its type and its labels', async () => {
      const server = setup(settings({ mapping: mapping() }));
      const { root } = await render();
      expect(root.textContent).toContain('QUAL · Qualor');
      expect(server.requestsTo('GET', TYPES)[0]!.query.get('jiraProject')).toBe('QUAL');
      expect(root.querySelector<HTMLSelectElement>('#jira-issue-type')!.value).toBe('10001');
      expect(root.querySelector<HTMLInputElement>('#jira-labels')!.value).toBe('team-a');
      expect(button(root, 'Save').disabled).toBe(true);
    });
  });

  describe('labels', () => {
    it('refuses a label with a space and blocks Save', async () => {
      setup();
      const { root } = await render();
      await pick(root);
      type(root, '#jira-labels', 'team a');
      await flush();
      expect(root.querySelector('#jira-labels-error')?.textContent).toContain('space');
      expect(button(root, 'Save').disabled).toBe(true);
    });

    it('allows 10 labels and refuses an eleventh', async () => {
      setup();
      const { root } = await render();
      await pick(root);
      type(root, '#jira-labels', 'a1,a2,a3,a4,a5,a6,a7,a8,a9,a10');
      await flush();
      expect(root.querySelector('#jira-labels-error')).toBeNull();
      expect(button(root, 'Save').disabled).toBe(false);
      type(root, '#jira-labels', 'a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11');
      await flush();
      expect(root.querySelector('#jira-labels-error')?.textContent).toContain('10');
      expect(button(root, 'Save').disabled).toBe(true);
    });

    it('accepts a label of 100 characters and refuses one of 101', async () => {
      setup();
      const { root } = await render();
      await pick(root);
      type(root, '#jira-labels', 'a'.repeat(100));
      await flush();
      expect(root.querySelector('#jira-labels-error')).toBeNull();
      expect(button(root, 'Save').disabled).toBe(false);
      type(root, '#jira-labels', 'a'.repeat(101));
      await flush();
      expect(root.querySelector('#jira-labels-error')?.textContent).toContain('100 characters');
      expect(root.querySelector('#jira-labels')?.getAttribute('aria-describedby')).toContain(
        'jira-labels-error',
      );
      expect(button(root, 'Save').disabled).toBe(true);
    });

    it('is not offered for a type without a labels field', async () => {
      setup(settings(), { types: [issueType({ labels: false })] });
      const { root } = await render();
      await pick(root);
      expect(root.querySelector('#jira-labels')).toBeNull();
    });
  });

  describe('priorities', () => {
    const withPriority = (required: boolean) => [
      issueType({ priority: { allowed: PRIORITIES, required } }),
    ];

    it('are not offered for a type without a priority field', async () => {
      setup();
      const { root } = await render();
      await pick(root);
      expect(root.querySelector('#jira-priority-blocker')).toBeNull();
    });

    it('are optional when the type allows them: a severity may have none', async () => {
      const server = setup(settings(), { types: withPriority(false) });
      server.on('PUT', URL, { body: settings({ mapping: mapping() }) });
      const { root } = await render();
      await pick(root);
      expect(optionTexts(root, '#jira-priority-blocker')).toEqual([
        'No priority',
        'Highest',
        'High',
        'Medium',
      ]);
      expect(button(root, 'Save').disabled).toBe(false);
      choose(root, '#jira-priority-blocker', '1');
      await flush();
      button(root, 'Save').click();
      await flush();
      const body = server.requestsTo('PUT', URL)[0]!.body as { priorities: unknown };
      expect(body.priorities).toEqual({ blocker: '1' });
    });

    it('need one for every severity when the type requires it', async () => {
      const server = setup(settings(), { types: withPriority(true) });
      server.on('PUT', URL, { body: settings({ mapping: mapping() }) });
      const { root } = await render();
      await pick(root);
      expect(optionTexts(root, '#jira-priority-blocker')).toEqual([
        'Choose a priority',
        'Highest',
        'High',
        'Medium',
      ]);
      expect(button(root, 'Save').disabled).toBe(true);
      for (const severity of ['blocker', 'high', 'medium', 'low']) {
        choose(root, `#jira-priority-${severity}`, '2');
        await flush();
        expect(button(root, 'Save').disabled).toBe(true);
      }
      choose(root, '#jira-priority-info', '3');
      await flush();
      expect(button(root, 'Save').disabled).toBe(false);
      button(root, 'Save').click();
      await flush();
      const body = server.requestsTo('PUT', URL)[0]!.body as { priorities: unknown };
      expect(body.priorities).toEqual({
        blocker: '2',
        high: '2',
        medium: '2',
        low: '2',
        info: '3',
      });
    });
  });

  describe('automatic creation', () => {
    it('offers Off and the four severities, and the notes', async () => {
      setup();
      const { root } = await render();
      expect(optionTexts(root, '#jira-auto')).toEqual([
        'Off',
        'Critical',
        'High and above',
        'Medium and above',
        'Low and above',
      ]);
      expect(root.textContent).toContain('Counts vulnerabilities first found after you save');
      expect(root.textContent).not.toContain('Vulnerability monitoring is off for this project');
    });

    it('says so when vulnerability monitoring is off for the project', async () => {
      setup(settings({ monitoringOn: false }));
      const { root } = await render();
      expect(root.textContent).toContain('Vulnerability monitoring is off for this project');
    });

    it('disables the exploited option without vuln.priority', async () => {
      setup(settings({ exploitedAvailable: false }));
      const { root } = await render();
      const box = root.querySelector<HTMLInputElement>('#jira-exploited')!;
      expect(box.disabled).toBe(true);
      expect(root.querySelector('label[for="jira-exploited"]')?.textContent).toContain(
        'Exploited vulnerabilities (CISA KEV)',
      );
    });

    it('enables the exploited option with vuln.priority', async () => {
      setup(settings({ exploitedAvailable: true }));
      const { root } = await render();
      expect(root.querySelector<HTMLInputElement>('#jira-exploited')!.disabled).toBe(false);
    });
  });

  describe('Save', () => {
    it('sends the mapping and the rule, then shows what the server stored', async () => {
      const server = setup();
      server.on('PUT', URL, {
        body: settings({
          mapping: mapping({
            autoCreate: { minSeverity: 'high', exploited: true, since: '2026-11-17T11:00:00.000Z' },
          }),
        }),
      });
      const { root } = await render();
      await pick(root);
      type(root, '#jira-labels', 'team-a, infra');
      choose(root, '#jira-auto', 'high');
      await flush();
      const exploited = root.querySelector<HTMLInputElement>('#jira-exploited')!;
      exploited.checked = true;
      exploited.dispatchEvent(new Event('change'));
      await flush();
      button(root, 'Save').click();
      await flush();
      const sent = server.requestsTo('PUT', URL);
      expect(sent).toHaveLength(1);
      expect(sent[0]!.body).toEqual({
        jiraProject: { id: '10000', key: 'QUAL', name: 'Qualor' },
        issueType: { id: '10001', name: 'Bug' },
        labels: ['team-a', 'infra'],
        priorities: null,
        autoCreate: { minSeverity: 'high', exploited: true },
      });
      expect(root.querySelector('[role=status]')?.textContent).toContain('Saved.');
      expect(button(root, 'Save').disabled).toBe(true);
    });

    it('lists the fields of a refused issue type', async () => {
      const server = setup();
      server.on('PUT', URL, {
        status: 422,
        body: { ...problem(422, 'JIRA_ISSUE_TYPE_UNSUPPORTED'), missingFields: ['Components'] },
      });
      const { root } = await render();
      await pick(root);
      button(root, 'Save').click();
      await flush();
      const alert = root.querySelector('.alert-error')!;
      expect(alert.textContent).toContain('Components');
      expect(alert.textContent).toContain('cannot fill');
    });

    it('shows the detail of a 502', async () => {
      const server = setup();
      server.on('PUT', URL, {
        status: 502,
        body: { ...problem(502, 'JIRA_UNAVAILABLE'), detail: 'Jira did not answer in time.' },
      });
      const { root } = await render();
      await pick(root);
      button(root, 'Save').click();
      await flush();
      expect(root.querySelector('.alert-error')?.textContent).toContain(
        'Jira did not answer in time.',
      );
    });

    it('says the licence is missing when exploited is refused', async () => {
      const server = setup();
      server.on('PUT', URL, { status: 403, body: problem(403, 'FEATURE_NOT_LICENSED') });
      const { root } = await render();
      await pick(root);
      button(root, 'Save').click();
      await flush();
      expect(root.querySelector('.alert-error')?.textContent).toContain('licence');
    });
  });

  describe('Remove mapping', () => {
    it('is not offered without a mapping', async () => {
      setup();
      const { root } = await render();
      expect(button(root, 'Remove mapping')).toBeUndefined();
    });

    it('asks first, and sends nothing when cancelled', async () => {
      const server = setup(settings({ mapping: mapping() }));
      const { root } = await render();
      button(root, 'Remove mapping').click();
      await flush();
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      expect(dialog.open).toBe(true);
      button(dialog, 'Cancel').click();
      await flush();
      expect(dialog.open).toBe(false);
      expect(server.requestsTo('DELETE', URL)).toHaveLength(0);
    });

    it('deletes on confirmation and shows the empty form', async () => {
      const server = setup(settings({ mapping: mapping() }));
      server.on('DELETE', URL, { status: 204 });
      const { root } = await render();
      button(root, 'Remove mapping').click();
      await flush();
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      server.on('GET', URL, { body: settings() });
      button(dialog, 'Remove mapping').click();
      await flush();
      expect(server.requestsTo('DELETE', URL)).toHaveLength(1);
      expect(dialog.open).toBe(false);
      expect(root.querySelector('#jira-project-search')).not.toBeNull();
      expect(button(root, 'Remove mapping')).toBeUndefined();
    });
  });
});

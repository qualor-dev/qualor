import { type ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  BOARDS_CONNECTION_ID,
  boardsProjectSettings,
  FakeServer,
  jiraProjectSettings,
  me,
  ORG_ID,
  problem,
  provideFakeServer,
} from '../../../testing/fake-server';
import type {
  BoardsMapping,
  BoardsProjectSettings,
  BoardsWorkItemType,
  JiraProjectSettings,
} from '../../api/types';
import { SessionStore } from '../../auth/session';
import type { ProjectDto } from '../current-project';
import { ProjectBoardsPanel } from './boards-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const URL = `/api/v0/projects/${PROJECT}/boards`;
const JIRA = `/api/v0/projects/${PROJECT}/jira`;
const PROJECTS = `${URL}/projects`;
const TYPES = `${URL}/work-item-types`;
const PATHS = `${URL}/paths`;

const SERVER_CONNECTION = '0190a6c2-0000-7000-8000-0000000000a8';
const GITHUB_CONNECTION = '0190a6c2-0000-7000-8000-0000000000a9';
const FABRIKAM = '6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c';
const PAYMENTS = '0d6f3c1e-8f0a-4c55-a1b7-3c2d1e0f9a8b';
const BUG = 'Microsoft.VSTS.WorkItemTypes.Bug';

function project(scmConnectionId: string | null = null): ProjectDto {
  return {
    id: PROJECT,
    organizationId: ORG_ID,
    key: 'acme/payments',
    name: 'Payments',
    mainBranchName: 'main',
    qualityGateId: null,
    newCodeDefinition: null,
    scmConnectionId,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    permissions: ['project.read', 'project.settings'],
  } as ProjectDto;
}

function workItemType(over: Partial<BoardsWorkItemType> = {}): BoardsWorkItemType {
  return { referenceName: BUG, name: 'Bug', supported: true, missingFields: [], ...over };
}

const TYPE_LIST = [
  workItemType(),
  workItemType({
    referenceName: 'Custom.Defect',
    name: 'Defect',
    supported: false,
    missingFields: ['Custom.Team', 'Custom.Severity'],
  }),
  workItemType({ referenceName: 'Microsoft.VSTS.WorkItemTypes.Task', name: 'Task' }),
];

const SERVER_ENTRY: BoardsProjectSettings['connections'][number] = {
  id: SERVER_CONNECTION,
  name: 'DefaultCollection',
  baseUrl: 'https://tfs.example.com/tfs/DefaultCollection',
  problem: null,
};

function settings(over: Partial<BoardsProjectSettings> = {}): BoardsProjectSettings {
  return { ...boardsProjectSettings({ mapped: false }), exploitedAvailable: true, ...over };
}

function mapping(over: Partial<BoardsMapping> = {}): BoardsMapping {
  return { ...boardsProjectSettings().mapping!, ...over };
}

interface Options {
  admin?: boolean;
  jira?: JiraProjectSettings;
  types?: BoardsWorkItemType[];
  scmConnectionId?: string | null;
}

let fixture: ComponentFixture<ProjectBoardsPanel>;

function setup(body: BoardsProjectSettings = settings(), options: Options = {}): FakeServer {
  const server = new FakeServer();
  server.on('GET', URL, { body });
  server.on('GET', JIRA, { body: options.jira ?? jiraProjectSettings({ mapped: false }) });
  server.on('GET', PROJECTS, {
    body: {
      items: [
        { id: FABRIKAM, name: 'Fabrikam' },
        { id: PAYMENTS, name: 'Payments' },
      ],
    },
  });
  server.on('GET', TYPES, { body: { items: options.types ?? TYPE_LIST } });
  server.on('GET', PATHS, (r) => {
    const root = r.query.get('azureProject') === PAYMENTS ? 'Payments' : 'Fabrikam';
    return {
      body: {
        areas: [root, `${root}\\Team A`, `${root}\\Team A\\Web`],
        iterations: [root, `${root}\\Sprint 1`],
      },
    };
  });
  TestBed.configureTestingModule({ providers: [provideRouter([]), provideFakeServer(server)] });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? false }));
  return server;
}

/** Lets the fake server answer and the view render, several rounds deep. */
async function flush(): Promise<void> {
  for (let i = 0; i < 8; i++) {
    await new Promise((resolve) => setTimeout(resolve));
    fixture.detectChanges();
    await fixture.whenStable();
  }
}

async function render(scmConnectionId: string | null = null) {
  fixture = TestBed.createComponent(ProjectBoardsPanel);
  fixture.componentRef.setInput('project', project(scmConnectionId));
  await flush();
  return { root: fixture.nativeElement as HTMLElement };
}

const button = (root: ParentNode, text: string) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;

function choose(root: HTMLElement, selector: string, value: string): void {
  const select = root.querySelector<HTMLSelectElement>(selector)!;
  select.value = value;
  select.dispatchEvent(new Event('change'));
}

const optionTexts = (root: HTMLElement, selector: string) =>
  [...root.querySelectorAll<HTMLOptionElement>(`${selector} option`)].map((o) =>
    o.textContent?.replace(/\s+/g, ' ').trim(),
  );

const value = (root: HTMLElement, selector: string) =>
  root.querySelector<HTMLSelectElement>(selector)!.value;

/** Types `text` into the tag field and presses Enter. */
function addTag(root: HTMLElement, text: string): void {
  const input = root.querySelector<HTMLInputElement>('#boards-tags')!;
  input.value = text;
  input.dispatchEvent(new Event('input'));
  input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', cancelable: true }));
}

const chips = (root: HTMLElement) =>
  [...root.querySelectorAll('.tag-list .tag-text')].map((c) => c.textContent?.trim());

/** Maps a new project: choose Fabrikam, then the type. */
async function pick(root: HTMLElement, type = BUG): Promise<void> {
  choose(root, '#boards-project', FABRIKAM);
  await flush();
  choose(root, '#boards-type', type);
  await flush();
}

describe('ProjectBoardsPanel', () => {
  describe('without an Azure connection', () => {
    it('shows nothing at all without an Azure connection, to a project admin either', async () => {
      const server = setup(boardsProjectSettings({ connected: false }));
      fixture = TestBed.createComponent(ProjectBoardsPanel);
      fixture.componentRef.setInput('project', project());
      const shown: boolean[] = [];
      fixture.componentInstance.shown.subscribe((s) => shown.push(s));
      await flush();
      const root = fixture.nativeElement as HTMLElement;
      expect(root.querySelector('section')).toBeNull();
      expect(root.textContent?.trim()).toBe('');
      expect(shown.at(-1)).toBe(false);
      expect(server.requestsTo('GET', PROJECTS)).toHaveLength(0);
    });

    it('shows an organisation admin a link to Settings → Azure DevOps', async () => {
      setup(boardsProjectSettings({ connected: false }), { admin: true });
      const { root } = await render();
      expect(root.textContent).toContain('This organization is not connected to Azure DevOps.');
      const link = [...root.querySelectorAll('a')].find((a) =>
        a.textContent?.includes('Settings → Azure DevOps'),
      )!;
      expect(link.getAttribute('href')).toBe('/settings/azure-devops');
      expect(root.querySelector('#boards-project')).toBeNull();
      expect(button(root, 'Save')).toBeUndefined();
    });
  });

  it('links its heading text to the guide section', async () => {
    setup();
    const { root } = await render();
    expect(root.querySelector('h2')?.textContent?.trim()).toBe('Azure Boards');
    const guide = [...root.querySelectorAll('a')].find((a) =>
      a.getAttribute('href')?.startsWith('/docs/'),
    )!;
    expect(guide.getAttribute('href')).toBe('/docs/azure-devops#azure-boards');
  });

  it('after a failed load shows only the error and Try again, never the form', async () => {
    const server = setup();
    server.on('GET', URL, { status: 500, body: problem(500, 'INTERNAL') });
    const { root } = await render();
    expect(root.querySelector('.alert-error')).not.toBeNull();
    expect(button(root, 'Save')).toBeUndefined();
    expect(root.querySelector('#boards-project')).toBeNull();
    server.on('GET', URL, { body: settings() });
    button(root, 'Try again').click();
    await flush();
    expect(root.querySelector('#boards-project')).not.toBeNull();
  });

  describe('one tracker', () => {
    it('shows only "This project uses Jira." while Jira is mapped', async () => {
      const server = setup(settings(), { jira: jiraProjectSettings() });
      const { root } = await render();
      const section = root.querySelector('section#boards')!;
      expect(section.textContent).toContain('This project uses Jira.');
      expect(root.querySelector('#boards-project')).toBeNull();
      expect(button(root, 'Save')).toBeUndefined();
      expect(server.requestsTo('GET', PROJECTS)).toHaveLength(0);
    });

    it('reads the Jira mapping again when the page says it changed', async () => {
      const server = setup(settings(), { jira: jiraProjectSettings() });
      const { root } = await render();
      server.on('GET', JIRA, { body: jiraProjectSettings({ mapped: false }) });
      fixture.componentRef.setInput('otherTrackerVersion', 1);
      await flush();
      expect(root.textContent).not.toContain('This project uses Jira.');
      expect(root.querySelector('#boards-project')).not.toBeNull();
      expect(server.requestsTo('GET', URL)).toHaveLength(1);
    });
  });

  describe('the connection', () => {
    it('is not offered with one connection, and the pickers use that one', async () => {
      const server = setup();
      const { root } = await render();
      expect(root.querySelector('#boards-connection')).toBeNull();
      expect(server.requestsTo('GET', PROJECTS)[0]!.query.get('connection')).toBe(
        BOARDS_CONNECTION_ID,
      );
    });

    it("is offered with two, defaulting to the project's repository connection", async () => {
      const base = settings();
      const server = setup({ ...base, connections: [...base.connections, SERVER_ENTRY] });
      const { root } = await render(SERVER_CONNECTION);
      expect(optionTexts(root, '#boards-connection')).toEqual([
        'contoso (dev.azure.com)',
        'DefaultCollection (tfs.example.com)',
      ]);
      expect(value(root, '#boards-connection')).toBe(SERVER_CONNECTION);
      expect(server.requestsTo('GET', PROJECTS)[0]!.query.get('connection')).toBe(
        SERVER_CONNECTION,
      );
    });

    it('defaults to the first when the repository connection is not an Azure one', async () => {
      const base = settings();
      setup({ ...base, connections: [...base.connections, SERVER_ENTRY] });
      const { root } = await render(GITHUB_CONNECTION);
      expect(value(root, '#boards-connection')).toBe(BOARDS_CONNECTION_ID);
    });

    it('reads the projects of another connection when it changes, and clears the choices', async () => {
      const base = settings();
      const server = setup({ ...base, connections: [...base.connections, SERVER_ENTRY] });
      const { root } = await render();
      await pick(root);
      choose(root, '#boards-connection', SERVER_CONNECTION);
      await flush();
      const sent = server.requestsTo('GET', PROJECTS);
      expect(sent.at(-1)!.query.get('connection')).toBe(SERVER_CONNECTION);
      expect(value(root, '#boards-project')).toBe('');
      expect(root.querySelector('#boards-type')).toBeNull();
    });

    it("shows the connection's credential problem as a banner", async () => {
      const base = settings();
      setup({
        ...base,
        connections: [
          {
            ...base.connections[0]!,
            problem: { code: 'token_refused', at: '2026-11-25T10:00:00.000Z' },
          },
        ],
      });
      const { root } = await render();
      const banner = root.querySelector('.alert-error')!;
      expect(banner.textContent).toContain('Azure DevOps refused the credential.');
      expect(banner.textContent).toContain('Settings → Azure DevOps');
    });
  });

  describe('the Azure DevOps project, type and paths', () => {
    it('choosing a project loads its work item types and paths', async () => {
      const server = setup();
      const { root } = await render();
      expect(optionTexts(root, '#boards-project')).toEqual([
        'Choose a project',
        'Fabrikam',
        'Payments',
      ]);
      choose(root, '#boards-project', FABRIKAM);
      await flush();
      const types = server.requestsTo('GET', TYPES);
      expect(types).toHaveLength(1);
      expect(types[0]!.query.get('connection')).toBe(BOARDS_CONNECTION_ID);
      expect(types[0]!.query.get('azureProject')).toBe(FABRIKAM);
      expect(server.requestsTo('GET', PATHS)[0]!.query.get('azureProject')).toBe(FABRIKAM);
      expect(root.querySelector('#boards-type')).not.toBeNull();
    });

    it('lists an unsupported type disabled, with the fields it needs', async () => {
      setup();
      const { root } = await render();
      choose(root, '#boards-project', FABRIKAM);
      await flush();
      const options = [...root.querySelectorAll<HTMLOptionElement>('#boards-type option')];
      const defect = options.find((o) => o.value === 'Custom.Defect')!;
      expect(defect.textContent?.trim()).toBe('Defect — Needs: Custom.Team, Custom.Severity');
      expect(defect.disabled).toBe(true);
      expect(options.find((o) => o.value === BUG)!.disabled).toBe(false);
    });

    it('offers "Project root" first for both paths, without the root again', async () => {
      setup();
      const { root } = await render();
      await pick(root);
      expect(optionTexts(root, '#boards-area')).toEqual([
        'Project root',
        'Fabrikam\\Team A',
        'Fabrikam\\Team A\\Web',
      ]);
      expect(optionTexts(root, '#boards-iteration')).toEqual([
        'Project root',
        'Fabrikam\\Sprint 1',
      ]);
      expect(value(root, '#boards-area')).toBe('');
    });

    it('starts from the stored mapping: its project, type, paths and tags', async () => {
      const server = setup(
        settings({
          mapping: mapping({
            areaPath: 'Fabrikam\\Team A',
            iterationPath: 'Fabrikam\\Sprint 1',
            tags: ['security'],
          }),
        }),
      );
      const { root } = await render();
      expect(server.requestsTo('GET', TYPES)[0]!.query.get('azureProject')).toBe(FABRIKAM);
      expect(value(root, '#boards-project')).toBe(FABRIKAM);
      expect(value(root, '#boards-type')).toBe(BUG);
      expect(value(root, '#boards-area')).toBe('Fabrikam\\Team A');
      expect(value(root, '#boards-iteration')).toBe('Fabrikam\\Sprint 1');
      expect(chips(root)).toEqual(['security']);
      expect(button(root, 'Save').disabled).toBe(true);
    });
  });

  describe('tags', () => {
    it('adds a tag with Enter and removes it with its button', async () => {
      setup();
      const { root } = await render();
      await pick(root);
      addTag(root, '  team a ');
      await flush();
      addTag(root, 'security');
      await flush();
      expect(chips(root)).toEqual(['team a', 'security']);
      expect(root.querySelector<HTMLInputElement>('#boards-tags')!.value).toBe('');
      const remove = root.querySelector<HTMLButtonElement>(
        'button[aria-label="Remove the tag team a"]',
      )!;
      remove.click();
      await flush();
      expect(chips(root)).toEqual(['security']);
    });

    it('takes the tags typed before a comma or a semicolon', async () => {
      setup();
      const { root } = await render();
      await pick(root);
      const input = root.querySelector<HTMLInputElement>('#boards-tags')!;
      input.value = 'web, api;cli';
      input.dispatchEvent(new Event('input'));
      await flush();
      expect(chips(root)).toEqual(['web', 'api']);
      expect(input.value).toBe('cli');
    });

    it('refuses qualor, a tag twice, one of 101 characters and an eleventh', async () => {
      setup();
      const { root } = await render();
      await pick(root);
      const error = () => root.querySelector('#boards-tags-error')?.textContent ?? '';
      addTag(root, 'Qualor');
      await flush();
      expect(error()).toContain('qualor');
      addTag(root, 'web');
      await flush();
      expect(error()).toBe('');
      addTag(root, 'WEB');
      await flush();
      expect(error()).toContain('already');
      addTag(root, 'a'.repeat(101));
      await flush();
      expect(error()).toContain('100 characters');
      addTag(root, 'a'.repeat(100));
      await flush();
      for (let i = 1; i <= 8; i++) {
        addTag(root, `t${i}`);
        await flush();
      }
      expect(chips(root)).toHaveLength(10);
      expect(error()).toBe('');
      addTag(root, 't9');
      await flush();
      expect(error()).toContain('10');
      expect(chips(root)).toHaveLength(10);
    });
  });

  describe('automatic creation', () => {
    it('offers Off and the four severities, and disables exploited without vuln.priority', async () => {
      setup(settings({ exploitedAvailable: false, monitoringOn: false }));
      const { root } = await render();
      expect(optionTexts(root, '#boards-auto')).toEqual([
        'Off',
        'Critical',
        'High and above',
        'Medium and above',
        'Low and above',
      ]);
      expect(root.querySelector<HTMLInputElement>('#boards-exploited')!.disabled).toBe(true);
      expect(root.textContent).toContain('Vulnerability monitoring is off for this project');
    });
  });

  describe('Save', () => {
    it('map and save sends the PUT body, then shows what the server stored', async () => {
      const server = setup();
      server.on('PUT', URL, {
        body: settings({
          mapping: mapping({
            areaPath: 'Fabrikam\\Team A',
            tags: ['security'],
            autoCreate: { minSeverity: 'high', exploited: true, since: '2026-11-25T11:00:00.000Z' },
          }),
        }),
      });
      const { root } = await render();
      const changed: unknown[] = [];
      fixture.componentInstance.mappingChanged.subscribe((v) => changed.push(v));
      await pick(root);
      choose(root, '#boards-area', 'Fabrikam\\Team A');
      addTag(root, 'security');
      choose(root, '#boards-auto', 'high');
      await flush();
      const exploited = root.querySelector<HTMLInputElement>('#boards-exploited')!;
      exploited.checked = true;
      exploited.dispatchEvent(new Event('change'));
      await flush();
      button(root, 'Save').click();
      await flush();
      const sent = server.requestsTo('PUT', URL);
      expect(sent).toHaveLength(1);
      expect(sent[0]!.body).toEqual({
        connectionId: BOARDS_CONNECTION_ID,
        azureProject: { id: FABRIKAM, name: 'Fabrikam' },
        workItemType: { referenceName: BUG },
        areaPath: 'Fabrikam\\Team A',
        iterationPath: null,
        tags: ['security'],
        autoCreate: { minSeverity: 'high', exploited: true },
      });
      expect(root.querySelector('[role=status]')?.textContent).toContain('Saved.');
      expect(button(root, 'Save').disabled).toBe(true);
      expect(changed).toHaveLength(1);
    });

    it('cannot save before a project and a supported type are chosen', async () => {
      setup();
      const { root } = await render();
      expect(button(root, 'Save').disabled).toBe(true);
      choose(root, '#boards-project', FABRIKAM);
      await flush();
      expect(button(root, 'Save').disabled).toBe(true);
    });

    it('says the project uses Jira on TRACKER_IN_USE, with a link to the Jira section', async () => {
      const server = setup();
      server.on('PUT', URL, { status: 409, body: problem(409, 'TRACKER_IN_USE') });
      const { root } = await render();
      await pick(root);
      button(root, 'Save').click();
      await flush();
      const alert = root.querySelector('.alert-error')!;
      expect(alert.textContent).toContain('This project uses Jira. Remove its Jira mapping first.');
      const link = alert.querySelector('a')!;
      expect(link.getAttribute('href')).toBe('/#jira');
    });

    it("shows Azure's words of BOARDS_CREATE_REFUSED inside a quote block, as text", async () => {
      const server = setup();
      server.on('PUT', URL, {
        status: 422,
        body: {
          ...problem(422, 'BOARDS_CREATE_REFUSED'),
          detail: 'TF401320: Rule Error for field <b>Team</b>.',
        },
      });
      const { root } = await render();
      await pick(root);
      button(root, 'Save').click();
      await flush();
      const alert = root.querySelector('.alert-error')!;
      expect(alert.textContent).toContain(
        'Azure DevOps refused a test work item with this mapping',
      );
      const quote = alert.querySelector('blockquote')!;
      expect(quote.textContent?.trim()).toBe('TF401320: Rule Error for field <b>Team</b>.');
      expect(quote.querySelector('b')).toBeNull();
    });

    it('lists the fields of a refused work item type', async () => {
      const server = setup();
      server.on('PUT', URL, {
        status: 422,
        body: {
          ...problem(422, 'BOARDS_WORK_ITEM_TYPE_UNSUPPORTED'),
          missingFields: ['Custom.Team'],
        },
      });
      const { root } = await render();
      await pick(root);
      button(root, 'Save').click();
      await flush();
      const alert = root.querySelector('.alert-error')!;
      expect(alert.textContent).toContain('cannot fill');
      expect(alert.textContent).toContain('Custom.Team');
    });

    it("explains BOARDS_UNAVAILABLE by its problem code, never in the server's words", async () => {
      const server = setup();
      server.on('PUT', URL, {
        status: 502,
        body: {
          ...problem(502, 'BOARDS_UNAVAILABLE'),
          detail: 'Server text that is never shown.',
          problemCode: 'permission_missing',
        },
      });
      const { root } = await render();
      await pick(root);
      button(root, 'Save').click();
      await flush();
      const alert = root.querySelector('.alert-error')!;
      expect(alert.textContent).toContain('Work Items');
      expect(alert.textContent).not.toContain('Server text');
    });

    it('explains a failed picker by its problem code', async () => {
      const server = setup();
      server.on('GET', PROJECTS, {
        status: 502,
        body: { ...problem(502, 'BOARDS_UNAVAILABLE'), problemCode: 'token_refused' },
      });
      const { root } = await render();
      expect(root.querySelector('#boards-project-error')?.textContent).toContain(
        'Azure DevOps refused the credential.',
      );
    });
  });

  describe('Remove mapping', () => {
    it('is not offered without a mapping', async () => {
      setup();
      const { root } = await render();
      expect(button(root, 'Remove mapping')).toBeUndefined();
    });

    it('asks first, then deletes and shows the empty form', async () => {
      const server = setup(settings({ mapping: mapping() }));
      server.on('DELETE', URL, { status: 204 });
      const { root } = await render();
      const changed: unknown[] = [];
      fixture.componentInstance.mappingChanged.subscribe((v) => changed.push(v));
      button(root, 'Remove mapping').click();
      await flush();
      const dialog = root.querySelector<HTMLDialogElement>('dialog')!;
      expect(dialog.open).toBe(true);
      button(dialog, 'Cancel').click();
      await flush();
      expect(dialog.open).toBe(false);
      expect(server.requestsTo('DELETE', URL)).toHaveLength(0);

      button(root, 'Remove mapping').click();
      await flush();
      server.on('GET', URL, { body: settings() });
      button(dialog, 'Remove mapping').click();
      await flush();
      expect(server.requestsTo('DELETE', URL)).toHaveLength(1);
      expect(dialog.open).toBe(false);
      expect(value(root, '#boards-project')).toBe('');
      expect(button(root, 'Remove mapping')).toBeUndefined();
      expect(changed).toHaveLength(1);
    });
  });
});

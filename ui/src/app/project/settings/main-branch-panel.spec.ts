import { TestBed } from '@angular/core/testing';
import {
  FakeServer,
  ORG_ID,
  problem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import type { ProjectDto } from '../current-project';
import { MainBranchPanel } from './main-branch-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';

function project(mainBranchName = 'main'): ProjectDto {
  return {
    id: PROJECT,
    organizationId: ORG_ID,
    key: 'acme/payments',
    name: 'Payments',
    mainBranchName,
    qualityGateId: null,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    permissions: ['project.read', 'project.settings'],
  } as ProjectDto;
}

function setup(): FakeServer {
  const server = new FakeServer();
  TestBed.configureTestingModule({ providers: [provideFakeServer(server)] });
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(MainBranchPanel);
  fixture.componentRef.setInput('project', project());
  const saved = vi.fn();
  fixture.componentInstance.saved.subscribe(saved);
  await settle(fixture);
  return { fixture, saved, root: fixture.nativeElement as HTMLElement };
}

const field = (root: HTMLElement) => root.querySelector<HTMLInputElement>('#main-branch-name')!;
const save = (root: HTMLElement) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Save')!;

function type(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

describe('MainBranchPanel (spec §3.3)', () => {
  it('renders its section and heading, and the field holds the main branch name', async () => {
    setup();
    const { root } = await render();
    const section = root.querySelector('section.card.panel')!;
    expect(section.id).toBe('main-branch');
    expect(section.querySelector('.panel-head h2')?.textContent?.trim()).toBe('Main branch');
    expect(field(root).value).toBe('main');
    expect(root.textContent).toContain(
      'Analyses of the previous main branch stay on that branch. New code on the new main branch starts from its own analyses.',
    );
  });

  it('keeps Save disabled until the trimmed value differs and is not empty', async () => {
    setup();
    const { root, fixture } = await render();
    expect(save(root).disabled).toBe(true);
    type(field(root), '   ');
    await settle(fixture);
    expect(save(root).disabled).toBe(true);
    type(field(root), ' main ');
    await settle(fixture);
    expect(save(root).disabled).toBe(true);
    type(field(root), 'trunk');
    await settle(fixture);
    expect(save(root).disabled).toBe(false);
  });

  it('sends the trimmed name, emits saved and announces the new main branch', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, { body: project('trunk') });
    const { root, fixture, saved } = await render();
    type(field(root), '  trunk ');
    await settle(fixture);
    save(root).click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', `/api/v0/projects/${PROJECT}`)[0]?.body).toEqual({
      mainBranchName: 'trunk',
    });
    expect(saved).toHaveBeenCalledTimes(1);
    expect(root.querySelector('[role=status]')?.textContent).toContain('Main branch is now trunk.');
  });

  for (const status of [409, 422]) {
    it(`shows a ${status} on body.mainBranchName on the field`, async () => {
      const server = setup();
      server.on('PATCH', `/api/v0/projects/${PROJECT}`, {
        status,
        body: problem(status, status === 409 ? 'CONFLICT' : 'VALIDATION_FAILED', [
          { path: 'body.mainBranchName', message: 'Branch "trunk" already exists.' },
        ]),
      });
      const { root, fixture, saved } = await render();
      type(field(root), 'trunk');
      await settle(fixture);
      save(root).click();
      await settle(fixture);
      expect(root.querySelector('.field-error')?.textContent).toContain(
        'Branch "trunk" already exists.',
      );
      expect(field(root).getAttribute('aria-invalid')).toBe('true');
      expect(root.querySelector('.alert-error')).toBeNull();
      expect(saved).not.toHaveBeenCalled();
    });
  }

  it('shows any other error in an alert', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, {
      status: 403,
      body: problem(403, 'FORBIDDEN'),
    });
    const { root, fixture } = await render();
    type(field(root), 'trunk');
    await settle(fixture);
    save(root).click();
    await settle(fixture);
    expect(root.querySelector('.alert-error[role=alert]')).not.toBeNull();
    expect(root.querySelector('.field-error')).toBeNull();
  });
});

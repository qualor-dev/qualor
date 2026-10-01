import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ID,
  problem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import { SessionStore } from '../../auth/session';
import { CurrentProject, type ProjectDto } from '../current-project';
import { DeleteProjectPanel } from './delete-project-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const URL = `/api/v0/projects/${PROJECT}`;

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
    permissions: ['project.read', 'project.delete'],
  } as ProjectDto;
}

function setup(del: () => { status: number; body?: unknown } = () => ({ status: 204 })) {
  const server = new FakeServer();
  server.on('GET', URL, () => ({ body: project() }));
  server.on('DELETE', URL, del);
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(DeleteProjectPanel);
  fixture.componentRef.setInput('project', project());
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

const button = (root: ParentNode, text: string) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;

function type(root: ParentNode, value: string): void {
  const input = root.querySelector<HTMLInputElement>('#delete-confirm-key')!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

describe('DeleteProjectPanel (spec §3.6)', () => {
  it('renders the danger card with the heading and a Delete project button', async () => {
    setup();
    const { root } = await render();
    const section = root.querySelector('section.card.panel.danger')!;
    expect(section.id).toBe('danger');
    const h2 = section.querySelector('.panel-head h2')!;
    expect(h2.textContent?.trim()).toBe('Danger zone');
    expect(h2.getAttribute('tabindex')).toBe('-1');
    expect(button(section, 'Delete project')).toBeTruthy();
  });

  it('lists what goes and enables the danger button only for the exact key', async () => {
    setup();
    const { fixture, root } = await render();
    const dialog = root.querySelector<HTMLDialogElement>('dialog#delete-project')!;
    expect(dialog.open).toBe(false);
    button(root.querySelector('section')!, 'Delete project').click();
    await settle(fixture);
    expect(dialog.open).toBe(true);
    expect(dialog.textContent).toContain(
      'Branches and merge requests, analyses, issues and their history, analysis tokens and project webhooks.',
    );
    const confirm = dialog.querySelector<HTMLElement>('.btn-danger-solid')!;
    expect(confirm.getAttribute('aria-disabled')).toBe('true');
    for (const wrong of [' acme/payments', 'acme/payments ', 'ACME/PAYMENTS', 'acme/pay']) {
      type(dialog, wrong);
      await settle(fixture);
      expect(confirm.getAttribute('aria-disabled')).toBe('true');
    }
    type(dialog, 'acme/payments');
    await settle(fixture);
    expect(confirm.getAttribute('aria-disabled')).toBeNull();
  });

  it('sends nothing while the key does not match', async () => {
    const server = setup();
    const { fixture, root } = await render();
    button(root.querySelector('section')!, 'Delete project').click();
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#delete-project')!;
    type(dialog, 'nope');
    await settle(fixture);
    dialog.querySelector<HTMLElement>('.btn-danger-solid')!.click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', URL)).toHaveLength(0);
  });

  it('deletes with ?confirm=<key>, forgets the project, goes to Projects with a notice', async () => {
    const server = setup();
    TestBed.inject(SessionStore).set(me());
    const store = TestBed.inject(CurrentProject);
    store.use(PROJECT);
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate');
    const forget = vi.spyOn(store, 'forget');
    const { fixture, root } = await render();
    const gets = () => server.requestsTo('GET', URL).length;
    expect(gets()).toBe(1);
    button(root.querySelector('section')!, 'Delete project').click();
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#delete-project')!;
    type(dialog, 'acme/payments');
    await settle(fixture);
    const before = gets();
    dialog.querySelector<HTMLElement>('.btn-danger-solid')!.click();
    await settle(fixture);
    const sent = server.requestsTo('DELETE', URL);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.query.get('confirm')).toBe('acme/payments');
    expect(forget).toHaveBeenCalledTimes(1);
    expect(navigate).toHaveBeenCalledWith(['/projects'], {
      state: { notice: 'Project Payments deleted.' },
    });
    expect(gets()).toBe(before);
    expect(store.current()).toBeNull();
    expect(router.url).toBe('/projects');
  });

  it.each([
    [409, 'CONFLICT', 'Someone else changed this at the same time.'],
    [422, 'VALIDATION_FAILED', 'Some values are not valid.'],
  ])('shows the message of a %i and keeps the dialog open', async (status, code, message) => {
    const server = setup(() => ({ status, body: problem(status, code) }));
    const store = TestBed.inject(CurrentProject);
    const forget = vi.spyOn(store, 'forget');
    const { fixture, root } = await render();
    button(root.querySelector('section')!, 'Delete project').click();
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#delete-project')!;
    type(dialog, 'acme/payments');
    await settle(fixture);
    dialog.querySelector<HTMLElement>('.btn-danger-solid')!.click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', URL)).toHaveLength(1);
    expect(dialog.open).toBe(true);
    expect(dialog.querySelector('.alert-error')?.textContent).toContain(message);
    expect(forget).not.toHaveBeenCalled();
  });
});

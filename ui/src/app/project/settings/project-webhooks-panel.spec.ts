import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ADMIN_PERMISSIONS,
  ORG_ID,
  page,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import { SessionStore } from '../../auth/session';
import type { ProjectDto } from '../current-project';
import { ProjectWebhooksPanel } from './project-webhooks-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';

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
    permissions: ['project.read'],
  } as ProjectDto;
}

function hook(id: string, projectId: string | null) {
  return {
    id,
    organizationId: ORG_ID,
    projectId,
    url: `https://ci.example.com/${id}`,
    events: ['analysis.completed'],
    active: true,
    secretPrefix: 'whsec_abcd',
    createdAt: '2026-09-01T10:00:00.000Z',
    updatedAt: '2026-09-01T10:00:00.000Z',
  };
}

function setup(
  permissions: (typeof ORG_ADMIN_PERMISSIONS)[number][] = [...ORG_ADMIN_PERMISSIONS],
): void {
  const server = new FakeServer();
  server.on('GET', '/api/v0/webhooks', {
    body: page([hook('w1', PROJECT), hook('w2', null)]),
  });
  server.on('GET', '/api/v0/webhooks/w1/deliveries', { body: page([]) });
  TestBed.configureTestingModule({
    providers: [provideRouter([]), provideFakeServer(server)],
  });
  const base = me();
  TestBed.inject(SessionStore).set({
    ...base,
    memberships: [{ ...base.memberships[0]!, role: 'admin', permissions }],
  });
}

async function render() {
  const fixture = TestBed.createComponent(ProjectWebhooksPanel);
  fixture.componentRef.setInput('project', project());
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

describe('ProjectWebhooksPanel (spec §3.5)', () => {
  it('renders its section, heading, intro with the link and the project list', async () => {
    setup();
    const { root } = await render();
    const section = root.querySelector('section.card.panel#webhooks')!;
    expect(section.querySelector('.panel-head h2')?.textContent?.trim()).toBe('Webhooks');
    expect(section.querySelector('.panel-head h2')?.getAttribute('tabindex')).toBe('-1');
    const intro = root.querySelector('p.hint')!;
    expect(intro.textContent?.replace(/\s+/g, ' ').trim()).toBe(
      'Qualor posts to these only for this project. Webhooks for every project are in Settings → Webhooks.',
    );
    expect(intro.querySelector('a')?.getAttribute('href')).toBe('/settings/webhooks');
    expect(root.querySelector('q-webhook-list')).not.toBeNull();
    expect(root.textContent).toContain('https://ci.example.com/w1');
    expect(root.textContent).not.toContain('https://ci.example.com/w2');
  });

  it('offers New webhook to a caller who can change webhooks and opens the dialog', async () => {
    setup();
    const { fixture, root } = await render();
    const open = [...root.querySelectorAll('.panel-head button')].find(
      (b) => b.textContent?.trim() === 'New webhook',
    ) as HTMLButtonElement;
    expect(open).toBeDefined();
    expect(open.classList.contains('btn')).toBe(true);
    expect(open.classList.contains('btn-primary')).toBe(false);
    expect(open.querySelector('q-icon')).not.toBeNull();
    open.click();
    await settle(fixture);
    expect(root.querySelector('dialog[open]')).not.toBeNull();
  });

  it('hides New webhook without the manage permission', async () => {
    setup(['org.read']);
    const { root } = await render();
    expect(root.querySelector('.panel-head button')).toBeNull();
  });
});

import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, problem, provideFakeServer, settle } from '../../../testing/fake-server';
import type { ProjectDto } from '../current-project';
import { NewCodePanel } from './new-code-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const BRANCH = '0190a6c2-0000-7000-8000-0000000000b1';
const A1 = '0190a6c2-0000-7000-8000-0000000000a1';
const A2 = '0190a6c2-0000-7000-8000-0000000000a2';
const A3 = '0190a6c2-0000-7000-8000-0000000000a3';

function project(newCodeDefinition: ProjectDto['newCodeDefinition'] = null): ProjectDto {
  return {
    id: PROJECT,
    organizationId: '0190a6c2-0000-7000-8000-000000000001',
    key: 'acme/payments',
    name: 'Payments',
    mainBranchName: 'main',
    qualityGateId: null,
    newCodeDefinition,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    mainBranch: {
      id: BRANCH,
      name: 'main',
      gateStatus: null,
      lastAnalysisId: null,
      lastAnalyzedAt: null,
      measures: {},
    },
    permissions: ['project.read', 'project.settings', 'project.analyze'],
  } as ProjectDto;
}

function analysis(id: string, status: string, revision: string | null, date: string) {
  return {
    id,
    projectId: PROJECT,
    status,
    branch: { id: BRANCH, kind: 'branch', name: 'main' },
    revision,
    analysisDate: date,
  };
}

const BASELINE = {
  revision: '3f2a1c4d9e8b7a6f5e4d3c2b1a09f8e7d6c5b4a3',
  analysisId: A1,
  analysisDate: '2026-09-12T10:00:00.000Z',
  definition: { type: 'days', value: 30 },
  warnings: [],
};

interface Setup {
  definition?: ProjectDto['newCodeDefinition'];
  canSeeBaseline?: boolean;
}

function setup(): FakeServer {
  const server = new FakeServer();
  server.on('GET', `/api/v0/branches/${BRANCH}/analyses`, {
    body: {
      items: [
        analysis(A1, 'succeeded', 'abcdef1234567', '2026-09-12T10:00:00.000Z'),
        analysis(A2, 'failed', 'bbbbbbb1234', '2026-09-11T10:00:00.000Z'),
        analysis(A3, 'succeeded', null, '2026-09-10T10:00:00.000Z'),
      ],
      nextCursor: null,
    },
  });
  server.on('GET', '/api/v0/projects/new-code-baseline', { body: BASELINE });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  return server;
}

async function render(options: Setup = {}) {
  const fixture = TestBed.createComponent(NewCodePanel);
  fixture.componentRef.setInput('project', project(options.definition));
  fixture.componentRef.setInput('canSeeBaseline', options.canSeeBaseline ?? true);
  const saved = vi.fn();
  fixture.componentInstance.saved.subscribe(saved);
  await settle(fixture);
  return { fixture, saved, root: fixture.nativeElement as HTMLElement };
}

const radios = (root: HTMLElement) => [
  ...root.querySelectorAll<HTMLInputElement>('input[type=radio][name=new-code]'),
];

async function pick(root: HTMLElement, fixture: { whenStable(): Promise<unknown> }, index: number) {
  radios(root)[index]!.click();
  await settle(fixture);
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

const save = (root: HTMLElement) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Save')!;

describe('NewCodePanel (spec §3.1)', () => {
  it('shows four radio cards and checks the current definition', async () => {
    setup();
    const { root } = await render({ definition: { type: 'previous_version' } });
    expect(
      radios(root).map((r) =>
        r.closest('label')?.querySelector('.choice-title')?.textContent?.trim(),
      ),
    ).toEqual([
      'Default (30 days)',
      'Last days',
      'Since the previous version',
      'From a specific analysis',
    ]);
    expect(radios(root).map((r) => r.checked)).toEqual([false, false, true, false]);
    expect(root.querySelector('h2')?.textContent).toBe('New code');
    expect(root.querySelector('section#new-code.card.panel')).not.toBeNull();
  });

  it('links the previous-version hint to the configuration guide', async () => {
    setup();
    const { root } = await render();
    const link = root.querySelector<HTMLAnchorElement>('a[href="/docs/configuration"]');
    expect(link).not.toBeNull();
  });

  it('checks the default card for a project without a definition', async () => {
    setup();
    const { root } = await render();
    expect(radios(root).map((r) => r.checked)).toEqual([true, false, false, false]);
  });

  it('lists the succeeded analyses of the main branch, only once that card is chosen', async () => {
    const server = setup();
    const { root, fixture } = await render();
    expect(server.requestsTo('GET', `/api/v0/branches/${BRANCH}/analyses`)).toHaveLength(0);
    await pick(root, fixture, 3);
    const requests = server.requestsTo('GET', `/api/v0/branches/${BRANCH}/analyses`);
    expect(requests).toHaveLength(1);
    expect(requests[0]!.query.get('limit')).toBe('20');
    expect(
      [...root.querySelectorAll('select#new-code-analysis option')].map((o) =>
        o.textContent?.trim(),
      ),
    ).toEqual(['Choose an analysis', 'Sep 12, 2026 · abcdef1', 'Sep 10, 2026 · —']);
  });

  it('keeps Save disabled until the form differs, then sends the definition exactly', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, {
      body: project({ type: 'days', value: 14 }),
    });
    const { root, fixture, saved } = await render();
    expect(save(root).disabled).toBe(true);
    await pick(root, fixture, 1);
    type(root, '#new-code-days', '14');
    await settle(fixture);
    expect(save(root).disabled).toBe(false);
    save(root).click();
    await settle(fixture);
    const [patch] = server.requestsTo('PATCH', `/api/v0/projects/${PROJECT}`);
    expect(patch!.body).toEqual({ newCodeDefinition: { type: 'days', value: 14 } });
    expect(saved).toHaveBeenCalledTimes(1);
    expect(root.querySelector('[role=status]')?.textContent).toContain(
      'New code definition saved.',
    );
  });

  it('resets to the default with null', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, { body: project() });
    const { root, fixture } = await render({ definition: { type: 'days', value: 14 } });
    await pick(root, fixture, 0);
    save(root).click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', `/api/v0/projects/${PROJECT}`)[0]!.body).toEqual({
      newCodeDefinition: null,
    });
  });

  it('shows a 422 on the analysis select, not in the panel alert', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.newCodeDefinition.analysisId', message: 'Not an analysis of this project' },
      ]),
    });
    const { root, fixture, saved } = await render();
    await pick(root, fixture, 3);
    const select = root.querySelector<HTMLSelectElement>('select#new-code-analysis')!;
    select.value = A1;
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    save(root).click();
    await settle(fixture);
    expect(root.querySelector('.field-error')?.textContent).toContain(
      'Not an analysis of this project',
    );
    expect(root.querySelector('.alert-error')).toBeNull();
    expect(saved).not.toHaveBeenCalled();
  });

  it('refuses days 0 on the field and sends nothing', async () => {
    const server = setup();
    const { root, fixture } = await render();
    await pick(root, fixture, 1);
    type(root, '#new-code-days', '0');
    await settle(fixture);
    save(root).click();
    await settle(fixture);
    expect(root.querySelector('.field-error')?.textContent).toContain(
      'Enter a whole number of days from 1 to 3650.',
    );
    expect(server.requestsTo('PATCH', `/api/v0/projects/${PROJECT}`)).toHaveLength(0);
  });

  it('shows another failure in the panel alert', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, {
      status: 403,
      body: problem(403, 'FORBIDDEN'),
    });
    const { root, fixture } = await render();
    await pick(root, fixture, 2);
    save(root).click();
    await settle(fixture);
    expect(root.querySelector('.alert-error')?.textContent).toContain('You are not allowed');
  });

  describe('baseline', () => {
    it('names the analysis the new code is measured from', async () => {
      const server = setup();
      const { root } = await render();
      const [req] = server.requestsTo('GET', '/api/v0/projects/new-code-baseline');
      expect(req!.query.get('projectKey')).toBe('acme/payments');
      expect(req!.query.get('branch')).toBe('main');
      expect(root.querySelector('.baseline')?.textContent).toContain(
        'New code is currently measured from analysis 3f2a1c4 · Sep 12, 2026',
      );
      expect(root.querySelector('.baseline code')?.textContent).toBe('3f2a1c4');
    });

    it('says so when the main branch has no earlier analysis', async () => {
      const server = setup();
      server.on('GET', '/api/v0/projects/new-code-baseline', {
        body: { ...BASELINE, revision: null, analysisId: null, analysisDate: null },
      });
      const { root } = await render();
      expect(root.querySelector('.baseline')?.textContent).toContain(
        'No baseline yet: the main branch has no earlier analysis.',
      );
    });

    it('shows the fallback and missing-baseline warnings as alerts', async () => {
      const server = setup();
      server.on('GET', '/api/v0/projects/new-code-baseline', {
        body: {
          ...BASELINE,
          warnings: ['NEW_CODE_DEFINITION_FALLBACK', 'NEW_CODE_BASELINE_MISSING'],
        },
      });
      const { root } = await render();
      const alerts = [...root.querySelectorAll('.alert-warn')].map((a) => a.textContent?.trim());
      expect(alerts).toEqual([
        'No analysis has a version label yet, so the last 30 days are used. Set project.version in qualor.yml.',
        'The baseline analysis is no longer available; the last 30 days are used.',
      ]);
    });

    it('is not requested without project.analyze', async () => {
      const server = setup();
      const { root } = await render({ canSeeBaseline: false });
      expect(server.requestsTo('GET', '/api/v0/projects/new-code-baseline')).toHaveLength(0);
      expect(root.querySelector('.baseline')).toBeNull();
    });

    it('is read again after a save', async () => {
      const server = setup();
      server.on('PATCH', `/api/v0/projects/${PROJECT}`, {
        body: project({ type: 'previous_version' }),
      });
      const { root, fixture } = await render();
      await pick(root, fixture, 2);
      save(root).click();
      await settle(fixture);
      expect(server.requestsTo('GET', '/api/v0/projects/new-code-baseline')).toHaveLength(2);
    });
  });
});

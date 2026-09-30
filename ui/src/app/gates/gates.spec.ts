import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ADMIN_PERMISSIONS,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { copyName } from '../shared/names';
import { GatePage, metricOptions, thresholdRange } from './gate.page';
import { type Gate, GatesPage } from './gates.page';

function gate(id: string, name: string, overrides: Partial<Gate> = {}): Gate {
  return {
    id,
    organizationId: ORG_ID,
    name,
    isDefault: false,
    isBuiltin: false,
    conditions: [{ id: 'c1', metric: 'new_issues', operator: 'gt', threshold: 0 }],
    createdAt: '',
    updatedAt: '',
    ...overrides,
  };
}

function setup(admin: boolean): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin }));
  return server;
}

const COVERAGE = {
  key: 'coverage',
  name: 'Coverage',
  type: 'percent' as const,
  direction: 'higher_is_better' as const,
  scopes: ['overall' as const, 'new' as const],
  domain: 'coverage',
};

/** A project of the organisation, using gate `qualityGateId` (null: the default gate). */
function project(id: string, qualityGateId: string | null) {
  return {
    id,
    organizationId: ORG_ID,
    key: `acme/${id}`,
    name: id,
    mainBranchName: 'main',
    qualityGateId,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    mainBranch: null,
  };
}

function dialogIn(root: HTMLElement, id: string): HTMLDialogElement {
  return root.querySelector<HTMLDialogElement>(`dialog#${id}`)!;
}

function buttonIn(root: ParentNode, text: string): HTMLButtonElement {
  return [...root.querySelectorAll<HTMLButtonElement>('button')].find(
    (b) => b.textContent?.trim() === text,
  )!;
}

describe('GatesPage', () => {
  it('lists the gates and lets an admin copy the built-in one', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates', {
      body: page([
        gate('g1', 'Qualor way', { isBuiltin: true, isDefault: true }),
        gate('g2', 'Strict'),
      ]),
    });
    server.on('POST', '/api/v0/quality-gates/g1/copy', {
      status: 201,
      body: gate('g3', 'Qualor way (copy)'),
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const rows = [...root.querySelectorAll('tbody tr')];
    expect(rows[0]?.textContent).toContain('Default');
    expect(rows[0]?.textContent).toContain('Built-in');
    // The built-in gate can be copied, not deleted; the default is not offered as default again.
    const buttons = (row: Element | undefined) =>
      [...(row?.querySelectorAll('button') ?? [])].map((b) => b.textContent?.trim());
    expect(buttons(rows[0])).toEqual(['Copy']);
    expect(buttons(rows[1])).toEqual(['Copy', 'Make default', 'Delete']);
    rows[0]?.querySelector('button')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/quality-gates/g1/copy')[0]?.body).toEqual({
      name: 'Qualor way (copy)',
    });
    expect(TestBed.inject(Router).url).toBe('/gates/g3');
  });

  it('offers no change to a member', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/quality-gates', { body: page([gate('g2', 'Strict')]) });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelectorAll('button')).toHaveLength(0);
    expect(root.querySelector('#gate-name')).toBeNull();
  });

  it('offers the changes to an organization admin by the permissions of their membership', async () => {
    const server = setup(false);
    const base = me();
    TestBed.inject(SessionStore).set({
      ...base,
      memberships: [
        { ...base.memberships[0]!, role: 'admin', permissions: [...ORG_ADMIN_PERMISSIONS] },
      ],
    });
    server.on('GET', '/api/v0/quality-gates', { body: page([gate('g2', 'Strict')]) });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('#gate-name')).not.toBeNull();
    expect(buttonIn(root, 'New gate')).toBeDefined();
  });

  it('asks before deleting, and deletes nothing when the question is dismissed', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates', { body: page([gate('g2', 'Strict <b>')]) });
    server.on('DELETE', '/api/v0/quality-gates/g2', { status: 204 });
    const confirm = vi.spyOn(window, 'confirm');
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const ask = dialogIn(root, 'confirm-dialog');
    const remove = () => buttonIn(root.querySelector('tbody')!, 'Delete');
    remove().click();
    await settle(fixture);
    // Intended change (step 6): the page's own dialog asks, not the browser's.
    expect(confirm).not.toHaveBeenCalled();
    expect(ask.open).toBe(true);
    expect(ask.querySelector('#confirm-text')?.textContent?.trim()).toBe(
      'Delete the quality gate "Strict <b>"? Its projects fall back to the default gate.',
    );
    buttonIn(ask, 'Cancel').click();
    await settle(fixture);
    expect(ask.open).toBe(false);
    expect(server.requestsTo('DELETE', '/api/v0/quality-gates/g2')).toHaveLength(0);
    remove().click();
    await settle(fixture);
    buttonIn(ask, 'Delete').click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', '/api/v0/quality-gates/g2')).toHaveLength(1);
    // The list is loaded again after the change.
    expect(server.requestsTo('GET', '/api/v0/quality-gates')).toHaveLength(2);
    confirm.mockRestore();
  });

  it('makes a gate the default and shows a refusal as a localized alert', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates', { body: page([gate('g2', 'Strict')]) });
    server.on('POST', '/api/v0/quality-gates/g2/set-default', {
      status: 403,
      body: problem(403, 'FORBIDDEN'),
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    [...root.querySelectorAll('button')]
      .find((b) => b.textContent?.trim() === 'Make default')!
      .click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/quality-gates/g2/set-default')).toHaveLength(1);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'You are not allowed to do this.',
    );
  });

  it('creates a gate with the trimmed name and opens it', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates', { body: page([]) });
    server.on('POST', '/api/v0/quality-gates', { status: 201, body: gate('g9', 'Release') });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    // Intended change (step 6): the form is in the "New gate" dialog.
    buttonIn(root, 'New gate').click();
    await settle(fixture);
    expect(dialogIn(root, 'create-dialog').open).toBe(true);
    const name = root.querySelector<HTMLInputElement>('#gate-name')!;
    name.value = '  Release ';
    name.dispatchEvent(new Event('input'));
    await settle(fixture);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/quality-gates')[0]?.body).toEqual({
      organizationId: ORG_ID,
      name: 'Release',
    });
    expect(TestBed.inject(Router).url).toBe('/gates/g9');
  });

  it('sums up the conditions of each gate', async () => {
    const server = setup(false);
    const c = (id: string, metric: string) => ({
      id,
      metric,
      operator: 'gt' as const,
      threshold: 0,
    });
    server.on('GET', '/api/v0/quality-gates', {
      body: page([
        gate('g1', 'New code', { conditions: [c('a', 'new_issues'), c('b', 'new_coverage')] }),
        gate('g2', 'Mixed', { conditions: [c('a', 'coverage'), c('b', 'new_issues')] }),
        gate('g3', 'Empty', { conditions: [] }),
        gate('g4', 'One overall', { conditions: [c('a', 'coverage')] }),
      ]),
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const summary = (id: string) =>
      root.querySelector(`tr[data-key="${id}"] td.summary`)?.textContent?.trim();
    expect(summary('g1')).toBe('2 conditions on new code');
    expect(summary('g2')).toBe('2 conditions, 1 on new code');
    expect(summary('g3')).toBe('No conditions');
    expect(summary('g4')).toBe('1 condition');
  });

  it('counts the projects using each gate: the default one also counts projects without a gate', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/quality-gates', {
      body: page([
        gate('g1', 'Qualor way', { isDefault: true }),
        gate('g2', 'Strict'),
        gate('g3', 'Unused'),
      ]),
    });
    server.on('GET', '/api/v0/projects', {
      body: page([project('a', null), project('b', 'g2'), project('c', 'g2'), project('d', 'g1')]),
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const usage = (id: string) =>
      root.querySelector(`tr[data-key="${id}"] td.usage`)?.textContent?.trim();
    expect(usage('g1')).toBe('2');
    expect(usage('g2')).toBe('2');
    expect(usage('g3')).toBe('0');
    const query = server.requestsTo('GET', '/api/v0/projects')[0]?.query;
    expect(query?.get('organizationId')).toBe(ORG_ID);
    expect(query?.get('limit')).toBe('500');
    expect(root.querySelector('.usage-note')).toBeNull();
  });

  it('shows dashes, not zeros, for an organization without projects', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/quality-gates', {
      body: page([gate('g1', 'Qualor way', { isDefault: true }), gate('g2', 'Strict')]),
    });
    server.on('GET', '/api/v0/projects', { body: page([]) });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('tr[data-key="g1"] td.usage')?.textContent?.trim()).toBe('–');
    expect(root.querySelector('tr[data-key="g2"] td.usage')?.textContent?.trim()).toBe('–');
  });

  it('says in the panel when the projects could not be counted', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/quality-gates', { body: page([gate('g2', 'Strict')]) });
    server.on('GET', '/api/v0/projects', { status: 500, body: problem(500, 'INTERNAL') });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('tr[data-key="g2"] td.usage')?.textContent?.trim()).toBe('–');
    expect(root.querySelector('section.panel [role="alert"]')?.textContent?.trim()).toBe(
      'The projects using each gate could not be counted.',
    );
  });

  it('groups large counts, and counts again after a delete moves projects to the default', async () => {
    const server = setup(true);
    let deleted = false;
    server.on('GET', '/api/v0/quality-gates', () => ({
      body: page([
        gate('g1', 'Qualor way', { isDefault: true }),
        ...(deleted ? [] : [gate('g2', 'Strict')]),
      ]),
    }));
    // 1 200 projects over three pages; two use Strict until it is deleted.
    server.on('GET', '/api/v0/projects', (request) => {
      const all = Array.from({ length: 1200 }, (_, i) =>
        project(`p${i}`, !deleted && i < 2 ? 'g2' : null),
      );
      const start = Number(request.query.get('cursor') ?? 0);
      const next = start + 500 < all.length ? String(start + 500) : null;
      return { body: page(all.slice(start, start + 500), next) };
    });
    server.on('DELETE', '/api/v0/quality-gates/g2', () => {
      deleted = true;
      return { status: 204 };
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const usage = (id: string) =>
      root.querySelector(`tr[data-key="${id}"] td.usage`)?.textContent?.trim();
    expect(usage('g1')).toBe('1,198');
    buttonIn(root.querySelector('tr[data-key="g2"]')!, 'Delete').click();
    await settle(fixture);
    buttonIn(dialogIn(root, 'confirm-dialog'), 'Delete').click();
    await settle(fixture);
    expect(usage('g1')).toBe('1,200');
  });

  it('says so when the counts cover only the first 5 000 projects', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/quality-gates', { body: page([gate('g2', 'Strict')]) });
    server.on('GET', '/api/v0/projects', { body: page([project('b', 'g2')], 'more') });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(10);
    expect(root.querySelector('.usage-note')?.textContent).toContain('first 5,000 projects');
  });

  it('counts nothing for someone who sees the organization only through a project grant', async () => {
    const server = setup(false);
    const base = me();
    TestBed.inject(SessionStore).set({
      ...base,
      memberships: [{ ...base.memberships[0]!, role: null, permissions: ['org.read'] }],
      projectGrants: [
        { projectId: 'b', projectKey: 'acme/b', organizationId: ORG_ID, role: 'viewer' },
      ],
    });
    server.on('GET', '/api/v0/quality-gates', {
      body: page([gate('g1', 'Qualor way', { isDefault: true })]),
    });
    // The server lists only the granted project: a count from it would say 1 of the organization's.
    server.on('GET', '/api/v0/projects', { body: page([project('b', null)]) });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('tr[data-key="g1"] td.usage')?.textContent?.trim()).toBe('–');
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(0);
  });
});

describe('GatePage', () => {
  it('adds a condition with the operator the metric direction suggests', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/metrics', {
      body: [
        {
          key: 'coverage',
          name: 'Coverage',
          type: 'percent',
          direction: 'higher_is_better',
          scopes: ['overall', 'new'],
          domain: 'coverage',
        },
      ],
    });
    server.on('POST', '/api/v0/quality-gates/g2/conditions', {
      status: 201,
      body: { id: 'c2', metric: 'new_coverage', operator: 'lt', threshold: 80 },
    });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    // Intended change (step 6): an editable condition is edited in place.
    expect(root.querySelector('tbody th')?.textContent?.trim()).toBe('Issues on new code');
    expect(root.querySelector<HTMLSelectElement>('#cond-op-c1')?.value).toBe('gt');
    expect(root.querySelector<HTMLInputElement>('#cond-th-c1')?.value).toBe('0');
    const metric = root.querySelector<HTMLSelectElement>('#condition-metric')!;
    metric.value = 'new_coverage';
    metric.dispatchEvent(new Event('change'));
    const threshold = root.querySelector<HTMLInputElement>('#condition-threshold')!;
    threshold.value = '80';
    threshold.dispatchEvent(new Event('input'));
    await settle(fixture);
    expect(root.querySelector<HTMLSelectElement>('#condition-operator')!.value).toBe('lt');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/quality-gates/g2/conditions')[0]?.body).toEqual({
      metric: 'new_coverage',
      operator: 'lt',
      threshold: 80,
    });
    expect(server.requestsTo('GET', '/api/v0/quality-gates/g2')).toHaveLength(2);
  });

  it('keeps the built-in gate read-only', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g1', {
      body: gate('g1', 'Qualor way', { isBuiltin: true }),
    });
    server.on('GET', '/api/v0/metrics', { body: [] });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g1');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.textContent).toContain('The built-in gate cannot change.');
    expect(root.querySelector('form')).toBeNull();
  });

  it('offers no editing to a member', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/metrics', { body: [COVERAGE] });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('form')).toBeNull();
    expect(root.querySelectorAll('button')).toHaveLength(0);
  });

  it('refuses a threshold outside the range of the metric before asking the server', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/metrics', { body: [COVERAGE] });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const metric = root.querySelector<HTMLSelectElement>('#condition-metric')!;
    metric.value = 'coverage';
    metric.dispatchEvent(new Event('change'));
    const threshold = root.querySelector<HTMLInputElement>('#condition-threshold')!;
    for (const value of ['150', '-1', '', 'abc']) {
      threshold.value = value;
      threshold.dispatchEvent(new Event('input'));
      await settle(fixture);
      root.querySelector('form')!.dispatchEvent(new Event('submit'));
      await settle(fixture);
      expect(root.querySelector('#condition-threshold-error')?.textContent?.trim()).toMatch(
        value === '150' || value === '-1' ? 'Enter a number from 0 to 100.' : /^Enter a number/,
      );
      expect(threshold.getAttribute('aria-invalid')).toBe('true');
    }
    expect(server.requestsTo('POST', '/api/v0/quality-gates/g2/conditions')).toHaveLength(0);
  });

  it('shows a 422 on the threshold next to the field, and a taken metric as an alert', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/metrics', { body: [COVERAGE] });
    let answer = {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.threshold', message: 'Must be between 0 and 100 for coverage' },
      ]),
    };
    server.on('POST', '/api/v0/quality-gates/g2/conditions', () => answer);
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const metric = root.querySelector<HTMLSelectElement>('#condition-metric')!;
    metric.value = 'coverage';
    metric.dispatchEvent(new Event('change'));
    const threshold = root.querySelector<HTMLInputElement>('#condition-threshold')!;
    threshold.value = '50';
    threshold.dispatchEvent(new Event('input'));
    await settle(fixture);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const error = root.querySelector('#condition-threshold-error')?.textContent ?? '';
    expect(error).toContain('outside what the metric allows');
    // The server's English message is never shown.
    expect(root.textContent).not.toContain('Must be between');
    answer = { status: 409, body: problem(409, 'CONDITION_EXISTS') };
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This gate already has a condition on that metric.',
    );
    expect(root.querySelector('#condition-threshold-error')).toBeNull();
  });

  it('removes a condition and loads the gate again', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/metrics', { body: [] });
    server.on('DELETE', '/api/v0/quality-gates/g2/conditions/c1', { status: 204 });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    root.querySelector<HTMLButtonElement>('tbody button.danger')!.click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', '/api/v0/quality-gates/g2/conditions/c1')).toHaveLength(1);
    expect(server.requestsTo('GET', '/api/v0/quality-gates/g2')).toHaveLength(2);
  });

  it('shows a missing gate as a localized alert', async () => {
    setup(true);
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'nope');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This item does not exist, or you cannot see it.',
    );
  });
});

describe('GatePage on the band (step 6)', () => {
  async function renderGate(server: FakeServer, id = 'g2') {
    server.on('GET', '/api/v0/metrics', { body: [COVERAGE] });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', id);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }
  const actions = (root: HTMLElement) =>
    [...root.querySelectorAll('.band-actions button')].map((b) => b.textContent?.trim());

  it('names the gate on the band, with its tags and the actions an admin may take', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict <b>') });
    const { root } = await renderGate(server);
    expect(root.querySelector('h1')?.textContent?.trim()).toBe('Strict <b>');
    expect(root.querySelector('h1 b')).toBeNull();
    expect(root.querySelector('nav[aria-label="Breadcrumb"] a')?.getAttribute('href')).toBe(
      '/gates',
    );
    expect(actions(root)).toEqual(['Copy', 'Rename', 'Make default', 'Delete']);
  });

  it('offers only Copy on the built-in default gate, and nothing to a member', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g1', {
      body: gate('g1', 'Qualor way', { isBuiltin: true, isDefault: true }),
    });
    const { root } = await renderGate(server, 'g1');
    expect(actions(root)).toEqual(['Copy']);
    expect(root.querySelector('.page-title')?.textContent).toContain('Default');
    expect(root.querySelector('.page-title')?.textContent).toContain('Built-in');
    // A member may not copy (create) a gate: the band offers nothing.
    TestBed.resetTestingModule();
    const member = setup(false);
    member.on('GET', '/api/v0/quality-gates/g1', {
      body: gate('g1', 'Qualor way', { isBuiltin: true, isDefault: true }),
    });
    const other = await renderGate(member, 'g1');
    expect(actions(other.root)).toEqual([]);
  });

  it('renames the gate in a dialog, and keeps a refused name there', async () => {
    const server = setup(true);
    let name = 'Strict';
    server.on('GET', '/api/v0/quality-gates/g2', () => ({ body: gate('g2', name) }));
    let refuse = true;
    server.on('PATCH', '/api/v0/quality-gates/g2', (request) => {
      if (refuse) {
        refuse = false;
        return {
          status: 422,
          body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.name', message: 'Too long' }]),
        };
      }
      name = (request.body as { name: string }).name;
      return { body: gate('g2', name) };
    });
    const { fixture, root } = await renderGate(server);
    buttonIn(root.querySelector('.band-actions')!, 'Rename').click();
    await settle(fixture);
    const dialog = dialogIn(root, 'rename-dialog');
    expect(dialog.open).toBe(true);
    const field = root.querySelector<HTMLInputElement>('#gate-rename')!;
    expect(field.value).toBe('Strict');
    field.value = '  Stricter ';
    field.dispatchEvent(new Event('input'));
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(dialog.open).toBe(true);
    expect(root.querySelector('#gate-rename-error')?.textContent).toContain(
      'at most 100 characters',
    );
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/quality-gates/g2').map((r) => r.body)).toEqual([
      { name: 'Stricter' },
      { name: 'Stricter' },
    ]);
    expect(dialog.open).toBe(false);
    expect(root.querySelector('h1')?.textContent?.trim()).toBe('Stricter');
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Renamed to Stricter.');
  });

  it('deletes the gate after the confirmation, then opens the list', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('DELETE', '/api/v0/quality-gates/g2', { status: 204 });
    const { fixture, root } = await renderGate(server);
    buttonIn(root.querySelector('.band-actions')!, 'Delete').click();
    await settle(fixture);
    const ask = dialogIn(root, 'confirm-dialog');
    expect(ask.querySelector('#confirm-text')?.textContent?.trim()).toBe(
      'Delete the quality gate "Strict"? Its projects fall back to the default gate.',
    );
    buttonIn(ask, 'Delete').click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', '/api/v0/quality-gates/g2')).toHaveLength(1);
    expect(TestBed.inject(Router).url).toBe('/gates');
  });

  it('makes the gate the default from the band', async () => {
    const server = setup(true);
    let isDefault = false;
    server.on('GET', '/api/v0/quality-gates/g2', () => ({
      body: gate('g2', 'Strict', { isDefault }),
    }));
    server.on('POST', '/api/v0/quality-gates/g2/set-default', () => {
      isDefault = true;
      return { body: gate('g2', 'Strict', { isDefault: true }) };
    });
    const { fixture, root } = await renderGate(server);
    const makeDefault = buttonIn(root.querySelector('.band-actions')!, 'Make default');
    makeDefault.focus();
    makeDefault.click();
    await settle(fixture);
    expect(root.querySelector('.page-title')?.textContent).toContain('Default');
    expect(actions(root)).toEqual(['Copy', 'Rename', 'Delete']);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Strict is now the default quality gate.',
    );
    // "Make default" is gone: focus moves to the band's first action, never to the page.
    expect(document.activeElement).toBe(buttonIn(root.querySelector('.band-actions')!, 'Copy'));
  });

  it('takes a decimal typed key by key, with a point or a comma, in place and in the add form', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', {
      body: gate('g2', 'Strict', {
        conditions: [{ id: 'c1', metric: 'new_coverage', operator: 'lt', threshold: 80 }],
      }),
    });
    server.on('PATCH', '/api/v0/quality-gates/g2/conditions/c1', {
      body: { id: 'c1', metric: 'new_coverage', operator: 'lt', threshold: 80.5 },
    });
    server.on('POST', '/api/v0/quality-gates/g2/conditions', {
      status: 201,
      body: { id: 'c2', metric: 'coverage', operator: 'lt', threshold: 1.5 },
    });
    const { fixture, root } = await renderGate(server);
    async function type(input: HTMLInputElement, text: string): Promise<void> {
      input.value = '';
      for (const key of text) {
        input.value += key;
        input.dispatchEvent(new Event('input'));
        await settle(fixture);
      }
    }
    const inPlace = root.querySelector<HTMLInputElement>('#cond-th-c1')!;
    await type(inPlace, '80.5');
    expect(inPlace.value).toBe('80.5');
    buttonIn(root.querySelector('tr[data-key="c1"]')!, 'Save').click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/quality-gates/g2/conditions/c1')[0]?.body).toEqual({
      operator: 'lt',
      threshold: 80.5,
    });
    const metric = root.querySelector<HTMLSelectElement>('#condition-metric')!;
    metric.value = 'coverage';
    metric.dispatchEvent(new Event('change'));
    const add = root.querySelector<HTMLInputElement>('#condition-threshold')!;
    await type(add, '1,5');
    expect(add.value).toBe('1,5');
    root.querySelector<HTMLFormElement>('form.panel-add')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/quality-gates/g2/conditions')[0]?.body).toEqual({
      metric: 'coverage',
      operator: 'lt',
      threshold: 1.5,
    });
  });

  it('edits a condition in place, offering Save only once it changed', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', {
      body: gate('g2', 'Strict', {
        conditions: [{ id: 'c1', metric: 'new_coverage', operator: 'lt', threshold: 80 }],
      }),
    });
    server.on('PATCH', '/api/v0/quality-gates/g2/conditions/c1', {
      body: { id: 'c1', metric: 'new_coverage', operator: 'lt', threshold: 85 },
    });
    const { fixture, root } = await renderGate(server);
    const row = root.querySelector('tr[data-key="c1"]')!;
    // Intended change (step 11): Save keeps its place, out of sight until the row changes.
    expect(buttonIn(row, 'Save').classList).toContain('idle');
    const threshold = root.querySelector<HTMLInputElement>('#cond-th-c1')!;
    threshold.value = '85';
    threshold.dispatchEvent(new Event('input'));
    await settle(fixture);
    const save = buttonIn(row, 'Save');
    expect(save.getAttribute('aria-label')).toBe('Save the condition on Coverage on new code');
    save.click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/quality-gates/g2/conditions/c1')[0]?.body).toEqual({
      operator: 'lt',
      threshold: 85,
    });
    expect(buttonIn(row, 'Save').classList).toContain('idle');
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Condition changed: Coverage on new code is less than 85 %.',
    );
  });

  it('keeps a refused edit in its row and says why, and checks the range before asking', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', {
      body: gate('g2', 'Strict', {
        conditions: [{ id: 'c1', metric: 'coverage', operator: 'lt', threshold: 80 }],
      }),
    });
    server.on('PATCH', '/api/v0/quality-gates/g2/conditions/c1', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.threshold', message: 'Out of range' },
      ]),
    });
    const { fixture, root } = await renderGate(server);
    const row = root.querySelector('tr[data-key="c1"]')!;
    const threshold = root.querySelector<HTMLInputElement>('#cond-th-c1')!;
    threshold.value = '150';
    threshold.dispatchEvent(new Event('input'));
    await settle(fixture);
    buttonIn(row, 'Save').click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/quality-gates/g2/conditions/c1')).toHaveLength(0);
    expect(row.querySelector('[role="alert"]')?.textContent).toContain(
      'Enter a number from 0 to 100.',
    );
    threshold.value = '50';
    threshold.dispatchEvent(new Event('input'));
    await settle(fixture);
    buttonIn(row, 'Save').click();
    await settle(fixture);
    expect(row.querySelector('[role="alert"]')?.textContent).toContain(
      'outside what the metric allows',
    );
    expect(threshold.value).toBe('50');
    expect(threshold.getAttribute('aria-invalid')).toBe('true');
  });
});

describe('metricOptions', () => {
  it('lists each scope of each metric under its localized label', () => {
    expect(
      metricOptions([
        {
          key: 'issues',
          name: 'Issues',
          type: 'int',
          direction: 'lower_is_better',
          scopes: ['overall', 'new'],
          domain: 'issues',
        },
      ]),
    ).toEqual([
      { key: 'issues', label: 'Issues', operator: 'gt' },
      { key: 'new_issues', label: 'Issues on new code', operator: 'gt' },
    ]);
  });
});

describe('thresholdRange', () => {
  it('follows the server: ratings 1–5, percentages 0–100, counts from 0', () => {
    const catalog = [
      COVERAGE,
      { ...COVERAGE, key: 'security_rating', type: 'rating' as const },
      { ...COVERAGE, key: 'issues', type: 'int' as const },
    ];
    expect(thresholdRange(catalog, 'new_coverage')).toEqual({ min: 0, max: 100 });
    expect(thresholdRange(catalog, 'security_rating')).toEqual({ min: 1, max: 5 });
    expect(thresholdRange(catalog, 'new_issues')).toEqual({
      min: 0,
      max: Number.MAX_SAFE_INTEGER,
    });
    expect(thresholdRange(catalog, 'unknown')).toBeNull();
  });
});

describe('gates: focus, announcements and route reuse (fix round 1)', () => {
  function button(root: ParentNode, text: string): HTMLButtonElement {
    return [...root.querySelectorAll<HTMLButtonElement>('button')].find(
      (b) => b.textContent?.trim() === text,
    )!;
  }

  function chooseCoverage(root: HTMLElement, value: string): void {
    const metric = root.querySelector<HTMLSelectElement>('#condition-metric')!;
    metric.value = 'coverage';
    metric.dispatchEvent(new Event('change'));
    const threshold = root.querySelector<HTMLInputElement>('#condition-threshold')!;
    threshold.value = value;
    threshold.dispatchEvent(new Event('input'));
  }

  it('makes a gate the default in place, announces it and keeps focus in its row', async () => {
    const server = setup(true);
    let isDefault = false;
    server.on('GET', '/api/v0/quality-gates', () => ({
      body: page([
        gate('g1', 'Qualor way', { isBuiltin: true, isDefault: !isDefault }),
        gate('g2', 'Strict', { isDefault }),
      ]),
    }));
    server.on('POST', '/api/v0/quality-gates/g2/set-default', () => {
      isDefault = true;
      return { body: gate('g2', 'Strict', { isDefault: true }) };
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const row = root.querySelector('tr[data-key="g2"]')!;
    const makeDefault = button(row, 'Make default');
    makeDefault.focus();
    makeDefault.click();
    await settle(fixture);
    // The row kept its element; its "Make default" button is gone, so its first button has focus.
    expect(root.querySelector('tr[data-key="g2"]')).toBe(row);
    expect(button(row, 'Make default')).toBeUndefined();
    expect(document.activeElement).toBe(button(row, 'Copy'));
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Strict is now the default quality gate.',
    );
  });

  it('warns that deleting the default gate stops gating the projects using the default', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates', {
      body: page([gate('g2', 'Strict', { isDefault: true })]),
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    button(root, 'Delete').click();
    await settle(fixture);
    expect(root.querySelector('#confirm-text')?.textContent?.trim()).toBe(
      'Delete the default quality gate "Strict"? The organization is then left without a default gate: every project that uses the default is no longer gated until you make another gate the default.',
    );
  });

  it('after a delete, focus goes to the next row and the result is announced', async () => {
    const server = setup(true);
    let deleted = false;
    server.on('GET', '/api/v0/quality-gates', () => ({
      body: page([
        gate('g1', 'Alpha'),
        ...(deleted ? [] : [gate('g2', 'Beta')]),
        gate('g3', 'Gamma'),
      ]),
    }));
    server.on('DELETE', '/api/v0/quality-gates/g2', () => {
      deleted = true;
      return { status: 204 };
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const gamma = root.querySelector('tr[data-key="g3"]')!;
    const remove = button(root.querySelector('tr[data-key="g2"]')!, 'Delete');
    remove.focus();
    remove.click();
    await settle(fixture);
    button(root.querySelector('dialog#confirm-dialog')!, 'Delete').click();
    await settle(fixture);
    expect(root.querySelector('tr[data-key="g2"]')).toBeNull();
    expect(root.querySelector('tr[data-key="g3"]')).toBe(gamma);
    expect(document.activeElement).toBe(button(gamma, 'Copy'));
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Quality gate Beta deleted.',
    );
  });

  it('reports a refused copy name as the copy failing, and keeps copy names within 100 characters', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates', { body: page([gate('g2', 'L'.repeat(98))]) });
    server.on('POST', '/api/v0/quality-gates/g2/copy', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.name', message: 'Too long' }]),
    });
    const fixture = TestBed.createComponent(GatesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    button(root, 'Copy').click();
    await settle(fixture);
    const sent = server.requestsTo('POST', '/api/v0/quality-gates/g2/copy')[0]?.body as {
      name: string;
    };
    expect(sent.name.length).toBeLessThanOrEqual(100);
    expect(sent.name.endsWith('… (copy)')).toBe(true);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'The copy could not be named after this gate.',
    );
    expect(root.querySelector('#gate-name-error')).toBeNull();
  });

  it('removes a condition, announces it and moves focus to the next Remove button', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', {
      body: gate('g2', 'Strict', {
        conditions: [
          { id: 'c1', metric: 'coverage', operator: 'lt', threshold: 80 },
          { id: 'c2', metric: 'new_issues', operator: 'gt', threshold: 0 },
        ],
      }),
    });
    server.on('GET', '/api/v0/metrics', { body: [] });
    let release: () => void = () => undefined;
    server.on('DELETE', '/api/v0/quality-gates/g2/conditions/c1', async () => {
      await new Promise<void>((resolve) => (release = resolve));
      return { status: 204 };
    });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const first = root.querySelector<HTMLButtonElement>('tr[data-key="c1"] button.danger')!;
    first.focus();
    first.click();
    await settle(fixture);
    // While the change runs the buttons stay enabled and focused, only marked busy.
    expect(first.disabled).toBe(false);
    expect(first.getAttribute('aria-disabled')).toBe('true');
    expect(document.activeElement).toBe(first);
    release();
    await settle(fixture);
    expect(document.activeElement).toBe(root.querySelector('tr[data-key="c2"] button.danger'));
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Condition removed: Coverage.',
    );
  });

  it('focuses the Conditions heading when the last condition is removed', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/metrics', { body: [] });
    server.on('DELETE', '/api/v0/quality-gates/g2/conditions/c1', { status: 204 });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const only = root.querySelector<HTMLButtonElement>('tbody button.danger')!;
    only.focus();
    only.click();
    await settle(fixture);
    expect(document.activeElement?.textContent?.trim()).toBe('Conditions');
  });

  it('shows a refused metric on the metric field', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/metrics', { body: [COVERAGE] });
    server.on('POST', '/api/v0/quality-gates/g2/conditions', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.metric', message: 'Unknown' }]),
    });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    chooseCoverage(root, '50');
    await settle(fixture);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#condition-metric-error')?.textContent).toContain(
      'This server does not know this metric.',
    );
    expect(root.querySelector('#condition-metric')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.textContent).not.toContain('Check the highlighted fields');
  });

  it('says so when the metric catalog cannot be loaded', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/metrics', { status: 500, body: problem(500, 'INTERNAL') });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const alert = (fixture.nativeElement as HTMLElement).querySelector('form [role="alert"]');
    expect(alert?.textContent).toContain('The metrics could not be loaded:');
  });

  it('resets the form when another gate opens, and ignores the late answer for the old one', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict') });
    server.on('GET', '/api/v0/quality-gates/g3', { body: gate('g3', 'Other') });
    server.on('GET', '/api/v0/metrics', { body: [COVERAGE] });
    let release: () => void = () => undefined;
    server.on('POST', '/api/v0/quality-gates/g2/conditions', async () => {
      await new Promise<void>((resolve) => (release = resolve));
      return {
        status: 422,
        body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.threshold', message: 'x' }]),
      };
    });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    chooseCoverage(root, '50');
    await settle(fixture);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    fixture.componentRef.setInput('gateId', 'g3');
    await settle(fixture);
    release();
    await settle(fixture);
    expect(root.querySelector('h1')?.textContent).toBe('Other');
    expect(root.querySelector<HTMLSelectElement>('#condition-metric')!.value).toBe('');
    expect(root.querySelector<HTMLInputElement>('#condition-threshold')!.value).toBe('');
    expect(root.querySelector('#condition-threshold-error')).toBeNull();
    expect(root.querySelector('[role="alert"]')).toBeNull();
    // The new gate is usable at once (the old change no longer holds the page busy).
    expect(root.querySelector('tbody button.danger')?.getAttribute('aria-disabled')).toBeNull();
  });
});

describe('copyName', () => {
  it('shortens the original so the copy fits 100 characters', () => {
    const format = (n: string) => `${n} (copy)`;
    expect(copyName('Strict', format)).toBe('Strict (copy)');
    const long = copyName('x'.repeat(100), format);
    expect(long).toHaveLength(100);
    expect(long.endsWith('x… (copy)')).toBe(true);
    // A surrogate pair is never cut in half.
    const emoji = copyName('😀'.repeat(50), format);
    expect(emoji.length).toBeLessThanOrEqual(100);
    expect(() => encodeURIComponent(emoji)).not.toThrow();
  });
});

describe('GatePage: editing in place, and busy states (step 11)', () => {
  const RATING = {
    key: 'security_rating',
    name: 'Security rating',
    type: 'rating' as const,
    direction: 'lower_is_better' as const,
    scopes: ['overall' as const, 'new' as const],
    domain: 'security',
  };
  const TWO: Gate['conditions'] = [
    { id: 'c1', metric: 'new_coverage', operator: 'lt' as const, threshold: 80 },
    { id: 'c2', metric: 'coverage', operator: 'lt' as const, threshold: 70 },
  ];

  async function renderGate(server: FakeServer, conditions: Gate['conditions'] = TWO) {
    server.on('GET', '/api/v0/quality-gates/g2', { body: gate('g2', 'Strict', { conditions }) });
    server.on('GET', '/api/v0/metrics', { body: [COVERAGE, RATING] });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g2');
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  function type(root: HTMLElement, id: string, value: string): HTMLInputElement {
    const input = root.querySelector<HTMLInputElement>(`#cond-th-${id}`)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    return input;
  }

  it('names the conditions table by its heading', async () => {
    const { root } = await renderGate(setup(true));
    expect(root.querySelector('table')?.getAttribute('aria-labelledby')).toBe('conditions-heading');
  });

  it('saves an edit with Enter, and drops a draft with Escape', async () => {
    const server = setup(true);
    server.on('PATCH', '/api/v0/quality-gates/g2/conditions/c1', {
      body: { id: 'c1', metric: 'new_coverage', operator: 'lt', threshold: 85 },
    });
    const { fixture, root } = await renderGate(server);
    type(root, 'c1', '85').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    await settle(fixture);
    expect(server.requestsTo('PATCH', '/api/v0/quality-gates/g2/conditions/c1')).toHaveLength(1);
    const input = type(root, 'c2', '60');
    await settle(fixture);
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await settle(fixture);
    expect(input.value).toBe('70');
    expect(server.requestsTo('PATCH', '/api/v0/quality-gates/g2/conditions/c2')).toHaveLength(0);
  });

  it("keeps Save's place while nothing changed, so the fields never move", async () => {
    const { fixture, root } = await renderGate(setup(true));
    const save = () => root.querySelector<HTMLButtonElement>('tr[data-key="c1"] button.cond-save')!;
    expect(getComputedStyle(save()).visibility).toBe('hidden');
    type(root, 'c1', '85');
    await settle(fixture);
    expect(getComputedStyle(save()).visibility).toBe('visible');
  });

  it("writes a rating threshold's letter beside its number", async () => {
    const { fixture, root } = await renderGate(setup(true), [
      { id: 'c3', metric: 'security_rating', operator: 'gt', threshold: 1 },
    ]);
    const letter = () => root.querySelector('tr[data-key="c3"] .cond-unit')?.textContent?.trim();
    expect(letter()).toBe('A');
    type(root, 'c3', '3');
    await settle(fixture);
    expect(letter()).toBe('C');
  });

  it('says a built-in gate is copied from its own band', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g1', {
      body: gate('g1', 'Qualor way', { isBuiltin: true, isDefault: true }),
    });
    server.on('GET', '/api/v0/metrics', { body: [COVERAGE] });
    const fixture = TestBed.createComponent(GatePage);
    fixture.componentRef.setInput('gateId', 'g1');
    await settle(fixture);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain(
      'The built-in gate cannot change. Copy it to make your own.',
    );
  });

  it('shows each refused row its own reason, and a save clears an older page error', async () => {
    const server = setup(true);
    server.on('POST', '/api/v0/quality-gates/g2/set-default', {
      status: 403,
      body: problem(403, 'FORBIDDEN'),
    });
    const { fixture, root } = await renderGate(server);
    buttonIn(root, 'Make default').click();
    await settle(fixture);
    expect(root.querySelector('.page-body > [role="alert"], [role="alert"]')).not.toBeNull();
    type(root, 'c1', '101');
    type(root, 'c2', '-1');
    await settle(fixture);
    for (const id of ['c1', 'c2']) {
      root.querySelector<HTMLButtonElement>(`tr[data-key="${id}"] button.cond-save`)!.click();
      await settle(fixture);
    }
    expect(root.querySelector('#cond-error-c1')?.textContent).toContain(
      'Enter a number from 0 to 100.',
    );
    expect(root.querySelector('#cond-error-c2')?.textContent).toContain(
      'Enter a number from 0 to 100.',
    );
    // The band's refusal is older than these: a save clears it.
    expect(root.textContent).not.toContain('You are not allowed to do this.');
  });

  it('marks Save, Remove, Rename and Delete busy while a change runs', async () => {
    const server = setup(true);
    let answer!: () => void;
    server.on(
      'PATCH',
      '/api/v0/quality-gates/g2/conditions/c1',
      () =>
        new Promise((resolve) => {
          answer = () =>
            resolve({ body: { id: 'c1', metric: 'new_coverage', operator: 'lt', threshold: 85 } });
        }),
    );
    const { fixture, root } = await renderGate(server);
    type(root, 'c1', '85');
    await settle(fixture);
    root.querySelector<HTMLButtonElement>('tr[data-key="c1"] button.cond-save')!.click();
    await settle(fixture);
    const busy = (text: string) =>
      [...root.querySelectorAll('.band-actions button, tbody button')]
        .filter((b) => b.textContent?.trim() === text)
        .every((b) => b.getAttribute('aria-disabled') === 'true');
    expect(['Remove', 'Rename', 'Delete'].map(busy)).toEqual([true, true, true]);
    answer();
    await settle(fixture);
    expect(['Remove', 'Rename', 'Delete'].map(busy)).toEqual([false, false, false]);
  });

  it('closes the rename dialog when the route shows another gate', async () => {
    const server = setup(true);
    server.on('GET', '/api/v0/quality-gates/g3', { body: gate('g3', 'Other') });
    const { fixture, root } = await renderGate(server);
    buttonIn(root, 'Rename').click();
    await settle(fixture);
    const rename = root.querySelector<HTMLDialogElement>('dialog#rename-dialog')!;
    expect(rename.open).toBe(true);
    fixture.componentRef.setInput('gateId', 'g3');
    await settle(fixture);
    expect(rename.open).toBe(false);
  });
});

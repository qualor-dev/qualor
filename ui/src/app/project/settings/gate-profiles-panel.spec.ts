import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import type { ProjectDto } from '../current-project';
import { GateProfilesPanel } from './gate-profiles-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const G1 = '0190a6c2-0000-7000-8000-0000000000c1';
const G2 = '0190a6c2-0000-7000-8000-0000000000c2';
const G3 = '0190a6c2-0000-7000-8000-0000000000c3';
const P_TS_DEFAULT = '0190a6c2-0000-7000-8000-0000000000d1';
const P_TS_STRICT = '0190a6c2-0000-7000-8000-0000000000d2';
const P_JAVA_DEFAULT = '0190a6c2-0000-7000-8000-0000000000d3';
const P_ANY = '0190a6c2-0000-7000-8000-0000000000d4';

function project(qualityGateId: string | null = null): ProjectDto {
  return {
    id: PROJECT,
    organizationId: ORG_ID,
    key: 'acme/payments',
    name: 'Payments',
    mainBranchName: 'main',
    qualityGateId,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    permissions: ['project.read', 'project.settings'],
  } as ProjectDto;
}

const gate = (id: string, name: string, isDefault = false) => ({
  id,
  organizationId: ORG_ID,
  name,
  isDefault,
  isBuiltin: false,
  conditions: [],
});

const profile = (id: string, name: string, language: string, isDefault = false) => ({
  id,
  organizationId: ORG_ID,
  name,
  language,
  parentId: null,
  isDefault,
  isBuiltin: false,
  unknownRules: 'ignore',
  createdAt: '',
  updatedAt: '',
});

const TS_PROFILES = [
  profile(P_TS_DEFAULT, 'Qualor way', 'typescript', true),
  profile(P_TS_STRICT, 'Strict', 'typescript'),
];

function setup(): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/quality-gates', (request) =>
    request.query.get('cursor') === 'next'
      ? { body: page([gate(G3, 'Strict gate')]) }
      : { body: page([gate(G1, 'Qualor way', true), gate(G2, 'Relaxed')], 'next') },
  );
  server.on('GET', `/api/v0/projects/${PROJECT}/quality-profiles`, {
    body: [
      { language: '*', profile: profile(P_ANY, 'Any', '*', true), source: 'default' },
      {
        language: 'typescript',
        profile: profile(P_TS_DEFAULT, 'Qualor way', 'typescript', true),
        source: 'default',
      },
      {
        language: 'java',
        profile: profile(P_JAVA_DEFAULT, 'Java way', 'java'),
        source: 'project',
      },
    ],
  });
  server.on('GET', '/api/v0/quality-profiles', (request) => {
    const language = request.query.get('language');
    if (language === 'typescript') return { body: page(TS_PROFILES) };
    if (language === 'java') return { body: page([profile(P_JAVA_DEFAULT, 'Java way', 'java')]) };
    return { body: page([profile(P_ANY, 'Any', '*', true)]) };
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  return server;
}

async function render(qualityGateId: string | null = null) {
  const fixture = TestBed.createComponent(GateProfilesPanel);
  fixture.componentRef.setInput('project', project(qualityGateId));
  const saved = vi.fn();
  fixture.componentInstance.saved.subscribe(saved);
  await settle(fixture);
  return { fixture, saved, root: fixture.nativeElement as HTMLElement };
}

const gateSelect = (root: HTMLElement) => root.querySelector<HTMLSelectElement>('#project-gate')!;
const save = (root: HTMLElement) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Save')!;
const rows = (root: HTMLElement) => [...root.querySelectorAll<HTMLElement>('tbody tr')];
const rowSelect = (row: HTMLElement) => row.querySelector<HTMLSelectElement>('select')!;
const optionTexts = (select: HTMLSelectElement) =>
  [...select.options].map((o) => o.textContent?.trim());

function choose(select: HTMLSelectElement, value: string): void {
  select.value = value;
  select.dispatchEvent(new Event('change'));
}

describe('GateProfilesPanel gate (spec §3.2)', () => {
  it('renders the panel section with its heading', async () => {
    setup();
    const { root } = await render();
    const section = root.querySelector('section.card.panel')!;
    expect(section.id).toBe('gate');
    expect(section.querySelector('.panel-head h2')?.textContent?.trim()).toBe(
      'Quality gate and profiles',
    );
  });

  it('lists every page of gates, suffixes the default and selects it for a project without one', async () => {
    const server = setup();
    const { root } = await render(null);
    const queries = server.requestsTo('GET', '/api/v0/quality-gates').map((r) => r.query);
    expect(queries.map((q) => [q.get('organizationId'), q.get('limit'), q.get('cursor')])).toEqual([
      [ORG_ID, '100', null],
      [ORG_ID, '100', 'next'],
    ]);
    expect(optionTexts(gateSelect(root))).toEqual([
      'Qualor way (default)',
      'Relaxed',
      'Strict gate',
    ]);
    expect(gateSelect(root).value).toBe(G1);
    expect(
      root.querySelector<HTMLAnchorElement>('a[href="/gates/' + G1 + '"]')?.textContent,
    ).toContain('View gate');
    expect(save(root).disabled).toBe(true);
    expect(save(root).className).toBe('btn');
  });

  it('selects the project gate and points the link at it', async () => {
    setup();
    const { root, fixture } = await render(G2);
    expect(gateSelect(root).value).toBe(G2);
    expect(root.querySelector('a[href="/gates/' + G2 + '"]')).not.toBeNull();
    choose(gateSelect(root), G3);
    await settle(fixture);
    expect(root.querySelector('a[href="/gates/' + G3 + '"]')).not.toBeNull();
  });

  it('saves the chosen gate, emits saved and announces it', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, { body: project(G2) });
    const { root, fixture, saved } = await render();
    choose(gateSelect(root), G2);
    await settle(fixture);
    expect(save(root).disabled).toBe(false);
    expect(save(root).classList).toContain('btn');
    expect(save(root).classList).toContain('btn-primary');
    save(root).click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', `/api/v0/projects/${PROJECT}`)[0]?.body).toEqual({
      qualityGateId: G2,
    });
    expect(saved).toHaveBeenCalledTimes(1);
    expect(root.querySelector('[role=status]')?.textContent).toContain('Quality gate saved.');
  });

  it('keeps an unsaved gate choice when the project is read again', async () => {
    setup();
    const { root, fixture } = await render();
    choose(gateSelect(root), G2);
    await settle(fixture);
    fixture.componentRef.setInput('project', project());
    await settle(fixture);
    expect(gateSelect(root).value).toBe(G2);
    expect(save(root).disabled).toBe(false);
  });

  it('shows a refused save as an alert and does not emit saved', async () => {
    const server = setup();
    server.on('PATCH', `/api/v0/projects/${PROJECT}`, {
      status: 404,
      body: problem(404, 'NOT_FOUND'),
    });
    const { root, fixture, saved } = await render();
    choose(gateSelect(root), G2);
    await settle(fixture);
    save(root).click();
    await settle(fixture);
    expect(root.querySelector('.alert-error[role=alert]')).not.toBeNull();
    expect(saved).not.toHaveBeenCalled();
  });
});

describe('GateProfilesPanel profiles (spec §3.2)', () => {
  it('has one row per language, the catch-all last as Other languages', async () => {
    const server = setup();
    const { root } = await render();
    expect(rows(root).map((r) => r.querySelector('th, td')?.textContent?.trim())).toEqual([
      'TypeScript',
      'Java',
      'Other languages',
    ]);
    const languages = server
      .requestsTo('GET', '/api/v0/quality-profiles')
      .map((r) => [r.query.get('organizationId'), r.query.get('language'), r.query.get('limit')]);
    expect(languages).toEqual(
      expect.arrayContaining([
        [ORG_ID, 'typescript', '100'],
        [ORG_ID, 'java', '100'],
      ]),
    );
    const [ts, java] = rows(root);
    expect(optionTexts(rowSelect(ts!))).toEqual(['Qualor way', 'Strict']);
    expect(rowSelect(ts!).value).toBe(P_TS_DEFAULT);
    expect(rowSelect(java!).value).toBe(P_JAVA_DEFAULT);
  });

  it('does not read the profiles again when the project is read again', async () => {
    const server = setup();
    const { fixture } = await render();
    const assigned = `/api/v0/projects/${PROJECT}/quality-profiles`;
    const before = [
      server.requestsTo('GET', assigned).length,
      server.requestsTo('GET', '/api/v0/quality-profiles').length,
    ];
    fixture.componentRef.setInput('project', project());
    await settle(fixture);
    expect([
      server.requestsTo('GET', assigned).length,
      server.requestsTo('GET', '/api/v0/quality-profiles').length,
    ]).toEqual(before);
  });

  it('tags only the rows that use the organisation default', async () => {
    setup();
    const { root } = await render();
    const [ts, java] = rows(root);
    expect(ts!.querySelector('.badge')?.textContent?.trim()).toBe('Default');
    expect(java!.querySelector('.badge')).toBeNull();
  });

  it('saves a change at once, marks the select busy meanwhile and announces it', async () => {
    const server = setup();
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    server.on('PUT', `/api/v0/projects/${PROJECT}/quality-profiles/typescript`, async () => {
      await held;
      return {
        body: { language: 'typescript', profile: TS_PROFILES[1], source: 'project' },
      };
    });
    const { root, fixture } = await render();
    const [ts] = rows(root);
    choose(rowSelect(ts!), P_TS_STRICT);
    await settle(fixture);
    expect(rowSelect(ts!).getAttribute('aria-busy')).toBe('true');
    // Busy, not disabled: the select keeps focus and stays in the tab order.
    expect(rowSelect(ts!).disabled).toBe(false);
    expect(rowSelect(ts!).getAttribute('aria-disabled')).toBe('true');
    // A change meanwhile is ignored and put back.
    choose(rowSelect(ts!), P_TS_DEFAULT);
    await settle(fixture);
    expect(
      server.requestsTo('PUT', `/api/v0/projects/${PROJECT}/quality-profiles/typescript`),
    ).toHaveLength(1);
    release();
    await settle(fixture);
    const put = server.requestsTo('PUT', `/api/v0/projects/${PROJECT}/quality-profiles/typescript`);
    expect(put[0]?.body).toEqual({ profileId: P_TS_STRICT });
    expect(rowSelect(ts!).getAttribute('aria-busy')).toBeNull();
    expect(rowSelect(ts!).getAttribute('aria-disabled')).toBeNull();
    expect(rowSelect(ts!).value).toBe(P_TS_STRICT);
    expect(ts!.querySelector('.badge')).toBeNull();
    expect(root.querySelector('[role=status]')?.textContent).toContain(
      'Profile for TypeScript saved.',
    );
  });

  it('shows a failure in its row and restores the previous profile', async () => {
    const server = setup();
    server.on('PUT', `/api/v0/projects/${PROJECT}/quality-profiles/typescript`, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED'),
    });
    const { root, fixture } = await render();
    const [ts, java] = rows(root);
    choose(rowSelect(ts!), P_TS_STRICT);
    await settle(fixture);
    expect(ts!.querySelector('td .field-error')?.textContent?.trim()).not.toBe('');
    expect(rowSelect(ts!).value).toBe(P_TS_DEFAULT);
    expect(ts!.querySelector('.badge')).not.toBeNull();
    expect(java!.querySelector('.field-error')).toBeNull();
  });
});

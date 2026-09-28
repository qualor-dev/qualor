import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
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
import type { AuditEvent } from '../api/ee';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { AuditLogPage } from './audit-log.page';
import { SettingsPage } from './settings.page';

const OTHER_ORG = '0190a6c2-0000-7000-8000-000000000002';
const BOB = '0190a6c2-0000-7000-8000-00000000000b';
const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const HASH = 'ab'.repeat(32);
const EVENTS = '/api/v0/ee/audit/events';

function event(seq: string, action: string, overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    v: 1,
    seq,
    id: `0190a6c2-0000-7000-8000-${seq.padStart(12, '0')}`,
    occurredAt: '2026-09-20T10:00:00.000Z',
    action,
    outcome: 'success',
    actor: { type: 'user', userId: BOB, username: 'bob', tokenId: null },
    organization: { id: ORG_ID, key: 'default' },
    project: { id: PROJECT, key: 'acme/payments' },
    target: { type: 'user', id: BOB, label: 'carol' },
    ip: '203.0.113.7',
    userAgent: 'Mozilla/5.0',
    details: { role: 'viewer' },
    prevHash: '0'.repeat(64),
    hash: HASH,
    ...overrides,
  };
}

interface Setup {
  /** An instance admin (else an organisation admin of ORG_ID, or a member with `role: 'member'`). */
  instanceAdmin?: boolean;
  role?: 'admin' | 'member';
  features?: string[];
}

function setup(options: Setup = {}): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([
      {
        id: ORG_ID,
        key: 'default',
        name: 'Default',
        createdAt: '',
        updatedAt: '',
      },
      { id: OTHER_ORG, key: 'other', name: 'Other', createdAt: '', updatedAt: '' },
    ]),
  });
  server.on('GET', '/api/v0/system/info', {
    body: {
      version: '0.1.0',
      edition: 'enterprise',
      features: options.features ?? ['audit-log'],
      extensions: [],
    },
  });
  server.on('GET', EVENTS, {
    body: page([event('12', 'project_member.added'), event('11', 'auth.login')], 'c-11'),
  });
  server.on('GET', '/api/v0/ee/audit/head', {
    body: {
      seq: '12',
      hash: HASH,
      occurredAt: '2026-09-20T10:00:00.000Z',
      count: 12,
      anchor: null,
    },
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  const base = me({ admin: options.instanceAdmin ?? false });
  const role = options.role ?? 'admin';
  TestBed.inject(SessionStore).set(
    options.instanceAdmin
      ? base
      : {
          ...base,
          memberships: [
            {
              ...base.memberships[0]!,
              role,
              permissions: role === 'admin' ? [...ORG_ADMIN_PERMISSIONS] : ['org.read'],
            },
          ],
        },
  );
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(AuditLogPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

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

function button(root: HTMLElement, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

async function apply(fixture: { whenStable(): Promise<unknown> }, root: HTMLElement) {
  root.querySelector<HTMLFormElement>('form.filters')!.dispatchEvent(new Event('submit'));
  await settle(fixture);
}

describe('AuditLogPage (rbac-audit.md §13, §17)', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-27T15:00:00.000Z'));
  });
  afterEach(() => {
    vi.useRealTimers();
    // The organization switch test chooses an organization, which the browser remembers.
    localStorage.clear();
  });

  it('lists the events newest first for the last 30 days, and follows nextCursor', async () => {
    const server = setup({ instanceAdmin: true });
    const { fixture, root } = await render();
    const [first] = server.requestsTo('GET', EVENTS);
    expect(first?.query.get('from')).toBe('2026-08-29T00:00:00.000Z');
    expect(first?.query.get('to')).toBe('2026-09-28T00:00:00.000Z');
    expect(first?.query.has('organizationId')).toBe(false);
    const rows = [...root.querySelectorAll('tbody tr[data-key]')];
    expect(rows.map((r) => r.getAttribute('data-key'))).toEqual(['12', '11']);
    expect(rows[0]?.textContent).toContain('project_member.added');
    expect(rows[0]?.textContent).toContain('bob');
    expect(rows[0]?.textContent).toContain('Succeeded');
    button(root, 'Load more').click();
    await settle(fixture);
    expect(server.requestsTo('GET', EVENTS).at(-1)?.query.get('cursor')).toBe('c-11');
  });

  it('builds the query from the filters: period, repeated actions, outcome, user, project and organization', async () => {
    const server = setup({ instanceAdmin: true });
    server.on('GET', '/api/v0/users/lookup', {
      body: { id: BOB, username: 'bob', displayName: null },
    });
    server.on('GET', '/api/v0/projects/by-key', {
      body: { id: PROJECT, organizationId: ORG_ID, key: 'acme/payments', name: 'Payments' },
    });
    const { fixture, root } = await render();
    type(root, '#audit-from', '2026-09-01');
    type(root, '#audit-to', '2026-09-10');
    type(root, '#audit-action', 'project_member.*, auth.login');
    choose(root, '#audit-outcome', 'failure');
    type(root, '#audit-user', 'bob');
    type(root, '#audit-project', 'acme/payments');
    choose(root, '#audit-organization', OTHER_ORG);
    await apply(fixture, root);
    const last = server.requestsTo('GET', EVENTS).at(-1)!;
    expect(last.query.get('from')).toBe('2026-09-01T00:00:00.000Z');
    expect(last.query.get('to')).toBe('2026-09-11T00:00:00.000Z');
    expect(last.query.getAll('action')).toEqual(['project_member.*', 'auth.login']);
    expect(last.query.get('outcome')).toBe('failure');
    expect(last.query.get('actorUserId')).toBe(BOB);
    expect(last.query.get('projectId')).toBe(PROJECT);
    expect(last.query.get('organizationId')).toBe(OTHER_ORG);
    expect(
      server.requestsTo('GET', '/api/v0/users/lookup').map((r) => r.query.get('username')),
    ).toEqual(['bob']);
  });

  it('refuses an action filter that is not a name or a prefix ending in .*, on the field', async () => {
    const server = setup({ instanceAdmin: true });
    const { fixture, root } = await render();
    const before = server.requestsTo('GET', EVENTS).length;
    type(root, '#audit-action', '*');
    await apply(fixture, root);
    expect(root.querySelector('#audit-action-error')?.textContent).toContain(
      'Use action names such as auth.login, or a prefix such as project_member.*',
    );
    expect(root.querySelector('#audit-action')?.getAttribute('aria-invalid')).toBe('true');
    expect(server.requestsTo('GET', EVENTS)).toHaveLength(before);
  });

  it('says so on the field when no active user has that name', async () => {
    const server = setup({ instanceAdmin: true });
    server.on('GET', '/api/v0/users/lookup', { status: 404, body: problem(404, 'NOT_FOUND') });
    const { fixture, root } = await render();
    const before = server.requestsTo('GET', EVENTS).length;
    type(root, '#audit-user', 'ghost');
    await apply(fixture, root);
    expect(root.querySelector('#audit-user-error')?.textContent).toContain(
      'No active user has that name',
    );
    expect(server.requestsTo('GET', EVENTS)).toHaveLength(before);
  });

  it("always sends an organization admin's own organization, and offers no organization filter", async () => {
    const server = setup();
    const { fixture, root } = await render();
    expect(root.querySelector('#audit-organization')).toBeNull();
    expect(server.requestsTo('GET', EVENTS)[0]?.query.get('organizationId')).toBe(ORG_ID);
    type(root, '#audit-action', 'issue.*');
    await apply(fixture, root);
    expect(server.requestsTo('GET', EVENTS).at(-1)?.query.get('organizationId')).toBe(ORG_ID);
    const link = root.querySelector<HTMLAnchorElement>('a[download]')!;
    expect(new URL(link.href).searchParams.get('organizationId')).toBe(ORG_ID);
    const hint = root.querySelector(`#${link.getAttribute('aria-describedby') ?? ''}`);
    expect(hint?.textContent).toContain('Another of your exports may still be running');
  });

  it('shows no chain head and no verification to an organization admin, and never asks for them', async () => {
    const server = setup();
    const { root } = await render();
    expect(root.textContent).not.toContain('Verify chain');
    expect(server.requestsTo('GET', '/api/v0/ee/audit/head')).toEqual([]);
  });

  it('expands a row to its details', async () => {
    setup({ instanceAdmin: true });
    const { fixture, root } = await render();
    const toggle = root.querySelector<HTMLButtonElement>('tr[data-key="12"] button')!;
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    toggle.click();
    await settle(fixture);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    const details = root.querySelector(`#${toggle.getAttribute('aria-controls')}`)!;
    expect(details.textContent).toContain('203.0.113.7');
    expect(details.textContent).toContain('"role": "viewer"');
    expect(details.textContent).toContain(HASH);
  });

  it('exports JSON Lines through a download link with the period and the filters, not a request that reads the body', async () => {
    const server = setup({ instanceAdmin: true });
    const { fixture, root } = await render();
    type(root, '#audit-action', 'project_member.*');
    choose(root, '#audit-outcome', 'success');
    await apply(fixture, root);
    const link = root.querySelector<HTMLAnchorElement>('a[download]')!;
    expect(link.textContent?.trim()).toBe('Export JSON Lines');
    const url = new URL(link.href);
    expect(url.pathname).toBe('/api/v0/ee/audit/export');
    expect(url.searchParams.get('from')).toBe('2026-08-29T00:00:00.000Z');
    expect(url.searchParams.get('to')).toBe('2026-09-28T00:00:00.000Z');
    expect(url.searchParams.getAll('action')).toEqual(['project_member.*']);
    expect(url.searchParams.get('outcome')).toBe('success');
    expect(url.searchParams.has('cursor')).toBe(false);
    expect(server.requestsTo('GET', '/api/v0/ee/audit/export')).toEqual([]);
  });

  it('shows the chain head to an instance admin, with a copy button for the full hash', async () => {
    setup({ instanceAdmin: true });
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const { fixture, root } = await render();
    const head = root.querySelector('#audit-head')!;
    expect(head.textContent).toContain('12');
    expect(head.textContent).toContain(HASH.slice(0, 12));
    expect(head.textContent).not.toContain(HASH);
    button(root, 'Copy the full hash').click();
    await settle(fixture);
    expect(writeText).toHaveBeenCalledWith(HASH);
  });

  it('verifies the chain and says it is intact, with a plural', async () => {
    const server = setup({ instanceAdmin: true });
    server.on('GET', '/api/v0/ee/audit/verify', {
      body: { ok: true, checked: 12, firstSeq: '1', lastSeq: '12', anchor: null, break: null },
    });
    const { fixture, root } = await render();
    button(root, 'Verify chain').click();
    await settle(fixture);
    expect(server.requestsTo('GET', '/api/v0/ee/audit/verify')).toHaveLength(1);
    expect(root.querySelector('#audit-verify-result')?.textContent?.trim()).toBe(
      'The chain is intact (12 events).',
    );
  });

  it('says where the chain breaks and why', async () => {
    const server = setup({ instanceAdmin: true });
    server.on('GET', '/api/v0/ee/audit/verify', {
      body: {
        ok: false,
        checked: 7,
        firstSeq: '1',
        lastSeq: '7',
        anchor: null,
        break: { seq: '7', reason: 'hash_mismatch' },
      },
    });
    const { fixture, root } = await render();
    button(root, 'Verify chain').click();
    await settle(fixture);
    expect(root.querySelector('#audit-verify-result')?.textContent?.trim()).toBe(
      'The chain breaks at event 7: the event was changed after it was recorded (its hash does not match).',
    );
  });

  it('explains a damaged chain anchor (409 AUDIT_CHAIN_ANCHOR_MALFORMED)', async () => {
    const server = setup({ instanceAdmin: true });
    server.on('GET', '/api/v0/ee/audit/head', {
      status: 409,
      body: problem(409, 'AUDIT_CHAIN_ANCHOR_MALFORMED'),
    });
    const { root } = await render();
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      "The audit log's anchor record (the instance setting audit-chain) is damaged",
    );
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'most audited changes are refused (removing access still works)',
    );
  });

  it("drops the previous organization's events on a switch, even while its search is still busy", async () => {
    const server = setup();
    const session = TestBed.inject(SessionStore);
    const base = me();
    session.set({
      ...base,
      memberships: [
        { ...base.memberships[0]!, role: 'admin', permissions: [...ORG_ADMIN_PERMISSIONS] },
        {
          organizationId: OTHER_ORG,
          organizationKey: 'other',
          organizationName: 'Other',
          role: 'admin',
          permissions: [...ORG_ADMIN_PERMISSIONS],
        },
      ],
    });
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    server.on('GET', EVENTS, async (request) => {
      if (request.query.get('organizationId') === ORG_ID) {
        await held;
        return { body: page([event('12', 'project_member.added')]) };
      }
      return { body: page([event('30', 'webhook.created', { organization: null })]) };
    });
    const { fixture, root } = await render();
    TestBed.inject(OrgContext).select(OTHER_ORG);
    await settle(fixture);
    release();
    await settle(fixture);
    expect(server.requestsTo('GET', EVENTS).map((r) => r.query.get('organizationId'))).toEqual([
      ORG_ID,
      OTHER_ORG,
    ]);
    const rows = [...root.querySelectorAll('tbody tr[data-key]')];
    expect(rows.map((r) => r.getAttribute('data-key'))).toEqual(['30']);
    expect(
      root
        .querySelector<HTMLButtonElement>('form.filters button[type="submit"]')
        ?.getAttribute('aria-disabled'),
    ).toBeNull();
  });

  it('frees the search button when a scope change replaces a busy search that it cannot redo', async () => {
    const server = setup();
    const session = TestBed.inject(SessionStore);
    const base = me();
    session.set({
      ...base,
      memberships: [
        { ...base.memberships[0]!, role: 'admin', permissions: [...ORG_ADMIN_PERMISSIONS] },
        {
          organizationId: OTHER_ORG,
          organizationKey: 'other',
          organizationName: 'Other',
          role: 'admin',
          permissions: [...ORG_ADMIN_PERMISSIONS],
        },
      ],
    });
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    server.on('GET', EVENTS, async () => {
      await held;
      return { body: page([event('12', 'project_member.added')]) };
    });
    const { fixture, root } = await render();
    const submit = () =>
      root
        .querySelector<HTMLButtonElement>('form.filters button[type="submit"]')
        ?.getAttribute('aria-disabled');
    expect(submit()).toBe('true');
    // The new scope's search stops at the invalid day, before it would mark itself busy.
    type(root, '#audit-from', 'not a day');
    TestBed.inject(OrgContext).select(OTHER_ORG);
    await settle(fixture);
    release();
    await settle(fixture);
    expect(server.requestsTo('GET', EVENTS)).toHaveLength(1);
    expect(root.querySelector('#audit-from-error')?.textContent).toContain('Enter a day.');
    expect(submit()).toBeNull();
  });

  it('says so when the server information cannot be loaded, instead of an empty page', async () => {
    const server = setup({ instanceAdmin: true });
    server.on('GET', '/api/v0/system/info', { status: 500, body: problem(500, 'INTERNAL') });
    const { root } = await render();
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
  });

  it('asks nothing of the enterprise API without audit-log', async () => {
    const server = setup({ instanceAdmin: true, features: ['sso'] });
    const { root } = await render();
    expect(root.textContent).toContain('The audit log needs an enterprise licence');
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
  });

  it('asks nothing for a member who may not read the audit log', async () => {
    const server = setup({ role: 'member' });
    const { root } = await render();
    expect(root.textContent).toContain(
      'Only instance administrators and organization administrators read the audit log.',
    );
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/ee/'))).toEqual([]);
  });
});

describe('SettingsPage audit entries (rbac-audit.md §17)', () => {
  const EXTENSIONS = [
    { point: 'settings.nav', id: 'audit-log', label: 'Audit log', path: '/settings/ee/audit-log' },
    {
      point: 'settings.nav',
      id: 'audit-settings',
      label: 'Audit settings',
      path: '/settings/ee/audit-settings',
    },
  ];

  async function links(options: Setup): Promise<(string | null)[]> {
    const server = setup(options);
    server.on('GET', '/api/v0/system/info', {
      body: {
        version: '0.1.0',
        edition: 'enterprise',
        features: options.features ?? ['audit-log'],
        extensions: EXTENSIONS,
      },
    });
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    return [...(fixture.nativeElement as HTMLElement).querySelectorAll('nav a')].map((a) =>
      a.getAttribute('href'),
    );
  }

  it('lists both entries for an instance admin, at their own routes', async () => {
    const hrefs = await links({ instanceAdmin: true });
    expect(hrefs).toContain('/ee/audit-log');
    expect(hrefs).toContain('/ee/audit-settings');
  });

  it('lists the audit log, and not its settings, for an organization admin', async () => {
    const hrefs = await links({});
    expect(hrefs).toContain('/ee/audit-log');
    expect(hrefs).not.toContain('/ee/audit-settings');
  });

  it('lists neither for a member, nor without audit-log', async () => {
    expect((await links({ role: 'member' })).some((h) => h?.includes('audit'))).toBe(false);
    TestBed.resetTestingModule();
    expect(
      (await links({ instanceAdmin: true, features: ['sso'] })).some((h) => h?.includes('audit')),
    ).toBe(false);
  });
});

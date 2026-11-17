import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  expectNoPasswordManager,
  FakeServer,
  jiraConnection,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import type { JiraConnection, JiraSettingsAnswer, JiraTestResult } from '../api/types';
import { SessionStore } from '../auth/session';
import { jiraFailureText, jiraProblemFix, jiraProblemText } from '../jira/jira-text';
import { JiraSettingsPage } from './jira.page';
import { SettingsPage } from './settings.page';

const URL = `/api/v0/organizations/${ORG_ID}/jira`;

function setup(
  connection: JiraConnection | null = jiraConnection(),
  options: { admin?: boolean; publicUrlSet?: boolean } = {},
): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
  const answer: JiraSettingsAnswer = { connection, publicUrlSet: options.publicUrlSet ?? true };
  server.on('GET', URL, { body: answer });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? true }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(JiraSettingsPage);
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

function button(root: ParentNode, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

function submit(root: HTMLElement): void {
  root.querySelector<HTMLFormElement>('form#jira-form')!.dispatchEvent(new Event('submit'));
}

const OK_TEST: JiraTestResult = {
  ok: true,
  user: { displayName: 'Ada' },
  projectsVisible: 3,
  problem: null,
};

describe('SettingsPage: Jira (0.16 §6.1)', () => {
  afterEach(() => localStorage.clear());

  async function labels(admin: boolean): Promise<(string | undefined)[]> {
    setup(null, { admin });
    const fixture = TestBed.createComponent(SettingsPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    return [...root.querySelectorAll('nav a')].map((a) => a.textContent?.trim());
  }

  it('lists Jira for org.jira.manage only, after GitHub', async () => {
    const admin = await labels(true);
    expect(admin).toContain('Jira');
    expect(admin.indexOf('Jira')).toBe(admin.indexOf('GitHub') + 1);
    TestBed.resetTestingModule();
    expect(await labels(false)).not.toContain('Jira');
  });
});

describe('JiraSettingsPage', () => {
  afterEach(() => localStorage.clear());

  it('Cloud shows Email and the scoped-token API URL; Data Center hides both', async () => {
    setup(null);
    const { fixture, root } = await render();
    choose(root, '#jira-deployment', 'cloud');
    await settle(fixture);
    expect(root.querySelector('#jira-email')).not.toBeNull();
    expect(root.querySelector('#jira-api-url')).not.toBeNull();
    expect(root.textContent).toContain('Scoped token? API URL');
    expect(root.querySelector('label[for="jira-token"]')?.textContent).toContain('API token');
    choose(root, '#jira-deployment', 'data_center');
    await settle(fixture);
    expect(root.querySelector('#jira-email')).toBeNull();
    expect(root.querySelector('#jira-api-url')).toBeNull();
    expect(root.querySelector('label[for="jira-token"]')?.textContent).toContain(
      'Personal access token',
    );
    expectNoPasswordManager(root.querySelector('#jira-token')!);
  });

  it('creates the connection with the fields, and empties the token field', async () => {
    const server = setup(null);
    server.on('PUT', URL, { body: jiraConnection({ siteUrl: 'https://acme.atlassian.net' }) });
    const { fixture, root } = await render();
    choose(root, '#jira-deployment', 'cloud');
    await settle(fixture);
    type(root, '#jira-site-url', 'https://acme.atlassian.net');
    type(root, '#jira-email', 'ada@example.com');
    type(root, '#jira-token', 'secret-token');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)[0]?.body).toEqual({
      deployment: 'cloud',
      siteUrl: 'https://acme.atlassian.net',
      email: 'ada@example.com',
      apiUrl: null,
      token: 'secret-token',
    });
    expect(root.querySelector<HTMLInputElement>('#jira-token')!.value).toBe('');
    expect(root.textContent).not.toContain('secret-token');
  });

  it('asks for the token when there is no connection yet', async () => {
    const server = setup(null);
    const { fixture, root } = await render();
    type(root, '#jira-site-url', 'https://jira.example.com');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', URL)).toHaveLength(0);
    expect(root.querySelector('#jira-token-error')).not.toBeNull();
  });

  it('an update with an empty token field sends no token', async () => {
    const server = setup(jiraConnection({ deployment: 'cloud', email: 'ada@example.com' }));
    server.on('PUT', URL, {
      body: jiraConnection({ deployment: 'cloud', email: 'b@example.com' }),
    });
    const { fixture, root } = await render();
    type(root, '#jira-email', 'b@example.com');
    submit(root);
    await settle(fixture);
    const body = server.requestsTo('PUT', URL)[0]?.body as Record<string, unknown>;
    expect(body).toEqual({
      deployment: 'cloud',
      siteUrl: 'https://jira.example.com',
      email: 'b@example.com',
      apiUrl: null,
    });
    expect('token' in body).toBe(false);
  });

  it('a changed address asks first, naming the mappings and links, then sends the token', async () => {
    const server = setup(
      jiraConnection({
        mappedProjects: 2,
        links: { pending: 1, created: 10, failed: 1, missing: 1, dismissed: 1 },
      }),
    );
    server.on('PUT', URL, { body: jiraConnection({ siteUrl: 'https://jira2.example.com' }) });
    const { fixture, root } = await render();
    type(root, '#jira-site-url', 'https://jira2.example.com');
    type(root, '#jira-token', 'new-token');
    submit(root);
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#jira-confirm-dialog')!;
    expect(dialog.open).toBe(true);
    expect(dialog.textContent).toContain('2 mapped projects');
    expect(dialog.textContent).toContain('14 links');
    expect(server.requestsTo('PUT', URL)).toHaveLength(0);
    button(dialog, 'Change the address').click();
    await settle(fixture);
    expect(dialog.open).toBe(false);
    expect(server.requestsTo('PUT', URL)[0]?.body).toMatchObject({
      siteUrl: 'https://jira2.example.com',
      token: 'new-token',
    });
  });

  it('a changed address without a token shows the 422 under the token field', async () => {
    const server = setup(jiraConnection());
    server.on('PUT', URL, {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.token', message: 'Needed' }]),
    });
    const { fixture, root } = await render();
    type(root, '#jira-site-url', 'https://jira2.example.com');
    submit(root);
    await settle(fixture);
    button(root.querySelector('dialog#jira-confirm-dialog')!, 'Change the address').click();
    await settle(fixture);
    expect(root.querySelector('#jira-token-error')?.textContent).toContain('token');
    expect(root.querySelector('.alert-error')).toBeNull();
  });

  it('Test shows who is connected and how many projects, with a plural', async () => {
    const server = setup();
    server.on('POST', `${URL}/test`, { body: OK_TEST });
    const { fixture, root } = await render();
    button(root, 'Test').click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Connected as Ada; 3 projects visible',
    );
    server.on('POST', `${URL}/test`, { body: { ...OK_TEST, projectsVisible: 1 } });
    button(root, 'Test').click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Connected as Ada; 1 project visible',
    );
    expect(root.querySelector('[role="status"]')?.textContent).not.toContain('1 projects');
  });

  it('Test shows the problem and its fix when it fails', async () => {
    const server = setup();
    server.on('POST', `${URL}/test`, {
      body: {
        ok: false,
        user: null,
        projectsVisible: null,
        problem: { code: 'token_refused', message: 'fixed English' },
      } satisfies JiraTestResult,
    });
    const { fixture, root } = await render();
    button(root, 'Test').click();
    await settle(fixture);
    const alert = root.querySelector('.alert-error')!;
    expect(alert.textContent).toContain(jiraProblemText('token_refused'));
    expect(alert.textContent).toContain(jiraProblemFix('token_refused'));
    expect(alert.textContent).not.toContain('fixed English');
  });

  it('shows a stored problem as a banner with its fix', async () => {
    setup(
      jiraConnection({
        problem: { code: 'captcha', message: 'x', at: '2026-11-17T09:00:00.000Z' },
      }),
    );
    const { root } = await render();
    const banner = root.querySelector('.alert-error')!;
    expect(banner.textContent).toContain(jiraProblemText('captcha'));
    expect(banner.textContent).toContain(jiraProblemFix('captcha'));
  });

  it('warns about QUALOR_PUBLIC_URL while it is not set, before the first save too', async () => {
    setup(null, { publicUrlSet: false });
    const { root } = await render();
    expect(root.textContent).toContain('QUALOR_PUBLIC_URL');
    TestBed.resetTestingModule();
    setup(jiraConnection(), { publicUrlSet: true });
    const again = await render();
    expect(again.root.textContent).not.toContain('QUALOR_PUBLIC_URL');
  });

  it('shows the link counts and the mapped projects', async () => {
    setup(
      jiraConnection({
        mappedProjects: 2,
        links: { pending: 1, created: 10, failed: 3, missing: 4, dismissed: 5 },
      }),
    );
    const { root } = await render();
    const facts = [...root.querySelectorAll('.jira-facts > div')].map(
      (row) => `${row.querySelector('dt')?.textContent} ${row.querySelector('dd')?.textContent}`,
    );
    expect(facts).toEqual([
      'Mapped projects 2',
      'Waiting 1',
      'Created 10',
      'Failed 3',
      'Missing 4',
      'Unlinked 5',
    ]);
  });

  it('Remove confirms that Jira keeps its issues, then deletes', async () => {
    const server = setup(jiraConnection());
    server.on('DELETE', URL, { status: 204 });
    const { fixture, root } = await render();
    button(root, 'Remove').click();
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#jira-remove-dialog')!;
    expect(dialog.open).toBe(true);
    expect(dialog.textContent).toContain('Jira keeps its issues');
    expect(server.requestsTo('DELETE', URL)).toHaveLength(0);
    button(dialog, 'Remove connection').click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', URL)).toHaveLength(1);
    expect(root.querySelector('.jira-facts')).toBeNull();
    expect(root.querySelector('[role="status"]')?.textContent).toContain('removed');
  });

  it('tells a user without the permission, and asks the server nothing', async () => {
    const server = setup(null, { admin: false });
    const { root } = await render();
    expect(root.textContent).toContain('Only organization administrators');
    expect(server.requestsTo('GET', URL)).toHaveLength(0);
  });
});

describe('jiraFailureText', () => {
  it('shows the server message for field_refused and its own text for other codes', () => {
    expect(jiraFailureText({ code: 'field_refused', message: 'Summary is required' })).toBe(
      'Summary is required',
    );
    expect(jiraFailureText({ code: 'not_found', message: 'raw' })).toBe(
      jiraProblemText('not_found'),
    );
  });
});

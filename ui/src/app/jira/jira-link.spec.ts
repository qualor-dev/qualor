import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  jiraLink,
  jiraProjectSettings,
  me,
  MEMBER_PROJECT_PERMISSIONS,
  ORG_ID,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import type { JiraLink, JiraProjectSettings } from '../api/types';
import { SessionStore } from '../auth/session';
import { CurrentProject } from '../project/current-project';
import { JiraLinkView } from './jira-link';

const PROJECT = 'p1';
const ISSUE = '0190a6c2-0000-7000-8000-0000000000a1';
const LINK = jiraLink().id;
const LINKS = `/api/v0/projects/${PROJECT}/jira/links`;
const RETRY = `/api/v0/jira-links/${LINK}/retry`;
const UNLINK = `/api/v0/jira-links/${LINK}`;
/** A project admin's permissions on the project: triage and its settings. */
const ADMIN = [...MEMBER_PROJECT_PERMISSIONS, 'project.settings'];

const PENDING = jiraLink({
  state: 'pending',
  key: null,
  url: null,
  status: null,
  statusCheckedAt: null,
});

const text = (el: Element | null | undefined) => el?.textContent.replace(/\s+/g, ' ').trim();
const button = (root: HTMLElement, label: string) =>
  [...root.querySelectorAll('button')].find((b) => text(b) === label);

interface Inputs {
  link?: JiraLink | null;
  linkable?: boolean;
  canTriage?: boolean;
  compact?: boolean;
  target?: { issueId: string } | { packageName: string; vulnerabilityId: string };
}

describe('JiraLinkView', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  /** The project (with `permissions`) and its Jira state; null leaves the Jira read unanswered. */
  function setup(
    settings: JiraProjectSettings | null,
    permissions: readonly string[] = MEMBER_PROJECT_PERMISSIONS,
  ) {
    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: { id: PROJECT, organizationId: ORG_ID, permissions: [...permissions] },
    });
    if (settings) server.on('GET', `/api/v0/projects/${PROJECT}/jira`, { body: settings });
  }

  async function render(inputs: Inputs = {}) {
    TestBed.inject(CurrentProject).use(PROJECT);
    const fixture = TestBed.createComponent(JiraLinkView);
    fixture.componentRef.setInput('projectId', PROJECT);
    fixture.componentRef.setInput('target', inputs.target ?? { issueId: ISSUE });
    fixture.componentRef.setInput('link', inputs.link ?? null);
    fixture.componentRef.setInput('linkable', inputs.linkable ?? true);
    fixture.componentRef.setInput('canTriage', inputs.canTriage ?? true);
    fixture.componentRef.setInput('compact', inputs.compact ?? false);
    const changed = vi.fn();
    fixture.componentInstance.changed.subscribe(changed);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement, changed };
  }

  it('shows nothing at all without a Jira connection, to a project admin either', async () => {
    setup(jiraProjectSettings({ connected: false }), ADMIN);
    const { root } = await render();
    expect(root.children).toHaveLength(0);
    expect(text(root)).toBe('');
  });

  it('offers "Create Jira issue" only with issue.triage, a linkable finding and a mapped project', async () => {
    setup(jiraProjectSettings());
    const { fixture, root } = await render();
    expect(text(root.querySelector('h3'))).toBe('Jira');
    expect(button(root, 'Create Jira issue')).toBeDefined();

    fixture.componentRef.setInput('canTriage', false);
    await settle(fixture);
    expect(button(root, 'Create Jira issue')).toBeUndefined();
    expect(text(root)).toBe('');

    fixture.componentRef.setInput('canTriage', true);
    fixture.componentRef.setInput('linkable', false);
    await settle(fixture);
    expect(text(root)).toBe('');
  });

  it('shows a project admin of an unmapped project the way to map it, and others nothing', async () => {
    setup(jiraProjectSettings({ mapped: false }), ADMIN);
    const { fixture, root } = await render();
    expect(button(root, 'Create Jira issue')).toBeUndefined();
    const map = [...root.querySelectorAll('a')].find((a) => text(a) === 'Map this project to Jira');
    expect(map?.getAttribute('href')).toBe(`/projects/${PROJECT}/settings#jira`);

    // Not linkable (a closed issue, another branch): nothing at all.
    fixture.componentRef.setInput('linkable', false);
    await settle(fixture);
    expect(text(root)).toBe('');
  });

  it('shows a member of an unmapped project nothing', async () => {
    setup(jiraProjectSettings({ mapped: false }));
    const { root } = await render();
    expect(text(root)).toBe('');
  });

  it('creates the Jira issue of an issue, then says "Creating…" and tells the page', async () => {
    setup(jiraProjectSettings());
    server.on('POST', LINKS, {
      status: 202,
      body: { items: [{ issueId: ISSUE, link: PENDING, skipped: null }] },
    });
    const { fixture, root, changed } = await render();
    button(root, 'Create Jira issue')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', LINKS)[0]?.body).toEqual({ issueIds: [ISSUE] });
    expect(text(root)).toContain('Creating…');
    expect(button(root, 'Create Jira issue')).toBeUndefined();
    expect(changed).toHaveBeenCalledOnce();
  });

  it('creates the Jira issue of a vulnerability by its package and id', async () => {
    setup(jiraProjectSettings());
    const target = { packageName: 'lodash', vulnerabilityId: 'CVE-2026-0001' };
    server.on('POST', LINKS, {
      status: 202,
      body: { items: [{ ...target, link: PENDING, skipped: null }] },
    });
    const { fixture, root } = await render({ target });
    button(root, 'Create Jira issue')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', LINKS)[0]?.body).toEqual({ vulnerabilities: [target] });
    expect(text(root)).toContain('Creating…');
  });

  it('says why a finding was not linked', async () => {
    setup(jiraProjectSettings());
    server.on('POST', LINKS, {
      status: 202,
      body: { items: [{ issueId: ISSUE, link: null, skipped: 'NOT_ELIGIBLE' }] },
    });
    const { fixture, root } = await render();
    button(root, 'Create Jira issue')?.click();
    await settle(fixture);
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'This finding cannot get a Jira issue now.',
    );
  });

  it('explains a broken connection by its problem (409 JIRA_CONNECTION_BROKEN)', async () => {
    setup(jiraProjectSettings());
    server.on('POST', LINKS, {
      status: 409,
      body: { ...problem(409, 'JIRA_CONNECTION_BROKEN'), problemCode: 'token_refused' },
    });
    const { fixture, root } = await render();
    button(root, 'Create Jira issue')?.click();
    await settle(fixture);
    expect(text(root.querySelector('[role="alert"]'))).toContain(
      'Jira refused the token or the email.',
    );
  });

  it('says "Creating…" while the link is pending', async () => {
    setup(jiraProjectSettings());
    const { root } = await render({ link: PENDING });
    expect(text(root)).toContain('Creating…');
    expect(button(root, 'Create Jira issue')).toBeUndefined();
  });

  it('links the key to Jira in a new tab, with a status pill by category and when it was checked', async () => {
    setup(jiraProjectSettings());
    const checked = new Date(Date.now() - 5 * 60_000 - 10_000).toISOString();
    const { fixture, root } = await render({ link: jiraLink({ statusCheckedAt: checked }) });
    const key = root.querySelector('a.jira-key');
    expect(text(key)).toBe('PAY-12');
    expect(key?.getAttribute('href')).toBe('https://jira.example.com/browse/PAY-12');
    expect(key?.getAttribute('target')).toBe('_blank');
    expect(key?.getAttribute('rel')).toBe('noopener noreferrer');
    const pill = root.querySelector('.jira-status');
    expect(text(pill)).toBe('In Progress');
    expect(pill?.classList).toContain('jira-status-indeterminate');
    expect(text(root)).toContain('checked 5 min ago');

    for (const category of ['new', 'done'] as const) {
      fixture.componentRef.setInput(
        'link',
        jiraLink({ statusCheckedAt: checked, status: { name: 'Status', category } }),
      );
      await settle(fixture);
      expect(root.querySelector('.jira-status')?.classList).toContain(`jira-status-${category}`);
    }
  });

  it('shows a link without any action to a role without issue.triage', async () => {
    setup(jiraProjectSettings());
    const { root } = await render({ link: jiraLink(), canTriage: false });
    expect(text(root.querySelector('a.jira-key'))).toBe('PAY-12');
    expect(root.querySelectorAll('button')).toHaveLength(0);
  });

  it('shows why a link failed in the UI’s words, and retries it', async () => {
    setup(jiraProjectSettings());
    server.on('POST', RETRY, { status: 202, body: PENDING });
    const failed = jiraLink({
      state: 'failed',
      key: null,
      url: null,
      status: null,
      failure: { code: 'permission_missing', message: 'permission_missing' },
    });
    const { fixture, root, changed } = await render({ link: failed });
    expect(text(root)).toContain('The account lacks a permission in Jira.');
    button(root, 'Retry')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', RETRY)).toHaveLength(1);
    expect(text(root)).toContain('Creating…');
    expect(changed).toHaveBeenCalledOnce();
  });

  it('shows Jira’s own reason for a refused field', async () => {
    setup(jiraProjectSettings());
    const failed = jiraLink({
      state: 'failed',
      key: null,
      url: null,
      status: null,
      failure: { code: 'field_refused', message: 'Component is required.' },
    });
    const { root } = await render({ link: failed });
    expect(text(root)).toContain('Component is required.');
  });

  it('says a Jira issue that is gone is not found in Jira, and creates it again', async () => {
    setup(jiraProjectSettings());
    server.on('POST', RETRY, { status: 202, body: PENDING });
    const { fixture, root } = await render({ link: jiraLink({ state: 'missing' }) });
    expect(text(root)).toContain('Not found in Jira');
    button(root, 'Create again')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', RETRY)).toHaveLength(1);
    expect(text(root)).toContain('Creating…');
  });

  it('asks before it unlinks, sends nothing on Cancel, and DELETEs the link on Unlink', async () => {
    setup(jiraProjectSettings());
    server.on('DELETE', UNLINK, { status: 204 });
    const { fixture, root, changed } = await render({ link: jiraLink() });
    button(root, 'Unlink')?.click();
    await settle(fixture);
    let dialog = root.querySelector<HTMLDialogElement>('dialog');
    expect(dialog?.open).toBe(true);
    expect(text(dialog)).toContain('PAY-12');
    button(dialog!, 'Cancel')?.click();
    await settle(fixture);
    expect(root.querySelector('dialog')?.open ?? false).toBe(false);
    expect(server.requestsTo('DELETE', UNLINK)).toHaveLength(0);

    button(root, 'Unlink')?.click();
    await settle(fixture);
    dialog = root.querySelector<HTMLDialogElement>('dialog');
    button(dialog!, 'Unlink')?.click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', UNLINK)).toHaveLength(1);
    expect(root.querySelector('a.jira-key')).toBeNull();
    expect(button(root, 'Create Jira issue')).toBeDefined();
    expect(changed).toHaveBeenCalledOnce();
  });

  describe('as a pill', () => {
    const target = { packageName: 'lodash', vulnerabilityId: 'CVE-2026-0001' };

    it('names its row action after the vulnerability', async () => {
      setup(jiraProjectSettings());
      const { root } = await render({ compact: true, target });
      expect(root.querySelector('h3')).toBeNull();
      expect(button(root, 'Create Jira issue')?.getAttribute('aria-label')).toBe(
        'Create Jira issue for CVE-2026-0001 in lodash',
      );
    });

    it('shows the key and the status, and says "Creating Jira issue…" while pending', async () => {
      setup(jiraProjectSettings());
      const { fixture, root } = await render({ compact: true, target, link: jiraLink() });
      expect(text(root.querySelector('a.jira-key'))).toBe('PAY-12');
      expect(text(root.querySelector('.jira-status'))).toBe('In Progress');
      fixture.componentRef.setInput('link', PENDING);
      await settle(fixture);
      expect(text(root)).toContain('Creating Jira issue…');
    });

    it('never repeats "Map this project to Jira" in a row', async () => {
      setup(jiraProjectSettings({ mapped: false }), ADMIN);
      const { root } = await render({ compact: true, target });
      expect(text(root)).toBe('');
    });
  });
});

import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  boardsLink,
  boardsProjectSettings,
  type FakeReply,
  FakeServer,
  me,
  MEMBER_PROJECT_PERMISSIONS,
  ORG_ID,
  pendingBoardsLink,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import type { BoardsLink, BoardsProjectSettings } from '../api/types';
import { SessionStore } from '../auth/session';
import { CurrentProject } from '../project/current-project';
import { BoardsLinkView } from './boards-link';
import { boardsFailureText } from './boards-text';

const PROJECT = 'p1';
const ISSUE = '0190a6c2-0000-7000-8000-0000000000a1';
const LINK = boardsLink().id;
const LINKS = `/api/v0/projects/${PROJECT}/boards/links`;
const RETRY = `/api/v0/boards-links/${LINK}/retry`;
const UNLINK = `/api/v0/boards-links/${LINK}`;
const URL_42 =
  'https://dev.azure.com/contoso/6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c/_workitems/edit/42';
/** A project admin's permissions on the project: triage and its settings. */
const ADMIN = [...MEMBER_PROJECT_PERMISSIONS, 'project.settings'];

const PENDING = pendingBoardsLink();
const failed = (code: string, message = code) =>
  boardsLink({
    state: 'failed',
    workItemId: null,
    url: null,
    workItemState: null,
    stateCheckedAt: null,
    failure: { code, message },
  });

const text = (el: Element | null | undefined) => el?.textContent.replace(/\s+/g, ' ').trim();
const button = (root: HTMLElement, label: string) =>
  [...root.querySelectorAll('button')].find((b) => text(b) === label);

interface Inputs {
  link?: BoardsLink | null;
  linkable?: boolean;
  canTriage?: boolean;
  compact?: boolean;
  target?: { issueId: string } | { packageName: string; vulnerabilityId: string };
}

describe('BoardsLinkView', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  /** The project (with `permissions`) and its Boards state; null leaves the Boards read unanswered. */
  function setup(
    settings: BoardsProjectSettings | null,
    permissions: readonly string[] = MEMBER_PROJECT_PERMISSIONS,
  ) {
    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: { id: PROJECT, organizationId: ORG_ID, permissions: [...permissions] },
    });
    if (settings) server.on('GET', `/api/v0/projects/${PROJECT}/boards`, { body: settings });
  }

  async function render(inputs: Inputs = {}) {
    TestBed.inject(CurrentProject).use(PROJECT);
    const fixture = TestBed.createComponent(BoardsLinkView);
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

  it('shows nothing at all without a Boards mapping or link, to a project admin either', async () => {
    setup(boardsProjectSettings({ mapped: false }), ADMIN);
    const { fixture, root } = await render();
    expect(root.children).toHaveLength(0);
    expect(text(root)).toBe('');

    // No Azure DevOps connection at all: nothing either, in a row too.
    fixture.componentRef.setInput('compact', true);
    await settle(fixture);
    expect(text(root)).toBe('');
  });

  it('shows nothing while the Boards state is unread or unreadable', async () => {
    setup(null, ADMIN);
    const { root } = await render();
    expect(text(root)).toBe('');
  });

  it('offers "Create work item" only with issue.triage, a linkable finding and a mapped project', async () => {
    setup(boardsProjectSettings());
    const { fixture, root } = await render();
    expect(text(root.querySelector('h3'))).toBe('Azure Boards');
    expect(button(root, 'Create work item')).toBeDefined();

    fixture.componentRef.setInput('canTriage', false);
    await settle(fixture);
    expect(button(root, 'Create work item')).toBeUndefined();
    expect(text(root)).toBe('');

    fixture.componentRef.setInput('canTriage', true);
    fixture.componentRef.setInput('linkable', false);
    await settle(fixture);
    expect(text(root)).toBe('');
  });

  it('creates the work item of an issue by its issueIds, then says "Creating…" and tells the page', async () => {
    setup(boardsProjectSettings());
    server.on('POST', LINKS, {
      status: 202,
      body: { items: [{ issueId: ISSUE, link: PENDING, skipped: null }] },
    });
    const { fixture, root, changed } = await render();
    button(root, 'Create work item')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', LINKS)[0]?.body).toEqual({ issueIds: [ISSUE] });
    expect(text(root)).toContain('Creating…');
    expect(button(root, 'Create work item')).toBeUndefined();
    expect(changed).toHaveBeenCalledOnce();
  });

  it('creates the work item of a vulnerability by its package and id', async () => {
    setup(boardsProjectSettings());
    const target = { packageName: 'lodash', vulnerabilityId: 'CVE-2026-0001' };
    server.on('POST', LINKS, {
      status: 202,
      body: { items: [{ ...target, link: PENDING, skipped: null }] },
    });
    const { fixture, root } = await render({ target });
    button(root, 'Create work item')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', LINKS)[0]?.body).toEqual({ vulnerabilities: [target] });
    expect(text(root)).toContain('Creating…');
  });

  it('says why a finding was not linked, a Jira link included', async () => {
    setup(boardsProjectSettings());
    server.on('POST', LINKS, {
      status: 202,
      body: { items: [{ issueId: ISSUE, link: null, skipped: 'NOT_ELIGIBLE' }] },
    });
    const { fixture, root, changed } = await render();
    button(root, 'Create work item')?.click();
    await settle(fixture);
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'This finding cannot get a work item now.',
    );
    expect(changed).not.toHaveBeenCalled();

    server.on('POST', LINKS, {
      status: 202,
      body: { items: [{ issueId: ISSUE, link: null, skipped: 'ALREADY_LINKED' }] },
    });
    button(root, 'Create work item')?.click();
    await settle(fixture);
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'This finding already has a Jira issue.',
    );
  });

  it('explains a broken connection by its problem (409 BOARDS_CONNECTION_BROKEN)', async () => {
    setup(boardsProjectSettings());
    server.on('POST', LINKS, {
      status: 409,
      body: { ...problem(409, 'BOARDS_CONNECTION_BROKEN'), problemCode: 'token_refused' },
    });
    const { fixture, root } = await render();
    button(root, 'Create work item')?.click();
    await settle(fixture);
    const alert = text(root.querySelector('[role="alert"]'));
    expect(alert).toContain('Azure DevOps refused the credential.');
    expect(alert).toContain('an organization admin must fix under Settings → Azure DevOps');
    expect(alert).not.toContain('BOARDS_CONNECTION_BROKEN');
  });

  it('says how long to wait when the server refuses too many changes (429)', async () => {
    setup(boardsProjectSettings());
    server.on('POST', LINKS, {
      status: 429,
      headers: { 'retry-after': '30' },
      body: problem(429, 'RATE_LIMITED'),
    });
    const { fixture, root } = await render();
    button(root, 'Create work item')?.click();
    await settle(fixture);
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'Too many issue changes in a short time. Try again in 30 s.',
    );
  });

  it('reads the project again when the mapping went (409 BOARDS_PROJECT_NOT_MAPPED)', async () => {
    setup(boardsProjectSettings());
    server.on('POST', LINKS, { status: 409, body: problem(409, 'BOARDS_PROJECT_NOT_MAPPED') });
    const { fixture, root } = await render();
    expect(server.requestsTo('GET', `/api/v0/projects/${PROJECT}/boards`)).toHaveLength(1);
    server.on('GET', `/api/v0/projects/${PROJECT}/boards`, {
      body: boardsProjectSettings({ mapped: false }),
    });
    button(root, 'Create work item')?.click();
    await settle(fixture);
    expect(text(root.querySelector('[role="alert"]'))).toBe(
      'This project is not mapped to an Azure DevOps project any more.',
    );
    expect(server.requestsTo('GET', `/api/v0/projects/${PROJECT}/boards`)).toHaveLength(2);
    expect(button(root, 'Create work item')).toBeUndefined();
  });

  it('says "Creating…" while the link is pending', async () => {
    setup(boardsProjectSettings());
    const { root } = await render({ link: PENDING });
    expect(text(root)).toContain('Creating…');
    expect(button(root, 'Create work item')).toBeUndefined();
  });

  it('links #<id> to the work item in a new tab, with its state by category and when it was checked', async () => {
    setup(boardsProjectSettings());
    const checked = new Date(Date.now() - 5 * 60_000 - 10_000).toISOString();
    const { fixture, root } = await render({ link: boardsLink({ stateCheckedAt: checked }) });
    const id = root.querySelector('a.boards-id');
    expect(text(id)).toBe('#42');
    expect(id?.getAttribute('href')).toBe(URL_42);
    expect(id?.getAttribute('target')).toBe('_blank');
    expect(id?.getAttribute('rel')).toBe('noopener noreferrer');
    const pill = root.querySelector('.boards-state');
    expect(text(pill)).toBe('Active');
    expect(pill?.classList).toContain('boards-state-inprogress');
    expect(text(root)).toContain('checked 5 min ago');

    for (const category of ['proposed', 'resolved', 'completed', 'removed'] as const) {
      fixture.componentRef.setInput(
        'link',
        boardsLink({ stateCheckedAt: checked, workItemState: { name: 'State', category } }),
      );
      await settle(fixture);
      expect(root.querySelector('.boards-state')?.classList).toContain(`boards-state-${category}`);
    }
    // A state Azure DevOps renamed since: its name, in the plain pill.
    fixture.componentRef.setInput(
      'link',
      boardsLink({ workItemState: { name: 'Triage', category: null } }),
    );
    await settle(fixture);
    expect(text(root.querySelector('.boards-state'))).toBe('Triage');
    expect(root.querySelector('.boards-state')?.className).not.toContain('boards-state-');
  });

  it('shows the id as text when the link has no usable address', async () => {
    setup(boardsProjectSettings());
    const { root } = await render({ link: boardsLink({ url: 'javascript:alert(1)' }) });
    expect(root.querySelector('a.boards-id')).toBeNull();
    expect(text(root.querySelector('.boards-id'))).toBe('#42');
  });

  it('shows a link without any action to a role without issue.triage', async () => {
    setup(boardsProjectSettings());
    const { root } = await render({ link: boardsLink(), canTriage: false });
    expect(text(root.querySelector('a.boards-id'))).toBe('#42');
    expect(root.querySelectorAll('button')).toHaveLength(0);
  });

  it('shows a link of a project that is no longer mapped', async () => {
    setup(boardsProjectSettings({ mapped: false }));
    const { root } = await render({ link: boardsLink(), linkable: false });
    expect(text(root.querySelector('a.boards-id'))).toBe('#42');
    expect(button(root, 'Unlink')).toBeDefined();
  });

  it('shows why a link failed in the UI’s words, and retries it', async () => {
    setup(boardsProjectSettings());
    server.on('POST', RETRY, { status: 202, body: PENDING });
    const { fixture, root, changed } = await render({
      link: failed('permission_missing', 'The server’s fixed English text'),
    });
    expect(text(root)).toContain(
      'The credential may not create work items in the mapped area path of Azure DevOps.',
    );
    expect(text(root)).not.toContain('fixed English text');
    button(root, 'Retry')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', RETRY)).toHaveLength(1);
    expect(text(root)).toContain('Creating…');
    expect(changed).toHaveBeenCalledOnce();
  });

  it('shows Azure DevOps’ own words for a refused field, as text after a fixed lead', async () => {
    setup(boardsProjectSettings());
    const words = 'TF401320: Rule Error for field <b>Value Area</b>.';
    const { root } = await render({ link: failed('field_refused', words) });
    expect(root.querySelector('.boards-failure')?.textContent?.trim()).toBe(
      `Azure DevOps refused the work item. It said: ${words}`,
    );
    expect(root.querySelector('.boards-failure b')).toBeNull();
  });

  it('says a refused field in its own words when Azure DevOps gave none', () => {
    const plain =
      'Azure DevOps refused a field of the work item. Check the mapping of the project.';
    expect(boardsFailureText({ code: 'field_refused', message: '' })).toBe(plain);
    // The server's stand-in for no words is not framed as Azure DevOps' own.
    expect(boardsFailureText({ code: 'field_refused', message: plain })).toBe(plain);
  });

  it('has its own text for every failure code, never the server’s', () => {
    const codes = [
      'permission_missing',
      'not_found',
      'limit_reached',
      'not_mapped',
      'finding_gone',
      'outcome_unknown',
      'type_unsupported',
      'note_refused',
    ];
    const texts = codes.map((code) => boardsFailureText({ code, message: 'server words' }));
    expect(new Set(texts).size).toBe(codes.length);
    for (const shown of texts) expect(shown).not.toContain('server words');
    expect(texts).not.toContain(boardsFailureText({ code: 'something_new', message: 'x' }));
    expect(boardsFailureText({ code: 'something_new', message: 'x' })).toBe(
      'The work item could not be created.',
    );
  });

  it('says a work item that is gone is not found in Azure Boards, and creates it again', async () => {
    setup(boardsProjectSettings());
    server.on('POST', RETRY, { status: 202, body: PENDING });
    const { fixture, root } = await render({ link: boardsLink({ state: 'missing' }) });
    expect(text(root)).toContain('Not found in Azure Boards');
    button(root, 'Create again')?.click();
    await settle(fixture);
    expect(server.requestsTo('POST', RETRY)).toHaveLength(1);
    expect(text(root)).toContain('Creating…');
  });

  it('tells the page when a retry is refused because the link changed meanwhile', async () => {
    setup(boardsProjectSettings());
    server.on('POST', RETRY, { status: 409, body: problem(409, 'BOARDS_LINK_NOT_RETRYABLE') });
    const { fixture, root, changed } = await render({ link: failed('not_found') });
    button(root, 'Retry')?.click();
    await settle(fixture);
    expect(text(root.querySelector('[role="alert"]'))).toContain(
      'This can no longer be tried again',
    );
    expect(changed).toHaveBeenCalledOnce();
  });

  it('reads a dismissed link as none', async () => {
    setup(boardsProjectSettings());
    const { root } = await render({ link: boardsLink({ state: 'dismissed' }) });
    expect(root.querySelector('.boards-id')).toBeNull();
    expect(button(root, 'Unlink')).toBeUndefined();
    expect(button(root, 'Create work item')).toBeDefined();
  });

  it('offers neither Retry nor Create again for a finding that is not linkable, only Unlink (R7)', async () => {
    setup(boardsProjectSettings());
    const { fixture, root } = await render({ link: failed('not_found'), linkable: false });
    expect(text(root)).toContain(boardsFailureText({ code: 'not_found', message: '' }));
    expect(button(root, 'Retry')).toBeUndefined();
    expect(button(root, 'Unlink')).toBeDefined();

    fixture.componentRef.setInput('link', boardsLink({ state: 'missing' }));
    await settle(fixture);
    expect(text(root)).toContain('Not found in Azure Boards');
    expect(button(root, 'Create again')).toBeUndefined();
    expect(button(root, 'Unlink')).toBeDefined();
  });

  it('does no more once it is gone while its request is out: no emit, no error', async () => {
    setup(boardsProjectSettings());
    let answer: (reply: FakeReply) => void = () => undefined;
    server.on('POST', LINKS, () => new Promise<FakeReply>((resolve) => (answer = resolve)));
    const { fixture, changed } = await render();
    const warned = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const pending = (fixture.componentInstance as unknown as { create(): Promise<void> }).create();
    await settle();
    expect(server.requestsTo('POST', LINKS)).toHaveLength(1);
    fixture.destroy();
    answer({ status: 202, body: { items: [{ issueId: ISSUE, link: PENDING, skipped: null }] } });
    await expect(pending).resolves.toBeUndefined();
    await settle();
    expect(changed).not.toHaveBeenCalled();
    expect(warned).not.toHaveBeenCalled();
    expect(logged).not.toHaveBeenCalled();
  });

  it('asks before it unlinks, sends nothing on Cancel, and DELETEs the link on Unlink', async () => {
    setup(boardsProjectSettings());
    server.on('DELETE', UNLINK, { status: 204 });
    const { fixture, root, changed } = await render({ link: boardsLink() });
    button(root, 'Unlink')?.click();
    await settle(fixture);
    let dialog = root.querySelector<HTMLDialogElement>('dialog');
    expect(dialog?.open).toBe(true);
    expect(text(dialog?.querySelector('h2'))).toBe('Unlink the work item');
    expect(text(dialog)).toContain('#42');
    expect(text(dialog)).toContain('The work item stays in Azure Boards');
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
    expect(root.querySelector('a.boards-id')).toBeNull();
    expect(button(root, 'Create work item')).toBeDefined();
    expect(changed).toHaveBeenCalledOnce();
  });

  it('asks before it unlinks a pending link too, without an id to name', async () => {
    setup(boardsProjectSettings());
    const { fixture, root } = await render({ link: PENDING });
    button(root, 'Unlink')?.click();
    await settle(fixture);
    expect(text(root.querySelector('dialog'))).toContain('Qualor stops creating this work item');
  });

  describe('as a pill', () => {
    const target = { packageName: 'lodash', vulnerabilityId: 'CVE-2026-0001' };

    it('names its row action after the vulnerability', async () => {
      setup(boardsProjectSettings());
      const { root } = await render({ compact: true, target });
      expect(root.querySelector('h3')).toBeNull();
      expect(button(root, 'Create work item')?.getAttribute('aria-label')).toBe(
        'Create an Azure Boards work item for CVE-2026-0001 in lodash',
      );
    });

    it('shows #<id> and the state, and says "Creating work item…" while pending', async () => {
      setup(boardsProjectSettings());
      const { fixture, root } = await render({ compact: true, target, link: boardsLink() });
      expect(text(root.querySelector('a.boards-id'))).toBe('#42');
      expect(text(root.querySelector('.boards-state'))).toBe('Active');
      expect(text(root)).not.toContain('checked');
      fixture.componentRef.setInput('link', PENDING);
      await settle(fixture);
      expect(text(root)).toContain('Creating work item…');
    });
  });
});

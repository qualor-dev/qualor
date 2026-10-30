import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ADMIN_PERMISSIONS,
  ORG_ID,
  page,
  type RecordedRequest,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import type { Me } from '../api/types';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import {
  type Checklist,
  REVEAL_MS,
  SetupChecklist,
  setupChecklistKey,
  type StepId,
} from './setup-checklist';

const ORG_2 = '0190a6c2-0000-7000-8000-000000000002';
const ORDER: StepId[] = ['connect', 'repositories', 'analysis', 'ai_review', 'team'];
type Hint = 'merge_request' | 'ask_server_admin';

/** A checklist as the server sends it: the steps in order, `done` given, AI not counted on a hint. */
function checklist(done: StepId[], hints: Partial<Record<StepId, Hint>> = {}, closed = false) {
  const steps = ORDER.map((id) => ({
    id,
    done: done.includes(id),
    hint: hints[id] ?? null,
    blocking: hints[id] !== 'ask_server_admin',
  }));
  return {
    steps,
    closed,
    allDone: steps.every((s) => s.done || !s.blocking),
  } satisfies Checklist;
}

function membership(organizationId: string, role: 'admin' | 'member'): Me['memberships'][number] {
  const name = organizationId === ORG_ID ? 'Default' : 'Acme';
  return {
    organizationId,
    organizationKey: name.toLowerCase(),
    organizationName: name,
    role,
    permissions: role === 'admin' ? [...ORG_ADMIN_PERMISSIONS] : ['org.read'],
  };
}

/** An organisation admin who is not an instance admin, with a role in Default and in Acme. */
function orgAdmin(acme: 'admin' | 'member' = 'admin', demo = false): Me {
  return {
    ...me({ demo }),
    memberships: [membership(ORG_ID, 'admin'), membership(ORG_2, acme)],
  };
}

const CHECKLIST_PATH = /^\/api\/v0\/organizations\/[^/]+\/setup-checklist$/;
const orgOf = (r: RecordedRequest) => r.path.split('/')[4];

interface Server {
  server: FakeServer;
  /** The checklist each organisation's GET answers; a PUT changes its `closed`. */
  lists: Record<string, ReturnType<typeof checklist>>;
  gets: () => RecordedRequest[];
  puts: () => RecordedRequest[];
}

function setup(
  user: Me = orgAdmin(),
  lists: Record<string, ReturnType<typeof checklist>> = {
    [ORG_ID]: checklist(['connect', 'repositories'], { analysis: 'merge_request' }),
    [ORG_2]: checklist(['connect']),
  },
): Server {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([
      { id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' },
      { id: ORG_2, key: 'acme', name: 'Acme', createdAt: '', updatedAt: '' },
    ]),
  });
  server.on('GET', CHECKLIST_PATH, (r) => ({ body: lists[orgOf(r)!] }));
  server.on('PUT', CHECKLIST_PATH, (r) => {
    const id = orgOf(r)!;
    lists[id] = { ...lists[id]!, closed: (r.body as { closed: boolean }).closed };
    return { body: lists[id] };
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(user);
  const of = (method: string) => () =>
    server.requests.filter((r) => r.method === method && CHECKLIST_PATH.test(r.path));
  return { server, lists, gets: of('GET'), puts: of('PUT') };
}

async function render() {
  const fixture = TestBed.createComponent(SetupChecklist);
  await settle(fixture);
  const root = fixture.nativeElement as HTMLElement;
  return { fixture, root };
}

const region = (root: HTMLElement) => root.querySelector<HTMLElement>('aside');
const panel = (root: HTMLElement) => root.querySelector<HTMLElement>('#setup-panel');
const launcher = (root: HTMLElement) => root.querySelector<HTMLButtonElement>('.setup-launcher');
const rows = (root: HTMLElement) => [
  ...root.querySelectorAll<HTMLLIElement>('ol.setup-steps > li'),
];
const row = (root: HTMLElement, name: string) =>
  rows(root).find((li) => li.textContent?.includes(name))!;
const text = (el: Element | null | undefined) =>
  (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
const button = (root: HTMLElement, name: string) =>
  [...root.querySelectorAll('button')].find(
    (b) => b.getAttribute('aria-label') === name || text(b) === name,
  )!;

/** Stubs `matchMedia`: the media queries given match, the others do not. */
function media(...matching: string[]): void {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: matching.includes(query),
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  }));
}

function saved(orgId: string): unknown {
  const raw = localStorage.getItem(setupChecklistKey(orgId));
  return raw === null ? null : JSON.parse(raw);
}

describe('SetupChecklist (onboarding, "The checklist (UI)")', () => {
  afterEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    document.querySelectorAll('.float-bar').forEach((bar) => bar.remove());
  });

  describe('who sees it', () => {
    it('is not even requested for someone who may not create projects', async () => {
      const s = setup(me());
      const { root } = await render();
      expect(s.gets()).toHaveLength(0);
      expect(region(root)).toBeNull();
    });

    it('is asked for the current organization only, and not where the user is a member', async () => {
      const s = setup(orgAdmin('member'));
      TestBed.inject(OrgContext).select(ORG_2);
      const { fixture, root } = await render();
      expect(s.gets()).toHaveLength(0);
      expect(region(root)).toBeNull();
      // Their own organization: asked and shown.
      TestBed.inject(OrgContext).select(ORG_ID);
      await settle(fixture);
      expect(s.gets().map(orgOf)).toEqual([ORG_ID]);
      expect(region(root)).not.toBeNull();
    });

    it('is not shown in the read-only demo', async () => {
      const s = setup(orgAdmin('admin', true));
      const { root } = await render();
      expect(s.gets()).toHaveLength(0);
      expect(region(root)).toBeNull();
    });
  });

  describe('the steps', () => {
    it('is a labelled region, not a modal, with the steps as a list and the count in text', async () => {
      setup();
      const { root } = await render();
      const aside = region(root)!;
      const title = root.querySelector(`#${aside.getAttribute('aria-labelledby')}`);
      expect(text(title)).toBe('Set up Qualor');
      expect(aside.getAttribute('role')).toBeNull();
      expect(root.querySelector('[role="dialog"], dialog, [aria-modal]')).toBeNull();
      expect(text(root.querySelector('.setup-count'))).toBe('2 of 5 done');
      expect(rows(root).map((li) => text(li.querySelector('.step-name')))).toEqual([
        'Connect GitHub or GitLab',
        'Add repositories',
        'Get the first analysis',
        'Turn on AI review',
        'Invite your team',
      ]);
      // Done or not is said in words, not by colour only.
      expect(rows(root).map((li) => text(li.querySelector('.visually-hidden')))).toEqual([
        'Done:',
        'Done:',
        'To do:',
        'To do:',
        'To do:',
      ]);
      expect(row(root, 'Connect GitHub').classList).toContain('done');
      // The first open step is the next one.
      expect(row(root, 'Get the first analysis').classList).toContain('next');
      expect(text(row(root, 'Get the first analysis'))).toContain(
        "The Qualor merge request's pipeline runs it",
      );
    });

    it('links each open step to where it is done; step 2 also to the SonarQube import', async () => {
      setup(orgAdmin(), { [ORG_ID]: checklist([]), [ORG_2]: checklist([]) });
      const { root } = await render();
      const links = (name: string) =>
        [...row(root, name).querySelectorAll('a')].map((a) => [text(a), a.getAttribute('href')]);
      expect(links('Connect GitHub or GitLab')).toEqual([
        ['Connect GitHub or GitLab', '/settings/github'],
        ['connect GitLab', '/settings/gitlab'],
      ]);
      expect(links('Add repositories')).toEqual([
        ['Add repositories', '/projects/add'],
        ['import from SonarQube', '/docs/migrate-from-sonarqube'],
      ]);
      expect(links('Get the first analysis')).toEqual([['Get the first analysis', '/projects']]);
      expect(links('Turn on AI review')).toEqual([['Turn on AI review', '/settings/ai-review']]);
      expect(links('Invite your team')).toEqual([['Invite your team', '/settings/members']]);
    });

    it('shows done steps as text, without their hints', async () => {
      setup();
      const { root } = await render();
      expect(row(root, 'Connect GitHub').querySelector('a')).toBeNull();
      expect(row(root, 'Add repositories').querySelector('a')).toBeNull();
      expect(text(row(root, 'Add repositories'))).not.toContain('SonarQube');
    });

    it("leaves the AI step out of the count when it is the server admin's to do", async () => {
      setup(orgAdmin(), {
        [ORG_ID]: checklist(['connect', 'repositories', 'analysis'], {
          ai_review: 'ask_server_admin',
        }),
        [ORG_2]: checklist([]),
      });
      const { root } = await render();
      expect(text(root.querySelector('.setup-count'))).toBe('3 of 4 done');
      expect(rows(root)).toHaveLength(5);
      const ai = row(root, 'Turn on AI review');
      expect(text(ai)).toContain('Ask your server admin to set up an AI provider');
      expect(text(ai.querySelector('.visually-hidden'))).toBe('Not counted:');
      expect(ai.querySelector('a')).toBeNull();
      expect(ai.classList).toContain('waiting');
      expect(row(root, 'Invite your team').classList).toContain('next');
      expect(launcher(root)?.textContent).toContain('Set up Qualor, 3 of 4 done');
    });

    it('is reached with the keyboard: every control is a link or a button in the tab order', async () => {
      setup();
      const { root } = await render();
      const controls = [...root.querySelectorAll<HTMLElement>('a, button')];
      expect(controls.length).toBeGreaterThan(3);
      expect(controls.every((c) => c.tabIndex >= 0)).toBe(true);
      expect(button(root, 'Collapse').getAttribute('aria-expanded')).toBe('true');
      expect(button(root, 'Collapse').getAttribute('aria-controls')).toBe('setup-panel');
    });
  });

  describe('collapse, close and "All set"', () => {
    it('collapses to the corner button, remembered per organization in this browser', async () => {
      setup();
      const { fixture, root } = await render();
      button(root, 'Collapse').click();
      await settle(fixture);
      expect(panel(root)?.hidden).toBe(true);
      const corner = launcher(root)!;
      expect(corner.hidden).toBe(false);
      expect(corner.getAttribute('aria-expanded')).toBe('false');
      expect(corner.getAttribute('aria-controls')).toBe('setup-panel');
      expect(text(corner.querySelector('.visually-hidden'))).toBe('Set up Qualor, 2 of 5 done');
      // Focus follows to the button that stays.
      expect(document.activeElement).toBe(corner);
      expect(saved(ORG_ID)).toMatchObject({ collapsed: true });
      fixture.destroy();

      // A new page: still collapsed here, open in the other organization.
      const next = await render();
      expect(panel(next.root)?.hidden).toBe(true);
      TestBed.inject(OrgContext).select(ORG_2);
      await settle(next.fixture);
      expect(panel(next.root)?.hidden).toBe(false);
      expect(text(next.root.querySelector('.setup-count'))).toBe('1 of 5 done');

      // And it opens again from the corner.
      TestBed.inject(OrgContext).select(ORG_ID);
      await settle(next.fixture);
      launcher(next.root)!.click();
      await settle(next.fixture);
      expect(panel(next.root)?.hidden).toBe(false);
      expect(saved(ORG_ID)).toMatchObject({ collapsed: false });
    });

    it('collapses with Escape and keeps working when the browser refuses storage', async () => {
      vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('blocked');
      });
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('blocked');
      });
      setup();
      const { fixture, root } = await render();
      expect(panel(root)?.hidden).toBe(false);
      button(root, 'Collapse').dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }),
      );
      await settle(fixture);
      expect(panel(root)?.hidden).toBe(true);
      expect(document.activeElement).toBe(launcher(root));
      launcher(root)!.click();
      await settle(fixture);
      expect(panel(root)?.hidden).toBe(false);
    });

    it('closes for good with "Don\'t show again"', async () => {
      const s = setup();
      const { fixture, root } = await render();
      button(root, "Don't show again").click();
      await settle(fixture);
      expect(s.puts().map((r) => [orgOf(r), r.body])).toEqual([[ORG_ID, { closed: true }]]);
      expect(region(root)).toBeNull();
      // No more questions for it on this page.
      vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
      document.dispatchEvent(new Event('visibilitychange'));
      await settle(fixture);
      expect(s.gets()).toHaveLength(1);
      fixture.destroy();

      // On the next page the server says it is closed: nothing shows.
      const next = await render();
      expect(s.gets()).toHaveLength(2);
      expect(region(next.root)).toBeNull();
    });

    it('shows "All set" once, then stays collapsed', async () => {
      setup(orgAdmin(), { [ORG_ID]: checklist(ORDER), [ORG_2]: checklist([]) });
      // Collapsed earlier: "All set" opens it once all the same.
      localStorage.setItem(setupChecklistKey(ORG_ID), JSON.stringify({ collapsed: true }));
      const { fixture, root } = await render();
      expect(panel(root)?.hidden).toBe(false);
      expect(region(root)?.classList).toContain('all-set');
      expect(text(root.querySelector('.setup-count'))).toBe('All set');
      expect(text(root.querySelector('.setup-note'))).toBe(
        'Every step is done. Add more repositories from Projects at any time.',
      );
      expect(rows(root).every((li) => li.classList.contains('done'))).toBe(true);
      fixture.destroy();

      const next = await render();
      expect(panel(next.root)?.hidden).toBe(true);
      expect(text(launcher(next.root)?.querySelector('.visually-hidden'))).toBe(
        'Set up Qualor, all set',
      );
    });
  });

  describe('refreshing', () => {
    it('asks again when the organization changes and when the person comes back to the tab', async () => {
      const s = setup();
      const { fixture, root } = await render();
      expect(s.gets().map(orgOf)).toEqual([ORG_ID]);
      TestBed.inject(OrgContext).select(ORG_2);
      await settle(fixture);
      expect(s.gets().map(orgOf)).toEqual([ORG_ID, ORG_2]);
      expect(text(root.querySelector('.setup-count'))).toBe('1 of 5 done');

      s.lists[ORG_2] = checklist(['connect', 'repositories']);
      vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
      document.dispatchEvent(new Event('visibilitychange'));
      await settle(fixture);
      expect(s.gets()).toHaveLength(2);
      vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
      document.dispatchEvent(new Event('visibilitychange'));
      await settle(fixture);
      expect(s.gets().map(orgOf)).toEqual([ORG_ID, ORG_2, ORG_2]);
      expect(text(root.querySelector('.setup-count'))).toBe('2 of 5 done');
    });

    it('asks again after a move to another page', async () => {
      const s = setup();
      await TestBed.inject(Router).navigateByUrl('/projects');
      const { fixture } = await render();
      expect(s.gets()).toHaveLength(1);
      await TestBed.inject(Router).navigateByUrl('/settings/github');
      await settle(fixture);
      expect(s.gets()).toHaveLength(2);
      // The same page with another query is not a new page.
      await TestBed.inject(Router).navigateByUrl('/settings/github?x=1');
      await settle(fixture);
      expect(s.gets()).toHaveLength(2);
    });
  });

  describe('the reveal', () => {
    it('plays once for a step done since this browser last saw the checklist', async () => {
      setup();
      localStorage.setItem(setupChecklistKey(ORG_ID), JSON.stringify({ seen: ['connect'] }));
      const { fixture, root } = await render();
      const added = row(root, 'Add repositories');
      expect(added.classList).toContain('just-done');
      expect(row(root, 'Connect GitHub').classList).not.toContain('just-done');
      expect(root.querySelectorAll('.setup-head .lens-dots .new').length).toBeGreaterThan(0);
      expect(text(root.querySelector('[aria-live="polite"]'))).toBe('Add repositories: done');
      expect(saved(ORG_ID)).toMatchObject({ seen: ['connect', 'repositories'] });

      await new Promise((resolve) => setTimeout(resolve, REVEAL_MS + 50));
      await settle(fixture);
      expect(added.classList).not.toContain('just-done');
      expect(root.querySelectorAll('.lens-dots .new')).toHaveLength(0);
      fixture.destroy();

      // Seen: the next page shows it done without the reveal.
      const next = await render();
      expect(row(next.root, 'Add repositories').classList).not.toContain('just-done');
      expect(next.root.querySelectorAll('.lens-dots .new')).toHaveLength(0);
    });

    it('does not play the first time this browser sees the checklist', async () => {
      setup();
      const { root } = await render();
      expect(root.querySelectorAll('li.just-done')).toHaveLength(0);
      expect(saved(ORG_ID)).toMatchObject({ seen: ['connect', 'repositories'] });
    });

    it('plays when a step is ticked while the page is open', async () => {
      const s = setup();
      const { fixture, root } = await render();
      s.lists[ORG_ID] = checklist(['connect', 'repositories', 'analysis']);
      vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
      document.dispatchEvent(new Event('visibilitychange'));
      await settle(fixture);
      expect(row(root, 'Get the first analysis').classList).toContain('just-done');
      expect(text(root.querySelector('[aria-live="polite"]'))).toBe('Get the first analysis: done');
      expect(text(root.querySelector('.setup-count'))).toBe('3 of 5 done');
    });

    it('is the end state at once under reduced motion, and still said', async () => {
      media('(prefers-reduced-motion: reduce)');
      setup();
      localStorage.setItem(setupChecklistKey(ORG_ID), JSON.stringify({ seen: ['connect'] }));
      const { root } = await render();
      expect(root.querySelectorAll('li.just-done')).toHaveLength(0);
      expect(root.querySelectorAll('.lens-dots .new')).toHaveLength(0);
      expect(row(root, 'Add repositories').classList).toContain('done');
      expect(text(root.querySelector('[aria-live="polite"]'))).toBe('Add repositories: done');
    });
  });

  describe('on a phone and beside a float bar', () => {
    it('starts as a small button in the header row that stays, pressed, while open', async () => {
      media('(max-width: 40rem)');
      setup();
      const { fixture, root } = await render();
      expect(panel(root)?.hidden).toBe(true);
      const corner = launcher(root)!;
      expect(text(corner.querySelector('.launch-short'))).toBe('2/5');
      corner.click();
      await settle(fixture);
      expect(panel(root)?.hidden).toBe(false);
      expect(corner.hidden).toBe(false);
      expect(corner.getAttribute('aria-expanded')).toBe('true');
      corner.click();
      await settle(fixture);
      expect(panel(root)?.hidden).toBe(true);
    });

    it("steps aside while a page's float bar shows, and comes back after", async () => {
      setup();
      const { fixture, root } = await render();
      const bar = document.createElement('div');
      bar.className = 'float-bar';
      document.body.append(bar);
      await settle(fixture);
      expect(panel(root)?.hidden).toBe(true);
      expect(launcher(root)?.getAttribute('aria-expanded')).toBe('false');
      // Not a choice of the person's: nothing is stored.
      expect(saved(ORG_ID)).not.toMatchObject({ collapsed: true });
      bar.remove();
      await settle(fixture);
      expect(panel(root)?.hidden).toBe(false);
    });
  });
});

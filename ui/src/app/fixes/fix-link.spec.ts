import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  dependencyFix,
  FakeServer,
  fixSettings,
  me,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { FixLinkView } from './fix-link';
import type { FixShown } from './fix-request';

const PROJECT = 'p1';
const FIX = dependencyFix().id;
const SETTINGS = `/api/v0/projects/${PROJECT}/fixes/settings`;
const CREATE = `/api/v0/projects/${PROJECT}/fixes`;
const RETRY = `/api/v0/fixes/${FIX}/retry`;
const CANCEL = `/api/v0/fixes/${FIX}`;
const LODASH = { ecosystem: 'npm', packageName: 'lodash' };

const text = (el: Element | null | undefined) => el?.textContent.replace(/\s+/g, ' ').trim();
const button = (root: HTMLElement, label: string) =>
  [...root.querySelectorAll('button')].find((b) => text(b) === label);

interface Inputs {
  fix?: FixShown | null;
  fixable?: boolean;
  canTriage?: boolean;
  compact?: boolean;
  target?: { ecosystem: string; packageName: string };
}

describe('FixLinkView', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  /** The project's fix settings: on and usable, GitLab, by default. */
  function setup(answer = fixSettings({ settings: { enabled: true } })) {
    server.on('GET', SETTINGS, { body: answer });
  }

  async function render(inputs: Inputs = {}) {
    const fixture = TestBed.createComponent(FixLinkView);
    fixture.componentRef.setInput('projectId', PROJECT);
    fixture.componentRef.setInput('target', inputs.target ?? LODASH);
    fixture.componentRef.setInput('fix', inputs.fix ?? null);
    fixture.componentRef.setInput('fixable', inputs.fixable ?? true);
    fixture.componentRef.setInput('canTriage', inputs.canTriage ?? true);
    fixture.componentRef.setInput('compact', inputs.compact ?? false);
    const changed = vi.fn();
    fixture.componentInstance.changed.subscribe(changed);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement, changed };
  }

  describe('when fix MRs are not usable', () => {
    it('shows nothing while fix MRs are off, for an ended fix or none', async () => {
      setup(fixSettings());
      for (const fix of [null, dependencyFix({ state: 'merged' })]) {
        const { root } = await render({ fix });
        expect(root.children).toHaveLength(0);
        expect(text(root)).toBe('');
      }
    });

    it('shows a fix in flight while fix MRs are off for the project, with Cancel only (ruling FW11)', async () => {
      setup(fixSettings());
      for (const fix of [
        dependencyFix({ state: 'requested', mrNumber: null, mrUrl: null }),
        dependencyFix({ state: 'preparing', mrNumber: null, mrUrl: null }),
        dependencyFix({ refresh: true }),
        dependencyFix({ failure: { code: 'scm_unavailable', message: '' } }),
      ]) {
        const { root } = await render({ fix });
        expect(text(root), fix.state).not.toBe('');
        expect(button(root, 'Cancel'), fix.state).toBeDefined();
        expect(button(root, 'Retry'), fix.state).toBeUndefined();
        expect(button(root, 'Create again'), fix.state).toBeUndefined();
      }
      const { root } = await render({ fix: dependencyFix({ state: 'committing' }) });
      expect(text(root)).toContain('Preparing');
      expect(button(root, 'Cancel')).toBeUndefined();
    });

    it('cancels a fix in flight while fix MRs are off for the project (ruling FW11)', async () => {
      setup(fixSettings());
      server.on('DELETE', CANCEL, { status: 204 });
      const { fixture, root, changed } = await render({ fix: dependencyFix() });
      button(root, 'Cancel')?.click();
      await settle(fixture);
      button(root.querySelector<HTMLDialogElement>('dialog')!, 'Cancel the fix')?.click();
      await settle(fixture);
      expect(server.requestsTo('DELETE', CANCEL)).toHaveLength(1);
      expect(changed).toHaveBeenCalledOnce();
    });

    it.each([
      ['no repository', { scmBound: false }],
      ['no allowance on the connection', { fixMrsAllowed: false }],
      ['monitoring off', { monitoringOn: false }],
    ])('shows nothing with %s', async (_name, preconditions) => {
      setup(fixSettings({ settings: { enabled: true }, preconditions }));
      const { root } = await render();
      expect(text(root)).toBe('');
    });

    it('shows nothing while the settings are unread, or unreadable', async () => {
      server.on('GET', SETTINGS, { status: 500, body: problem(500, 'INTERNAL') });
      const { root } = await render();
      expect(text(root)).toBe('');
    });
  });

  describe('the states', () => {
    it.each([
      ['requested', 'Waiting for the fix job'],
      ['preparing', 'Preparing'],
      ['committing', 'Preparing'],
      ['merged', 'Merged'],
      ['fixed', 'Fixed'],
      ['declined', 'Declined'],
      ['taken_over', 'Taken over'],
      ['cancelled', 'Cancelled'],
    ] as const)('says %s as "%s"', async (state, label) => {
      setup();
      const { root } = await render({ fix: dependencyFix({ state, mrNumber: null, mrUrl: null }) });
      expect(text(root.querySelector('.fix-state'))).toContain(label);
    });

    it('keeps declined (a person closed the MR) apart from fixed (the vulnerability left main)', async () => {
      setup();
      const declined = await render({ fix: dependencyFix({ state: 'declined' }) });
      const fixed = await render({ fix: dependencyFix({ state: 'fixed' }) });
      expect(text(declined.root)).toContain('Declined');
      expect(text(declined.root)).not.toContain('Fixed');
      expect(text(fixed.root)).toContain('Fixed');
      expect(text(fixed.root)).not.toContain('Declined');
    });

    it.each(['requested', 'preparing', 'committing'] as const)(
      'never shows the old version of a %s fix (T8d)',
      async (state) => {
        setup();
        const { root } = await render({ fix: dependencyFix({ state, targetVersion: '1.2.6' }) });
        expect(text(root)).not.toContain('1.2.6');
      },
    );

    it.each(['open', 'merged', 'fixed'] as const)(
      'shows the version of a %s fix',
      async (state) => {
        setup();
        const { root } = await render({ fix: dependencyFix({ state, targetVersion: '1.2.6' }) });
        expect(text(root)).toContain('to 1.2.6');
      },
    );

    it('names an open MR on GitLab, as a link to a new tab', async () => {
      setup();
      const gitlab = await render({ fix: dependencyFix() });
      const link = gitlab.root.querySelector('a.fix-mr');
      expect(text(link)).toBe('MR !12');
      expect(link?.getAttribute('href')).toBe(
        'https://gitlab.example.com/acme/payments/-/merge_requests/12',
      );
      expect(link?.getAttribute('target')).toBe('_blank');
      expect(link?.getAttribute('rel')).toBe('noopener noreferrer');
    });

    it('names it a PR on GitHub', async () => {
      setup(fixSettings({ settings: { enabled: true }, preconditions: { provider: 'github' } }));
      const github = await render({
        fix: dependencyFix({ mrUrl: 'https://github.com/acme/payments/pull/12' }),
      });
      expect(text(github.root.querySelector('a.fix-mr'))).toBe('PR #12');
    });

    it('does not link an MR address that is not http(s)', async () => {
      setup();
      const { root } = await render({ fix: dependencyFix({ mrUrl: 'javascript:alert(1)' }) });
      expect(root.querySelector('a')).toBeNull();
      expect(text(root.querySelector('.fix-mr'))).toBe('MR !12');
    });

    it('says "updating" while an open MR is rebuilt', async () => {
      setup();
      const { fixture, root } = await render({ fix: dependencyFix({ refresh: true }) });
      expect(text(root)).toContain('updating');
      fixture.componentRef.setInput('fix', dependencyFix({ refresh: false }));
      await settle(fixture);
      expect(text(root)).not.toContain('updating');
    });

    it('shows an open MR with a failed rebuild together with its reason and Retry (R8)', async () => {
      setup();
      const { root } = await render({
        fix: dependencyFix({ failure: { code: 'scm_unavailable', message: '' } }),
      });
      expect(text(root.querySelector('a.fix-mr'))).toBe('MR !12');
      expect(text(root)).toContain('The repository could not be reached. Try the fix again later.');
      expect(button(root, 'Retry')).toBeDefined();
      expect(button(root, 'Cancel')).toBeDefined();
    });

    it('retries an open fix whose refresh failed: the retry request, then the page reads again (T18a)', async () => {
      setup();
      server.on('POST', RETRY, {
        status: 202,
        body: dependencyFix({ refresh: true, failure: null }),
      });
      const { fixture, root, changed } = await render({
        fix: dependencyFix({ failure: { code: 'scm_permission', message: '' } }),
      });
      button(root, 'Retry')?.click();
      await settle(fixture);
      expect(server.requestsTo('POST', RETRY)).toHaveLength(1);
      expect(changed).toHaveBeenCalledOnce();
      expect(text(root)).toContain('updating');
      expect(text(root)).not.toContain('The connection');
      expect(button(root, 'Retry')).toBeUndefined();
    });

    it('shows a failure with the fix text, and a server message only as text', async () => {
      setup();
      const { root } = await render({
        fix: dependencyFix({
          state: 'failed',
          mrNumber: null,
          mrUrl: null,
          failure: { code: 'package_manager', message: 'npm ERR! <b>not found</b>' },
        }),
      });
      expect(text(root.querySelector('.fix-failure'))).toBe('npm ERR! <b>not found</b>');
      expect(root.querySelector('b')).toBeNull();
      expect(button(root, 'Retry')).toBeDefined();
    });

    it('reads a no-fix reason on an open MR as that reason, not as a failure (ruling FW12)', async () => {
      setup();
      const { root } = await render({
        fix: dependencyFix({ failure: { code: 'no_fixed_version', message: 'x' } }),
      });
      expect(text(root.querySelector('.fix-failure'))).toBe(
        'No released version of this package fixes the vulnerabilities yet.',
      );
      expect(text(root)).not.toContain('The fix failed.');
      expect(text(root.querySelector('a.fix-mr'))).toBe('MR !12');
    });

    it('shows the CLI message after the sentence of a failed manifest edit, as text (ruling FW12)', async () => {
      setup();
      const { root } = await render({
        fix: dependencyFix({
          state: 'failed',
          mrNumber: null,
          mrUrl: null,
          failure: { code: 'manifest_unsupported', message: 'package.json uses <b>catalog:</b>' },
        }),
      });
      expect(text(root.querySelector('.fix-failure'))).toBe(
        "Qualor cannot edit this project's dependency files automatically. package.json uses <b>catalog:</b>",
      );
      expect(root.querySelector('b')).toBeNull();
    });

    it('says why there is no fix, with Retry', async () => {
      setup();
      const { root } = await render({
        fix: dependencyFix({
          state: 'no_fix',
          mrNumber: null,
          mrUrl: null,
          failure: { code: 'no_fixed_version', message: '' },
        }),
      });
      expect(text(root)).toContain('No released version of this package fixes');
      expect(button(root, 'Retry')).toBeDefined();
    });
  });

  describe('the actions', () => {
    it('creates the fix MR of the row: its ecosystem and package', async () => {
      setup();
      server.on('POST', CREATE, {
        status: 202,
        body: dependencyFix({ state: 'requested', mrNumber: null, mrUrl: null }),
      });
      const { fixture, root, changed } = await render();
      expect(text(root.querySelector('h3'))).toBe('Fix MR');
      button(root, 'Create fix MR')?.click();
      await settle(fixture);
      expect(server.requestsTo('POST', CREATE)[0]?.body).toEqual(LODASH);
      expect(text(root)).toContain('Waiting for the fix job');
      expect(button(root, 'Create fix MR')).toBeUndefined();
      expect(changed).toHaveBeenCalledOnce();
    });

    it('offers Create only for a fixable package and a known ecosystem', async () => {
      setup();
      const { fixture, root } = await render({ fixable: false });
      expect(text(root)).toBe('');
      fixture.componentRef.setInput('fixable', true);
      fixture.componentRef.setInput('target', { ecosystem: '', packageName: 'lodash' });
      await settle(fixture);
      expect(text(root)).toBe('');
    });

    it('retries a failed fix and shows it requested again', async () => {
      setup();
      server.on('POST', RETRY, {
        status: 202,
        body: dependencyFix({ state: 'requested', mrNumber: null, mrUrl: null }),
      });
      const { fixture, root, changed } = await render({
        fix: dependencyFix({
          state: 'failed',
          mrNumber: null,
          mrUrl: null,
          failure: { code: 'timeout', message: '' },
        }),
      });
      button(root, 'Retry')?.click();
      await settle(fixture);
      expect(server.requestsTo('POST', RETRY)).toHaveLength(1);
      expect(text(root)).toContain('Waiting for the fix job');
      expect(changed).toHaveBeenCalledOnce();
    });

    it('offers Create again for an ended fix, only while the package is fixable', async () => {
      setup();
      server.on('POST', RETRY, {
        status: 202,
        body: dependencyFix({ state: 'requested', mrNumber: null, mrUrl: null }),
      });
      for (const state of ['merged', 'fixed', 'declined', 'taken_over', 'cancelled'] as const) {
        const { root } = await render({ fix: dependencyFix({ state }) });
        expect(button(root, 'Create again')).toBeDefined();
        const gone = await render({ fix: dependencyFix({ state }), fixable: false });
        expect(button(gone.root, 'Create again')).toBeUndefined();
      }
      const { fixture, root } = await render({ fix: dependencyFix({ state: 'merged' }) });
      button(root, 'Create again')?.click();
      await settle(fixture);
      expect(server.requestsTo('POST', RETRY)).toHaveLength(1);
      expect(text(root)).toContain('Waiting for the fix job');
    });

    it('asks before it cancels, sends nothing on Keep, and DELETEs on Cancel the fix', async () => {
      setup();
      server.on('DELETE', CANCEL, { status: 204 });
      const { fixture, root, changed } = await render({ fix: dependencyFix() });
      button(root, 'Cancel')?.click();
      await settle(fixture);
      let dialog = root.querySelector<HTMLDialogElement>('dialog');
      expect(dialog?.open).toBe(true);
      expect(text(dialog)).toContain('closes the MR for lodash');
      button(dialog!, 'Keep it')?.click();
      await settle(fixture);
      expect(root.querySelector('dialog')?.open ?? false).toBe(false);
      expect(server.requestsTo('DELETE', CANCEL)).toHaveLength(0);

      button(root, 'Cancel')?.click();
      await settle(fixture);
      dialog = root.querySelector<HTMLDialogElement>('dialog');
      button(dialog!, 'Cancel the fix')?.click();
      await settle(fixture);
      expect(server.requestsTo('DELETE', CANCEL)).toHaveLength(1);
      expect(text(root)).toContain('Cancelled');
      expect(changed).toHaveBeenCalledOnce();
    });

    it('offers Cancel on a fix in flight, not while it is being written', async () => {
      setup();
      for (const state of ['requested', 'preparing', 'open'] as const) {
        const { root } = await render({ fix: dependencyFix({ state }) });
        expect(button(root, 'Cancel')).toBeDefined();
      }
      const { root } = await render({ fix: dependencyFix({ state: 'committing' }) });
      expect(button(root, 'Cancel')).toBeUndefined();
    });

    it('says how full the project is when the limit is reached', async () => {
      setup(fixSettings({ settings: { enabled: true, maxOpen: 5 }, counts: { open: 5 } }));
      server.on('POST', CREATE, { status: 409, body: problem(409, 'FIX_LIMIT_REACHED') });
      const { fixture, root, changed } = await render();
      button(root, 'Create fix MR')?.click();
      await settle(fixture);
      expect(text(root.querySelector('[role="alert"]'))).toContain('5 of 5 fix MRs are open');
      expect(changed).not.toHaveBeenCalled();
      // The settings were read again.
      expect(server.requestsTo('GET', SETTINGS).length).toBeGreaterThan(1);
    });

    it('shows the other refusals in their own words', async () => {
      setup();
      server.on('POST', CREATE, { status: 422, body: problem(422, 'NOT_FIXABLE') });
      const { fixture, root } = await render();
      button(root, 'Create fix MR')?.click();
      await settle(fixture);
      expect(text(root.querySelector('[role="alert"]'))).toContain('No version of this package');
    });

    it('shows no action without issue.triage', async () => {
      setup();
      for (const fix of [
        null,
        dependencyFix(),
        dependencyFix({ state: 'failed', mrNumber: null, mrUrl: null }),
        dependencyFix({ state: 'merged' }),
      ]) {
        const { root } = await render({ fix, canTriage: false });
        expect(root.querySelectorAll('button')).toHaveLength(0);
      }
    });
  });

  describe('as a pill', () => {
    it('starts each action name with its visible text (WCAG 2.5.3)', async () => {
      setup();
      const states = [
        dependencyFix({ state: 'failed', mrNumber: null, mrUrl: null }),
        dependencyFix({ state: 'merged' }),
        dependencyFix(),
      ];
      for (const fix of [null, ...states]) {
        const { root } = await render({ compact: true, fix });
        for (const b of root.querySelectorAll('button')) {
          expect(b.getAttribute('aria-label')).toMatch(new RegExp('^' + text(b)));
        }
        expect(root.querySelectorAll('button').length).toBeGreaterThan(0);
      }
    });

    it('names its actions after the package and has no card', async () => {
      setup();
      const { root } = await render({ compact: true });
      expect(root.querySelector('.card')).toBeNull();
      expect(root.querySelector('h3')).toBeNull();
      expect(button(root, 'Create fix MR')?.getAttribute('aria-label')).toBe(
        'Create fix MR for lodash',
      );
    });
  });
});

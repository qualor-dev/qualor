import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, provideRouter } from '@angular/router';
import { of } from 'rxjs';
import {
  FakeServer,
  FakeVulnerabilities,
  problem,
  MEMBER_PROJECT_PERMISSIONS,
  me,
  ORG_ID,
  provideFakeServer,
  settle,
  untrackedVersion,
  vulnerabilityCard,
  VIEWER_PROJECT_PERMISSIONS,
  type VulnerabilityTargets,
  vulnerabilityTarget,
} from '../../../testing/fake-server';
import { SessionStore } from '../../auth/session';
import { CurrentProject } from '../current-project';
import { VulnerabilitiesPage } from './vulnerabilities.page';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000a1';
const MAIN = '0190a6c2-0000-7000-8000-0000000000d1';
const V21 = '0190a6c2-0000-7000-8000-0000000000d2';
const V20 = '0190a6c2-0000-7000-8000-0000000000d3';
const SETTINGS = [...MEMBER_PROJECT_PERMISSIONS, 'project.settings'];
const TARGETS_URL = `/api/v0/projects/${PROJECT}/vulnerabilities/targets`;

const TARGETS = [
  vulnerabilityTarget({
    kind: 'version',
    id: V21,
    name: '2.1.0',
    tracking: 'pinned',
    counts: { critical: 0, high: 2, medium: 5, low: 7, unknown: 1 },
  }),
  vulnerabilityTarget({
    id: MAIN,
    name: 'main',
    isMain: true,
    counts: { critical: 1, high: 3, medium: 4, low: 0, unknown: 0 },
    new: 2,
  }),
  vulnerabilityTarget({
    kind: 'version',
    id: V20,
    name: '2.0.0',
    tracking: 'auto',
    hasInventory: false,
  }),
];

function untracked(count: number) {
  return Array.from({ length: count }, (_, i) =>
    untrackedVersion({
      id: `0190a6c2-0000-7000-8000-00000000f${String(i).padStart(3, '0')}`,
      name: `1.${i}.0`,
    }),
  );
}

const text = (el: Element | null | undefined) => el?.textContent.replace(/\s+/g, ' ').trim();
const rows = (root: HTMLElement) => [...root.querySelectorAll('tbody tr')];
const button = (root: HTMLElement, label: string) =>
  [...root.querySelectorAll('button')].find((b) => text(b) === label);

describe('VulnerabilitiesPage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [VulnerabilitiesPage],
      providers: [provideRouter([]), provideFakeServer(server)],
    });
  });

  async function render(
    answer: Partial<VulnerabilityTargets>,
    options: {
      permissions?: readonly string[];
      admin?: boolean;
      summary?: { status: number; body: unknown };
    } = {},
  ): Promise<HTMLElement> {
    TestBed.inject(SessionStore).set(me({ admin: options.admin ?? false }));
    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: {
        id: PROJECT,
        organizationId: ORG_ID,
        key: 'acme/x',
        name: 'X',
        permissions: [...(options.permissions ?? VIEWER_PROJECT_PERMISSIONS)],
        vulnerabilities: { newIn: { main: true, branches: 0, versions: 0 } },
      },
    });
    FakeVulnerabilities.install(server, PROJECT, answer);
    if (options.summary) {
      server.on('GET', `/api/v0/projects/${PROJECT}/vulnerabilities/targets`, options.summary);
    }
    TestBed.inject(CurrentProject).use(PROJECT);
    const fixture = TestBed.createComponent(VulnerabilitiesPage);
    fixture.componentRef.setInput('projectId', PROJECT);
    await settle(fixture);
    return fixture.nativeElement as HTMLElement;
  }

  it('shows the data date and the check time in the header', async () => {
    const root = await render({ targets: TARGETS });
    expect(text(root.querySelector('.vuln-header'))).toBe(
      'Vulnerability data from Oct 29, 2026 · checked Oct 30, 2026, 9:00 AM UTC',
    );
  });

  it('shows only the data part when nothing was checked yet', async () => {
    const root = await render({ targets: TARGETS, checkedAt: null });
    expect(text(root.querySelector('.vuln-header'))).toBe('Vulnerability data from Oct 29, 2026');
  });

  it('lists main first with the counts, the marker, Pinned and No dependency list', async () => {
    const root = await render({ targets: TARGETS });
    expect([...root.querySelectorAll('thead th')].map((th) => text(th))).toEqual([
      'Branch or version',
      'Critical',
      'High',
      'Medium',
      'New',
    ]);
    const body = rows(root);
    expect(body.map((r) => text(r.querySelector('th a')))).toEqual(['main', '2.1.0', '2.0.0']);
    expect([...(body[0]?.querySelectorAll('td') ?? [])].map((td) => text(td))).toEqual([
      '1',
      '3',
      '4',
      '2 new',
    ]);
    expect(text(body[1])).toContain('Pinned');
    expect(text(body[0])).not.toContain('Pinned');
    expect(text(body[2])).toContain('No dependency list');
    expect(text(body[1])).not.toContain('No dependency list');
  });

  it('links a row to its own target', async () => {
    const root = await render({ targets: TARGETS });
    const hrefs = rows(root).map((r) =>
      decodeURIComponent(r.querySelector('th a')?.getAttribute('href') ?? ''),
    );
    expect(hrefs[0]).toContain(`target=branch:${MAIN}`);
    expect(hrefs[1]).toContain(`target=version:${V21}`);
  });

  it('keeps a zero quiet, tags the main branch and makes the row one link (brief §C)', async () => {
    const root = await render({
      targets: [
        vulnerabilityTarget({
          id: MAIN,
          name: 'master',
          isMain: true,
          counts: { critical: 0, high: 3, medium: 0, low: 0, unknown: 0 },
        }),
        vulnerabilityTarget({ kind: 'version', id: V21, name: '2.1.0', tracking: 'auto' }),
      ],
    });
    const [main, version] = rows(root);
    const cells = [...(main?.querySelectorAll('td.count') ?? [])];
    // A zero is muted; a count carries its severity, which colours it and draws its dot.
    expect(cells.map((c) => c.classList.contains('zero'))).toEqual([true, false, true]);
    expect(cells.map((c) => c.getAttribute('data-severity'))).toEqual([
      'critical',
      'high',
      'medium',
    ]);
    expect(text(main?.querySelector('th .badge-tag'))).toBe('main');
    expect(version?.querySelector('th .badge-tag')).toBeNull();
    // One link per row, which the stylesheet stretches over the row.
    expect(main?.querySelectorAll('a')).toHaveLength(1);
    expect(main?.querySelector('a.row-link')).not.toBeNull();
  });

  it('gives a main branch named main no second "main" tag', async () => {
    const root = await render({ targets: TARGETS });
    expect(rows(root)[0]?.querySelector('.badge-tag')).toBeNull();
  });

  it('puts the row menus in a last column of their own', async () => {
    const root = await render({ targets: TARGETS }, { permissions: SETTINGS });
    const head = [...root.querySelectorAll('thead th')];
    expect(text(head.at(-1))).toBe('Actions');
    const [main, version] = rows(root);
    expect(main?.querySelector('td:last-child .row-menu')).toBeNull();
    expect(version?.querySelector('td:last-child .row-menu')).not.toBeNull();
    expect(version?.querySelector('th .row-menu')).toBeNull();
  });

  describe('the Exploited column', () => {
    const withExploited = [
      vulnerabilityTarget({
        id: MAIN,
        name: 'main',
        isMain: true,
        counts: { critical: 1, high: 3, medium: 4, low: 0, unknown: 0 },
        exploited: 2,
        new: 2,
      }),
      vulnerabilityTarget({ kind: 'version', id: V21, name: '2.1.0', exploited: 0 }),
    ];

    it('comes after Medium and before New with priority, in tracked and untracked rows', async () => {
      const root = await render({
        priority: true,
        targets: withExploited,
        untracked: [untrackedVersion({ exploited: 5 })],
      });
      expect([...root.querySelectorAll('thead th')].map((th) => text(th))).toEqual([
        'Branch or version',
        'Critical',
        'High',
        'Medium',
        'Exploited',
        'New',
      ]);
      button(root, 'Show')?.click();
      await settle();
      const cells = rows(root).map((r) => [...r.querySelectorAll('td')].map((td) => text(td)));
      expect(cells[0]).toEqual(['1', '3', '4', '2', '2 new']);
      expect(cells[1]?.[3]).toBe('0');
      expect(cells[2]?.[3]).toBe('5');
      // More than zero takes the exploited badge; zero stays a quiet number.
      expect(text(rows(root)[0]?.querySelector('td .badge-exploited'))).toBe('2');
      expect(rows(root)[1]?.querySelector('td .badge-exploited')).toBeNull();
    });

    it('is absent without priority', async () => {
      const root = await render({ priority: false, targets: withExploited });
      expect([...root.querySelectorAll('thead th')].map((th) => text(th))).not.toContain(
        'Exploited',
      );
      expect(rows(root)[0]?.querySelectorAll('td')).toHaveLength(4);
    });
  });

  describe('the untracked fold', () => {
    it('shows two labels and a count; Show lists every untracked version', async () => {
      const root = await render({ targets: TARGETS, untracked: untracked(16) });
      const fold = root.querySelector('.untracked');
      expect(text(fold)).toContain('1.0.0 · 1.1.0 · 14 more — not tracked');
      expect(text(fold?.querySelector('.mono'))).toBe('1.0.0 · 1.1.0');
      expect(rows(root)).toHaveLength(3);
      const show = button(root, 'Show');
      expect(show?.getAttribute('aria-expanded')).toBe('false');
      show?.click();
      await settle();
      const shown = rows(root);
      expect(shown).toHaveLength(19);
      expect(shown.filter((r) => text(r)?.includes('Not tracked'))).toHaveLength(16);
      expect(button(root, 'Hide')?.getAttribute('aria-expanded')).toBe('true');
    });

    it('points the fold button at the fold rows only', async () => {
      const root = await render({ targets: TARGETS, untracked: untracked(3) });
      const show = button(root, 'Show');
      const body = () => root.querySelector('#' + show?.getAttribute('aria-controls'));
      expect(show?.getAttribute('aria-controls')).toBe('vuln-untracked');
      expect(body()?.children).toHaveLength(0);
      show?.click();
      await settle();
      const fold = [...(body()?.children ?? [])];
      expect(fold).toHaveLength(3);
      expect(fold.every((r) => r.classList.contains('untracked-row'))).toBe(true);
      expect(body()?.querySelector('.target-row:not(.untracked-row)')).toBeNull();
      expect(rows(root)).toHaveLength(6);
    });

    it('gives the fold button nothing to control while no table is rendered', async () => {
      const root = await render({
        targets: [vulnerabilityTarget({ id: MAIN, name: 'main', isMain: true })],
        untracked: untracked(1),
      });
      expect(root.querySelector('table')).toBeNull();
      expect(button(root, 'Show')?.hasAttribute('aria-controls')).toBe(false);
    });

    it('shows just the labels for two untracked versions', async () => {
      const root = await render({ targets: TARGETS, untracked: untracked(2) });
      expect(text(root.querySelector('.untracked'))).toContain('1.0.0 · 1.1.0 — not tracked');
      expect(text(root.querySelector('.untracked'))).not.toContain('more');
    });

    it('has no fold without untracked versions', async () => {
      const root = await render({ targets: TARGETS, untracked: [] });
      expect(root.querySelector('.untracked')).toBeNull();
    });
  });

  describe('the row menu', () => {
    it('is hidden for a viewer and for a member without project.settings', async () => {
      const root = await render({ targets: TARGETS });
      expect(root.querySelector('.row-menu')).toBeNull();
    });

    it('offers pin, unpin and unsupported by state, and none on a branch', async () => {
      const root = await render({ targets: TARGETS }, { permissions: SETTINGS });
      const body = rows(root);
      expect(body[0]?.querySelector('.row-menu')).toBeNull();
      const items = (row: Element | undefined) =>
        [...(row?.querySelectorAll('.row-menu-panel button') ?? [])].map((b) => text(b));
      expect(items(body[1])).toEqual(['Unpin', 'Mark as unsupported', 'Delete version']);
      expect(items(body[2])).toEqual(['Pin', 'Mark as unsupported', 'Delete version']);
    });

    it('names the trigger and the group after the version, as attributes', async () => {
      const root = await render({ targets: TARGETS }, { permissions: SETTINGS });
      const row = rows(root)[1];
      const name = row?.querySelector('th a')?.textContent?.trim() ?? '';
      expect(name).not.toBe('');
      expect(row?.querySelector('.menu-trigger')?.getAttribute('aria-label')).toBe(
        'Change tracking of ' + name + ' or delete it',
      );
      expect(row?.querySelector('.row-menu-panel')?.getAttribute('aria-label')).toBe(
        'Tracking and deletion of ' + name,
      );
    });

    it('offers tracking again and pinning for an unsupported version', async () => {
      const root = await render(
        {
          targets: [
            vulnerabilityTarget({
              kind: 'version',
              id: V20,
              name: '2.0.0',
              tracking: 'unsupported',
              counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
            }),
          ],
        },
        { permissions: SETTINGS },
      );
      expect([...root.querySelectorAll('.row-menu-panel button')].map((b) => text(b))).toEqual([
        'Track automatically',
        'Pin',
        'Delete version',
      ]);
    });

    it('Pin sends tracking pinned and reads the summary again', async () => {
      const root = await render({ targets: TARGETS }, { permissions: SETTINGS });
      const pin = [...root.querySelectorAll('.row-menu-panel button')].find(
        (b) => text(b) === 'Pin',
      ) as HTMLButtonElement;
      pin.click();
      await settle();
      expect(
        server
          .requestsTo('PATCH', `/api/v0/projects/${PROJECT}/versions/${V20}`)
          .map((p) => p.body),
      ).toEqual([{ tracking: 'pinned' }]);
      expect(server.requestsTo('GET', TARGETS_URL)).toHaveLength(2);
      expect(text(rows(root)[2])).toContain('Pinned');
    });

    it('is a menu of menu items', async () => {
      const root = await render({ targets: TARGETS }, { permissions: SETTINGS });
      const row = rows(root)[2];
      expect(row?.querySelector('.row-menu-panel')?.getAttribute('role')).toBe('menu');
      expect(row?.querySelector('.menu-trigger')?.getAttribute('aria-haspopup')).toBe('menu');
      const items = [...(row?.querySelectorAll('.row-menu-panel button') ?? [])];
      expect(items).toHaveLength(3);
      for (const item of items) {
        expect(item.getAttribute('role')).toBe('menuitem');
        expect(item.getAttribute('tabindex')).toBe('-1');
      }
    });

    describe('with the keyboard', () => {
      const toggle = (state: 'open' | 'closed') =>
        Object.assign(new Event('toggle'), { newState: state });
      const key = (target: Element, name: string) => {
        const event = new KeyboardEvent('keydown', { key: name, bubbles: true, cancelable: true });
        target.dispatchEvent(event);
        return event;
      };
      let root: HTMLElement;
      let panel: HTMLElement;
      let items: HTMLElement[];

      beforeEach(async () => {
        root = await render({ targets: TARGETS }, { permissions: SETTINGS });
        document.body.append(root);
        panel = rows(root)[2]?.querySelector('.row-menu-panel') as HTMLElement;
        items = [...panel.querySelectorAll<HTMLElement>('button')];
      });
      afterEach(() => root.remove());

      it('focuses the first item when the menu opens', () => {
        panel.dispatchEvent(toggle('closed'));
        expect(document.activeElement).not.toBe(items[0]);
        panel.dispatchEvent(toggle('open'));
        expect(document.activeElement).toBe(items[0]);
      });

      it('moves between the items with the arrow keys, Home and End', () => {
        items[0]?.focus();
        const steps: [string, number][] = [
          ['ArrowDown', 1],
          ['ArrowUp', 0],
          ['ArrowUp', 2],
          ['Home', 0],
          ['End', 2],
        ];
        for (const [name, index] of steps) {
          const event = key(document.activeElement as Element, name);
          expect(event.defaultPrevented).toBe(true);
          expect(document.activeElement).toBe(items[index]);
        }
      });

      describe('and a popover', () => {
        const proto = HTMLElement.prototype as unknown as Record<string, unknown>;
        const original = { matches: proto['matches'], hidePopover: proto['hidePopover'] };
        let hide: ReturnType<typeof vi.fn>;
        beforeEach(() => {
          hide = vi.fn();
          proto['hidePopover'] = hide;
          proto['matches'] = function (this: Element, selector: string) {
            return selector === ':popover-open'
              ? true
              : (original.matches as (s: string) => boolean).call(this, selector);
          };
        });
        afterEach(() => {
          proto['matches'] = original.matches;
          if (original.hidePopover) proto['hidePopover'] = original.hidePopover;
          else delete proto['hidePopover'];
        });

        it('closes on Tab and keeps the Tab', () => {
          items[0]?.focus();
          const event = key(items[0] as Element, 'Tab');
          expect(hide).toHaveBeenCalledTimes(1);
          expect(event.defaultPrevented).toBe(false);
        });

        it('closes an open menu when the page or the table scrolls, or the window resizes', () => {
          const scrolls: [EventTarget, string][] = [
            [window, 'scroll'],
            [window, 'resize'],
            [root.querySelector('.panel-scroll') as Element, 'scroll'],
          ];
          for (const [target, type] of scrolls) {
            hide.mockClear();
            target.dispatchEvent(new Event(type));
            expect(hide, type).toHaveBeenCalled();
          }
        });
      });
    });

    it('disables the trigger and the items while a change runs', async () => {
      const root = await render({ targets: TARGETS }, { permissions: SETTINGS });
      let release!: (reply: { body: unknown }) => void;
      server.on(
        'PATCH',
        `/api/v0/projects/${PROJECT}/versions/${V20}`,
        () => new Promise((resolve) => (release = resolve)),
      );
      const pin = [...root.querySelectorAll('.row-menu-panel button')].find(
        (b) => text(b) === 'Pin',
      ) as HTMLButtonElement;
      pin.click();
      await settle();
      const controls = () => [
        ...root.querySelectorAll<HTMLButtonElement>('.row-menu-panel button, .menu-trigger'),
      ];
      expect(controls().length).toBeGreaterThan(0);
      expect(controls().every((b) => b.disabled)).toBe(true);
      expect(root.querySelector('.row-menu-panel')?.getAttribute('aria-busy')).toBe('true');
      release({ body: {} });
      await settle();
      expect(controls().some((b) => b.disabled)).toBe(false);
      expect(root.querySelector('.row-menu-panel')?.hasAttribute('aria-busy')).toBe(false);
    });

    it('shows the error and keeps the table when a change is refused', async () => {
      const root = await render({ targets: TARGETS }, { permissions: SETTINGS });
      server.on('PATCH', `/api/v0/projects/${PROJECT}/versions/${V20}`, {
        status: 403,
        body: {
          type: 'urn:qualor:problem:forbidden',
          title: 'FORBIDDEN',
          status: 403,
          code: 'FORBIDDEN',
        },
      });
      const pin = [...root.querySelectorAll('.row-menu-panel button')].find(
        (b) => text(b) === 'Pin',
      ) as HTMLButtonElement;
      pin.click();
      await settle();
      expect(root.querySelector('[role="alert"]')).not.toBeNull();
      expect(rows(root)).toHaveLength(3);
    });

    it('closes on a scroll of the table, which leaves an export menu open', async () => {
      const root = await render({ sbom: true, targets: TARGETS }, { permissions: SETTINGS });
      const exportHide = vi.fn();
      const rowHide = vi.fn();
      const panels: [Element | null, ReturnType<typeof vi.fn>][] = [
        [root.querySelector('#vuln-export-sbom'), exportHide],
        [root.querySelector('.row-menu-panel'), rowHide],
      ];
      for (const [panel, hide] of panels) {
        if (!panel) throw new Error('no panel');
        // jsdom has no Popover API.
        Object.assign(panel, { hidePopover: hide });
        vi.spyOn(panel, 'matches').mockReturnValue(true);
      }
      root.querySelector('.panel-scroll')?.dispatchEvent(new Event('scroll'));
      expect(rowHide).toHaveBeenCalledTimes(1);
      expect(exportHide).not.toHaveBeenCalled();
    });
  });

  describe('the untracked rows of the expanded fold', () => {
    const UNTRACKED = '0190a6c2-0000-7000-8000-00000000f000';

    async function expand(permissions?: readonly string[], untrackedList = untracked(3)) {
      const root = await render({ targets: TARGETS, untracked: untrackedList }, { permissions });
      button(root, 'Show')?.click();
      await settle();
      return root;
    }
    const foldRow = (root: HTMLElement) =>
      rows(root).find((r) => text(r)?.includes('Not tracked')) as HTMLElement;

    it('link to their own target', async () => {
      const root = await expand();
      const href = decodeURIComponent(
        foldRow(root).querySelector('th a')?.getAttribute('href') ?? '',
      );
      expect(href).toContain(`target=version:${UNTRACKED}`);
    });

    it('show no menu to a viewer', async () => {
      const root = await expand();
      expect(foldRow(root).querySelector('.row-menu')).toBeNull();
    });

    it('offer Pin and Mark as unsupported, or Track automatically and Pin', async () => {
      const root = await expand(SETTINGS, [
        untrackedVersion({ id: UNTRACKED, name: '1.0.0' }),
        untrackedVersion({ id: 'u-unsupported', name: '0.9.0', tracking: 'unsupported' }),
      ]);
      const items = (row: Element | undefined) =>
        [...(row?.querySelectorAll('.row-menu-panel button') ?? [])].map((b) => text(b));
      const fold = rows(root).filter((r) => text(r)?.includes('Not tracked'));
      expect(items(fold[0])).toEqual(['Pin', 'Mark as unsupported', 'Delete version']);
      expect(items(fold[1])).toEqual(['Track automatically', 'Pin', 'Delete version']);
    });

    describe('focus after a change', () => {
      /**
       * The fake's PATCH only flips `tracking`, so the summary is answered again by hand: `after`
       * once a PATCH ran, the version having moved between the table and the fold.
       */
      async function renderMoving(
        before: Partial<VulnerabilityTargets>,
        after: Partial<VulnerabilityTargets>,
      ): Promise<HTMLElement> {
        const root = await render(before, { permissions: SETTINGS });
        document.body.append(root);
        const answers = (given: Partial<VulnerabilityTargets>) =>
          FakeVulnerabilities.install(new FakeServer(), PROJECT, given).answer;
        let patched = false;
        server.on('PATCH', /^\/api\/v0\/projects\/[^/]+\/versions\/[^/]+$/, () => {
          patched = true;
          return { body: {} };
        });
        server.on('GET', TARGETS_URL, () => ({ body: answers(patched ? after : before) }));
        return root;
      }
      const focusItem = (row: Element | undefined, label: string) => {
        const item = [...(row?.querySelectorAll<HTMLElement>('.row-menu-panel button') ?? [])].find(
          (b) => text(b) === label,
        ) as HTMLElement;
        item.focus();
        return item;
      };
      const link = (root: HTMLElement, name: string) =>
        [...root.querySelectorAll<HTMLElement>('tbody a.row-link')].find((a) => text(a) === name);
      const moved = (id: string, name: string) =>
        vulnerabilityTarget({ kind: 'version', id, name, tracking: 'pinned' });
      let attached: HTMLElement | undefined;
      afterEach(() => attached?.remove());

      it('let an admin pin one, which sends pinned, reads the summary again and focuses the moved row', async () => {
        const UNTRACKED = '0190a6c2-0000-7000-8000-00000000f000';
        const root = (attached = await renderMoving(
          { targets: TARGETS, untracked: untracked(3) },
          { targets: [...TARGETS, moved(UNTRACKED, '1.0.0')], untracked: untracked(3).slice(1) },
        ));
        button(root, 'Show')?.click();
        await settle();
        const fold = rows(root).find((r) => text(r)?.includes('Not tracked'));
        focusItem(fold, 'Pin').click();
        await settle();
        expect(
          server
            .requestsTo('PATCH', '/api/v0/projects/' + PROJECT + '/versions/' + UNTRACKED)
            .map((p) => p.body),
        ).toEqual([{ tracking: 'pinned' }]);
        expect(server.requestsTo('GET', TARGETS_URL)).toHaveLength(2);
        const target = link(root, '1.0.0');
        expect(target?.closest('tr')?.classList.contains('untracked-row')).toBe(false);
        expect(document.activeElement).toBe(target);
      });

      it('focuses the fold button when the changed row leaves the table', async () => {
        const root = (attached = await renderMoving(
          { targets: TARGETS, untracked: untracked(1) },
          {
            targets: TARGETS.filter((t) => t.id !== V21),
            untracked: [untrackedVersion({ id: V21, name: '2.1.0' }), ...untracked(1)],
          },
        ));
        focusItem(rows(root)[1], 'Unpin').click();
        await settle();
        expect(rows(root).some((r) => text(r)?.includes('2.1.0'))).toBe(false);
        expect(document.activeElement).toBe(button(root, 'Show'));
      });

      it('finds the moved row among hundreds', async () => {
        const all = untracked(300);
        const root = (attached = await renderMoving(
          { targets: TARGETS, untracked: all },
          {
            targets: [...TARGETS, moved(all[249]?.id ?? '', '1.249.0')],
            untracked: all.filter((_, i) => i !== 249),
          },
        ));
        button(root, 'Show')?.click();
        await settle();
        const fold = rows(root).filter((r) => r.classList.contains('untracked-row'));
        expect(fold).toHaveLength(300);
        focusItem(fold[249], 'Pin').click();
        await settle();
        expect(document.activeElement).toBe(link(root, '1.249.0'));
      });

      it("focuses the link of a row that stays when its disabled trigger drops focus, as a browser's does", async () => {
        const root = (attached = await renderMoving(
          { targets: TARGETS },
          {
            targets: TARGETS.map((t) => (t.id === V20 ? { ...t, tracking: 'pinned' as const } : t)),
          },
        ));
        const trigger = rows(root)[2]?.querySelector<HTMLElement>('.menu-trigger');
        trigger?.focus();
        const pin = [...(rows(root)[2]?.querySelectorAll('.row-menu-panel button') ?? [])].find(
          (b) => text(b) === 'Pin',
        ) as HTMLElement;
        pin.click();
        // The menu closes and the trigger is disabled: a browser drops focus to the body.
        (document.activeElement as HTMLElement | null)?.blur();
        await settle();
        expect(document.activeElement).toBe(rows(root)[2]?.querySelector('a.row-link'));
      });

      it("focuses the row's link after a refused change", async () => {
        const root = (attached = await renderMoving({ targets: TARGETS }, { targets: TARGETS }));
        server.on('PATCH', /^\/api\/v0\/projects\/[^/]+\/versions\/[^/]+$/, {
          status: 403,
          body: problem(403, 'FORBIDDEN'),
        });
        const trigger = rows(root)[2]?.querySelector<HTMLElement>('.menu-trigger');
        trigger?.focus();
        focusItem(rows(root)[2], 'Pin').click();
        (document.activeElement as HTMLElement | null)?.blur();
        await settle();
        expect(root.querySelector('[role="alert"]')).not.toBeNull();
        expect(document.activeElement).toBe(rows(root)[2]?.querySelector('a.row-link'));
      });
    });

    it('show the table again when every tracked target is clean', async () => {
      const root = await render({
        targets: [vulnerabilityTarget({ id: MAIN, name: 'main', isMain: true })],
        untracked: untracked(1),
      });
      expect(root.querySelector('table')).toBeNull();
      button(root, 'Show')?.click();
      await settle();
      expect(root.querySelector('.empty-state')).toBeNull();
      expect(rows(root).map((r) => text(r.querySelector('th')))).toEqual([
        'main',
        '1.0.0Not tracked',
      ]);
    });
  });

  describe('SBOM versions', () => {
    const SBOM = '0190a6c2-0000-7000-8000-0000000000d9';
    const sbomTarget = () =>
      vulnerabilityTarget({
        kind: 'version',
        id: SBOM,
        name: '1.4.0',
        tracking: 'auto',
        source: 'sbom',
        sbomSubject: 'ghcr.io/acme/shop:1.4.0',
        distribution: { family: 'debian', version: '12.15' },
      });
    // A clean table is replaced by the empty state: one open vulnerability keeps the row.
    const withCounts = (t: ReturnType<typeof vulnerabilityTarget>) => ({
      ...t,
      counts: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
    });
    const deleteItem = (root: HTMLElement) =>
      [...root.querySelectorAll<HTMLButtonElement>('.row-menu-panel button')].find(
        (b) => text(b) === 'Delete version',
      );
    const inDialog = (dialog: Element, label: string) =>
      [...dialog.querySelectorAll('button')].find((b) => text(b) === label)!;

    it('shows the SBOM badge, the subject and the distribution of an SBOM target', async () => {
      const root = await render({ targets: [withCounts(sbomTarget())] });
      const row = text(rows(root)[0])!;
      expect(row).toContain('SBOM');
      expect(row).toContain('ghcr.io/acme/shop:1.4.0');
      expect(row).toContain('debian 12.15');
    });

    it('shows it on an untracked SBOM version too, and nothing on a tag version', async () => {
      const root = await render({
        targets: [vulnerabilityTarget({ id: MAIN, name: 'main', isMain: true })],
        untracked: [
          untrackedVersion({
            id: 'u-sbom',
            name: '0.9.0',
            source: 'sbom',
            sbomSubject: 'old-image',
            distribution: { family: 'alpine', version: '3.20.3' },
          }),
          untrackedVersion({ id: 'u-tag', name: '0.8.0' }),
        ],
      });
      button(root, 'Show')?.click();
      await settle();
      const fold = rows(root).filter((r) => text(r)?.includes('Not tracked'));
      expect(text(fold[0])).toContain('SBOM');
      expect(text(fold[0])).toContain('alpine 3.20.3');
      expect(text(fold[1])).not.toContain('SBOM');
    });

    it('offers no Delete version without project.settings', async () => {
      const root = await render({ targets: [withCounts(sbomTarget())] });
      expect(deleteItem(root)).toBeUndefined();
    });

    it('names the label in the confirmation, and Cancel sends nothing', async () => {
      const root = await render({ targets: [withCounts(sbomTarget())] }, { permissions: SETTINGS });
      deleteItem(root)!.click();
      await settle();
      const dialog = root.querySelector('dialog.delete-version-dialog')!;
      expect(dialog.hasAttribute('open')).toBe(true);
      expect(text(dialog)).toContain('1.4.0');
      inDialog(dialog, 'Cancel').click();
      await settle();
      expect(server.requests.filter((r) => r.method === 'DELETE')).toHaveLength(0);
      expect(dialog.hasAttribute('open')).toBe(false);
    });

    it('deletes the version after the confirmation and reads the summary again', async () => {
      const path = `/api/v0/projects/${PROJECT}/versions/${SBOM}`;
      server.on('DELETE', path, { status: 204 });
      const root = await render({ targets: [withCounts(sbomTarget())] }, { permissions: SETTINGS });
      deleteItem(root)!.click();
      await settle();
      const dialog = root.querySelector('dialog.delete-version-dialog')!;
      inDialog(dialog, 'Delete').click();
      await settle();
      expect(server.requestsTo('DELETE', path)).toHaveLength(1);
      expect(server.requestsTo('GET', TARGETS_URL)).toHaveLength(2);
      expect(dialog.hasAttribute('open')).toBe(false);
    });

    it('shows the refusal in the dialog and keeps it open', async () => {
      server.on('DELETE', `/api/v0/projects/${PROJECT}/versions/${SBOM}`, {
        status: 403,
        body: problem(403, 'FORBIDDEN'),
      });
      const root = await render({ targets: [withCounts(sbomTarget())] }, { permissions: SETTINGS });
      deleteItem(root)!.click();
      await settle();
      const dialog = root.querySelector('dialog.delete-version-dialog')!;
      inDialog(dialog, 'Delete').click();
      await settle();
      expect(dialog.querySelector('[role=alert]')).not.toBeNull();
      expect(dialog.hasAttribute('open')).toBe(true);
    });
  });

  describe('Upload SBOM', () => {
    const UPLOAD = [...MEMBER_PROJECT_PERMISSIONS, 'project.analyze'];

    it('is offered to a user with project.analyze', async () => {
      const root = await render({ targets: TARGETS }, { permissions: UPLOAD });
      expect(button(root, 'Upload SBOM')).toBeDefined();
      expect(root.querySelector('q-sbom-upload-dialog')).not.toBeNull();
    });

    const answer = {
      version: { id: '0190a6c2-0000-7000-8000-0000000000c9', label: '1.0.0', source: 'sbom' },
      format: 'CycloneDX 1.6',
      subject: null,
      distribution: null,
      packages: 3,
      osPackages: 0,
      skipped: { noPurl: 0, unsupportedType: 0, duplicate: 0 },
      warnings: [],
      monitoring: { enabled: false, recheckQueued: false },
    };

    async function uploadFrom(root: HTMLElement) {
      expect(button(root, 'Upload SBOM')).toBeDefined();
      button(root, 'Upload SBOM')!.click();
      await settle();
      const input = root.querySelector<HTMLInputElement>('#sbom-file')!;
      Object.defineProperty(input, 'files', {
        value: [new File(['{}'], 'bom.json')],
        configurable: true,
      });
      input.dispatchEvent(new Event('change'));
      await settle();
      root.querySelector('q-sbom-upload-dialog form')!.dispatchEvent(new Event('submit'));
      await settle();
    }

    it.each([
      [
        'monitoring is off for the project',
        { monitoring: 'off' as const, offBy: 'project' as const },
      ],
      [
        'monitoring is off for the server',
        { monitoring: 'off' as const, offBy: 'instance' as const },
      ],
      ['there is no vulnerability data', { data: null }],
    ])('is offered when %s, and says that monitoring is off', async (_name, state) => {
      server.on('PUT', '/api/v0/projects/sbom', { status: 201, body: answer });
      const root = await render(state, { permissions: UPLOAD });
      await uploadFrom(root);
      expect(server.requestsTo('PUT', '/api/v0/projects/sbom')).toHaveLength(1);
      expect(text(root.querySelector('.sbom-result'))).toContain('Monitoring is off');
      expect(text(root)).toContain('Uploaded SBOMs are listed under Dependencies');
    });

    it('is not offered to a viewer when monitoring is off or there is no data', async () => {
      for (const state of [
        { monitoring: 'off' as const, offBy: 'project' as const },
        { data: null },
      ]) {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
          imports: [VulnerabilitiesPage],
          providers: [provideRouter([]), provideFakeServer(server)],
        });
        const root = await render(state);
        expect(button(root, 'Upload SBOM')).toBeUndefined();
        expect(root.querySelector('q-sbom-upload-dialog')).toBeNull();
      }
    });

    it('is not offered to a viewer', async () => {
      const root = await render({ targets: TARGETS });
      expect(button(root, 'Upload SBOM')).toBeUndefined();
      expect(root.querySelector('q-sbom-upload-dialog')).toBeNull();
    });

    it('is offered in the empty state of a project without versions', async () => {
      const root = await render({ versionCount: 0, targets: TARGETS }, { permissions: UPLOAD });
      const hint = root.querySelector('.tag-hint');
      expect(
        [...(hint?.querySelectorAll('button') ?? [])].some((b) => text(b) === 'Upload SBOM'),
      ).toBe(true);
    });
  });

  describe('empty states', () => {
    it('sends an instance admin to Settings → Vulnerability database', async () => {
      const root = await render({ data: null }, { admin: true });
      expect(text(root.querySelector('.empty-state'))).toContain('No vulnerability data yet.');
      const link = root.querySelector('.empty-state a');
      expect(text(link)).toBe('Settings → Vulnerability database');
      expect(link?.getAttribute('href')).toBe('/settings/vulnerability-db');
      expect(root.querySelector('table')).toBeNull();
    });

    it('tells anyone else who sets it up, without a link', async () => {
      const root = await render({ data: null }, { permissions: SETTINGS });
      const empty = text(root.querySelector('.empty-state'));
      expect(empty).toContain('No vulnerability data yet.');
      expect(empty).toContain('An instance admin sets it up in Settings → Vulnerability database.');
      // The Dependencies link of the SBOM upload is the only link (SETTINGS holds project.analyze).
      expect(root.querySelector('.empty-state a[href="/settings/vulnerability-db"]')).toBeNull();
    });

    it('says nothing is open when every tracked target is clean', async () => {
      const root = await render({
        targets: [vulnerabilityTarget({ id: MAIN, name: 'main', isMain: true })],
      });
      expect(text(root.querySelector('.empty-state'))).toContain(
        'No open vulnerabilities in tracked branches and versions.',
      );
    });

    it('shows the tag hint under the table when the project has no versions', async () => {
      const root = await render({
        versionCount: 0,
        targets: [
          vulnerabilityTarget({
            id: MAIN,
            name: 'main',
            isMain: true,
            counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
          }),
        ],
      });
      const hint = root.querySelector('.tag-hint');
      expect(root.querySelector('table')).not.toBeNull();
      expect(text(hint)).toContain('No released versions yet. Run the Qualor job on tags:');
      expect(text(hint)).toContain('- if: $CI_COMMIT_TAG');
      expect(text(hint)).toContain("push: tags: ['**']");
    });

    it('shows no tag hint once a version exists', async () => {
      const root = await render({ versionCount: 3, targets: TARGETS });
      expect(root.querySelector('.tag-hint')).toBeNull();
    });

    it('says monitoring is off, with the settings link for project.settings (final review F2)', async () => {
      const off: Partial<VulnerabilityTargets> = {
        monitoring: 'off',
        offBy: 'project',
        checkedAt: null,
        targets: [],
      };
      const admin = await render(off, { permissions: SETTINGS });
      const empty = text(admin.querySelector('.empty-state'));
      expect(empty).toContain('Vulnerability monitoring is off for this project.');
      expect(empty).not.toContain('No open vulnerabilities');
      const link = admin.querySelector('.empty-state a');
      expect(text(link)).toBe('Project settings');
      expect(link?.getAttribute('href')).toBe(`/projects/${PROJECT}/settings#vulnerabilities`);
      expect(admin.querySelector('table')).toBeNull();
      expect(admin.querySelector('.vuln-header')).toBeNull();

      TestBed.resetTestingModule();
      server = new FakeServer();
      TestBed.configureTestingModule({
        imports: [VulnerabilitiesPage],
        providers: [provideRouter([]), provideFakeServer(server)],
      });
      const viewer = await render(off);
      expect(text(viewer.querySelector('.empty-state'))).toContain(
        'Vulnerability monitoring is off for this project.',
      );
      expect(viewer.querySelector('.empty-state a')).toBeNull();
    });

    it('says the server switch turned monitoring off, and who can turn it on (D25-1)', async () => {
      const off: Partial<VulnerabilityTargets> = {
        monitoring: 'off',
        offBy: 'instance',
        checkedAt: null,
        targets: [],
      };
      const sentence = 'Vulnerability monitoring is turned off for this server.';
      const admin = await render(off, { admin: true, permissions: SETTINGS });
      expect(text(admin.querySelector('.empty-state'))).toContain(sentence);
      expect(text(admin.querySelector('.empty-state'))).not.toContain('for this project');
      const links = admin.querySelectorAll('.empty-state a[href^="/settings"]');
      expect(links.length).toBe(1);
      expect(text(links[0])).toBe('Settings → Vulnerability database');
      expect(links[0]?.getAttribute('href')).toBe('/settings/vulnerability-db');

      TestBed.resetTestingModule();
      server = new FakeServer();
      TestBed.configureTestingModule({
        imports: [VulnerabilitiesPage],
        providers: [provideRouter([]), provideFakeServer(server)],
      });
      const projectAdmin = await render(off, { permissions: SETTINGS });
      const empty = text(projectAdmin.querySelector('.empty-state'));
      expect(empty).toContain(sentence);
      expect(empty).toContain(
        'Ask an instance admin to turn it on in Settings → Vulnerability database.',
      );
      expect(projectAdmin.querySelector('.empty-state a[href^="/settings"]')).toBeNull();
    });

    it('shows the alert when the summary fails', async () => {
      const root = await render({}, { summary: { status: 500, body: problem(500, 'INTERNAL') } });
      expect(text(root.querySelector('p.alert.alert-error[role=alert]'))).toBe(
        'The request failed (HTTP 500, INTERNAL).',
      );
      expect(root.querySelector('table')).toBeNull();
    });

    it('says not checked yet instead of the all-clear before the first check (final review F2)', async () => {
      const root = await render({
        checkedAt: null,
        targets: [vulnerabilityTarget({ id: MAIN, name: 'main', isMain: true, checkedAt: null })],
      });
      const empty = text(root.querySelector('.empty-state'));
      expect(empty).toContain(
        'Not checked yet. The server checks tracked branches and versions after the next database update or analysis.',
      );
      expect(empty).not.toContain('No open vulnerabilities');
    });
  });

  it('names an uploaded file without a build date in the header (final review F3)', async () => {
    const checked = await render({ data: { builtAt: null }, targets: TARGETS });
    expect(text(checked.querySelector('.vuln-header'))).toBe(
      'Vulnerability data from an uploaded file · checked Oct 30, 2026, 9:00 AM UTC',
    );
  });

  it('names an uploaded file alone before the first check (final review F3)', async () => {
    const root = await render({ data: { builtAt: null }, checkedAt: null, targets: TARGETS });
    expect(text(root.querySelector('.vuln-header'))).toBe(
      'Vulnerability data from an uploaded file',
    );
  });

  it('offers the two views, By version being the current one', async () => {
    const root = await render({ targets: TARGETS });
    expect([...root.querySelectorAll('.view-tabs a')].map((a) => text(a))).toEqual([
      'By version',
      'By vulnerability',
    ]);
    expect(text(root.querySelector('.view-tabs a[aria-current="page"]'))).toBe('By version');
  });
});

describe('VulnerabilitiesPage views', () => {
  async function renderWith(query: Record<string, string>): Promise<HTMLElement> {
    const server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [VulnerabilitiesPage],
      providers: [
        provideRouter([]),
        provideFakeServer(server),
        { provide: ActivatedRoute, useValue: { queryParams: of(query) } },
      ],
    });
    TestBed.inject(SessionStore).set(me());
    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: {
        id: PROJECT,
        organizationId: ORG_ID,
        key: 'acme/x',
        name: 'X',
        permissions: [...MEMBER_PROJECT_PERMISSIONS],
        vulnerabilities: { newIn: { main: false, branches: 0, versions: 0 } },
      },
    });
    const fake = FakeVulnerabilities.install(server, PROJECT, { targets: TARGETS });
    fake.cards = [vulnerabilityCard({ in: [{ kind: 'branch', id: MAIN, name: 'main' }] })];
    TestBed.inject(CurrentProject).use(PROJECT);
    const fixture = TestBed.createComponent(VulnerabilitiesPage);
    fixture.componentRef.setInput('projectId', PROJECT);
    await settle(fixture);
    return fixture.nativeElement as HTMLElement;
  }

  it('shows the cards in By vulnerability instead of the table', async () => {
    const root = await renderWith({ view: 'vulnerability' });
    expect(root.querySelector('table')).toBeNull();
    expect(root.querySelectorAll('.vuln-row')).toHaveLength(1);
  });

  it("puts the target's chips beside its name, with the main tag", async () => {
    const root = await renderWith({ target: `branch:${MAIN}` });
    const chips = [...root.querySelectorAll('.target-head q-severity-chips .badge')];
    expect(chips.map((c) => text(c))).toEqual(['1 Critical', '3 High', '4 Medium']);
    // The main branch here is named main: no second "main".
    expect(root.querySelector('.target-heading .badge-tag')).toBeNull();
  });

  it('names the target in the one-target view and links back to By version', async () => {
    const root = await renderWith({ target: `branch:${MAIN}` });
    expect(root.querySelector('table')).toBeNull();
    expect(text(root.querySelector('.target-heading'))).toBe('main');
    expect(text(root.querySelector('.target-head .back'))).toBe('← By version');
    expect(root.querySelector('.target-head .back')?.getAttribute('href')).toBe('/');
    expect(root.querySelectorAll('.vuln-row')).toHaveLength(1);
  });
});

describe('VulnerabilitiesPage export menus', () => {
  const OLD = '0190a6c2-0000-7000-8000-0000000000e1';
  const OLDER = '0190a6c2-0000-7000-8000-0000000000e3';
  const UNCHECKED = '0190a6c2-0000-7000-8000-0000000000e2';
  const RELEASE = '0190a6c2-0000-7000-8000-0000000000d4';
  const CHECKED = '2026-10-30T09:00:00.000Z';

  const targets = [
    vulnerabilityTarget({ id: RELEASE, name: 'release/2.x' }),
    vulnerabilityTarget({ id: MAIN, name: 'main', isMain: true }),
    vulnerabilityTarget({ kind: 'version', id: V21, name: '2.3.4+build.1', tracking: 'pinned' }),
    vulnerabilityTarget({ id: V20, name: 'no-inventory', hasInventory: false }),
    vulnerabilityTarget({ id: UNCHECKED, name: 'unchecked', checkedAt: null }),
  ];
  const old = [
    untrackedVersion({ id: OLD, name: '1.0.0', checkedAt: CHECKED }),
    untrackedVersion({ id: OLDER, name: '0.9.0', hasInventory: false, checkedAt: null }),
  ];

  async function renderExport(
    answer: Partial<VulnerabilityTargets>,
    query: Record<string, string> = {},
  ): Promise<HTMLElement> {
    const server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [VulnerabilitiesPage],
      providers: [
        provideRouter([]),
        provideFakeServer(server),
        { provide: ActivatedRoute, useValue: { queryParams: of(query) } },
      ],
    });
    TestBed.inject(SessionStore).set(me());
    server.on('GET', `/api/v0/projects/${PROJECT}`, {
      body: {
        id: PROJECT,
        organizationId: ORG_ID,
        key: 'acme/x',
        name: 'X',
        permissions: [...MEMBER_PROJECT_PERMISSIONS],
        vulnerabilities: { newIn: { main: false, branches: 0, versions: 0 } },
      },
    });
    FakeVulnerabilities.install(server, PROJECT, answer);
    TestBed.inject(CurrentProject).use(PROJECT);
    const fixture = TestBed.createComponent(VulnerabilitiesPage);
    fixture.componentRef.setInput('projectId', PROJECT);
    await settle(fixture);
    return fixture.nativeElement as HTMLElement;
  }

  const menu = (root: HTMLElement, kind: 'sbom' | 'vex') =>
    root.querySelector<HTMLElement>(`#vuln-export-${kind}`);
  const options = (root: HTMLElement, kind: 'sbom' | 'vex') =>
    [...(menu(root, kind)?.querySelectorAll('option') ?? [])].map((o) => text(o));
  const links = (root: HTMLElement, kind: 'sbom' | 'vex') =>
    [...(menu(root, kind)?.querySelectorAll('a') ?? [])].map((a) => [
      text(a),
      a.getAttribute('href'),
      a.hasAttribute('download'),
    ]);

  it('has the Export SBOM and Export VEX buttons with the feature', async () => {
    const root = await renderExport({ sbom: true, targets, untracked: old });
    expect(button(root, 'Export SBOM')).toBeDefined();
    expect(button(root, 'Export VEX')).toBeDefined();
  });

  it('lists the targets with an inventory in the SBOM menu, tracked first', async () => {
    const root = await renderExport({ sbom: true, targets, untracked: old });
    expect(options(root, 'sbom')).toEqual([
      'main',
      'release/2.x',
      '2.3.4+build.1',
      'unchecked',
      '1.0.0',
    ]);
  });

  it('lists the checked targets in the VEX menu, tracked first', async () => {
    const root = await renderExport({ sbom: true, targets, untracked: old });
    expect(options(root, 'vex')).toEqual([
      'main',
      'release/2.x',
      '2.3.4+build.1',
      'no-inventory',
      '1.0.0',
    ]);
  });

  it('shows no button whose list would be empty', async () => {
    const none = await renderExport({
      sbom: true,
      targets: [vulnerabilityTarget({ id: MAIN, name: 'main', isMain: true, checkedAt: null })],
    });
    expect(button(none, 'Export VEX')).toBeUndefined();
    expect(button(none, 'Export SBOM')).toBeDefined();

    TestBed.resetTestingModule();
    const noInventory = await renderExport({
      sbom: true,
      targets: [vulnerabilityTarget({ id: MAIN, name: 'main', isMain: true, hasInventory: false })],
    });
    expect(button(noInventory, 'Export SBOM')).toBeUndefined();
    expect(button(noInventory, 'Export VEX')).toBeDefined();

    TestBed.resetTestingModule();
    const off = await renderExport({ sbom: true, monitoring: 'off', targets: [] });
    expect(button(off, 'Export VEX')).toBeUndefined();
    expect(button(off, 'Export SBOM')).toBeUndefined();
  });

  it('defaults to the first target and links the formats of the SBOM', async () => {
    const root = await renderExport({ sbom: true, targets, untracked: old });
    expect(links(root, 'sbom')).toEqual([
      [
        'CycloneDX 1.6 (JSON)',
        '/api/v0/projects/sbom?projectKey=acme%2Fx&branch=main&format=cyclonedx',
        true,
      ],
      [
        'SPDX 2.3 (JSON)',
        '/api/v0/projects/sbom?projectKey=acme%2Fx&branch=main&format=spdx',
        true,
      ],
    ]);
  });

  it('closes the menu when a download link is clicked', async () => {
    const root = await renderExport({ sbom: true, targets, untracked: old });
    const panel = menu(root, 'sbom') as HTMLElement;
    const hide = vi.fn();
    // jsdom has no Popover API.
    Object.assign(panel, { hidePopover: hide });
    vi.spyOn(panel, 'matches').mockReturnValue(true);
    const link = panel.querySelector('a') as HTMLAnchorElement;
    link.addEventListener('click', (e) => e.preventDefault());
    link.click();
    expect(hide).toHaveBeenCalledTimes(1);
  });

  it('links the formats of the VEX', async () => {
    const root = await renderExport({ sbom: true, targets, untracked: old });
    expect(links(root, 'vex')).toEqual([
      [
        'CycloneDX VEX',
        '/api/v0/projects/vex?projectKey=acme%2Fx&branch=main&format=cyclonedx',
        true,
      ],
      ['OpenVEX', '/api/v0/projects/vex?projectKey=acme%2Fx&branch=main&format=openvex', true],
    ]);
  });

  it('defaults to the target being viewed, a version by its label', async () => {
    const root = await renderExport(
      { sbom: true, targets, untracked: old },
      { target: `version:${V21}` },
    );
    expect(menu(root, 'sbom')?.querySelector('select')?.value).toBe(`version:${V21}`);
    expect(links(root, 'sbom')[0]?.[1]).toBe(
      '/api/v0/projects/sbom?projectKey=acme%2Fx&version=2.3.4%2Bbuild.1&format=cyclonedx',
    );
  });

  it('falls back to the first target when the viewed one is not in the list', async () => {
    const root = await renderExport(
      { sbom: true, targets, untracked: old },
      { target: `branch:${V20}` },
    );
    expect(menu(root, 'sbom')?.querySelector('select')?.value).toBe(`branch:${MAIN}`);
    expect(menu(root, 'vex')?.querySelector('select')?.value).toBe(`branch:${V20}`);
  });

  it('changes the links with the select, a branch name URL-encoded', async () => {
    const root = await renderExport({ sbom: true, targets, untracked: old });
    const select = menu(root, 'sbom')?.querySelector('select');
    if (!select) throw new Error('no select');
    select.value = `branch:${RELEASE}`;
    select.dispatchEvent(new Event('change'));
    await settle();
    expect(links(root, 'sbom')[1]?.[1]).toBe(
      '/api/v0/projects/sbom?projectKey=acme%2Fx&branch=release%2F2.x&format=spdx',
    );
    expect(links(root, 'vex')[0]?.[1]).toContain('branch=main');
  });

  it('shows neither button, nor any mention of SBOM or VEX, without the feature', async () => {
    const root = await renderExport({ sbom: false, targets, untracked: old });
    expect(button(root, 'Export SBOM')).toBeUndefined();
    expect(button(root, 'Export VEX')).toBeUndefined();
    expect(root.querySelector('q-export-menu')).toBeNull();
    // The export is the feature; Upload SBOM is a Community action of project.analyze.
    expect(text(root)).not.toMatch(/VEX|Export SBOM/);
  });
});

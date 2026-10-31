import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, provideRouter } from '@angular/router';
import { of } from 'rxjs';
import {
  FakeServer,
  FakeVulnerabilities,
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
    options: { permissions?: readonly string[]; admin?: boolean } = {},
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

  describe('the untracked fold', () => {
    it('shows two labels and a count; Show lists every untracked version', async () => {
      const root = await render({ targets: TARGETS, untracked: untracked(16) });
      const fold = root.querySelector('.untracked');
      expect(text(fold)).toContain('1.0.0 · 1.1.0 · 14 more — not tracked');
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
      expect(items(body[1])).toEqual(['Unpin', 'Mark as unsupported']);
      expect(items(body[2])).toEqual(['Pin', 'Mark as unsupported']);
    });

    it('names the trigger and the group after the version, as attributes', async () => {
      const root = await render({ targets: TARGETS }, { permissions: SETTINGS });
      const row = rows(root)[1];
      const name = row?.querySelector('th a')?.textContent?.trim() ?? '';
      expect(name).not.toBe('');
      expect(row?.querySelector('.menu-trigger')?.getAttribute('aria-label')).toBe(
        'Change tracking of ' + name,
      );
      expect(row?.querySelector('.row-menu-panel')?.getAttribute('aria-label')).toBe(
        'Tracking of ' + name,
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
      expect(items(fold[0])).toEqual(['Pin', 'Mark as unsupported']);
      expect(items(fold[1])).toEqual(['Track automatically', 'Pin']);
    });

    it('let an admin pin one, which sends pinned and reads the summary again', async () => {
      const root = await expand(SETTINGS);
      const pin = foldRow(root).querySelector('.row-menu-panel button') as HTMLButtonElement;
      expect(text(pin)).toBe('Pin');
      pin.click();
      await settle();
      expect(
        server
          .requestsTo('PATCH', `/api/v0/projects/${PROJECT}/versions/${UNTRACKED}`)
          .map((p) => p.body),
      ).toEqual([{ tracking: 'pinned' }]);
      expect(server.requestsTo('GET', TARGETS_URL)).toHaveLength(2);
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
      expect(root.querySelector('.empty-state a')).toBeNull();
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
    expect(root.querySelectorAll('.vuln-card')).toHaveLength(1);
  });

  it('names the target in the one-target view and links back to By version', async () => {
    const root = await renderWith({ target: `branch:${MAIN}` });
    expect(root.querySelector('table')).toBeNull();
    expect(text(root.querySelector('.target-heading'))).toBe('main ← By version');
    expect(root.querySelector('.target-heading a')?.getAttribute('href')).not.toContain('target');
    expect(root.querySelectorAll('.vuln-card')).toHaveLength(1);
  });
});

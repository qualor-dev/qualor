import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { CONFIGURED, organizationsFixture } from '../../../testing/ai-settings';
import {
  type FakeReply,
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  projectItem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import { ApiError } from '../../api/errors';
import type { ItemOf, Organization } from '../../api/types';
import { SessionStore } from '../../auth/session';
import { OrgContext } from '../../org/org-context';
import { type OrgEntry, OrganizationsSection, type SaveEntry } from './organizations-section';

type Project = ItemOf<'/api/v0/projects'>;
type Features = OrgEntry['features'];

const ACME = ORG_ID;
const RESEARCH = '0190a6c2-0000-7000-8000-000000000002';
const LAB = '0190a6c2-0000-7000-8000-000000000003';
const organization = (id: string, key: string, name: string): Organization => ({
  id,
  key,
  name,
  deleting: false,
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
});
/** Listed out of order: the table sorts them by name. */
const ORGS = [organization(RESEARCH, 'research', 'Research'), organization(ACME, 'acme', 'Acme')];
const PROJECTS: Project[] = [
  projectItem({ id: 'p1', key: 'acme/payments', name: 'Payments' }),
  projectItem({ id: 'p2', key: 'acme/web-shop', name: 'Web Shop' }),
  projectItem({ id: 'p3', key: 'acme/legacy-billing', name: 'Legacy billing' }),
];
const ALL_ON: Features = { explain: true, triage: true, fix: true };
const NONE_ON: Features = { explain: false, triage: false, fix: false };

/** An organisation's entry as `GET /system/llm` answers it: allowed with every feature, by default. */
function stored(
  given: {
    enabled?: boolean;
    features?: Features;
    excludedProjectIds?: string[];
    autoFix?: boolean;
    review?: { enabled: boolean; consentCurrent: boolean };
  } = {},
) {
  return {
    enabled: given.enabled ?? true,
    features: given.features ?? ALL_ON,
    excludedProjectIds: given.excludedProjectIds ?? [],
    autoFix: { enabled: given.autoFix ?? false, minSeverity: 'high', maxPerAnalysis: 10 },
    autoFixDisabledProjectIds: ['p1'],
    reviewStatus: given.review ?? { enabled: false, consentCurrent: false },
  };
}
type Settings = Omit<typeof CONFIGURED, 'organizations' | 'provider'> & {
  provider: (typeof CONFIGURED)['provider'] | null;
  organizations: Record<string, ReturnType<typeof stored>>;
};

/**
 * Acme allows AI with every feature, never sends Legacy billing, and its admins switched on AI
 * review (confirmed for this provider) and automatic fix suggestions; Research does not allow AI.
 */
const SETTINGS: Settings = {
  ...CONFIGURED,
  organizations: {
    [ACME]: stored({
      excludedProjectIds: ['p3'],
      autoFix: true,
      review: { enabled: true, consentCurrent: true },
    }),
    [RESEARCH]: stored({ enabled: false, features: { explain: true, triage: false, fix: false } }),
  },
};

/** The settings once the server stored an organisation's entry, as `PUT /system/llm` answers. */
function withEntry(settings: Settings, id: string, entry: OrgEntry): Settings {
  const before = settings.organizations[id] ?? stored({ enabled: false, features: NONE_ON });
  return {
    ...settings,
    organizations: { ...settings.organizations, [id]: { ...before, ...entry } },
  };
}

/** `GET /projects` of one organisation, `limit` at a time; a cursor is the index of the next. */
function projectsPage(projects: readonly Project[], query: URLSearchParams) {
  const own = projects.filter((p) => p.organizationId === query.get('organizationId'));
  const start = Number(query.get('cursor') ?? 0);
  const end = start + Number(query.get('limit') ?? 50);
  return { body: page(own.slice(start, end), end < own.length ? String(end) : null) };
}

function setup(
  organizations: readonly Organization[] = ORGS,
  projects: readonly Project[] = PROJECTS,
): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', { body: page([...organizations]) });
  server.on('GET', '/api/v0/projects', (request) => projectsPage(projects, request.query));
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: true }));
  TestBed.inject(OrgContext).select(ACME);
  return server;
}

/**
 * The section with the organisations and settings given. Its save, unless one is given, does what
 * the page does: the entry goes to the server, whose answer comes back as the section's settings;
 * with `hold`, only once `release()` lets it.
 */
async function render(
  given: {
    settings?: Settings;
    organizations?: readonly Organization[];
    autoFixAvailable?: boolean;
    saveEntry?: SaveEntry;
    hold?: boolean;
  } = {},
) {
  const fixture = TestBed.createComponent(OrganizationsSection);
  const saves: [string, OrgEntry][] = [];
  const held: (() => void)[] = [];
  let settings = given.settings ?? SETTINGS;
  const saveEntry: SaveEntry =
    given.saveEntry ??
    ((id, entry) => {
      saves.push([id, structuredClone(entry)]);
      const answer = () => {
        settings = withEntry(settings, id, entry);
        fixture.componentRef.setInput('settings', settings);
      };
      if (!given.hold) {
        answer();
        return Promise.resolve();
      }
      return new Promise<void>((resolve) =>
        held.push(() => {
          answer();
          resolve();
        }),
      );
    });
  fixture.componentRef.setInput('settings', settings);
  fixture.componentRef.setInput('organizations', given.organizations ?? ORGS);
  fixture.componentRef.setInput('autoFixAvailable', given.autoFixAvailable ?? true);
  fixture.componentRef.setInput('saveEntry', saveEntry);
  await settle(fixture);
  return {
    fixture,
    root: fixture.nativeElement as HTMLElement,
    section: fixture.componentInstance,
    saves,
    /** Answers the save held back. */
    release: async () => {
      held.shift()?.();
      await settle(fixture);
    },
  };
}

type Fixture = { whenStable(): Promise<unknown> };

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();
/** The organisations' rows, without the editor's. */
const rows = (root: HTMLElement) => [
  ...root.querySelectorAll<HTMLTableRowElement>('tbody tr:not(.editor)'),
];
const nameOf = (tr: Element) => text(tr.querySelector('th .name-stack > :first-child'));
const row = (root: HTMLElement, name: string) => rows(root).find((tr) => nameOf(tr) === name)!;
const cells = (tr: Element) => [...tr.querySelectorAll('th, td')].map((cell) => text(cell));
const button = (within: Element, name: string) =>
  [...within.querySelectorAll<HTMLButtonElement>('button')].find((b) => text(b) === name);
const field = (root: HTMLElement, id: string) => root.querySelector<HTMLInputElement>(`#${id}`);
const editor = (root: HTMLElement) => root.querySelector<HTMLElement>('tr.editor');
const status = (root: HTMLElement) => text(root.querySelector('.orgs-status'));
const count = (root: HTMLElement) => text(root.querySelector('.orgs-count'));
const foot = (root: HTMLElement) => text(editor(root)?.querySelector('.foot-status'));
/** A button of the open editor's foot (the picker has a Cancel of its own). */
const footButton = (root: HTMLElement, name: string) =>
  button(editor(root)!.querySelector('q-section-foot')!, name);
const items = (root: HTMLElement) =>
  [...(editor(root)?.querySelectorAll('.list-editor li') ?? [])].map((li) => text(li));
/** The texts of the ids an attribute names (`aria-labelledby`, `aria-describedby`). */
const named = (root: HTMLElement, el: Element, attribute: string) =>
  (el.getAttribute(attribute) ?? '')
    .split(' ')
    .filter((id) => id !== '')
    .map((id) => text(root.querySelector(`#${id}`)));

async function click(fixture: Fixture, target: HTMLElement | null | undefined) {
  target!.click();
  await settle(fixture);
}

async function edit(fixture: Fixture, root: HTMLElement, name: string) {
  await click(fixture, button(row(root, name), 'Edit'));
}

function type(root: HTMLElement, id: string, value: string): void {
  const input = field(root, id)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

const ALLOW_HELP =
  "People in Acme can use the features below, and Acme's admins can switch on AI review, which sends repository code, and automatic fix suggestions.";

describe('OrganizationsSection (AI settings redesign, Task 8)', () => {
  it('shows each organisation as a row: allowed, the features on, what is never sent and what its admins switched on', async () => {
    setup();
    const { root } = await render();
    const section = root.querySelector<HTMLElement>('section#organizations')!;
    expect(text(section.querySelector('h3'))).toBe('Organizations');
    expect(text(section.querySelector('.sec-purpose'))).toBe(
      "Who may use AI, and which assistant features. An organization you don't allow sends nothing.",
    );
    expect(text(section.querySelector('.sec-chips'))).toBe('1 of 2 allowed');
    expect(section.querySelector('.sec-chips .badge')?.classList).toContain('badge-passed');
    expect([...section.querySelectorAll('thead th')].map((th) => text(th))).toEqual([
      'Organization',
      'AI',
      'Assistant features',
      'Never sent',
      'Switched on by its admins',
      'Actions',
    ]);
    expect(rows(root).map(nameOf)).toEqual(['Acme', 'Research']);

    const acme = row(root, 'Acme');
    expect(cells(acme)).toEqual([
      'Acme acme',
      'Allowed',
      'Explain Suggest triage Suggest a fix',
      '1 project',
      'AI review · Fix suggestions',
      'Edit Open',
    ]);
    expect(acme.querySelector('th code')?.classList).toContain('muted');
    expect(acme.querySelector('td .badge')?.classList).toContain('badge-passed');
    expect([...acme.querySelectorAll('.badge-accent')].map((b) => text(b))).toEqual([
      'Explain',
      'Suggest triage',
      'Suggest a fix',
    ]);
    // On a phone each cell is named by its column.
    expect(
      [...acme.querySelectorAll('td[data-label]')].map((td) => td.getAttribute('data-label')),
    ).toEqual(['AI', 'Assistant features', 'Never sent', 'Switched on by its admins']);

    const research = row(root, 'Research');
    expect(cells(research)).toEqual([
      'Research research',
      'Not allowed',
      '—',
      '—',
      '—',
      'Edit Open',
    ]);
    expect(research.querySelector('td .badge')?.classList).toContain('badge-none');

    const edit = button(acme, 'Edit')!;
    expect(edit.getAttribute('aria-expanded')).toBe('false');
    expect(edit.getAttribute('aria-controls')).toBe(`org-editor-${ACME}`);
    expect(button(acme, 'Open')?.getAttribute('aria-label')).toBe("Open Acme's AI page");
    expect(root.querySelectorAll('tbody input[type=checkbox]')).toHaveLength(0);
    expect(root.querySelectorAll('input[type=checkbox]')).toHaveLength(0);
  });

  it('says when a review is paused, or fix suggestions do not run', async () => {
    setup();
    const settings: Settings = {
      ...SETTINGS,
      organizations: {
        [ACME]: stored({
          features: { explain: true, triage: true, fix: false },
          autoFix: true,
          review: { enabled: true, consentCurrent: false },
        }),
        // Not allowed: whatever its admins switched on does not run, and is not shown.
        [RESEARCH]: stored({
          enabled: false,
          autoFix: true,
          review: { enabled: true, consentCurrent: false },
        }),
      },
    };
    const { fixture, root } = await render({ settings });
    expect(cells(row(root, 'Acme'))[4]).toBe('AI review (paused) · Fix suggestions (not running)');
    expect(cells(row(root, 'Research'))[4]).toBe('—');

    // Without the licence there are no automatic fix suggestions to show.
    fixture.componentRef.setInput('autoFixAvailable', false);
    await settle(fixture);
    expect(cells(row(root, 'Acme'))[4]).toBe('AI review (paused)');

    // Without a provider a review is not paused: there is nothing to confirm yet.
    fixture.componentRef.setInput('settings', { ...settings, provider: null });
    await settle(fixture);
    expect(cells(row(root, 'Acme'))[4]).toBe('AI review');
  });

  it('opens one editor, Allow AI with the three features under it, and saves the entry', async () => {
    setup();
    const { fixture, root, saves } = await render();
    await edit(fixture, root, 'Acme');
    const acme = row(root, 'Acme');
    expect(acme.classList).toContain('editing');
    expect(button(acme, 'Close')?.getAttribute('aria-expanded')).toBe('true');
    const region = root.querySelector<HTMLElement>(`#org-editor-${ACME}`)!;
    expect(region.getAttribute('role')).toBe('region');
    expect(region.getAttribute('aria-label')).toBe('Edit Acme');
    // Its foot, with Save, is the editor's too.
    expect(button(region, 'Save Acme')).toBeDefined();
    expect(region.closest('tr')).toBe(editor(root));
    expect(editor(root)?.previousElementSibling).toBe(acme);

    const allow = field(root, `org-${ACME}-allow`)!;
    expect(allow.checked).toBe(true);
    expect(allow.getAttribute('role')).toBe('switch');
    expect(document.activeElement).toBe(allow);
    // A switch is named by its name alone, and its help describes it.
    expect(named(root, allow, 'aria-labelledby')).toEqual(['Allow AI in Acme']);
    expect(named(root, allow, 'aria-describedby')).toEqual([ALLOW_HELP]);
    const triage = field(root, `org-${ACME}-triage`)!;
    expect(named(root, triage, 'aria-labelledby')).toEqual(['Suggest triage']);
    expect(named(root, triage, 'aria-describedby')).toEqual([
      'Whether the finding looks like a false positive. A person decides.',
    ]);
    expect(text(editor(root)?.querySelector('.dep > .dep-title'))).toBe('Assistant features');
    expect(
      ['explain', 'triage', 'fix'].map((f) => field(root, `org-${ACME}-${f}`)?.checked),
    ).toEqual([true, true, true]);
    expect(foot(root)).toBe('No unsaved changes');

    await click(fixture, triage);
    expect(foot(root)).toBe('1 unsaved change');
    await click(fixture, button(editor(root)!, 'Save Acme'));
    // Only the switches and the projects never sent: never what the organisation's admins set.
    expect(saves).toEqual([
      [
        ACME,
        {
          enabled: true,
          features: { explain: true, triage: false, fix: true },
          excludedProjectIds: ['p3'],
        },
      ],
    ]);
    expect(editor(root)).toBeNull();
    expect(root.querySelector('.orgs-status')?.getAttribute('role')).toBe('status');
    expect(status(root)).toBe('Acme saved.');
    expect(document.activeElement).toBe(button(row(root, 'Acme'), 'Edit'));
    expect(cells(row(root, 'Acme'))[2]).toBe('Explain Suggest a fix');
  });

  it('warns that switching off Suggest a fix stops automatic fix suggestions', async () => {
    setup();
    const { fixture, root } = await render();
    await edit(fixture, root, 'Acme');
    const fix = field(root, `org-${ACME}-fix`)!;
    expect(editor(root)?.querySelector('.req')).toBeNull();
    await click(fixture, fix);
    const note = editor(root)?.querySelector('.req');
    expect(text(note)).toBe("Acme's automatic fix suggestions stop without it.");
    // Right under the switch, which it describes after its help.
    expect(fix.closest('.switch-row')?.nextElementSibling?.contains(note!)).toBe(true);
    expect(named(root, fix, 'aria-describedby')).toEqual([
      'A replacement for the flagged lines, which a person may post to the merge request.',
      "Acme's automatic fix suggestions stop without it.",
    ]);
    await click(fixture, fix);
    expect(editor(root)?.querySelector('.req')).toBeNull();

    // Without the licence, there are none to stop.
    fixture.componentRef.setInput('autoFixAvailable', false);
    await click(fixture, fix);
    expect(editor(root)?.querySelector('.req')).toBeNull();
  });

  it('warns that disallowing AI stops the AI review and deletes its copies', async () => {
    setup();
    const { fixture, root } = await render();
    await edit(fixture, root, 'Acme');
    const allow = field(root, `org-${ACME}-allow`)!;
    await click(fixture, allow);
    const note =
      'AI review is on in Acme: it stops, and its repository copies are deleted, when you save.';
    expect(text(editor(root)?.querySelector('.req'))).toBe(note);
    expect(allow.closest('.switch-row')?.nextElementSibling?.textContent).toContain('AI review');
    expect(named(root, allow, 'aria-describedby')).toEqual([ALLOW_HELP, note]);
    // The features and the projects never sent give way to one line; their values stay.
    expect(editor(root)?.querySelector('.dep')).toBeNull();
    expect(field(root, `org-${ACME}-explain`)).toBeNull();
    expect(text(editor(root)?.querySelector('.dep-off'))).toBe(
      'Acme sends nothing to the provider.',
    );
    await click(fixture, allow);
    expect(editor(root)?.querySelector('.req')).toBeNull();
    expect(
      ['explain', 'triage', 'fix'].map((f) => field(root, `org-${ACME}-${f}`)?.checked),
    ).toEqual([true, true, true]);
    expect(items(root)).toEqual(['Legacy billing acme/legacy-billing Remove']);

    // Where AI review is off, switching AI off stops nothing of it.
    await click(fixture, button(editor(root)!.querySelector('q-section-foot')!, 'Cancel'));
    fixture.componentRef.setInput('settings', {
      ...SETTINGS,
      organizations: { ...SETTINGS.organizations, [ACME]: stored({ autoFix: true }) },
    });
    await edit(fixture, root, 'Acme');
    await click(fixture, field(root, `org-${ACME}-allow`));
    expect(editor(root)?.querySelector('.req')).toBeNull();
  });

  it('adds and removes projects that are never sent', async () => {
    const server = setup();
    const { fixture, root, saves } = await render();
    await edit(fixture, root, 'Acme');
    const dep = editor(root)!.querySelector('.dep')!;
    expect([...dep.querySelectorAll('.dep-title')].map((p) => text(p))).toEqual([
      'Assistant features',
      'Never sent to the provider',
    ]);
    expect(text(dep.querySelector('.list-editor')?.previousElementSibling)).toBe(
      'Their issues are never explained, triaged or fixed, and AI review never reviews them; its copies of their repositories are deleted.',
    );
    expect(items(root)).toEqual(['Legacy billing acme/legacy-billing Remove']);
    const asked = server.requestsTo('GET', '/api/v0/projects');
    expect(asked.map((r) => [r.query.get('organizationId'), r.query.get('limit')])).toEqual([
      [ACME, '100'],
    ]);

    // The picker lists Acme's projects, the one already never sent ticked.
    await click(fixture, button(editor(root)!, 'Add a project'));
    const options = [...editor(root)!.querySelectorAll<HTMLElement>('q-project-picker li')];
    expect(options.map((o) => text(o))).toEqual([
      'Payments acme/payments',
      'Web Shop acme/web-shop',
      'Legacy billing acme/legacy-billing Already in the list',
    ]);
    await click(fixture, options[1]!.querySelector('input'));
    await click(fixture, button(editor(root)!, 'Add 1 project'));
    expect(items(root)).toEqual([
      'Legacy billing acme/legacy-billing Remove',
      'Web Shop acme/web-shop Remove',
    ]);

    const remove = editor(root)!.querySelector<HTMLButtonElement>('.list-editor li button')!;
    expect(remove.getAttribute('aria-label')).toBe('Remove Legacy billing');
    remove.focus();
    await click(fixture, remove);
    expect(items(root)).toEqual(['Web Shop acme/web-shop Remove']);
    // The next project's Remove takes the focus of the one removed.
    expect(document.activeElement).toBe(editor(root)!.querySelector('.list-editor li button'));
    expect(foot(root)).toBe('2 unsaved changes');

    await click(fixture, button(editor(root)!, 'Save Acme'));
    expect(saves).toEqual([
      [ACME, { enabled: true, features: ALL_ON, excludedProjectIds: ['p2'] }],
    ]);
    expect(cells(row(root, 'Acme'))[3]).toBe('1 project');
  });

  it('counts the projects ticked and not added as changes, and its Save adds them first', async () => {
    setup();
    const { fixture, root, section, saves } = await render();
    await edit(fixture, root, 'Acme');
    await click(fixture, button(editor(root)!, 'Add a project'));
    const boxes = () => [
      ...editor(root)!.querySelectorAll<HTMLInputElement>('q-project-picker li input'),
    ];
    await click(fixture, boxes()[1]);
    await click(fixture, boxes()[0]);
    expect(section.dirty()).toBe(true);
    expect(foot(root)).toBe('2 unsaved changes');
    // Unticked, a project is no change.
    await click(fixture, boxes()[1]);
    expect(foot(root)).toBe('1 unsaved change');

    const save = button(editor(root)!, 'Save Acme')!;
    save.focus();
    await click(fixture, save);
    expect(saves).toEqual([
      [ACME, { enabled: true, features: ALL_ON, excludedProjectIds: ['p3', 'p1'] }],
    ]);
    expect(editor(root)).toBeNull();
    expect(cells(row(root, 'Acme'))[3]).toBe('2 projects');
  });

  it('forgets the projects ticked once its picker is cancelled', async () => {
    setup();
    const { fixture, root, section } = await render();
    await edit(fixture, root, 'Acme');
    await click(fixture, button(editor(root)!, 'Add a project'));
    await click(
      fixture,
      editor(root)!.querySelector<HTMLInputElement>('q-project-picker li input'),
    );
    expect(section.dirty()).toBe(true);
    await click(fixture, button(editor(root)!.querySelector('q-project-picker')!, 'Cancel'));
    expect(section.dirty()).toBe(false);
    expect(foot(root)).toBe('No unsaved changes');
  });

  it('names the projects never sent from their organisation’s list, page by page, and says when one is not listed', async () => {
    const many = Array.from({ length: 150 }, (_, i) =>
      projectItem({ id: `q${i}`, key: `acme/q${i}`, name: `Q ${i}` }),
    );
    const server = setup(ORGS, many);
    const { fixture, root } = await render({
      settings: {
        ...SETTINGS,
        organizations: { [ACME]: stored({ excludedProjectIds: ['q120', 'gone'] }) },
      },
    });
    await edit(fixture, root, 'Acme');
    expect(items(root)).toEqual([
      'Q 120 acme/q120 Remove',
      'A project not listed here (gone) Remove',
    ]);
    expect(
      server
        .requestsTo('GET', '/api/v0/projects')
        .map((r) => [r.query.get('organizationId'), r.query.get('limit'), r.query.get('cursor')]),
    ).toEqual([
      [ACME, '100', null],
      [ACME, '100', '100'],
    ]);
    // Found on the first page: the second is never read.
    await click(fixture, button(row(root, 'Acme'), 'Close'));
    fixture.componentRef.setInput('settings', {
      ...SETTINGS,
      organizations: { [ACME]: stored({ excludedProjectIds: ['q5'] }) },
    });
    await edit(fixture, root, 'Acme');
    expect(items(root)).toEqual(['Q 5 acme/q5 Remove']);
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(3);
  });

  it('names a project by its id alone when the names could not be read', async () => {
    const server = setup();
    server.on('GET', '/api/v0/projects', { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root } = await render();
    await edit(fixture, root, 'Acme');
    // Not "A project not listed here": whether it is listed is not known.
    expect(items(root)).toEqual(['p3 Remove']);
    expect(editor(root)?.querySelector('.list-editor .item code')?.textContent).toBe('p3');
    expect(editor(root)?.querySelector('.list-editor li button')?.getAttribute('aria-label')).toBe(
      'Remove p3',
    );
    expect(text(editor(root)?.querySelector('.list-editor + .field-error'))).toBe(
      'The request failed (HTTP 500, INTERNAL).',
    );
  });

  it('reads and offers only the projects of the organisation edited, whatever the header shows', async () => {
    const research = [
      projectItem({
        id: 'r1',
        key: 'research/api',
        name: 'Research API',
        organizationId: RESEARCH,
      }),
      projectItem({
        id: 'r2',
        key: 'research/web',
        name: 'Research web',
        organizationId: RESEARCH,
      }),
    ];
    const server = setup(ORGS, [...PROJECTS, ...research]);
    const { fixture, root } = await render({
      settings: {
        ...SETTINGS,
        organizations: {
          ...SETTINGS.organizations,
          [RESEARCH]: stored({ enabled: false, excludedProjectIds: ['r1'] }),
        },
      },
    });
    expect(TestBed.inject(OrgContext).currentId()).toBe(ACME);
    await edit(fixture, root, 'Research');
    await click(fixture, field(root, `org-${RESEARCH}-allow`));
    expect(items(root)).toEqual(['Research API research/api Remove']);
    await click(fixture, button(editor(root)!, 'Add a project'));
    expect(
      [...editor(root)!.querySelectorAll('q-project-picker li')].map((li) => text(li)),
    ).toEqual(['Research API research/api Already in the list', 'Research web research/web']);
    expect(
      server.requestsTo('GET', '/api/v0/projects').map((r) => r.query.get('organizationId')),
    ).toEqual([RESEARCH, RESEARCH]);
  });

  it('keeps a project never sent that its organisation does not list', async () => {
    setup();
    const { fixture, root, saves } = await render({
      settings: {
        ...SETTINGS,
        organizations: {
          ...SETTINGS.organizations,
          [ACME]: stored({ excludedProjectIds: ['p3', 'p9'] }),
        },
      },
    });
    await edit(fixture, root, 'Acme');
    expect(items(root)).toEqual([
      'Legacy billing acme/legacy-billing Remove',
      'A project not listed here (p9) Remove',
    ]);
    await click(fixture, editor(root)!.querySelector<HTMLElement>('.list-editor li button'));
    await click(fixture, button(editor(root)!, 'Add a project'));
    await click(
      fixture,
      editor(root)!.querySelectorAll<HTMLElement>('q-project-picker li input')[1],
    );
    await click(fixture, button(editor(root)!, 'Add 1 project'));
    await click(fixture, footButton(root, 'Save Acme'));
    expect(saves).toEqual([
      [ACME, { enabled: true, features: ALL_ON, excludedProjectIds: ['p9', 'p2'] }],
    ]);
  });

  it('drops the names read for an editor closed meanwhile', async () => {
    const research = [
      projectItem({
        id: 'r1',
        key: 'research/api',
        name: 'Research API',
        organizationId: RESEARCH,
      }),
    ];
    const server = setup(ORGS, [...PROJECTS, ...research]);
    // Every read waits for its answer.
    const held: { organizationId: string | null; answer: (reply: FakeReply) => void }[] = [];
    server.on(
      'GET',
      '/api/v0/projects',
      (request) =>
        new Promise<FakeReply>((answer) =>
          held.push({ organizationId: request.query.get('organizationId'), answer }),
        ),
    );
    const { fixture, root } = await render({
      settings: {
        ...SETTINGS,
        organizations: {
          ...SETTINGS.organizations,
          [RESEARCH]: stored({ excludedProjectIds: ['r1'] }),
        },
      },
    });
    const loading = () =>
      [...(editor(root)?.querySelectorAll('p.hint') ?? [])].some((p) => text(p) === 'Loading…');
    const error = () => editor(root)?.querySelector('.field-error');
    await edit(fixture, root, 'Acme');
    await edit(fixture, root, 'Research');
    expect(held.map((h) => h.organizationId)).toEqual([ACME, RESEARCH]);

    // Acme's answer comes after its editor closed, and says there is more: it is dropped, and no
    // more of Acme's list is read.
    held[0]!.answer({ body: page([], '100') });
    await settle(fixture);
    expect(loading()).toBe(true);
    expect(held).toHaveLength(2);
    held[1]!.answer({ body: page(research) });
    await settle(fixture);
    expect(items(root)).toEqual(['Research API research/api Remove']);
    expect(loading()).toBe(false);
    expect(error()).toBeNull();

    // A read that fails after its editor closed says nothing in the next one.
    await click(fixture, button(row(root, 'Research'), 'Close'));
    await edit(fixture, root, 'Acme');
    await edit(fixture, root, 'Research');
    held[2]!.answer({ status: 500, body: problem(500, 'INTERNAL') });
    await settle(fixture);
    expect(error()).toBeNull();
    expect(loading()).toBe(true);
    held[3]!.answer({ body: page(research) });
    await settle(fixture);
    expect(items(root)).toEqual(['Research API research/api Remove']);
    expect(error()).toBeNull();
  });

  it('reads 20 pages at most for the names, and nothing for an organisation that excludes none', async () => {
    const server = setup();
    // A list that never ends.
    server.on('GET', '/api/v0/projects', (request) => ({
      body: page([], String(Number(request.query.get('cursor') ?? 0) + 1)),
    }));
    const { fixture, root } = await render({
      settings: { ...SETTINGS, organizations: { [ACME]: stored({ excludedProjectIds: ['p9'] }) } },
    });
    await edit(fixture, root, 'Research');
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(0);
    await click(fixture, button(row(root, 'Research'), 'Close'));
    await edit(fixture, root, 'Acme');
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(20);
    expect(items(root)).toEqual(['A project not listed here (p9) Remove']);
  });

  it('pages 120 organisations 25 at a time, and finds one by name (Review Focus 4)', async () => {
    const organizations = organizationsFixture(120);
    setup(organizations);
    const { fixture, root } = await render({ organizations, settings: CONFIGURED as Settings });
    expect(rows(root)).toHaveLength(25);
    expect(rows(root).slice(0, 3).map(nameOf)).toEqual(['Org 1', 'Org 2', 'Org 3']);
    expect(rows(root).map(nameOf)).not.toContain('Org 101');
    expect(button(root, 'Show 25 more')).toBeDefined();
    expect(text(root.querySelector('.orgs-count'))).toBe('25 of 120 organizations');

    const filter = field(root, 'ai-orgs-filter')!;
    expect(text(root.querySelector('label[for="ai-orgs-filter"]'))).toBe('Filter organizations');
    // The filter sits in the shared toolbar, as the other lists' controls do.
    expect(filter.closest('.toolbar')).not.toBeNull();
    type(root, 'ai-orgs-filter', 'org 101');
    await settle(fixture);
    expect(rows(root).map(nameOf)).toEqual(['Org 101']);
    expect(button(root, 'Show 25 more')).toBeUndefined();
    // The key matches too.
    type(root, 'ai-orgs-filter', 'ORG-7');
    await settle(fixture);
    expect(rows(root).map(nameOf)).toEqual([
      'Org 7',
      ...Array.from({ length: 10 }, (_, i) => `Org ${70 + i}`),
    ]);
    type(root, 'ai-orgs-filter', 'nothing like it');
    await settle(fixture);
    expect(rows(root)).toHaveLength(0);
    expect(text(root.querySelector('.orgs-count'))).toBe('No organization matches.');

    filter.value = '';
    filter.dispatchEvent(new Event('input'));
    await settle(fixture);
    const more = button(root, 'Show 25 more')!;
    more.focus();
    await click(fixture, more);
    expect(rows(root)).toHaveLength(50);
    expect(text(root.querySelector('.orgs-count'))).toBe('50 of 120 organizations');
    expect(document.activeElement).toBe(more);
    await click(fixture, more);
    await click(fixture, more);
    expect(text(more)).toBe('Show 20 more');
    await click(fixture, more);
    expect(rows(root)).toHaveLength(120);
    expect(button(root, 'Show 20 more')).toBeUndefined();
    // The button is gone: the focus goes to the first organisation it showed.
    expect(document.activeElement).toBe(button(row(root, 'Org 101'), 'Edit'));
    // 120 rendered rows take about 3 s on a busy machine, near the default 5 s.
  }, 20_000);

  it('says the organizations could not be loaded in place of its table, and asks for them again', async () => {
    setup();
    const { fixture, root, section } = await render({ organizations: [] });
    let retries = 0;
    section.retry.subscribe(() => retries++);
    fixture.componentRef.setInput('listFailed', true);
    await settle(fixture);
    const alert = root.querySelector('[role="alert"]')!;
    expect(text(alert)).toBe('The organizations could not be loaded. Try again');
    expect(root.querySelector('table')).toBeNull();
    expect(root.querySelector('#ai-orgs-filter')).toBeNull();
    // No count of what is not known.
    expect(root.querySelector('.sec-chips')).toBeNull();
    expect(text(root.querySelector('#ai-orgs-heading'))).toBe('Organizations');
    await click(fixture, button(alert, 'Try again'));
    expect(retries).toBe(1);

    fixture.componentRef.setInput('organizations', ORGS);
    fixture.componentRef.setInput('listFailed', false);
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')).toBeNull();
    expect(rows(root)).toHaveLength(2);
  });

  it('asks the page to open an organisation’s AI page, and changes nothing itself', async () => {
    setup();
    const { fixture, root, section } = await render();
    const opened: string[] = [];
    section.openOrganization.subscribe((id) => opened.push(id));
    const open = button(row(root, 'Research'), 'Open')!;
    expect(open.getAttribute('aria-label')).toBe("Open Research's AI page");
    await click(fixture, open);
    expect(opened).toEqual([RESEARCH]);
    // The header's organisation and the address are the page's to change, once it may leave.
    expect(TestBed.inject(OrgContext).currentId()).toBe(ACME);
    expect(TestBed.inject(Router).url).toBe('/');
  });

  it('is dirty while its editor has changes', async () => {
    setup();
    const { fixture, root, section } = await render();
    expect(section.dirtyLabel).toBe('Organizations');
    expect(section.dirty()).toBe(false);
    await edit(fixture, root, 'Acme');
    expect(section.dirty()).toBe(false);
    const explain = field(root, `org-${ACME}-explain`)!;
    await click(fixture, explain);
    expect(section.dirty()).toBe(true);
    expect(text(explain.closest('.switch-row')?.querySelector('.sw-name.changed'))).toBe('Explain');
    await click(fixture, explain);
    expect(section.dirty()).toBe(false);
    await click(fixture, explain);
    // The foot's Cancel, not the picker's.
    await click(fixture, button(editor(root)!.querySelector('q-section-foot')!, 'Cancel'));
    expect(section.dirty()).toBe(false);
    expect(editor(root)).toBeNull();
    expect(document.activeElement).toBe(button(row(root, 'Acme'), 'Edit'));
    // Opened again, the editor shows what is saved.
    await edit(fixture, root, 'Acme');
    expect(field(root, `org-${ACME}-explain`)?.checked).toBe(true);
  });

  it('keeps an editor with changes open when another organisation’s Edit is pressed', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await edit(fixture, root, 'Acme');
    const triage = field(root, `org-${ACME}-triage`)!;
    await click(fixture, triage);
    await click(fixture, button(row(root, 'Research'), 'Edit'));
    expect(root.querySelectorAll('tr.editor')).toHaveLength(1);
    expect(editor(root)?.querySelector(`#org-editor-${ACME}`)).not.toBeNull();
    expect(button(row(root, 'Research'), 'Edit')?.getAttribute('aria-expanded')).toBe('false');
    expect(status(root)).toBe('Save or cancel the changes to Acme first.');

    // Without changes, Edit moves the editor.
    await click(fixture, triage);
    await click(fixture, button(row(root, 'Research'), 'Edit'));
    expect(root.querySelectorAll('tr.editor')).toHaveLength(1);
    expect(editor(root)?.previousElementSibling).toBe(row(root, 'Research'));
    expect(status(root)).toBe('');
    const allow = field(root, `org-${RESEARCH}-allow`)!;
    expect(allow.checked).toBe(false);
    expect(document.activeElement).toBe(allow);
    expect(text(editor(root)?.querySelector('.dep-off'))).toBe(
      'Research sends nothing to the provider.',
    );
    // Research never sends a project to leave out: the names were read for Acme only.
    expect(server.requestsTo('GET', '/api/v0/projects')).toHaveLength(1);

    // Close closes it, and gives the focus back to Edit.
    await click(fixture, button(row(root, 'Research'), 'Close'));
    expect(editor(root)).toBeNull();
    expect(document.activeElement).toBe(button(row(root, 'Research'), 'Edit'));
  });

  it('forgets “Save or cancel…” once the editor is cancelled', async () => {
    setup();
    const { fixture, root } = await render();
    await edit(fixture, root, 'Acme');
    await click(fixture, field(root, `org-${ACME}-triage`));
    await click(fixture, button(row(root, 'Research'), 'Edit'));
    expect(status(root)).toBe('Save or cancel the changes to Acme first.');
    await click(fixture, footButton(root, 'Cancel'));
    expect(editor(root)).toBeNull();
    expect(status(root)).toBe('');
  });

  it('keeps the row being edited in view whatever the filter finds', async () => {
    setup();
    const { fixture, root } = await render();
    await edit(fixture, root, 'Acme');
    type(root, 'ai-orgs-filter', 'research');
    await settle(fixture);
    expect(rows(root).map(nameOf)).toEqual(['Acme', 'Research']);
    expect(editor(root)?.previousElementSibling).toBe(row(root, 'Acme'));
    await click(fixture, button(row(root, 'Acme'), 'Close'));
    expect(rows(root).map(nameOf)).toEqual(['Research']);
  });

  it('counts what the filter finds, never the row held in view for its editor', async () => {
    setup();
    const { fixture, root } = await render();
    await edit(fixture, root, 'Acme');
    type(root, 'ai-orgs-filter', 'research');
    await settle(fixture);
    expect(rows(root).map(nameOf)).toEqual(['Acme', 'Research']);
    expect(count(root)).toBe('1 organization');
    type(root, 'ai-orgs-filter', 'nothing like it');
    await settle(fixture);
    expect(rows(root).map(nameOf)).toEqual(['Acme']);
    expect(count(root)).toBe('No organization matches.');
    // Closing changes no count: the count line and the status never speak at once.
    await click(fixture, button(row(root, 'Acme'), 'Close'));
    expect(rows(root)).toHaveLength(0);
    expect(count(root)).toBe('No organization matches.');
  });

  it('counts the page without the row held past it for its editor', async () => {
    const organizations = organizationsFixture(120);
    setup(organizations);
    const { fixture, root } = await render({ organizations, settings: CONFIGURED as Settings });
    await click(fixture, button(root, 'Show 25 more'));
    await edit(fixture, root, 'Org 30');
    // A filter starts again at 25 rows: Org 30 stays for its editor, and is not counted.
    type(root, 'ai-orgs-filter', 'org');
    await settle(fixture);
    expect(rows(root)).toHaveLength(26);
    expect(count(root)).toBe('25 of 120 organizations');
    expect(button(root, 'Show 25 more')).toBeDefined();
    await click(fixture, field(root, `org-${organizations[29]!.id}-allow`));
    await click(fixture, footButton(root, 'Save Org 30'));
    expect(rows(root)).toHaveLength(25);
    expect(status(root)).toBe('Org 30 saved.');
    expect(count(root)).toBe('25 of 120 organizations');
    // Fifty rendered rows take about 1 s, and several times that on a busy machine.
  }, 20_000);

  it('gives the focus to the filter when the row it edited leaves with its editor', async () => {
    setup();
    const { fixture, root } = await render();
    await edit(fixture, root, 'Acme');
    type(root, 'ai-orgs-filter', 'research');
    await settle(fixture);
    const cancel = footButton(root, 'Cancel')!;
    cancel.focus();
    await click(fixture, cancel);
    expect(rows(root).map(nameOf)).toEqual(['Research']);
    expect(document.activeElement).toBe(field(root, 'ai-orgs-filter'));

    // After a save too.
    type(root, 'ai-orgs-filter', '');
    await settle(fixture);
    await edit(fixture, root, 'Acme');
    await click(fixture, field(root, `org-${ACME}-triage`));
    type(root, 'ai-orgs-filter', 'research');
    await settle(fixture);
    const save = footButton(root, 'Save Acme')!;
    save.focus();
    await click(fixture, save);
    expect(status(root)).toBe('Acme saved.');
    expect(rows(root).map(nameOf)).toEqual(['Research']);
    expect(document.activeElement).toBe(field(root, 'ai-orgs-filter'));
  });

  it('shows new settings in an editor without changes, and keeps a draft that has some', async () => {
    setup();
    const { fixture, root, section } = await render();
    await edit(fixture, root, 'Acme');
    // Another section's save answers settings in which Acme's triage is off.
    const triageOff = (settings: Settings) =>
      withEntry(settings, ACME, {
        enabled: true,
        features: { explain: true, triage: false, fix: true },
        excludedProjectIds: ['p3'],
      });
    fixture.componentRef.setInput('settings', triageOff(SETTINGS));
    await settle(fixture);
    expect(field(root, `org-${ACME}-triage`)?.checked).toBe(false);
    expect(section.dirty()).toBe(false);

    await click(fixture, field(root, `org-${ACME}-explain`));
    fixture.componentRef.setInput('settings', SETTINGS);
    await settle(fixture);
    expect(field(root, `org-${ACME}-explain`)?.checked).toBe(false);
    expect(field(root, `org-${ACME}-triage`)?.checked).toBe(false);
    // The draft now compares with the new settings: explain and triage differ from them.
    expect(foot(root)).toBe('2 unsaved changes');
  });

  it('keeps an edit made while the save is on its way, unsaved', async () => {
    setup();
    const { fixture, root, section, saves, release } = await render({ hold: true });
    await edit(fixture, root, 'Acme');
    await click(fixture, field(root, `org-${ACME}-triage`));
    await click(fixture, button(editor(root)!, 'Save Acme'));
    expect(foot(root)).toBe('Saving…');
    // The editor stays editable while it saves.
    const explain = field(root, `org-${ACME}-explain`)!;
    expect(explain.disabled).toBe(false);
    await click(fixture, explain);
    await release();
    expect(saves).toEqual([
      [
        ACME,
        {
          enabled: true,
          features: { explain: true, triage: false, fix: true },
          excludedProjectIds: ['p3'],
        },
      ],
    ]);
    expect(status(root)).toBe('Acme saved.');
    expect(editor(root)).not.toBeNull();
    expect(field(root, `org-${ACME}-explain`)?.checked).toBe(false);
    expect(field(root, `org-${ACME}-triage`)?.checked).toBe(false);
    expect(foot(root)).toBe('1 unsaved change');
    expect(section.dirty()).toBe(true);
    expect(cells(row(root, 'Acme'))[2]).toBe('Explain Suggest a fix');
  });

  it('shows a refused save in the editor’s foot, and keeps Save and the edits', async () => {
    setup();
    const { fixture, root } = await render({
      saveEntry: () => Promise.reject(new ApiError(403, problem(403, 'FORBIDDEN'))),
    });
    await edit(fixture, root, 'Acme');
    await click(fixture, field(root, `org-${ACME}-triage`));
    await click(fixture, button(editor(root)!, 'Save Acme'));
    expect(foot(root)).toBe('You are not allowed to do this.');
    expect(button(editor(root)!, 'Save Acme')?.disabled).toBe(false);
    expect(field(root, `org-${ACME}-triage`)?.checked).toBe(false);
    expect(status(root)).toBe('');
    // The next edit is a change again.
    await click(fixture, field(root, `org-${ACME}-explain`));
    expect(foot(root)).toBe('2 unsaved changes');
  });

  it('counts the allowed organisations in its head, and the projects never sent in the singular and the plural', async () => {
    const organizations = [...ORGS, organization(LAB, 'lab', 'Lab')];
    setup(organizations);
    const settings: Settings = {
      ...SETTINGS,
      organizations: {
        [ACME]: stored({ excludedProjectIds: ['p1', 'p2'] }),
        [LAB]: stored({ features: NONE_ON }),
      },
    };
    const { fixture, root } = await render({ organizations, settings });
    expect(text(root.querySelector('.sec-chips'))).toBe('2 of 3 allowed');
    expect(cells(row(root, 'Acme')).slice(1, 5)).toEqual([
      'Allowed',
      'Explain Suggest triage Suggest a fix',
      '2 projects',
      '—',
    ]);
    expect(cells(row(root, 'Lab')).slice(1, 5)).toEqual(['Allowed', 'None', 'None', '—']);
    // Research is absent from the settings: not allowed.
    expect(cells(row(root, 'Research'))[1]).toBe('Not allowed');

    fixture.componentRef.setInput('settings', { ...settings, organizations: {} });
    await settle(fixture);
    expect(text(root.querySelector('.sec-chips'))).toBe('0 of 3 allowed');
    expect(root.querySelector('.sec-chips .badge')?.classList).toContain('badge-none');
  });

  it('allows an organisation absent from the settings, sending only its switches and exclusions', async () => {
    const organizations = [...ORGS, organization(LAB, 'lab', 'Lab')];
    setup(organizations);
    const { fixture, root, saves } = await render({ organizations });
    await edit(fixture, root, 'Lab');
    await click(fixture, field(root, `org-${LAB}-allow`));
    expect(
      ['explain', 'triage', 'fix'].map((f) => field(root, `org-${LAB}-${f}`)?.checked),
    ).toEqual([false, false, false]);
    expect(items(root)).toEqual([]);
    await click(fixture, field(root, `org-${LAB}-explain`));
    await click(fixture, button(editor(root)!, 'Save Lab'));
    expect(saves).toEqual([
      [
        LAB,
        {
          enabled: true,
          features: { explain: true, triage: false, fix: false },
          excludedProjectIds: [],
        },
      ],
    ]);
    expect(cells(row(root, 'Lab')).slice(1, 3)).toEqual(['Allowed', 'Explain']);
  });
});

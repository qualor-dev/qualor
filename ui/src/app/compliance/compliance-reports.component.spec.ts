import { type ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  complianceReport,
  complianceSummary,
  FakeCompliance,
  FakeServer,
  me,
  ORG_ID,
  problem,
  provideFakeServer,
} from '../../testing/fake-server';
import type { ComplianceReport } from '../api/ee';
import { SessionStore } from '../auth/session';
import { ComplianceReportsComponent } from './compliance-reports.component';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const REPORTS = '/api/v0/ee/compliance/reports';
const OLD = '0190a6c2-0000-7000-8000-0000000000c1';
const NEW = '0190a6c2-0000-7000-8000-0000000000c2';
const BRANCHES = [
  { id: '0190a6c2-0000-7000-8000-0000000000b2', name: 'develop', isMain: false },
  { id: '0190a6c2-0000-7000-8000-0000000000b1', name: 'main', isMain: true },
];

const VERSIONS = [
  { id: '0190a6c2-0000-7000-8000-0000000000a2', label: '2.0.0' },
  { id: '0190a6c2-0000-7000-8000-0000000000a1', label: '1.0.0' },
];

/** The name `aria-labelledby` gives `el`: the texts of the elements it names, in order. */
function labelOf(root: HTMLElement, el: Element | null | undefined): string {
  const ids = el?.getAttribute('aria-labelledby')?.split(/\s+/) ?? [];
  return ids
    .map((id) => root.querySelector(`[id="${id}"]`)?.textContent?.replace(/\s+/g, ' ').trim())
    .join(' ');
}

/** The trimmed text of each header and data cell of a table row. */
function cellTexts(row: Element): (string | undefined)[] {
  return [...row.querySelectorAll('th, td')].map((c) => c.textContent?.trim());
}

interface Render {
  scope?: { organizationId: string } | { projectId: string };
  canCreate?: boolean;
}

describe('ComplianceReportsComponent (4E-1 §4)', () => {
  let server: FakeServer;

  beforeEach(() => {
    // Only the timers: the fake fetch and Angular's scheduling still run, the 3 s poll waits.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    server = new FakeServer();
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  let current: ComponentFixture<ComplianceReportsComponent> | null = null;

  /** Lets the fake fetch answer and Angular render, without reaching the next poll. */
  async function flush(): Promise<void> {
    for (let i = 0; i < 10; i++) {
      await vi.advanceTimersByTimeAsync(0);
      current?.detectChanges();
    }
  }

  async function render(options: Render = {}) {
    const fixture = TestBed.createComponent(ComplianceReportsComponent);
    current = fixture;
    fixture.componentRef.setInput('scope', options.scope ?? { projectId: PROJECT });
    fixture.componentRef.setInput('canCreate', options.canCreate ?? false);
    fixture.componentRef.setInput('branches', BRANCHES);
    fixture.componentRef.setInput('versions', VERSIONS);
    await flush();
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  function rows(root: HTMLElement): HTMLTableRowElement[] {
    return [...root.querySelectorAll<HTMLTableRowElement>('.compliance-list tbody tr[data-key]')];
  }

  function downloads(row: HTMLElement): (string | null)[] {
    return [...row.querySelectorAll('a[download]')].map((a) => a.getAttribute('href'));
  }

  function button(root: HTMLElement, text: string): HTMLButtonElement {
    const found = [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text);
    if (!found) throw new Error(`no button "${text}"`);
    return found;
  }

  it('lists the reports newest first, and polls a pending one every 3 s until it is ready', async () => {
    const store = FakeCompliance.install(server, [
      complianceReport({ id: OLD, createdAt: '2026-10-10T10:00:00.000Z' }),
      complianceReport({
        id: NEW,
        status: 'pending',
        createdAt: '2026-10-12T10:00:00.000Z',
        completedAt: null,
        sha256: null,
        sizeBytes: null,
        summary: null,
      }),
    ]);
    const { root } = await render();

    expect(server.requestsTo('GET', REPORTS)[0]?.query.get('projectId')).toBe(PROJECT);
    const second = rows(root)[1];
    let first = rows(root)[0];
    expect(first?.dataset['key']).toBe(NEW);
    expect(second?.dataset['key']).toBe(OLD);
    expect(first?.querySelector('.badge')?.textContent?.trim()).toBe('Pending');
    expect(second?.querySelector('.badge')?.textContent?.trim()).toBe('Ready');
    // A pending report has nothing to download: its links have no address.
    expect(downloads(first!)).toEqual([null, null, null]);
    expect(
      [...first!.querySelectorAll('a[download]')].every(
        (a) => a.getAttribute('aria-disabled') === 'true',
      ),
    ).toBe(true);
    expect(second?.textContent).toContain('abababababab');
    expect(second?.textContent).not.toContain('ab'.repeat(7));

    store.complete(NEW);
    await vi.advanceTimersByTimeAsync(2_900);
    expect(server.requestsTo('GET', `${REPORTS}/${NEW}`)).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(100);
    await flush();

    expect(server.requestsTo('GET', `${REPORTS}/${NEW}`)).toHaveLength(1);
    [first] = rows(root);
    expect(first?.querySelector('.badge')?.textContent?.trim()).toBe('Ready');
    expect(downloads(first!)).toEqual([
      `${REPORTS}/${NEW}/download?format=json`,
      `${REPORTS}/${NEW}/download?format=csv`,
      `${REPORTS}/${NEW}/download?format=pdf`,
    ]);
    expect(first?.querySelector('a[download][aria-disabled]')).toBeNull();
    // No SBOM link for a report that attaches none.
    expect(first?.textContent).not.toContain('SBOM');
    expect(first?.querySelector('.compliance-total')?.textContent?.trim()).toBe('3');

    // Nothing is pending any more: the polling has stopped.
    await vi.advanceTimersByTimeAsync(10_000);
    expect(server.requestsTo('GET', `${REPORTS}/${NEW}`)).toHaveLength(1);
  });

  it('offers the SBOM download only for a report that attaches one', async () => {
    FakeCompliance.install(server, [
      complianceReport({ id: NEW, sbom: { sha256: 'cd'.repeat(32) } }),
      complianceReport({ id: OLD }),
    ]);
    const { root } = await render();
    const [withSbom, without] = rows(root);
    expect(downloads(withSbom!)).toEqual([
      `${REPORTS}/${NEW}/download?format=json`,
      `${REPORTS}/${NEW}/download?format=csv`,
      `${REPORTS}/${NEW}/download?format=pdf`,
      `${REPORTS}/${NEW}/download?format=sbom`,
    ]);
    expect(withSbom?.querySelector('a[href$="format=sbom"]')?.textContent?.trim()).toBe('SBOM');
    expect(downloads(without!)).toHaveLength(3);
  });

  it('stops polling when it is destroyed', async () => {
    FakeCompliance.install(server, [
      complianceReport({ id: NEW, status: 'pending', summary: null, sha256: null }),
    ]);
    const { fixture } = await render();
    fixture.destroy();
    current = null;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(server.requestsTo('GET', `${REPORTS}/${NEW}`)).toHaveLength(0);
  });

  it('shows Create report only to those who may, with the main branch chosen', async () => {
    const store = FakeCompliance.install(server, [complianceReport({ id: OLD })]);
    let { root } = await render();
    expect(root.textContent).not.toContain('Create report');
    expect(root.querySelector('select')).toBeNull();

    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
    ({ root } = await render({ canCreate: true }));
    const select = root.querySelector<HTMLSelectElement>('#compliance-target');
    expect(root.querySelector('label[for="compliance-target"]')?.textContent?.trim()).toBe(
      'Target',
    );
    expect([...(select?.options ?? [])].map((o) => o.textContent?.trim())).toEqual([
      'develop',
      'main',
      '2.0.0',
      '1.0.0',
    ]);
    expect([...(select?.querySelectorAll('optgroup') ?? [])].map((g) => g.label)).toEqual([
      'Branches',
      'Versions',
    ]);
    expect(select?.selectedOptions[0]?.textContent?.trim()).toBe('main');

    button(root, 'Create report').click();
    await flush();
    expect(server.requestsTo('POST', REPORTS).map((r) => r.body)).toEqual([
      { projectId: PROJECT, branchId: BRANCHES[1]!.id },
    ]);
    const [first, second] = rows(root);
    expect(first?.dataset['key']).toBe(store.reports[0]?.id);
    expect(first?.querySelector('.badge')?.textContent?.trim()).toBe('Pending');
    expect(second?.dataset['key']).toBe(OLD);

    server.on('POST', REPORTS, { status: 409, body: problem(409, 'NO_ANALYSIS') });
    button(root, 'Create report').click();
    await flush();
    expect(root.querySelector('.compliance-create [role="alert"]')?.textContent?.trim()).toBe(
      'This branch has no successful analysis yet. Analyze it first, then create the report.',
    );
    expect(rows(root)).toHaveLength(2);
  });

  it('creates the report of a chosen version, and shows its label in the list', async () => {
    FakeCompliance.install(server, [complianceReport({ id: OLD })]);
    const { root } = await render({ canCreate: true });
    const select = root.querySelector<HTMLSelectElement>('#compliance-target')!;
    select.selectedIndex = [...select.options].findIndex((o) => o.textContent?.trim() === '1.0.0');
    select.dispatchEvent(new Event('change'));
    await flush();
    button(root, 'Create report').click();
    await flush();
    expect(server.requestsTo('POST', REPORTS).map((r) => r.body)).toEqual([
      { projectId: PROJECT, versionId: VERSIONS[1]!.id },
    ]);
    const [created, old] = rows(root);
    expect(created?.textContent).toContain('1.0.0');
    expect(old?.textContent).toContain('main');
  });

  it('says why a version cannot be reported', async () => {
    FakeCompliance.install(server, []);
    const { root } = await render({ canCreate: true });
    const select = root.querySelector<HTMLSelectElement>('#compliance-target')!;
    select.selectedIndex = [...select.options].findIndex((o) => o.textContent?.trim() === '2.0.0');
    select.dispatchEvent(new Event('change'));
    await flush();
    const alert = () =>
      root.querySelector('.compliance-create [role="alert"]')?.textContent?.trim();
    server.on('POST', REPORTS, { status: 409, body: problem(409, 'MONITORING_OFF') });
    button(root, 'Create report').click();
    await flush();
    expect(alert()).toBe(
      "Vulnerability monitoring is off for this project. Switch it on in the project's settings, then create the report.",
    );
    server.on('POST', REPORTS, { status: 409, body: problem(409, 'NOT_CHECKED') });
    button(root, 'Create report').click();
    await flush();
    expect(alert()).toBe(
      'This version has not been checked for vulnerabilities yet. Create the report after its first check.',
    );
  });

  it('creates an organisation report with a single button', async () => {
    FakeCompliance.install(server, []);
    const { root } = await render({ scope: { organizationId: ORG_ID }, canCreate: true });
    expect(server.requestsTo('GET', REPORTS)[0]?.query.get('organizationId')).toBe(ORG_ID);
    expect(root.querySelector('select')).toBeNull();
    button(root, 'Create report').click();
    await flush();
    expect(server.requestsTo('POST', REPORTS).map((r) => r.body)).toEqual([
      { organizationId: ORG_ID },
    ]);
    expect(rows(root)).toHaveLength(1);
  });

  it('replaces "being built" once the created report is ready, and drops it when one fails', async () => {
    const store = FakeCompliance.install(server, []);
    const { root } = await render({ canCreate: true });
    const status = () => root.querySelector('.compliance-status')?.textContent?.trim();

    button(root, 'Create report').click();
    await flush();
    expect(status()).toBe('The report is being built. It appears here as ready when it is done.');
    // Still pending at the first poll: the message stays.
    await vi.advanceTimersByTimeAsync(3_000);
    await flush();
    expect(status()).toBe('The report is being built. It appears here as ready when it is done.');
    store.complete(store.reports[0]!.id);
    await vi.advanceTimersByTimeAsync(3_000);
    await flush();
    expect(status()).toBe('The report is ready to download.');

    // A failed build: its row says why; the live region no longer says it is being built.
    button(root, 'Create report').click();
    await flush();
    expect(status()).toBe('The report is being built. It appears here as ready when it is done.');
    store.complete(store.reports[0]!.id, {
      status: 'failed',
      error: 'the build failed',
      sha256: null,
      sizeBytes: null,
      summary: null,
    });
    await vi.advanceTimersByTimeAsync(3_000);
    await flush();
    expect(status()).toBe('');
    expect(rows(root)[0]?.querySelector('.badge')?.textContent?.trim()).toBe('Failed');
  });

  it('offers Delete only when the report says so, and deletes after confirmation', async () => {
    const store = FakeCompliance.install(server, [complianceReport({ id: OLD, canDelete: false })]);
    let { root } = await render();
    expect(rows(root)).toHaveLength(1);
    expect(
      [...root.querySelectorAll('button')].some((b) => b.textContent?.includes('Delete')),
    ).toBe(false);

    store.reports[0] = complianceReport({ id: OLD, canDelete: true });
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
    ({ root } = await render());
    rows(root)[0]!.querySelector<HTMLButtonElement>('button.row-delete')!.click();
    await flush();
    const dialog = root.querySelector('dialog');
    expect(dialog?.hasAttribute('open')).toBe(true);
    expect(server.requestsTo('DELETE', `${REPORTS}/${OLD}`)).toHaveLength(0);

    dialog!.querySelector<HTMLButtonElement>('.btn-danger-solid')!.click();
    await flush();
    expect(server.requestsTo('DELETE', `${REPORTS}/${OLD}`)).toHaveLength(1);
    expect(rows(root)).toHaveLength(0);
    expect(store.reports).toHaveLength(0);
  });

  it('previews a ready report: a standard switcher, the categories, Not mapped and the counts', async () => {
    const summary = complianceSummary({
      standards: [
        ...complianceSummary().standards,
        {
          id: 'cwe-top25-2025',
          categories: [
            {
              id: 'CWE-79',
              title: 'Cross-site Scripting',
              open: 4,
              bySeverity: { blocker: 0, high: 0, medium: 4, low: 0, info: 0 },
              inNewCode: 0,
              rules: 2,
              oldestFirstSeenAt: null,
            },
          ],
          notMapped: {
            open: 0,
            bySeverity: { blocker: 0, high: 0, medium: 0, low: 0, info: 0 },
            inNewCode: 0,
            rules: 0,
          },
          distinctTotal: 4,
        },
      ],
      secrets: { open: 5 },
      dependencies: { open: 6, bySeverity: { blocker: 0, high: 6, medium: 0, low: 0, info: 0 } },
      triage: { falsePositive: 7, wontFix: 8 },
      truncated: true,
    });
    const report: ComplianceReport = complianceReport({
      id: OLD,
      standards: [
        { id: 'owasp-top10-2021', version: '2021', sourceSha256: '1'.repeat(64) },
        { id: 'cwe-top25-2025', version: '2025', sourceSha256: '2'.repeat(64) },
      ],
      summary,
    });
    FakeCompliance.install(server, [report]);
    const { root } = await render();
    expect(root.querySelector('.compliance-preview')).toBeNull();

    button(rows(root)[0]!, 'Summary').click();
    await flush();
    const preview = root.querySelector<HTMLElement>('.compliance-preview')!;
    const switcher = [...preview.querySelectorAll('.segmented button')];
    expect(switcher.map((b) => b.textContent?.trim())).toEqual([
      'OWASP Top 10 2021',
      'CWE Top 25 2025',
    ]);
    expect(switcher[0]?.getAttribute('aria-pressed')).toBe('true');
    // The preview is named by its heading; its scrolling table by the table's caption.
    expect(labelOf(root, preview)).toBe('Summary');
    expect(labelOf(root, preview.querySelector('.panel-scroll'))).toBe(
      'Open findings by category of OWASP Top 10 2021',
    );
    const categoryRows = () =>
      [...preview.querySelectorAll('.compliance-categories tbody tr')].map(cellTexts);
    expect(categoryRows()[0]?.slice(0, 9)).toEqual([
      'A03',
      'Injection',
      '2',
      '0',
      '2',
      '0',
      '0',
      '0',
      '1',
    ]);
    expect(categoryRows().at(-1)?.slice(0, 3)).toEqual(['', 'Not mapped', '1']);

    (switcher[1] as HTMLButtonElement).click();
    await flush();
    expect(categoryRows()[0]?.slice(0, 3)).toEqual(['CWE-79', 'Cross-site Scripting', '4']);
    expect(categoryRows()).toHaveLength(2);

    const facts = preview.querySelector('.compliance-counts')?.textContent ?? '';
    for (const n of ['5', '6', '7', '8']) expect(facts).toContain(n);
    expect(preview.querySelector('.compliance-truncated')?.textContent).toContain(
      'This report holds the first 50 000 findings',
    );
  });

  it('says when there is no report yet', async () => {
    FakeCompliance.install(server, []);
    const { root } = await render();
    expect(root.querySelector('.empty-state')?.textContent?.trim()).toBe(
      'No compliance reports yet.',
    );
    expect(root.querySelector('table')).toBeNull();
  });
});

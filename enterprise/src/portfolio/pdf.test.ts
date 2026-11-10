// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs';
import type { PortfolioProjectRow } from '@qualor/server/plugin-contract';
import { RenderTimeoutError } from '../pdf/layout';
import { PDF_PROJECTS_MAX, renderPortfolioPdf } from './pdf';
import { sampleOverview, sampleRow, sampleRows } from './test-overview';

const OPTIONS = { generatedBy: 'Ann Admin', serverVersion: '0.7.1' };

async function textOf(pdf: Buffer): Promise<string> {
  const doc = await getDocument({ data: new Uint8Array(pdf), useSystemFonts: false }).promise;
  let text = '';
  for (let i = 1; i <= doc.numPages; i++) {
    const page = await doc.getPage(i);
    text +=
      (await page.getTextContent()).items.map((it) => ('str' in it ? it.str : '')).join(' ') + '\n';
  }
  return text;
}

describe('renderPortfolioPdf (4E-2 §3)', () => {
  it('renders the cover, totals, trend, organisations and attention lists', async () => {
    const overview = sampleOverview();
    const pdf = await renderPortfolioPdf(overview, sampleRows(), OPTIONS);
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
    const text = await textOf(pdf);
    // The cover.
    expect(text).toContain('Qualor portfolio report');
    expect(text).toContain('All organisations');
    expect(text).toContain('Ann Admin');
    expect(text).toContain('0.7.1');
    expect(text).toContain('Weekly');
    // The totals: grouped lines of code, one-decimal percentages.
    expect(text).toContain('12 345');
    expect(text).toContain('71.3%');
    expect(text).toContain('50.0%');
    // The trend: week start dates as the period labels.
    expect(text).toContain('2026-07-27');
    expect(text).toContain('2026-10-12');
    // The organisations, the attention lists and the project list.
    expect(text).toContain('Mobile apps');
    expect(text).toContain('Platform team');
    expect(text).toContain('Failing quality gates');
    expect(text).toContain('Abandoned projects');
    expect(text).toContain('Project 2 (proj-002)');
    // Header and footer: the footer id is generatedAt.
    expect(text).toMatch(/Page 1 of \d+ · 2026-10-13T09:30:00\.000Z/);
    // A null prints as a dash; ligatures are off.
    expect(text).toContain('—');
    const raw = pdf.toString('latin1');
    expect(raw).not.toContain('Helvetica');
    const doc = await getDocument({ data: new Uint8Array(pdf), useSystemFonts: false }).promise;
    expect((await doc.getMetadata()).info).toMatchObject({ CreationDate: 'D:20261013093000Z' });
  });

  it('shows the vulnerable releases and the exploited vulnerabilities, the exploited list first', async () => {
    const text = await textOf(await renderPortfolioPdf(sampleOverview(), sampleRows(), OPTIONS));
    expect(text).toMatch(/Vulnerable +releases/);
    expect(text).toContain('Exploited vulnerabilities');
    const attention = text.indexOf('Projects that need attention');
    expect(attention).toBeGreaterThan(-1);
    const exploited = text.indexOf('Exploited vulnerabilities', attention);
    expect(exploited).toBeGreaterThan(attention);
    expect(exploited).toBeLessThan(text.indexOf('Failing quality gates', attention));
  });

  it('keeps Lines of code and Coverage in the project table', async () => {
    const text = await textOf(await renderPortfolioPdf(sampleOverview(), sampleRows(), OPTIONS));
    const start = text.indexOf('3 projects, by quality gate');
    const head = text.slice(start, text.indexOf('Projects with vulnerable releases', start));
    expect(head).toMatch(/Lines of code/);
    expect(head).toMatch(/Coverage/);
    expect(head).not.toMatch(/Vulnerable/);
  });

  describe('Projects with vulnerable releases', () => {
    const OPTS = OPTIONS;
    const section = async (
      overview: ReturnType<typeof sampleOverview>,
      rows: PortfolioProjectRow[],
      vulnerable?: PortfolioProjectRow[],
    ): Promise<string> => {
      const text = await textOf(
        await renderPortfolioPdf(overview, rows, {
          ...OPTS,
          ...(vulnerable ? { vulnerable } : {}),
        }),
      );
      return text.slice(text.lastIndexOf('Projects with vulnerable releases'));
    };

    it('lists the right projects: exploited, then vulnerable releases, then key', async () => {
      const rows = [
        sampleRow(1, { vulnerableReleases: 5, exploited: 0 }),
        sampleRow(2, { vulnerableReleases: 1, exploited: 3 }),
        sampleRow(3, { vulnerableReleases: 2, exploited: 3 }),
        sampleRow(4, { vulnerableReleases: 0, exploited: 0 }),
        sampleRow(5, { vulnerableReleases: null, exploited: null }),
        sampleRow(6, { vulnerableReleases: 5, exploited: 0 }),
        sampleRow(7, { vulnerableReleases: 0, exploited: 1 }),
      ];
      const text = await section(sampleOverview(), rows);
      const order = ['proj-003', 'proj-002', 'proj-007', 'proj-001', 'proj-006'].map((k) =>
        text.indexOf(`(${k})`),
      );
      expect(order.every((i) => i > -1)).toBe(true);
      expect([...order].sort((a, b) => a - b)).toEqual(order);
      expect(text).not.toContain('(proj-004)');
      expect(text).not.toContain('(proj-005)');
    });

    it('orders by vulnerable releases alone, and skips exploited-only rows, without priority', async () => {
      const overview = sampleOverview();
      overview.attention.exploited = null;
      const rows = [
        sampleRow(1, { vulnerableReleases: 1, exploited: null }),
        sampleRow(2, { vulnerableReleases: 4, exploited: null }),
        sampleRow(3, { vulnerableReleases: 0, exploited: 9 }),
      ];
      const text = await section(overview, rows);
      expect(text.indexOf('(proj-002)')).toBeGreaterThan(-1);
      expect(text.indexOf('(proj-002)')).toBeLessThan(text.indexOf('(proj-001)'));
      expect(text).not.toContain('(proj-003)');
      expect(text).not.toContain('Exploited');
    });

    it('caps the list at 50 and says how many more there are', async () => {
      const rows = Array.from({ length: 53 }, (_, i) =>
        sampleRow(i, { vulnerableReleases: 1, exploited: 0 }),
      );
      const text = await section(sampleOverview(), rows);
      expect(text).toContain('(proj-049)');
      expect(text).not.toContain('(proj-050)');
      expect(text).toContain('…and 3 more.');
    });

    it('uses the given candidates rather than the first 50 rows', async () => {
      const text = await section(sampleOverview(), sampleRows(), [
        sampleRow(90, { vulnerableReleases: 4, exploited: 0 }),
      ]);
      expect(text).toContain('(proj-090)');
    });

    it('says so when no project has a vulnerable release', async () => {
      const rows = sampleRows().map((r) => ({ ...r, vulnerableReleases: 0, exploited: 0 }));
      const text = await section(sampleOverview(), rows);
      expect(text).toContain('No project has a vulnerable release.');
    });

    it('says monitoring is off, not that no project is vulnerable, when the total is null', async () => {
      const overview = sampleOverview();
      overview.totals.vulnerableReleases = null;
      overview.totals.exploited = null;
      const rows = sampleRows().map((r) => ({ ...r, vulnerableReleases: null, exploited: null }));
      const text = await section(overview, rows);
      expect(text).toContain('Vulnerability monitoring is off.');
      expect(text).not.toContain('No project has a vulnerable release.');
    });

    it('names the exploited vulnerabilities in the heading with priority only', async () => {
      const heading = 'Projects with vulnerable releases or exploited vulnerabilities';
      const rows = [sampleRow(1, { vulnerableReleases: 1, exploited: 1 })];
      expect(await section(sampleOverview(), rows)).toContain(heading);
      const plain = sampleOverview();
      plain.attention.exploited = null;
      const text = await section(plain, rows);
      expect(text).toContain('Projects with vulnerable releases');
      expect(text).not.toContain('exploited');
    });

    it('has no Organisation column in the organisation scope', async () => {
      const text = await section(sampleOverview('organization'), [sampleRow(1)]);
      expect(text).not.toContain('Organisation');
    });
  });

  it('prints nothing about exploited vulnerabilities without vuln.priority', async () => {
    const overview = sampleOverview();
    overview.attention.exploited = null;
    overview.totals.exploited = null;
    const rows = sampleRows().map((r) => ({ ...r, exploited: null }));
    const text = await textOf(await renderPortfolioPdf(overview, rows, OPTIONS));
    expect(text).toMatch(/Vulnerable +releases/);
    expect(text).toContain('Projects with vulnerable releases');
    expect(text).not.toContain('Exploited');
    expect(text).not.toContain('exploited');
    const again = await renderPortfolioPdf(overview, rows, OPTIONS);
    expect(again.equals(await renderPortfolioPdf(overview, rows, OPTIONS))).toBe(true);
  });

  it('is byte-identical across renders of the same input', async () => {
    const a = await renderPortfolioPdf(sampleOverview(), sampleRows(), OPTIONS);
    const b = await renderPortfolioPdf(sampleOverview(), sampleRows(), OPTIONS);
    expect(a.equals(b)).toBe(true);
  });

  it('has no organisations table in the organisation scope', async () => {
    const rows = sampleRows().filter((r) => r.organization.key === 'platform');
    const text = await textOf(
      await renderPortfolioPdf(sampleOverview('organization'), rows, OPTIONS),
    );
    expect(text).toContain('Organisation Platform team (platform)');
    expect(text).not.toContain('Mobile apps');
    expect(text).not.toContain('Organisations');
  });

  it('lists the first 50 projects and says the CSV has them all', async () => {
    const overview = sampleOverview();
    overview.totals.projects = 60;
    const rows = Array.from({ length: 60 }, (_, i) => sampleRow(i));
    const text = await textOf(await renderPortfolioPdf(overview, rows, OPTIONS));
    expect(PDF_PROJECTS_MAX).toBe(50);
    expect(text).toContain('The first 50 of 60 projects');
    expect(text).toContain('The CSV export lists every project.');
    expect(text).toContain('(proj-049)');
    expect(text).not.toContain('(proj-050)');
  });

  it('prints Cyrillic in a project name', async () => {
    const rows = sampleRows();
    rows[0]!.project.name = 'Платёжный шлюз';
    const text = await textOf(await renderPortfolioPdf(sampleOverview(), rows, OPTIONS));
    expect(text).toContain('Платёжный шлюз');
  });

  it('labels a monthly trend by month', async () => {
    const overview = sampleOverview();
    overview.granularity = 'month';
    const text = await textOf(await renderPortfolioPdf(overview, sampleRows(), OPTIONS));
    expect(text).toContain('Monthly');
    expect(text).toContain('2026-07');
    expect(text).not.toContain('2026-07-27');
  });

  it('stops at the deadline', async () => {
    await expect(
      renderPortfolioPdf(sampleOverview(), sampleRows(), { ...OPTIONS, deadline: Date.now() - 1 }),
    ).rejects.toBeInstanceOf(RenderTimeoutError);
  });

  describe('with a clock that ticks once per reading', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    /** Date.now() returns 0, 1, 2, …; `calls()` says how many readings were taken. */
    function tickingClock(): { calls: () => number } {
      let ticks = 0;
      vi.spyOn(Date, 'now').mockImplementation(() => ticks++);
      return { calls: () => ticks };
    }

    /** Fifty project rows without vulnerabilities, so the project table is the last long table. */
    function fiftyRows(): PortfolioProjectRow[] {
      return Array.from({ length: 50 }, (_, i) =>
        sampleRow(i, { vulnerableReleases: 0, exploited: 0 }),
      );
    }

    it('stops when the deadline passes in the middle of the project table', async () => {
      const overview = sampleOverview();
      overview.totals.projects = 50;
      const readings = async (projects: PortfolioProjectRow[]): Promise<number> => {
        const clock = tickingClock();
        await renderPortfolioPdf(overview, projects, { ...OPTIONS, deadline: Infinity });
        vi.restoreAllMocks();
        return clock.calls();
      };
      // Every section start and every table row reads the clock once; the project table, the last
      // thing that does, accounts for the last 50 readings.
      const total = await readings(fiftyRows());
      expect(total - (await readings([]))).toBe(50);
      // With a deadline 10 readings before the end, the 42nd row's reading is the first past it.
      const clock = tickingClock();
      await expect(
        renderPortfolioPdf(overview, fiftyRows(), { ...OPTIONS, deadline: total - 10 }),
      ).rejects.toBeInstanceOf(RenderTimeoutError);
      expect(clock.calls()).toBe(total - 8);
    });
  });
});

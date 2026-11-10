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
    expect(text.indexOf('Exploited vulnerabilities')).toBeLessThan(
      text.indexOf('Failing quality gates'),
    );
    expect(text).toContain('Exploited');
  });

  it('prints nothing about exploited vulnerabilities without vuln.priority', async () => {
    const overview = sampleOverview();
    overview.attention.exploited = null;
    overview.totals.exploited = null;
    const rows = sampleRows().map((r) => ({ ...r, exploited: null }));
    const text = await textOf(await renderPortfolioPdf(overview, rows, OPTIONS));
    expect(text).toMatch(/Vulnerable +releases/);
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

    /** Fifty project rows, enough for the project table to span pages. */
    function fiftyRows(): PortfolioProjectRow[] {
      return Array.from({ length: 50 }, (_, i) => sampleRow(i));
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

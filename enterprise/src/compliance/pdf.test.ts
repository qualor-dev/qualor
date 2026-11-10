// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs';
import { defaultFontsDir } from '../pdf/fonts';
import { RenderTimeoutError } from '../pdf/layout';
import { PDF_FINDINGS_MAX, renderPdf } from './pdf';
import { parseCanonical } from './assemble';
import { dependencyReport, sampleReport, sampleReportV1, versionReport } from './test-report';

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

describe('renderPdf (4E-1 §2.5)', () => {
  it('renders a PDF that carries the sha256 and the category titles', async () => {
    const report = sampleReport();
    const pdf = await renderPdf(report);
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
    const text = await textOf(pdf);
    expect(text).toContain(report.id);
    expect(text).toContain('Injection');
    expect(text).toMatch(/Page 1 of \d+/);
    // The cover names the SHA-256 of the canonical JSON, the bytes of the JSON export.
    expect(text).toContain(createHash('sha256').update(JSON.stringify(report)).digest('hex'));
    // No ligatures: copied or searched text keeps every letter ("fi" stays two).
    expect(text).toContain('Open findings in new code');
    // Only the embedded Noto Sans: the built-in Helvetica cannot print Cyrillic.
    const raw = pdf.toString('latin1');
    expect(raw).not.toContain('Helvetica');
    expect(raw.match(/\/BaseFont \/[A-Z]{6}\+NotoSans-(Regular|Bold)/g)?.length).toBeGreaterThan(0);
  });

  it('says on the cover that a version report holds its dependencies only', async () => {
    const text = (await textOf(await renderPdf(versionReport()))).replace(/\s+/g, ' ');
    expect(text).toContain(
      'Version 2.0.0. A version has no code analysis, so this report holds its dependencies only.',
    );
    expect(text).not.toContain('branch main');
    expect(await textOf(await renderPdf(sampleReport()))).not.toContain('A version has no code');
  });

  it('shows only the dependencies in the executive summary of a version report', async () => {
    const whole = (await textOf(await renderPdf(versionReport()))).replace(/\s+/g, ' ');
    const text = whole.slice(whole.indexOf('Executive summary'), whole.indexOf(' Projects '));
    expect(text).toContain('Dependencies');
    expect(text).not.toContain('All findings');
    expect(text).not.toContain('Open secrets');
    expect(text).not.toContain('Open findings in new code');
    expect(await textOf(await renderPdf(sampleReport()))).toContain('All findings');
  });

  it('lists the dataset dates on the cover', async () => {
    const text = await textOf(await renderPdf(dependencyReport()));
    expect(text).toContain('Vulnerability database built');
    expect(text).toContain('2026-05-31');
    expect(text).toContain('KEV refreshed');
    expect(text).toContain('2026-06-01');
    expect(text).toContain('EPSS data of');
  });

  it('leaves a missing dataset out of the cover', async () => {
    const text = await textOf(await renderPdf(sampleReport()));
    expect(text).toContain('Vulnerability database built');
    expect(text).not.toContain('KEV refreshed');
    expect(text).not.toContain('EPSS data of');
  });

  it('shows the fixed versions, KEV date and EPSS percentile of each dependency finding', async () => {
    const text = await textOf(await renderPdf(dependencyReport()));
    expect(text).toContain('Fixed in');
    expect(text).toContain('3.10.2, 4.17.21');
    expect(text).toContain('KEV');
    expect(text).toContain('2026-03-05');
    expect(text).toContain('EPSS');
    expect(text).toContain('42.0%');
    expect(text).toContain('2 open dependency findings.');
    expect(text).toContain('left-pad');
  });

  it('prints a dash for the package of a finding without facts', async () => {
    const report = dependencyReport();
    report.findings.find((f) => f.id === 'd2')!.vulnerability = null;
    const text = await textOf(await renderPdf(report));
    expect(text).not.toContain('left-pad');
    expect(text).not.toContain('Dependency ');
  });

  it('prints a tiny EPSS score as below 0.1%', async () => {
    const report = dependencyReport();
    report.findings.find((f) => f.id === 'd1')!.vulnerability!.epss = {
      score: 0.0004,
      percentile: 0.2,
    };
    expect(await textOf(await renderPdf(report))).toContain('<0.1%');
  });

  it('leaves the build time out of the cover when the dataset has none', async () => {
    const report = sampleReport();
    report.datasets.vulnerabilityDatabase = { builtAt: null, digest: 'sha256:x' };
    expect(await textOf(await renderPdf(report))).not.toContain('Vulnerability database built');
  });

  it('caps the dependency table and says where the rest is', async () => {
    const report = dependencyReport();
    const base = report.findings.find((f) => f.id === 'd1')!;
    report.findings = Array.from({ length: PDF_FINDINGS_MAX + 5 }, (_, i) => ({
      ...base,
      id: `d${i}`,
      vulnerability: { ...base.vulnerability!, packageName: `pkg-${i}` },
    }));
    report.summary.findings.total = report.findings.length;
    report.summary.dependencies.open = report.findings.length;
    const text = await textOf(await renderPdf(report));
    expect(text).toContain(
      `The first ${PDF_FINDINGS_MAX} of ${PDF_FINDINGS_MAX + 5} open dependency findings.`,
    );
    expect(text).toContain(`pkg-${PDF_FINDINGS_MAX - 1} `);
    expect(text).not.toContain(`pkg-${PDF_FINDINGS_MAX} `);
  }, 120_000);

  it('leaves the KEV and EPSS columns out without priority', async () => {
    const report = dependencyReport();
    report.datasets.kev = null;
    report.datasets.epss = null;
    for (const f of report.findings) {
      if (f.vulnerability) f.vulnerability = { ...f.vulnerability, kev: null, epss: null };
    }
    const text = await textOf(await renderPdf(report));
    expect(text).toContain('Fixed in');
    expect(text).not.toContain('KEV');
    expect(text).not.toContain('EPSS');
  });

  it('shows the reason of a triaged dependency finding with the UI label', async () => {
    const text = await textOf(await renderPdf(dependencyReport()));
    expect(text).toContain('Reason');
    expect(text).toContain('The vulnerable code is never called');
  });

  it('renders a stored version 1 report', async () => {
    const v1 = parseCanonical(Buffer.from(JSON.stringify(sampleReportV1())));
    const pdf = await renderPdf(v1);
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
    expect(await textOf(pdf)).not.toContain('KEV refreshed');
  });

  it('is byte-identical across renders of a report with dependency facts', async () => {
    const a = await renderPdf(dependencyReport());
    const b = await renderPdf(dependencyReport());
    expect(a.equals(b)).toBe(true);
  });

  it('is byte-identical across renders of the same report', async () => {
    const a = await renderPdf(sampleReport());
    const b = await renderPdf(sampleReport());
    expect(a.equals(b)).toBe(true);
  });

  it('prints Cyrillic, survives CJK, very long text and missing path or line (Review Focus 3)', async () => {
    const report = sampleReport();
    report.findings[0]!.message = 'Небезопасный SQL-запрос ' + 'x'.repeat(10_000);
    report.findings[1]!.message = 'SQL 注入';
    report.findings[1]!.path = null;
    report.findings[1]!.line = null;
    const text = await textOf(await renderPdf(report));
    expect(text).toContain('Небезопасный');
  });

  it('caps the findings list and says where the rest is', async () => {
    const report = sampleReport();
    const base = report.findings[0]!;
    report.findings = Array.from({ length: PDF_FINDINGS_MAX + 5 }, (_, i) => ({
      ...base,
      id: `f${i}`,
      path: `finding-${i}.ts`,
      line: i + 1,
    }));
    report.summary.findings.total = report.findings.length;
    const text = await textOf(await renderPdf(report));
    expect(text).toContain(
      `The first ${PDF_FINDINGS_MAX} of ${PDF_FINDINGS_MAX + 5} open findings`,
    );
    expect(text).toContain('The full list is in the CSV and JSON exports');
    // Rows 1 to 2 000 are listed; the 2 001st is not.
    expect(text).toContain(`finding-${PDF_FINDINGS_MAX - 1}.ts`);
    expect(text).not.toContain(`finding-${PDF_FINDINGS_MAX}.ts`);
  }, 60_000);

  it('caps the triage table at the newest decisions and says where the rest is (ruling R8)', async () => {
    const report = sampleReport();
    const base = report.triage[0]!;
    report.triage = Array.from({ length: PDF_FINDINGS_MAX + 5 }, (_, i) => ({
      ...base,
      id: `t${i}`,
      path: `decision-${i}.ts`,
    }));
    report.summary.triage.falsePositive = report.triage.length;
    const text = await textOf(await renderPdf(report));
    const note = 'The full list is in the CSV and JSON exports';
    expect(text).toContain(`decision-${PDF_FINDINGS_MAX - 1}.ts`);
    expect(text).not.toContain(`decision-${PDF_FINDINGS_MAX}.ts`);
    // The note follows the triage table, before the findings section (2 findings: no note there).
    const at = text.indexOf(note);
    expect(at).toBeGreaterThan(text.indexOf(`decision-${PDF_FINDINGS_MAX - 1}.ts`));
    expect(at).toBeLessThan(text.indexOf('open findings, by severity'));
    expect(text.indexOf(note, at + 1)).toBe(-1);
  }, 60_000);

  it('gives the exact totals of a truncated snapshot and says the exports are cut too', async () => {
    const report = sampleReport();
    report.findings[1]!.section = 'secret';
    report.summary.truncated = true;
    report.summary.findings.total = 123_456;
    report.summary.triage = { falsePositive: 60_000, wontFix: 7 };
    const text = await textOf(await renderPdf(report));
    expect(text).toContain('The first 2 of 123456 open findings, by severity.');
    expect(text).toContain('The newest 1 of 60007 decisions.');
    const note = 'The JSON and CSV exports list the first 50 000; all counts are exact.';
    // Under the triage table and under the findings list.
    expect(text.split(note)).toHaveLength(3);
    expect(text).not.toContain('The full list is in the CSV and JSON exports.');
    // The per-rule tables are built from the listed findings only.
    expect(text).toContain('Rules among the listed findings');
  });

  it('says on each standard page that a finding can count in more than one category', async () => {
    const text = await textOf(await renderPdf(sampleReport()));
    expect(text).toContain(
      'A finding can count in more than one category; the total counts each finding once.',
    );
    // Not truncated: no label on the per-rule tables, no truncated note.
    expect(text).not.toContain('Rules among the listed findings');
    expect(text).not.toContain('all counts are exact');
  });

  it('prints the stored sha256 when the caller gives it (ruling R9)', async () => {
    const report = sampleReport();
    const sha256 = 'ab'.repeat(32);
    const pdf = await renderPdf(report, { sha256 });
    const text = await textOf(pdf);
    expect(text).toContain(sha256);
    expect(text).not.toContain(createHash('sha256').update(JSON.stringify(report)).digest('hex'));
    expect(pdf.toString('latin1')).toContain(`SHA-256 ${sha256}`);
  });

  it('stops at the deadline', async () => {
    await expect(renderPdf(sampleReport(), { deadline: Date.now() - 1 })).rejects.toBeInstanceOf(
      RenderTimeoutError,
    );
  });

  it('finds the fonts next to the plugin in the image, in a local build and from the source', () => {
    const enterprise = fileURLToPath(new URL('../../', import.meta.url));
    const fonts = path.join(enterprise, 'fonts');
    expect(path.resolve(defaultFontsDir())).toBe(path.resolve(fonts));
    expect(
      path.resolve(defaultFontsDir(pathToFileURL(path.join(enterprise, 'dist', 'plugin.js')))),
    ).toBe(path.resolve(fonts));
    // The image: /app/enterprise/plugin.js next to /app/enterprise/fonts/.
    const app = mkdtempSync(path.join(tmpdir(), 'qualor-fonts-'));
    try {
      mkdirSync(path.join(app, 'enterprise', 'fonts'), { recursive: true });
      copyFileSync(
        path.join(fonts, 'NotoSans-Regular.ttf'),
        path.join(app, 'enterprise', 'fonts', 'NotoSans-Regular.ttf'),
      );
      const plugin = pathToFileURL(path.join(app, 'enterprise', 'plugin.js'));
      expect(path.resolve(defaultFontsDir(plugin))).toBe(path.join(app, 'enterprise', 'fonts'));
      expect(() => defaultFontsDir(pathToFileURL(path.join(app, 'plugin.js')))).toThrow(
        /NotoSans-Regular\.ttf/,
      );
    } finally {
      rmSync(app, { recursive: true, force: true });
    }
  });
});

describe('the PDF fonts (4E-1 C3)', () => {
  it('are the files enterprise/fonts/SOURCES.md records, byte for byte', () => {
    const fonts = fileURLToPath(new URL('../../fonts/', import.meta.url));
    const rows = [
      ...readFileSync(path.join(fonts, 'SOURCES.md'), 'utf8').matchAll(
        /^\| `([^`]+)` +\| `[^`]+` +\| `([0-9a-f]{64})` \|$/gm,
      ),
    ];
    expect(rows.map((r) => r[1])).toEqual(['NotoSans-Regular.ttf', 'NotoSans-Bold.ttf', 'OFL.txt']);
    for (const [, file, sha256] of rows) {
      const actual = createHash('sha256')
        .update(readFileSync(path.join(fonts, file!)))
        .digest('hex');
      expect(actual, file).toBe(sha256);
    }
  });
});

// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
// Test-only fixture: never imported from plugin.ts's graph, so never bundled.
import type { ReportFinding, ReportJson, ReportTriage, SeverityCounts } from './report';

const counts = (high: number): SeverityCounts => ({
  blocker: 0,
  high,
  medium: 0,
  low: 0,
  info: 0,
});

/** A fresh, valid project-scope report with two open findings and one triage row. */
export function sampleReport(): ReportJson {
  const finding = (id: string, path: string, line: number, firstSeenAt: string): ReportFinding => ({
    id,
    project: 'alpha',
    path,
    line,
    rule: 'semgrep:sqli',
    ruleName: 'SQLi',
    engine: 'semgrep',
    severity: 'high',
    kind: 'issue',
    cwe: [89],
    message: 'SQL injection',
    categories: { s: ['A', 'B'] },
    inNewCode: true,
    firstSeenAt,
    section: 'code',
    vulnerability: null,
  });
  const category = (id: string, title: string) => ({
    id,
    title,
    open: 2,
    bySeverity: counts(2),
    inNewCode: 2,
    rules: 1,
    oldestFirstSeenAt: '2026-01-01T00:00:00.000Z',
  });
  return {
    schemaVersion: 2,
    id: '0b6f1c1e-5d3a-4a8e-9f2b-7c1d2e3f4a5b',
    generatedAt: '2026-06-01T12:00:00.000Z',
    generatedBy: 'ann@example.test',
    server: { version: '0.7.0' },
    scope: {
      kind: 'project',
      organization: { id: 'org-1', name: 'Acme' },
      project: { id: 'p-1', key: 'alpha', name: 'Alpha' },
      branch: { id: 'b-1', name: 'main' },
    },
    standards: [
      {
        id: 's',
        version: '1',
        title: 'Sample standard',
        source: 'https://example.test/s',
        licence: 'CC-BY-4.0',
        sourceSha256: '0'.repeat(64),
      },
    ],
    datasets: {
      vulnerabilityDatabase: {
        builtAt: '2026-05-31T06:00:00.000Z',
        digest: 'sha256:' + 'a'.repeat(64),
      },
      kev: null,
      epss: null,
    },
    projects: [
      {
        id: 'p-1',
        key: 'alpha',
        name: 'Alpha',
        branch: 'main',
        analysis: {
          id: 'an-3',
          date: '2026-05-30T08:00:00.000Z',
          revision: 'abc1234',
          versionLabel: '1.2.0',
        },
        gate: {
          status: 'failed',
          failedConditions: [{ metric: 'security_issues', op: 'gt', threshold: 0, actual: 2 }],
        },
        trend: [
          {
            analysisId: 'an-1',
            date: '2026-05-01T08:00:00.000Z',
            security_issues: 5,
            security_rating: 4,
          },
          {
            analysisId: 'an-2',
            date: '2026-05-15T08:00:00.000Z',
            security_issues: 3,
            security_rating: 3,
          },
          {
            analysisId: 'an-3',
            date: '2026-05-30T08:00:00.000Z',
            security_issues: 2,
            security_rating: 3,
          },
        ],
      },
    ],
    summary: {
      findings: { total: 2, bySeverity: counts(2), inNewCode: 2 },
      standards: [
        {
          id: 's',
          categories: [category('A', 'Injection'), category('B', 'Secrets')],
          notMapped: { open: 0, bySeverity: counts(0), inNewCode: 0, rules: 0 },
          distinctTotal: 2,
        },
      ],
      secrets: { open: 0 },
      dependencies: { open: 0, bySeverity: counts(0) },
      triage: { falsePositive: 1, wontFix: 0 },
      truncated: false,
    },
    findings: [
      finding('f1', 'a.ts', 1, '2026-01-01T00:00:00.000Z'),
      finding('f2', 'b.ts', 2, '2026-01-02T00:00:00.000Z'),
    ],
    triage: [
      {
        id: 't1',
        project: 'alpha',
        path: 'c.ts',
        line: 3,
        rule: 'semgrep:sqli',
        severity: 'high',
        cwe: [89],
        categories: { s: ['A', 'B'] },
        status: 'false_positive',
        section: 'code',
        by: 'Ann',
        at: '2026-05-01T00:00:00.000Z',
        comment: 'not reachable, see "ADR-7"',
        reason: null,
        vulnerability: null,
      },
    ],
  };
}

/**
 * The sample with the server's facts: a dependency finding with KEV and EPSS, one without either,
 * and a dependency triage row with a reason; the KEV and EPSS datasets are present.
 */
export function dependencyReport(): ReportJson {
  const report = sampleReport();
  const [first] = report.findings as [ReportFinding];
  const [firstTriage] = report.triage as [ReportTriage];
  report.datasets.kev = { refreshedAt: '2026-06-01T05:00:00.000Z', digest: 'sha256:kev' };
  report.datasets.epss = {
    dataDate: '2026-05-31',
    refreshedAt: '2026-06-01T05:30:00.000Z',
    digest: 'sha256:epss',
  };
  const dep = (id: string, vulnerability: ReportFinding['vulnerability']): ReportFinding => ({
    ...first,
    id,
    path: 'package-lock.json',
    line: null,
    rule: `trivy:${vulnerability?.id ?? 'CVE-2026-0099'}`,
    ruleName: 'Dependency',
    engine: 'trivy',
    section: 'dependency',
    vulnerability,
  });
  report.findings.push(
    dep('d1', {
      id: 'CVE-2026-0001',
      packageName: 'lodash',
      fixedVersions: ['3.10.2', '4.17.21'],
      kev: { dateAdded: '2026-03-05' },
      epss: { score: 0.42, percentile: 0.973 },
    }),
    dep('d2', {
      id: 'CVE-2026-0002',
      packageName: 'left-pad',
      fixedVersions: [],
      kev: null,
      epss: null,
    }),
  );
  report.summary.findings.total = 4;
  report.summary.dependencies.open = 2;
  report.triage.push({
    ...firstTriage,
    id: 't2',
    path: 'package-lock.json',
    line: null,
    rule: 'trivy:CVE-2026-0004',
    section: 'dependency',
    reason: 'vulnerable_code_not_in_execute_path',
    vulnerability: {
      id: 'CVE-2026-0004',
      packageName: 'minimist',
      fixedVersions: ['1.2.6'],
      kev: null,
      epss: null,
    },
  });
  report.summary.triage.falsePositive = 2;
  return report;
}

/** A report as version 1 stored it: no dataset dates, vulnerability facts or reasons. */
export function sampleReportV1(): unknown {
  const report = sampleReport();
  const strip = (row: object, keys: string[]): object =>
    Object.fromEntries(Object.entries(row).filter(([key]) => !keys.includes(key)));
  return {
    ...strip(report, ['datasets']),
    schemaVersion: 1,
    findings: report.findings.map((f) => strip(f, ['vulnerability'])),
    triage: report.triage.map((t) => strip(t, ['reason', 'vulnerability'])),
  };
}

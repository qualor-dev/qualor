// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { CSV_BOM, csvLine as line } from '../csv';
import type { ReportJson, ReportVulnerability } from './report';

/** The vulnerability columns, empty when the finding has no facts. */
const vulnerabilityCells = (v: ReportVulnerability | null): (string | number | null)[] => [
  v?.id ?? null,
  v ? v.fixedVersions.join(';') : null,
  v?.kev?.dateAdded ?? null,
  v?.epss?.score ?? null,
  v?.epss?.percentile ?? null,
];

export function* csvRows(report: ReportJson): Generator<string> {
  const ids = report.standards.map((s) => s.id);
  yield CSV_BOM +
    line([
      'section',
      'project',
      'path',
      'line',
      'rule',
      'rule_name',
      'engine',
      'severity',
      'kind',
      'cwe',
      'status',
      'in_new_code',
      'first_seen_at',
      ...ids,
      'triage_by',
      'triage_at',
      'triage_comment',
      'triage_reason',
      'vulnerability_id',
      'fixed_versions',
      'kev_date_added',
      'epss_score',
      'epss_percentile',
    ]);
  for (const f of report.findings) {
    yield line([
      f.section,
      f.project,
      f.path,
      f.line,
      f.rule,
      f.ruleName,
      f.engine,
      f.severity,
      f.kind,
      f.cwe.join(';'),
      'open',
      f.inNewCode,
      f.firstSeenAt,
      ...ids.map((id) => (f.categories[id] ?? []).join(';')),
      null,
      null,
      null,
      null,
      ...vulnerabilityCells(f.vulnerability),
    ]);
  }
  for (const t of report.triage) {
    yield line([
      t.section,
      t.project,
      t.path,
      t.line,
      t.rule,
      null,
      null,
      t.severity,
      null,
      t.cwe.join(';'),
      t.status,
      null,
      null,
      ...ids.map((id) => (t.categories[id] ?? []).join(';')),
      t.by,
      t.at,
      t.comment,
      t.reason,
      ...vulnerabilityCells(t.vulnerability),
    ]);
  }
}

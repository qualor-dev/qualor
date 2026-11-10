// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import type { PortfolioProjectRow } from '@qualor/server/plugin-contract';
import { CSV_BOM, csvLine as line } from '../csv';

/** 4E-2 §3: the columns, in order. */
const HEADER = [
  'organization_key',
  'organization',
  'project_key',
  'project',
  'last_analysis_at',
  'abandoned',
  'gate',
  'security_rating',
  'reliability_rating',
  'ncloc',
  'coverage',
  'duplication',
  'issues',
  'blocker',
  'high',
  'medium',
  'low',
  'info',
  'new_issues',
  'secrets',
  'vulnerable_dependencies',
  'vulnerable_releases',
  'exploited_vulnerabilities',
] as const;

/**
 * 4E-2 §3: one CSV line per project, RFC 4180 in UTF-8 with a BOM, streamed from `rows` one row
 * at a time. The organisation and the project are each a key and a name; a missing value is an
 * empty cell.
 */
export async function* portfolioCsv(
  rows: AsyncIterable<PortfolioProjectRow>,
): AsyncGenerator<string> {
  yield CSV_BOM + line(HEADER);
  for await (const r of rows) {
    const s = r.bySeverity;
    yield line([
      r.organization.key,
      r.organization.name,
      r.project.key,
      r.project.name,
      r.lastAnalysisAt,
      r.abandoned,
      r.gate,
      r.securityRating,
      r.reliabilityRating,
      r.ncloc,
      r.coverage,
      r.duplication,
      r.issues,
      s?.blocker,
      s?.high,
      s?.medium,
      s?.low,
      s?.info,
      r.newIssues,
      r.secrets,
      r.vulnerableDependencies,
      r.vulnerableReleases,
      r.exploited,
    ]);
  }
}

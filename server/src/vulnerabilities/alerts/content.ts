import { sql } from 'drizzle-orm';
import { uuidList } from '../../db/bulk';
import type { Executor } from '../../db/client';
import type {
  MailSeverity,
  VulnerabilityMailRow,
} from '../../mail/templates/notify-vulnerability-common';
import { SEVERITIES, scopedRows } from '../summary';

export {
  capRows,
  type VulnerabilityMailLinks,
  type VulnerabilityMailProject,
  type VulnerabilityMailRow,
} from '../../mail/templates/notify-vulnerability-common';

interface Row extends Record<string, unknown> {
  project_id: string;
  vulnerability_id: string;
  package_name: string;
  package_version: string;
  severity: MailSeverity;
  title: string | null;
  fixed_version: string | null;
  kev: boolean;
  kev_date_added: string | null;
  target_name: string;
  target_is_main: boolean;
  target_is_version: boolean;
}

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The rows of an alert email for the given alert items (4b): one per (vulnerability, package) of
 * each project, every target the pair is open on named once. It only formats. Who qualifies and
 * what gets marked as sent are the callers' business; a row whose target's effective status is
 * not open, or that is ignored, is left out here too, so a pair with no row left is not listed.
 * `exploited` is the KEV entry and is filled only with `options.priority` (`vuln.priority`).
 *
 * Order: critical, high, medium, low, unknown; then the vulnerability id; then the package.
 * Targets: main, the other branches by name, then the versions by label.
 */
export async function alertRows(
  tx: Executor,
  itemIds: readonly string[],
  options: { priority: boolean },
): Promise<Map<string, VulnerabilityMailRow[]>> {
  const result = new Map<string, VulnerabilityMailRow[]>();
  if (itemIds.length === 0) return result;
  const found = await tx.execute<Row>(sql`
    WITH it AS (
      SELECT t.branch_id, t.version_id, i.vulnerability_id
        FROM vulnerability_alert_items i
        JOIN vulnerability_alert_targets t ON t.id = i.target_id
       WHERE i.id IN ${uuidList(itemIds)}
    ),
    r AS (${scopedRows(
      sql`EXISTS (
            SELECT 1 FROM it
             WHERE it.vulnerability_id = tv.vulnerability_id
               AND (it.branch_id = tv.branch_id OR it.version_id = tv.version_id))`,
    )})
    SELECT r.project_id, r.vulnerability_id, r.package_name, r.package_version, r.severity,
           r.title, r.fixed_version, r.kev, r.kev_date_added,
           COALESCE(b.name, v.label) AS target_name,
           COALESCE(b.is_main, false) AS target_is_main,
           r.version_id IS NOT NULL AS target_is_version
      FROM r
      LEFT JOIN branches b ON b.id = r.branch_id
      LEFT JOIN project_versions v ON v.id = r.version_id
     WHERE r.eff_status = 'open' AND NOT r.ignored`);

  const pairs = new Map<
    string,
    {
      projectId: string;
      row: VulnerabilityMailRow;
      targets: Map<string, { main: boolean; version: boolean }>;
      versions: Set<string>;
    }
  >();
  for (const r of found.rows) {
    const key = `${r.project_id}\u0000${r.package_name}\u0000${r.vulnerability_id}`;
    let pair = pairs.get(key);
    if (pair === undefined) {
      pair = {
        projectId: r.project_id,
        row: {
          vulnerabilityId: r.vulnerability_id,
          severity: r.severity,
          title: r.title,
          exploited:
            options.priority && r.kev && r.kev_date_added !== null
              ? { dateAdded: r.kev_date_added }
              : null,
          packageName: r.package_name,
          installedVersions: [],
          fixedVersion: r.fixed_version,
          targets: [],
        },
        targets: new Map(),
        versions: new Set(),
      };
      pairs.set(key, pair);
    } else {
      // The same pair can carry other matches (one per installed version): the worst severity, the
      // first title, the highest fixed version, like the Vulnerabilities tab groups them.
      if (SEVERITIES.indexOf(r.severity) < SEVERITIES.indexOf(pair.row.severity)) {
        pair.row.severity = r.severity;
      }
      pair.row.title ??= r.title;
      if (r.fixed_version !== null && (pair.row.fixedVersion ?? '') < r.fixed_version) {
        pair.row.fixedVersion = r.fixed_version;
      }
    }
    pair.versions.add(r.package_version);
    pair.targets.set(r.target_name, { main: r.target_is_main, version: r.target_is_version });
  }

  for (const pair of pairs.values()) {
    pair.row.installedVersions = [...pair.versions].sort(compare);
    pair.row.targets = [...pair.targets]
      .sort(
        ([an, a], [bn, b]) =>
          Number(b.main) - Number(a.main) ||
          Number(a.version) - Number(b.version) ||
          compare(an, bn),
      )
      .map(([name]) => name);
    const rows = result.get(pair.projectId);
    if (rows === undefined) result.set(pair.projectId, [pair.row]);
    else rows.push(pair.row);
  }
  for (const rows of result.values()) {
    rows.sort(
      (a, b) =>
        SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
        compare(a.vulnerabilityId, b.vulnerabilityId) ||
        compare(a.packageName, b.packageName),
    );
  }
  return result;
}

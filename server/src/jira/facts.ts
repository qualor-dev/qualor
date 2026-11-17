import type { Severity } from '@qualor/shared';
import { eq, inArray, sql } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { analyses, branches, issues, projects, rules } from '../db/schema';
import { isTrackedBranch, vulnerabilitySettings } from '../versions/settings';
import { highestFixedVersion } from '../vulnerabilities/fixed-version';
import { targetRefsOf } from '../vulnerabilities/list';
import { SEVERITIES, scopedRows, type VulnerabilitySeverity } from '../vulnerabilities/summary';
import { trackedTargets, type Target } from '../vulnerabilities/targets';
import { TRIVY_ENGINE } from '../vulnerabilities/trivy-issues';
import type { CodeIssueFacts, VulnerabilityFacts } from './content';
import { pairKey } from './links';

/** The code issues' facts for their Jira issue, by issue id; an issue that is gone is absent. */
export async function codeIssueFacts(
  db: Executor,
  issueIds: readonly string[],
): Promise<Map<string, CodeIssueFacts>> {
  if (issueIds.length === 0) return new Map();
  const rows = await db
    .select({
      issueId: issues.id,
      projectId: issues.projectId,
      projectName: projects.name,
      projectKey: projects.key,
      branchName: branches.name,
      path: issues.path,
      line: issues.startLine,
      ruleKey: rules.key,
      ruleName: rules.name,
      severity: issues.severity,
      quality: issues.quality,
      message: issues.message,
      firstSeenAt: issues.firstSeenAt,
      closedAt: issues.closedAt,
      lastSeenAt: analyses.analysisDate,
    })
    .from(issues)
    .innerJoin(projects, eq(projects.id, issues.projectId))
    .innerJoin(branches, eq(branches.id, issues.branchId))
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .leftJoin(analyses, eq(analyses.id, issues.lastSeenAnalysisId))
    .where(inArray(issues.id, uuidList([...new Set(issueIds)])));
  return new Map(rows.map((r) => [r.issueId, { ...r, severity: r.severity as Severity }]));
}

/** A Trivy issue's severity as a vulnerability's (the ingestion maps critical to blocker). */
const VULNERABILITY_SEVERITY: Record<Severity, VulnerabilitySeverity> = {
  blocker: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'low',
};

const SEVERITY_RANK = sql.raw(
  `CASE severity ${SEVERITIES.map((s, i) => `WHEN '${s}' THEN ${i}`).join(' ')} END`,
);

interface TrackedRow extends Record<string, unknown> {
  package_name: string;
  vulnerability_id: string;
  sev_rank: number;
  title: string | null;
  fixed_versions: string[] | null;
  primary_url: string | null;
  installed: string[];
  targets: string[];
}

interface TrivyRow extends Record<string, unknown> {
  package_name: string;
  vulnerability_id: string;
  message: string;
  severity: string;
  name: string;
  is_main: boolean;
  kind: string;
}

interface PriorityRow extends Record<string, unknown> {
  vulnerability_id: string;
  kev_date_added: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
}

/** Code-unit order (not locale-dependent). */
const compare = (a: string, b: string): number => (a === b ? 0 : a < b ? -1 : 1);

const refOf = (t: Target): { kind: 'branch' | 'version'; id: string } =>
  t.kind === 'branch' ? { kind: 'branch', id: t.branchId } : { kind: 'version', id: t.versionId };

/**
 * The project's vulnerabilities' facts for their Jira issue, by {@link pairKey}. A pair is read
 * from its rows on the tracked targets (`scopedRows`, as the Vulnerabilities tab groups them);
 * without any, from its newest non-closed Trivy issue on main or a tracked branch (spec §6.4: the
 * title is the issue's message, the severity mapped back); with neither, it is absent. The KEV
 * and EPSS facts only with `priority` (`vuln.priority`).
 */
export async function vulnerabilityFacts(
  db: Executor,
  projectId: string,
  pairs: readonly { packageName: string; vulnerabilityId: string }[],
  options: { priority: boolean },
): Promise<Map<string, VulnerabilityFacts>> {
  const found = new Map<string, VulnerabilityFacts>();
  if (pairs.length === 0) return found;
  const [project] = await db
    .select({ name: projects.name })
    .from(projects)
    .where(eq(projects.id, projectId));
  if (!project) return found;
  const wanted = (list: typeof pairs): string =>
    JSON.stringify(
      list.map((p) => ({ package_name: p.packageName, vulnerability_id: p.vulnerabilityId })),
    );
  const base = { projectId, projectName: project.name, exploited: null, epss: null };

  const scope = await targetRefsOf(db, projectId, (await trackedTargets(db, projectId)).map(refOf));
  if (scope.length > 0) {
    const branchIds = scope.filter((t) => t.kind === 'branch').map((t) => t.id);
    const versionIds = scope.filter((t) => t.kind === 'version').map((t) => t.id);
    const rows = await db.execute<TrackedRow>(sql`
      WITH r AS (${scopedRows(
        sql`tv.project_id = ${projectId}
            AND (tv.branch_id IN ${uuidList(branchIds)} OR tv.version_id IN ${uuidList(versionIds)})
            AND (tv.package_name, tv.vulnerability_id) IN (
                  SELECT p.package_name, p.vulnerability_id
                    FROM jsonb_to_recordset(${wanted(pairs)}::jsonb)
                         AS p(package_name text, vulnerability_id text))`,
      )})
      SELECT package_name, vulnerability_id,
             min(${SEVERITY_RANK}) AS sev_rank,
             min(title) AS title,
             array_agg(DISTINCT fixed_version) FILTER (WHERE fixed_version IS NOT NULL)
               AS fixed_versions,
             min(primary_url) AS primary_url,
             array_agg(DISTINCT package_version) AS installed,
             array_agg(DISTINCT CASE WHEN branch_id IS NOT NULL
                                     THEN 'branch:' || branch_id::text
                                     ELSE 'version:' || version_id::text END) AS targets
        FROM r
       GROUP BY package_name, vulnerability_id`);
    for (const row of rows.rows) {
      const present = new Set(row.targets);
      found.set(pairKey(row.package_name, row.vulnerability_id), {
        ...base,
        packageName: row.package_name,
        vulnerabilityId: row.vulnerability_id,
        title: row.title,
        severity: SEVERITIES[row.sev_rank] ?? 'unknown',
        installedVersions: [...row.installed].sort(compare),
        fixedVersion: highestFixedVersion(row.fixed_versions ?? []),
        primaryUrl: row.primary_url,
        foundIn: scope.filter((t) => present.has(`${t.kind}:${t.id}`)).map((t) => t.name),
      });
    }
  }

  const rest = pairs.filter((p) => !found.has(pairKey(p.packageName, p.vulnerabilityId)));
  if (rest.length > 0) await addTrivyFacts(db, projectId, rest, wanted(rest), base, found);
  if (options.priority && found.size > 0) await addPriorityFacts(db, found);
  return found;
}

/** {@link vulnerabilityFacts} of the pairs that only Trivy issues hold, added to `found`. */
async function addTrivyFacts(
  db: Executor,
  projectId: string,
  rest: readonly { packageName: string; vulnerabilityId: string }[],
  json: string,
  base: Pick<VulnerabilityFacts, 'projectId' | 'projectName' | 'exploited' | 'epss'>,
  found: Map<string, VulnerabilityFacts>,
): Promise<void> {
  const reported = await db.execute<TrivyRow>(sql`
    SELECT p.package_name, p.vulnerability_id, i.message, i.severity, b.name, b.is_main, b.kind
      FROM jsonb_to_recordset(${json}::jsonb) AS p(package_name text, vulnerability_id text)
      JOIN issues i ON i.project_id = ${projectId} AND i.package_name = p.package_name
                   AND i.status <> 'closed'
      JOIN rules r ON r.id = i.rule_id AND r.engine_id = ${TRIVY_ENGINE}
                  AND r.engine_rule_id = p.vulnerability_id
      JOIN branches b ON b.id = i.branch_id
     ORDER BY i.first_seen_at DESC, i.id DESC`);
  if (reported.rows.length === 0) return;
  const settings = await vulnerabilitySettings(db, projectId);
  const branchesOf = new Map<string, { name: string; isMain: boolean }[]>();
  for (const r of reported.rows) {
    if (!isTrackedBranch(settings, { name: r.name, isMain: r.is_main, kind: r.kind })) continue;
    const key = pairKey(r.package_name, r.vulnerability_id);
    const seen = branchesOf.get(key);
    if (seen) {
      if (!seen.some((b) => b.name === r.name)) seen.push({ name: r.name, isMain: r.is_main });
      continue;
    }
    // The newest issue, first in the order, gives the title and the severity.
    branchesOf.set(key, [{ name: r.name, isMain: r.is_main }]);
    found.set(key, {
      ...base,
      packageName: r.package_name,
      vulnerabilityId: r.vulnerability_id,
      title: r.message,
      severity: VULNERABILITY_SEVERITY[r.severity as Severity] ?? 'unknown',
      installedVersions: [],
      fixedVersion: null,
      primaryUrl: null,
      foundIn: [],
    });
  }
  for (const [key, list] of branchesOf) {
    const facts = found.get(key);
    if (!facts) continue;
    list.sort((a, b) => Number(b.isMain) - Number(a.isMain) || compare(a.name, b.name));
    facts.foundIn = list.map((b) => b.name);
  }
}

/** The CISA KEV entry (not delisted) and the EPSS score of each pair's id, set on its facts. */
async function addPriorityFacts(
  db: Executor,
  found: Map<string, VulnerabilityFacts>,
): Promise<void> {
  const ids = [...new Set([...found.values()].map((f) => f.vulnerabilityId))];
  const rows = await db.execute<PriorityRow>(sql`
    SELECT v.id AS vulnerability_id,
           to_char(k.date_added, 'YYYY-MM-DD') AS kev_date_added,
           e.score AS epss_score, e.percentile AS epss_percentile
      FROM jsonb_array_elements_text(${JSON.stringify(ids)}::jsonb) AS v(id)
      LEFT JOIN vulnerability_kev k ON k.vulnerability_id = v.id AND k.delisted_at IS NULL
      LEFT JOIN vulnerability_epss e ON e.vulnerability_id = v.id`);
  const byId = new Map(rows.rows.map((r) => [r.vulnerability_id, r]));
  for (const facts of found.values()) {
    const r = byId.get(facts.vulnerabilityId);
    if (!r) continue;
    facts.exploited = r.kev_date_added === null ? null : { dateAdded: r.kev_date_added };
    facts.epss =
      r.epss_score === null || r.epss_percentile === null
        ? null
        : { score: r.epss_score, percentile: r.epss_percentile };
  }
}

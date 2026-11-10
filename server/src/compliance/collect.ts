import { effectiveCwe } from '@qualor/shared';
import { and, asc, desc, eq, inArray, sql } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import {
  analyses,
  branches,
  complianceReports,
  measures,
  organizations,
  projects,
  projectVersions,
} from '../db/schema';
import { effectiveDecisionJoin, type VexJustification } from '../vulnerabilities/decisions';
import { projectTargets } from '../vulnerabilities/targets';
import { scopedRows } from '../vulnerabilities/summary';
import { readVulndbSettings } from '../vulndb/settings';
import { readPriorityState } from '../vulndb/priority/state';
import { readVulndbState } from '../vulndb/state';
import { currentDataset } from '../vulndb/store';
import { cut } from './text';
import {
  MAX_ORGANIZATION_PROJECTS,
  TREND_POINTS,
  TRIAGE_COMMENT_MAX,
  type ComplianceDatasets,
  type ComplianceFindingGroup,
  type ComplianceFindingRow,
  type ComplianceProjectSource,
  type ComplianceSource,
  type ComplianceTriageRow,
  type ComplianceVulnerability,
  type FindingSection,
} from './types';

/** A failure the job may show the user as it is (4E-1 §2.4); anything else is generic. */
export class ComplianceCollectError extends Error {
  override name = 'ComplianceCollectError';
}

const isoReq = (d: Date | string): string => new Date(d).toISOString();

function iso(d: Date | string | null): string | null {
  if (d === null) return null;
  return isoReq(d);
}

function sectionOf(engineId: string): FindingSection {
  if (engineId === 'gitleaks') return 'secret';
  if (engineId === 'trivy') return 'dependency';
  return 'code';
}

function abortCheck(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error('aborted');
}

/** A JS array as one bound parameter (a bare array would be spread into a value list). */
const uuidArray = (ids: string[]) => sql`${sql.param(ids)}::uuid[]`;

/**
 * The server's facts of the dependency issues `ids` (Trivy issues: the rule's `engine_rule_id` is
 * the vulnerability id), in one set-based query. Only the issues on `trackedBranchIds` are
 * enriched: the rows of a target that is no longer tracked are frozen (recheck R17). The rows of
 * those branches are grouped by (branch, package, vulnerability) and joined to the issues.
 * `openOnly` keeps the effective-open, not ignored rows (an open finding); a triaged finding
 * takes all rows, because the triage row describes the same pair. KEV and EPSS are per
 * vulnerability id and only given with `priority`.
 */
async function dependencyFacts(
  tx: Executor,
  ids: string[],
  trackedBranchIds: string[],
  options: { openOnly: boolean; priority: boolean },
): Promise<Map<string, ComplianceVulnerability>> {
  const out = new Map<string, ComplianceVulnerability>();
  if (ids.length === 0 || trackedBranchIds.length === 0) return out;
  const open = sql`r.eff_status = 'open' AND NOT r.ignored`;
  const rows = (
    await tx.execute<{
      id: string;
      vulnerability_id: string;
      package_name: string;
      n: number;
      fixed: string[] | null;
      kev: boolean;
      kev_date_added: string | null;
      epss_score: number | null;
      epss_percentile: number | null;
    }>(sql`
      WITH want AS (
        SELECT i.id, i.branch_id, i.package_name, rl.engine_rule_id AS vulnerability_id
          FROM issues i
          JOIN rules rl ON rl.id = i.rule_id AND rl.engine_id = 'trivy'
         WHERE i.id = ANY(${uuidArray(ids)}) AND i.package_name IS NOT NULL
           AND i.branch_id = ANY(${uuidArray(trackedBranchIds)})
      ), g AS (
        SELECT r.branch_id, r.package_name, r.vulnerability_id,
               count(*) FILTER (WHERE ${options.openOnly ? open : sql`true`})::int AS n,
               array_agg(DISTINCT r.fixed_version) FILTER (
                 WHERE r.fixed_version IS NOT NULL AND ${options.openOnly ? open : sql`true`}
               ) AS fixed,
               bool_or(r.kev) AS kev, max(r.kev_date_added) AS kev_date_added,
               max(r.epss_score) AS epss_score, max(r.epss_percentile) AS epss_percentile
          FROM (${scopedRows(
            sql`tv.branch_id = ANY(${uuidArray(trackedBranchIds)})
              AND tv.vulnerability_id IN (SELECT vulnerability_id FROM want)`,
          )}) r
         GROUP BY r.branch_id, r.package_name, r.vulnerability_id
      )
      SELECT w.id, w.vulnerability_id, w.package_name, g.n, g.fixed, g.kev, g.kev_date_added,
             g.epss_score, g.epss_percentile
        FROM want w
        JOIN g ON g.branch_id = w.branch_id AND g.package_name = w.package_name
              AND g.vulnerability_id = w.vulnerability_id`)
  ).rows;
  for (const r of rows) {
    if (r.n === 0) continue;
    out.set(r.id, {
      id: r.vulnerability_id,
      packageName: r.package_name,
      fixedVersions: [...(r.fixed ?? [])].sort(),
      kev: options.priority && r.kev && r.kev_date_added ? { dateAdded: r.kev_date_added } : null,
      epss:
        options.priority && r.epss_score !== null && r.epss_percentile !== null
          ? { score: r.epss_score, percentile: r.epss_percentile }
          : null,
    });
  }
  return out;
}

/** The dataset dates; KEV and EPSS only with `vuln.priority`. */
async function datasetsOf(
  tx: Executor,
  options: { enabled: boolean; priority: boolean },
): Promise<ComplianceDatasets> {
  // With monitoring off the report names no database: it used none.
  if (!options.enabled) return { vulnerabilityDatabase: null, kev: null, epss: null };
  const { priority } = options;
  const dataset = await currentDataset(tx, await readVulndbState(tx));
  const state = priority ? await readPriorityState(tx) : null;
  return {
    vulnerabilityDatabase: dataset
      ? { builtAt: iso(dataset.builtAt), digest: dataset.digest }
      : null,
    kev:
      state?.kev.refreshedAt && state.kev.digest
        ? { refreshedAt: state.kev.refreshedAt, digest: state.kev.digest }
        : null,
    epss:
      state?.epss.refreshedAt && state.epss.digest
        ? {
            dataDate: state.epss.dataDate,
            refreshedAt: state.epss.refreshedAt,
            digest: state.epss.digest,
          }
        : null,
  };
}

/**
 * Reads one consistent snapshot of a report's scope (4E-1 §2.1, §2.3): a repeatable-read,
 * read-only transaction, so the counts, the lists and the gate come from the same moment.
 */
export async function collectCompliance(
  db: Db,
  reportId: string,
  options: { limit: number; signal?: AbortSignal; priority?: boolean },
): Promise<ComplianceSource> {
  const priority = options.priority === true;
  return db.transaction(
    async (tx) => {
      const [report] = await tx
        .select({
          status: complianceReports.status,
          scope: complianceReports.scope,
          organizationId: complianceReports.organizationId,
          projectId: complianceReports.projectId,
          branchId: complianceReports.branchId,
          versionId: complianceReports.versionId,
          createdByName: complianceReports.createdByName,
          now: sql<Date>`now()`,
        })
        .from(complianceReports)
        .where(eq(complianceReports.id, reportId));
      if (!report) throw new ComplianceCollectError('the report no longer exists');
      // A job that starts after housekeeping failed its row does no work.
      if (report.status !== 'pending') {
        throw new ComplianceCollectError('the report is no longer pending');
      }
      const [org] = await tx
        .select({ id: organizations.id, key: organizations.key, name: organizations.name })
        .from(organizations)
        .where(eq(organizations.id, report.organizationId));
      if (!org) throw new ComplianceCollectError('the report no longer exists');
      abortCheck(options.signal);

      // The projects and the branch of each (§2.3: the report's branch, or each main branch).
      const scopeProjects = await tx
        .select({ id: projects.id, key: projects.key, name: projects.name })
        .from(projects)
        .where(
          report.projectId === null
            ? eq(projects.organizationId, org.id)
            : eq(projects.id, report.projectId),
        )
        .orderBy(asc(projects.key))
        .limit(MAX_ORGANIZATION_PROJECTS + 1);
      if (scopeProjects.length > MAX_ORGANIZATION_PROJECTS) {
        throw new ComplianceCollectError('too many projects for one report');
      }
      const projectIds = scopeProjects.map((p) => p.id);
      // The branches the server still monitors: the rows of any other are frozen (recheck R17).
      const monitoring = (await readVulndbSettings(tx)).enabled;
      if (report.versionId !== null) {
        const project = scopeProjects[0];
        if (!project) throw new ComplianceCollectError('the report no longer exists');
        if (!monitoring) {
          throw new ComplianceCollectError('vulnerability monitoring is off on this server');
        }
        return versionSource(tx, {
          versionId: report.versionId,
          org,
          project,
          generatedAt: isoReq(report.now),
          createdBy: report.createdByName,
          limit: options.limit,
          priority,
          signal: options.signal,
        });
      }
      const trackedBranchIds = monitoring
        ? [...(await projectTargets(tx, projectIds)).values()].flatMap((targets) =>
            targets.flatMap((target) => (target.kind === 'branch' ? [target.branchId] : [])),
          )
        : [];
      const branchRows = await scopeBranches(tx, projectIds, report.branchId);
      const branchOf = new Map(branchRows.map((b) => [b.projectId, b]));
      const branchIds = branchRows.map((b) => b.id);
      abortCheck(options.signal);

      const projectsOut: ComplianceProjectSource[] = [];
      for (const p of scopeProjects) {
        projectsOut.push(await projectSource(tx, p, branchOf.get(p.id) ?? null));
        abortCheck(options.signal);
      }

      // Effective CWE per rule used in scope (§2.1), in TS so engineCwe stays the one source.
      const ruleRows =
        branchIds.length === 0
          ? []
          : (
              await tx.execute<{
                id: string;
                key: string;
                engine_id: string;
                cwe: number[] | null;
                name: string;
              }>(sql`
                SELECT DISTINCT r.id, r.key, r.engine_id, r.cwe, r.name
                  FROM rules r JOIN issues i ON i.rule_id = r.id
                 WHERE i.branch_id = ANY(${uuidArray(branchIds)})`)
            ).rows;
      const ruleInfo = new Map(
        ruleRows.map((r) => [
          r.id,
          {
            key: r.key,
            name: r.name,
            engineId: r.engine_id,
            cwe: [...effectiveCwe({ key: r.key, engineId: r.engine_id, cwe: r.cwe ?? [] })].sort(
              (a, b) => a - b,
            ),
          },
        ]),
      );
      const ruleOf = (id: string) => {
        const r = ruleInfo.get(id);
        if (!r) throw new Error(`rule ${id} missing from the scope`);
        return r;
      };
      const cweRuleIds = [...ruleInfo].filter(([, r]) => r.cwe.length > 0).map(([id]) => id);
      abortCheck(options.signal);

      const relevant = sql`i.branch_id = ANY(${uuidArray(branchIds)})
        AND i.duplicate_of_issue_id IS NULL
        AND (i.rule_id = ANY(${uuidArray(cweRuleIds)}) OR i.quality = 'security' OR i.kind = 'hotspot')`;

      const groups: ComplianceFindingGroup[] =
        branchIds.length === 0
          ? []
          : (
              await tx.execute<{
                status: string;
                rule_id: string;
                severity: string;
                kind: string;
                in_new_code: boolean;
                count: number;
                oldest: Date;
              }>(sql`
                SELECT i.status, i.rule_id, i.severity, i.kind, i.in_new_code,
                       count(*)::int AS count, min(i.first_seen_at) AS oldest
                  FROM issues i
                 WHERE ${relevant} AND i.status IN ('open','false_positive','wont_fix')
                 GROUP BY i.status, i.rule_id, i.severity, i.kind, i.in_new_code`)
            ).rows
              .map((g) => {
                const r = ruleOf(g.rule_id);
                return {
                  status: g.status as ComplianceFindingGroup['status'],
                  section: sectionOf(r.engineId),
                  rule: r.key,
                  severity: g.severity as ComplianceFindingGroup['severity'],
                  kind: g.kind as 'issue' | 'hotspot',
                  inNewCode: g.in_new_code,
                  cwe: r.cwe,
                  count: g.count,
                  oldestFirstSeenAt: isoReq(g.oldest),
                };
              })
              .sort((a, b) =>
                (a.status + a.rule + a.severity + a.kind + String(a.inNewCode)).localeCompare(
                  b.status + b.rule + b.severity + b.kind + String(b.inNewCode),
                ),
              );
      abortCheck(options.signal);

      const findings: ComplianceFindingRow[] =
        branchIds.length === 0
          ? []
          : (
              await tx.execute<{
                id: string;
                project_key: string;
                path: string | null;
                start_line: number | null;
                rule_id: string;
                severity: string;
                kind: string;
                message: string;
                in_new_code: boolean;
                first_seen_at: Date;
              }>(sql`
                SELECT i.id, p.key AS project_key, i.path, i.start_line, i.rule_id, i.severity,
                       i.kind, i.message, i.in_new_code, i.first_seen_at
                  FROM issues i JOIN projects p ON p.id = i.project_id
                 WHERE ${relevant} AND i.status = 'open'
                 ORDER BY i.severity_rank, p.key, i.path NULLS FIRST, i.start_line NULLS FIRST, i.id
                 LIMIT ${options.limit + 1}`)
            ).rows.map((f) => {
              const r = ruleOf(f.rule_id);
              return {
                id: f.id,
                project: f.project_key,
                path: f.path,
                line: f.start_line,
                rule: r.key,
                ruleName: r.name,
                engine: r.engineId,
                severity: f.severity as ComplianceFindingRow['severity'],
                kind: f.kind as 'issue' | 'hotspot',
                cwe: r.cwe,
                message: f.message,
                inNewCode: f.in_new_code,
                firstSeenAt: isoReq(f.first_seen_at),
                section: sectionOf(r.engineId),
                vulnerability: null as ComplianceVulnerability | null,
              };
            });
      const openFacts = await dependencyFacts(
        tx,
        findings.filter((f) => f.section === 'dependency').map((f) => f.id),
        trackedBranchIds,
        { openOnly: true, priority },
      );
      for (const f of findings) f.vulnerability = openFacts.get(f.id) ?? null;
      abortCheck(options.signal);

      const triage: ComplianceTriageRow[] =
        branchIds.length === 0
          ? []
          : (
              await tx.execute<{
                id: string;
                project_key: string;
                path: string | null;
                start_line: number | null;
                rule_id: string;
                severity: string;
                status: string;
                by: string | null;
                at: Date | null;
                comment: string | null;
                reason: string | null;
              }>(sql`
                SELECT i.id, p.key AS project_key, i.path, i.start_line, i.rule_id, i.severity,
                       i.status, coalesce(u.display_name, u.username) AS by,
                       c.created_at AS at, c.comment, d.reason
                  FROM issues i JOIN projects p ON p.id = i.project_id
                  LEFT JOIN rules rl ON rl.id = i.rule_id AND rl.engine_id = 'trivy'
                  LEFT JOIN LATERAL (
                    SELECT i.project_id, i.package_name, rl.engine_rule_id AS vulnerability_id,
                           i.branch_id, NULL::uuid AS version_id
                     WHERE rl.id IS NOT NULL AND i.package_name IS NOT NULL) tv ON true
                  ${effectiveDecisionJoin('tv', 'd')}
                  LEFT JOIN LATERAL (
                    SELECT ic.user_id, ic.created_at, ic.comment FROM issue_changes ic
                     WHERE ic.issue_id = i.id AND ic.field = 'status' AND ic.new_value = i.status
                     ORDER BY ic.created_at DESC, ic.id DESC LIMIT 1) c ON true
                  LEFT JOIN users u ON u.id = c.user_id
                 WHERE ${relevant} AND i.status IN ('false_positive','wont_fix')
                 ORDER BY c.created_at DESC NULLS LAST, i.id
                 LIMIT ${options.limit + 1}`)
            ).rows.map((t) => {
              const r = ruleOf(t.rule_id);
              return {
                id: t.id,
                project: t.project_key,
                path: t.path,
                line: t.start_line,
                rule: r.key,
                severity: t.severity as ComplianceTriageRow['severity'],
                cwe: r.cwe,
                status: t.status as ComplianceTriageRow['status'],
                section: sectionOf(r.engineId),
                by: t.by,
                at: iso(t.at),
                comment: cut(t.comment, TRIAGE_COMMENT_MAX),
                reason: t.reason as VexJustification | null,
                vulnerability: null as ComplianceVulnerability | null,
              };
            });
      const triageFacts = await dependencyFacts(
        tx,
        triage.filter((t) => t.section === 'dependency').map((t) => t.id),
        trackedBranchIds,
        { openOnly: false, priority },
      );
      for (const t of triage) t.vulnerability = triageFacts.get(t.id) ?? null;
      abortCheck(options.signal);
      const datasets = await datasetsOf(tx, { enabled: monitoring, priority });
      abortCheck(options.signal);

      const single = report.projectId === null ? null : (scopeProjects[0] ?? null);
      const singleBranch = single ? (branchOf.get(single.id) ?? null) : null;
      return {
        generatedAt: isoReq(report.now),
        createdBy: report.createdByName,
        scope: {
          kind: report.scope,
          organization: org,
          project: single,
          branch: singleBranch ? { id: singleBranch.id, name: singleBranch.name } : null,
          version: null,
        },
        projects: projectsOut,
        groups,
        findings,
        triage,
        datasets,
      };
    },
    { isolationLevel: 'repeatable read', accessMode: 'read only' },
  );
}

/** The branch of each project in scope: the report's own branch, or else each main branch. */
async function scopeBranches(
  tx: Executor,
  projectIds: string[],
  branchId: string | null,
): Promise<{ id: string; name: string; projectId: string }[]> {
  if (projectIds.length === 0) return [];
  const which =
    branchId === null
      ? and(inArray(branches.projectId, projectIds), eq(branches.isMain, true))
      : eq(branches.id, branchId);
  return tx
    .select({ id: branches.id, name: branches.name, projectId: branches.projectId })
    .from(branches)
    .where(which);
}

async function projectSource(
  tx: Executor,
  p: { id: string; key: string; name: string },
  branch: { id: string; name: string } | null,
): Promise<ComplianceProjectSource> {
  if (branch === null) return { ...p, branch: null, analysis: null, gate: null, trend: [] };
  const recent = await tx
    .select({
      id: analyses.id,
      date: analyses.analysisDate,
      revision: analyses.revision,
      versionLabel: analyses.versionLabel,
      gateStatus: analyses.gateStatus,
      gateResult: analyses.gateResult,
    })
    .from(analyses)
    .where(and(eq(analyses.branchId, branch.id), eq(analyses.status, 'succeeded')))
    .orderBy(desc(analyses.analysisDate), desc(analyses.id))
    .limit(TREND_POINTS);
  const last = recent[0];
  const branchOut = { id: branch.id, name: branch.name };
  if (!last) return { ...p, branch: branchOut, analysis: null, gate: null, trend: [] };
  const points = await tx
    .select({
      analysisId: measures.analysisId,
      metricKey: measures.metricKey,
      value: measures.value,
    })
    .from(measures)
    .where(
      and(
        inArray(
          measures.analysisId,
          recent.map((a) => a.id),
        ),
        eq(measures.scope, 'overall'),
        inArray(measures.metricKey, ['security_issues', 'security_rating']),
      ),
    );
  const valueOf = (analysisId: string, key: string) =>
    points.find((m) => m.analysisId === analysisId && m.metricKey === key)?.value ?? null;
  const conditions =
    (
      last.gateResult as {
        conditions?: {
          metric: string;
          operator: 'gt' | 'lt';
          threshold: number;
          value: number | null;
          status: string;
        }[];
      } | null
    )?.conditions ?? [];
  return {
    ...p,
    branch: branchOut,
    analysis: {
      id: last.id,
      date: iso(last.date),
      revision: last.revision,
      versionLabel: last.versionLabel,
    },
    gate:
      last.gateStatus === null
        ? null
        : {
            status: last.gateStatus,
            failedConditions: conditions
              .filter((c) => c.status === 'failed')
              .map((c) => ({
                metric: c.metric,
                op: c.operator,
                threshold: c.threshold,
                actual: c.value,
              })),
          },
    trend: [...recent].reverse().map((a) => ({
      analysisId: a.id,
      date: iso(a.date),
      security_issues: valueOf(a.id, 'security_issues'),
      security_rating: valueOf(a.id, 'security_rating'),
    })),
  };
}

/** A vulnerability severity as the report's: critical is a blocker, unknown is medium. */
const REPORT_SEVERITY: Record<string, ComplianceFindingRow['severity']> = {
  critical: 'blocker',
  high: 'high',
  medium: 'medium',
  low: 'low',
  unknown: 'medium',
};
const severityOf = (s: string): ComplianceFindingRow['severity'] => REPORT_SEVERITY[s] ?? 'medium';

/** The facts of a vulnerability row as the report shows them; KEV and EPSS only with priority. */
function rowVulnerability(
  row: {
    vulnerability_id: string;
    package_name: string;
    fixed_version: string | null;
    kev: boolean;
    kev_date_added: string | null;
    epss_score: number | null;
    epss_percentile: number | null;
  },
  priority: boolean,
): ComplianceVulnerability {
  return {
    id: row.vulnerability_id,
    packageName: row.package_name,
    fixedVersions: row.fixed_version === null ? [] : [row.fixed_version],
    kev: priority && row.kev && row.kev_date_added ? { dateAdded: row.kev_date_added } : null,
    epss:
      priority && row.epss_score !== null && row.epss_percentile !== null
        ? { score: row.epss_score, percentile: row.epss_percentile }
        : null,
  };
}

/**
 * The source of the report of a version (plan 5, V12): it holds the version's dependencies only. A
 * version has no code analysis, so the project entry has its analysis and no branch, gate or
 * trend, and the findings, the triage and the group counts come from the version's rows
 * (`scopedRows`): a finding is a row, and its status is the effective decision's. Ignored rows are
 * left out. A vulnerability that has a Trivy rule takes its key and its CWE; any other takes the
 * vulnerability id as the key, with no CWE.
 */
async function versionSource(
  tx: Executor,
  input: {
    versionId: string;
    org: { id: string; key: string; name: string };
    project: { id: string; key: string; name: string };
    generatedAt: string;
    createdBy: string;
    limit: number;
    priority: boolean;
    signal: AbortSignal | undefined;
  },
): Promise<ComplianceSource> {
  const { project, priority, signal } = input;
  const [version] = await tx
    .select({
      id: projectVersions.id,
      label: projectVersions.label,
      analysisId: projectVersions.analysisId,
    })
    .from(projectVersions)
    .where(and(eq(projectVersions.id, input.versionId), eq(projectVersions.projectId, project.id)));
  if (!version) throw new ComplianceCollectError('the version no longer exists');
  const [analysis] =
    version.analysisId === null
      ? []
      : await tx
          .select({
            id: analyses.id,
            date: analyses.analysisDate,
            revision: analyses.revision,
            versionLabel: analyses.versionLabel,
          })
          .from(analyses)
          .where(eq(analyses.id, version.analysisId));
  abortCheck(signal);

  const rows = scopedRows(sql`tv.version_id = ${version.id}`);
  const groupRows = (
    await tx.execute<{
      status: string;
      vulnerability_id: string;
      severity: string;
      count: number;
      oldest: Date;
    }>(sql`
      SELECT r.eff_status AS status, r.vulnerability_id, r.severity, count(*)::int AS count,
             min(r.first_seen_at) AS oldest
        FROM (${rows}) r
       WHERE NOT r.ignored AND r.eff_status IN ('open','false_positive','wont_fix')
       GROUP BY r.eff_status, r.vulnerability_id, r.severity`)
  ).rows;
  abortCheck(signal);

  // The Trivy rule of each vulnerability id, in one query (the rule's engine rule id is the id).
  const ids = [...new Set(groupRows.map((g) => g.vulnerability_id))];
  const ruleRows =
    ids.length === 0
      ? []
      : (
          await tx.execute<{ key: string; engine_rule_id: string; cwe: number[] | null }>(sql`
            SELECT key, engine_rule_id, cwe FROM rules
             WHERE engine_id = 'trivy' AND engine_rule_id = ANY(${sql.param(ids)}::text[])`)
        ).rows;
  const ruleOf = new Map(
    ruleRows.map((r) => [
      r.engine_rule_id,
      {
        key: r.key,
        cwe: [...effectiveCwe({ key: r.key, engineId: 'trivy', cwe: r.cwe ?? [] })].sort(
          (a, b) => a - b,
        ),
      },
    ]),
  );
  const keyOf = (id: string) => ruleOf.get(id)?.key ?? id;
  const cweOf = (id: string) => ruleOf.get(id)?.cwe ?? [];

  // Unknown counts as medium, so two severities can share a group.
  const merged = new Map<string, ComplianceFindingGroup>();
  for (const g of groupRows) {
    const severity = severityOf(g.severity);
    const rule = keyOf(g.vulnerability_id);
    const key = [g.status, rule, severity].join('\u0000');
    const oldest = isoReq(g.oldest);
    const have = merged.get(key);
    if (have) {
      have.count += g.count;
      if (oldest < have.oldestFirstSeenAt) have.oldestFirstSeenAt = oldest;
    } else {
      merged.set(key, {
        status: g.status as ComplianceFindingGroup['status'],
        section: 'dependency',
        rule,
        severity,
        kind: 'issue',
        inNewCode: false,
        cwe: cweOf(g.vulnerability_id),
        count: g.count,
        oldestFirstSeenAt: oldest,
      });
    }
  }
  const groups = [...merged.values()].sort((a, b) =>
    (a.status + a.rule + a.severity).localeCompare(b.status + b.rule + b.severity),
  );
  abortCheck(signal);

  const rank = sql`CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
    WHEN 'unknown' THEN 2 ELSE 3 END`;
  const findingRows = (
    await tx.execute<{
      row_id: string;
      package_name: string;
      package_version: string;
      vulnerability_id: string;
      severity: string;
      title: string | null;
      fixed_version: string | null;
      first_seen_at: Date;
      kev: boolean;
      kev_date_added: string | null;
      epss_score: number | null;
      epss_percentile: number | null;
    }>(sql`
      SELECT r.row_id, r.package_name, r.package_version, r.vulnerability_id, r.severity, r.title,
             r.fixed_version, r.first_seen_at, r.kev, r.kev_date_added, r.epss_score,
             r.epss_percentile
        FROM (${rows}) r
       WHERE NOT r.ignored AND r.eff_status = 'open'
       ORDER BY ${rank}, r.vulnerability_id, r.package_name, r.package_version, r.row_id
       LIMIT ${input.limit + 1}`)
  ).rows;
  const findings: ComplianceFindingRow[] = findingRows.map((f) => ({
    id: f.row_id,
    project: project.key,
    path: null,
    line: null,
    rule: keyOf(f.vulnerability_id),
    ruleName: f.title ?? f.vulnerability_id,
    engine: 'trivy',
    severity: severityOf(f.severity),
    kind: 'issue',
    cwe: cweOf(f.vulnerability_id),
    message: `${f.package_name} ${f.package_version}: ${f.title ?? f.vulnerability_id}`,
    inNewCode: false,
    firstSeenAt: isoReq(f.first_seen_at),
    section: 'dependency',
    vulnerability: rowVulnerability(f, priority),
  }));
  abortCheck(signal);

  const triageRows = (
    await tx.execute<{
      row_id: string;
      package_name: string;
      vulnerability_id: string;
      severity: string;
      status: string;
      fixed_version: string | null;
      kev: boolean;
      kev_date_added: string | null;
      epss_score: number | null;
      epss_percentile: number | null;
      reason: string | null;
      comment: string | null;
      decided_at: Date | null;
      by: string | null;
    }>(sql`
      SELECT r.row_id, r.package_name, r.vulnerability_id, r.severity, r.eff_status AS status,
             r.fixed_version, r.kev, r.kev_date_added, r.epss_score, r.epss_percentile,
             d.reason, d.comment, d.decided_at, coalesce(u.display_name, u.username) AS by
        FROM (${rows}) r
        LEFT JOIN vulnerability_decisions d ON d.id = r.d_id
        LEFT JOIN users u ON u.id = d.decided_by
       WHERE NOT r.ignored AND r.eff_status IN ('false_positive','wont_fix')
       ORDER BY d.decided_at DESC NULLS LAST, r.vulnerability_id, r.package_name, r.row_id
       LIMIT ${input.limit + 1}`)
  ).rows;
  const triage: ComplianceTriageRow[] = triageRows.map((t) => ({
    id: t.row_id,
    project: project.key,
    path: null,
    line: null,
    rule: keyOf(t.vulnerability_id),
    severity: severityOf(t.severity),
    cwe: cweOf(t.vulnerability_id),
    status: t.status as ComplianceTriageRow['status'],
    section: 'dependency',
    by: t.by,
    at: iso(t.decided_at),
    comment: cut(t.comment, TRIAGE_COMMENT_MAX),
    reason: t.reason as VexJustification | null,
    vulnerability: rowVulnerability(t, priority),
  }));
  abortCheck(signal);
  const datasets = await datasetsOf(tx, { enabled: true, priority });

  return {
    generatedAt: input.generatedAt,
    createdBy: input.createdBy,
    scope: {
      kind: 'project',
      organization: input.org,
      project,
      branch: null,
      version: { id: version.id, label: version.label },
    },
    projects: [
      {
        ...project,
        branch: null,
        analysis: analysis
          ? {
              id: analysis.id,
              date: iso(analysis.date),
              revision: analysis.revision,
              versionLabel: analysis.versionLabel,
            }
          : null,
        gate: null,
        trend: [],
      },
    ],
    groups,
    findings,
    triage,
    datasets,
  };
}

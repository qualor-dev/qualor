import { and, eq, inArray, sql, type SQL } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { branches, projectVersions, users, vulnerabilityDecisions } from '../db/schema';
import { notFound } from '../http/problem';
import type { DecisionStatus, VexJustification } from './decisions';
import { IS_NEW, scopedRows, SEVERITIES, type VulnerabilitySeverity } from './summary';
import { monitoringOn, trackedTargets, type Target } from './targets';

export interface TargetRef {
  kind: 'branch' | 'version';
  id: string;
  name: string;
}

export interface DecisionDto {
  id: string;
  scope: 'project' | 'branch' | 'version';
  status: DecisionStatus;
  reason: VexJustification | null;
  comment: string | null;
  decidedAt: string;
  decidedBy: { id: string; name: string } | null;
}

export interface VulnerabilityItem {
  vulnerabilityId: string;
  packageName: string;
  ecosystem: string;
  severity: VulnerabilitySeverity;
  title: string | null;
  primaryUrl: string | null;
  installedVersions: string[];
  fixedVersion: string | null;
  in: TargetRef[];
  notIn: TargetRef[];
  foundAt: string;
  withoutScan: boolean;
  new: boolean;
  ignored: boolean;
  status: DecisionStatus;
  decision: DecisionDto | null;
}

export interface ListQuery {
  /** One target, tracked or not; else every tracked target. */
  target?: { kind: 'branch' | 'version'; id: string };
  status: 'all' | DecisionStatus;
  severity?: VulnerabilitySeverity;
  page: number;
  pageSize: number;
}

interface GroupRow extends Record<string, unknown> {
  package_name: string;
  vulnerability_id: string;
  sev_rank: number;
  ecosystem: string;
  title: string | null;
  fixed_version: string | null;
  primary_url: string | null;
  installed: string[];
  targets: string[];
  found_at: string;
  without_scan: boolean;
  is_new: boolean;
  ignored: boolean;
  status: DecisionStatus;
  decision_id: string | null;
  total: number;
}

const SEVERITY_RANK = sql.raw(
  `CASE severity ${SEVERITIES.map((s, i) => `WHEN '${s}' THEN ${i}`).join(' ')} END`,
);

/** The refs of the targets, in the order given, without any that no longer exists. */
async function refsOf(
  db: Executor,
  projectId: string,
  targets: readonly { kind: 'branch' | 'version'; id: string }[],
): Promise<TargetRef[]> {
  const branchIds = targets.filter((t) => t.kind === 'branch').map((t) => t.id);
  const versionIds = targets.filter((t) => t.kind === 'version').map((t) => t.id);
  const [branchRows, versionRows] = await Promise.all([
    branchIds.length === 0
      ? []
      : db
          .select({ id: branches.id, name: branches.name })
          .from(branches)
          .where(
            and(
              eq(branches.projectId, projectId),
              eq(branches.kind, 'branch'),
              inArray(branches.id, branchIds),
            ),
          ),
    versionIds.length === 0
      ? []
      : db
          .select({ id: projectVersions.id, name: projectVersions.label })
          .from(projectVersions)
          .where(
            and(eq(projectVersions.projectId, projectId), inArray(projectVersions.id, versionIds)),
          ),
  ]);
  const names = new Map<string, string>([
    ...branchRows.map((b) => [`branch:${b.id}`, b.name] as const),
    ...versionRows.map((v) => [`version:${v.id}`, v.name] as const),
  ]);
  return targets.flatMap((t) => {
    const name = names.get(`${t.kind}:${t.id}`);
    return name === undefined ? [] : [{ kind: t.kind, id: t.id, name }];
  });
}

const targetId = (t: Target): { kind: 'branch' | 'version'; id: string } =>
  t.kind === 'branch' ? { kind: 'branch', id: t.branchId } : { kind: 'version', id: t.versionId };

/** The grouped items (one per package and vulnerability) of the scope that pass the filters. */
function groups(projectId: string, scope: readonly TargetRef[], q: ListQuery): SQL {
  const own = q.target !== undefined;
  const decisionId = sql.raw(own ? 'd_id' : 'pd_id');
  const decisionStatus = sql.raw(own ? 'eff_status' : 'pd_status');
  const branchIds = scope.filter((t) => t.kind === 'branch').map((t) => t.id);
  const versionIds = scope.filter((t) => t.kind === 'version').map((t) => t.id);
  return sql`
    WITH r AS (${scopedRows(
      sql`tv.project_id = ${projectId}
          AND (tv.branch_id IN ${uuidList(branchIds)} OR tv.version_id IN ${uuidList(versionIds)})`,
    )}),
    g AS (
      SELECT package_name, vulnerability_id,
             min(${SEVERITY_RANK}) AS sev_rank,
             min(ecosystem) AS ecosystem,
             min(title) AS title,
             max(fixed_version) AS fixed_version,
             min(primary_url) AS primary_url,
             array_agg(DISTINCT package_version) AS installed,
             array_agg(DISTINCT CASE WHEN branch_id IS NOT NULL
                                     THEN 'branch:' || branch_id::text
                                     ELSE 'version:' || version_id::text END) AS targets,
             to_char(min(first_seen_at) AT TIME ZONE 'UTC',
                     'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS found_at,
             bool_or(after_baseline) AS without_scan,
             bool_or(${IS_NEW}) AS is_new,
             bool_and(ignored) AS ignored,
             ${decisionStatus} AS status,
             ${decisionId} AS decision_id
        FROM r
       GROUP BY package_name, vulnerability_id, ${decisionId}, ${decisionStatus}
    ),
    f AS (
      SELECT * FROM g
       WHERE true
         ${q.status === 'all' ? sql`` : sql`AND status = ${q.status}`}
         ${q.severity === undefined ? sql`` : sql`AND sev_rank = ${SEVERITIES.indexOf(q.severity)}`}
    )`;
}

/**
 * The vulnerabilities of the tracked targets (or of one target, tracked or not), grouped by
 * package and vulnerability id, open first, then by severity, id and package. The decision of an
 * item is the viewed target's effective one, or the project-wide one without a target. One
 * statement for the page, whatever the number of targets. Empty while monitoring is off, with or
 * without a target.
 */
export async function listVulnerabilities(
  db: Executor,
  projectId: string,
  q: ListQuery,
): Promise<{ items: VulnerabilityItem[]; total: number }> {
  let scope: TargetRef[];
  if (q.target) {
    scope = await refsOf(db, projectId, [q.target]);
    if (scope.length === 0) throw notFound('Target');
    // Final review F2: while monitoring is off one target is empty too, like the summary.
    if (!(await monitoringOn(db, projectId))) return { items: [], total: 0 };
  } else {
    scope = await refsOf(db, projectId, (await trackedTargets(db, projectId)).map(targetId));
  }
  if (scope.length === 0) return { items: [], total: 0 };

  const base = groups(projectId, scope, q);
  const page = await db.execute<GroupRow>(sql`
    ${base}
    SELECT f.*, count(*) OVER ()::int AS total
      FROM f
     ORDER BY (status = 'open') DESC, sev_rank, vulnerability_id, package_name
     LIMIT ${q.pageSize} OFFSET ${(q.page - 1) * q.pageSize}`);
  let total = page.rows[0]?.total ?? 0;
  if (page.rows.length === 0 && q.page > 1) {
    const count = await db.execute<{ total: number }>(
      sql`${base} SELECT count(*)::int AS total FROM f`,
    );
    total = count.rows[0]?.total ?? 0;
  }

  const decisions = await decisionsOf(
    db,
    page.rows.flatMap((r) => (r.decision_id === null ? [] : [r.decision_id])),
  );
  const items = page.rows.map((row): VulnerabilityItem => {
    const present = new Set(row.targets);
    return {
      vulnerabilityId: row.vulnerability_id,
      packageName: row.package_name,
      ecosystem: row.ecosystem,
      severity: SEVERITIES[row.sev_rank] ?? 'unknown',
      title: row.title,
      primaryUrl: row.primary_url,
      installedVersions: [...row.installed].sort(),
      fixedVersion: row.fixed_version,
      in: scope.filter((t) => present.has(`${t.kind}:${t.id}`)),
      notIn: q.target ? [] : scope.filter((t) => !present.has(`${t.kind}:${t.id}`)),
      foundAt: row.found_at,
      withoutScan: row.without_scan,
      new: row.is_new,
      ignored: row.ignored,
      status: row.status,
      decision: row.decision_id === null ? null : (decisions.get(row.decision_id) ?? null),
    };
  });
  return { items, total };
}

export async function decisionsOf(
  db: Executor,
  ids: readonly string[],
): Promise<Map<string, DecisionDto>> {
  if (ids.length === 0) return new Map();
  const rows = await db
    .select({
      decision: vulnerabilityDecisions,
      userId: users.id,
      displayName: users.displayName,
      username: users.username,
    })
    .from(vulnerabilityDecisions)
    .leftJoin(users, eq(users.id, vulnerabilityDecisions.decidedBy))
    .where(inArray(vulnerabilityDecisions.id, [...ids]));
  return new Map(
    rows.map(({ decision: d, userId, displayName, username }) => [
      d.id,
      {
        id: d.id,
        scope: d.branchId !== null ? 'branch' : d.versionId !== null ? 'version' : 'project',
        status: d.status,
        reason: d.reason as VexJustification | null,
        comment: d.comment,
        decidedAt: d.decidedAt.toISOString(),
        decidedBy: userId === null ? null : { id: userId, name: displayName ?? username ?? '' },
      },
    ]),
  );
}

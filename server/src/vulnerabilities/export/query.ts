import { and, eq, sql } from 'drizzle-orm';
import { listAllDependencies, type DependencyTarget } from '../../dependencies/query';
import type { Executor } from '../../db/client';
import { branches, projectVersions, vulnerabilityTargetChecks } from '../../db/schema';
import { notFound } from '../../http/problem';
import { decisionsOf } from '../list';
import { purlOf } from '../purl';
import { SEVERITIES, scopedRows, type VulnerabilitySeverity } from '../summary';
import type { ExportPackage } from './types';
import type { VexEntry } from './vex-documents';

/** Code-unit order: the same on every database collation. */
const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export interface ResolvedExportTarget {
  target: DependencyTarget;
  name: string;
  kind: 'branch' | 'version';
}

/**
 * E1: the version labelled `version`, else the branch named `branch`, else the main branch. A
 * merge request is no target. The caller has already refused both being given.
 */
export async function exportTarget(
  db: Executor,
  project: { id: string },
  query: { branch?: string; version?: string },
): Promise<ResolvedExportTarget> {
  if (query.version !== undefined) {
    const [row] = await db
      .select({ id: projectVersions.id, label: projectVersions.label })
      .from(projectVersions)
      .where(
        and(eq(projectVersions.projectId, project.id), eq(projectVersions.label, query.version)),
      );
    if (!row) throw notFound('Version');
    return { target: { kind: 'version', versionId: row.id }, name: row.label, kind: 'version' };
  }
  const [row] = await db
    .select({ id: branches.id, name: branches.name })
    .from(branches)
    .where(
      and(
        eq(branches.projectId, project.id),
        eq(branches.kind, 'branch'),
        query.branch === undefined ? eq(branches.isMain, true) : eq(branches.name, query.branch),
      ),
    );
  if (!row) throw notFound('Branch');
  return { target: { kind: 'branch', branchId: row.id }, name: row.name, kind: 'branch' };
}

/**
 * E5: the packages of the target, once each, sorted by name, version and ecosystem. A package is
 * the same when its reference is: its purl, which two ecosystems (npm and yarn) can share, else
 * its ecosystem, name and version. The licences of the copies are joined. The builders do not
 * deduplicate, and a repeated `bom-ref` makes a document invalid.
 */
export async function exportPackages(
  db: Executor,
  target: DependencyTarget,
): Promise<ExportPackage[]> {
  const rows = await listAllDependencies(db, target, {});
  const sorted = rows
    .map((r) => ({
      ecosystem: r.ecosystem,
      name: r.name,
      version: r.version,
      purl: purlOf(r.ecosystem, r.name, r.version),
      licenses: r.licenses,
    }))
    .sort(
      (a, b) =>
        compare(a.name, b.name) ||
        compare(a.version, b.version) ||
        compare(a.ecosystem, b.ecosystem),
    );
  const byRef = new Map<string, ExportPackage>();
  for (const p of sorted) {
    const ref = p.purl ?? `${p.ecosystem}:${p.name}@${p.version}`;
    const have = byRef.get(ref);
    if (!have) byRef.set(ref, { ...p, licenses: [...new Set(p.licenses)] });
    else
      for (const license of p.licenses)
        if (!have.licenses.includes(license)) have.licenses.push(license);
  }
  return [...byRef.values()];
}

interface VexRow extends Record<string, unknown> {
  vulnerability_id: string;
  package_name: string;
  purl: string;
  severity: VulnerabilitySeverity;
  title: string | null;
  primary_url: string | null;
  fixed_version: string | null;
  eff_status: VexEntry['status'];
  d_id: string | null;
}

const RANK = new Map<string, number>(SEVERITIES.map((s, i) => [s, i]));

/**
 * E6: one entry per (vulnerability id, package name) on the target, with the decision in force on
 * it. Rows ignored by `.trivyignore` are left out. When the versions of a package differ in
 * severity, title or fix, the entry carries the worst severity's (then the lowest purl's) facts.
 * Sorted by vulnerability id, then package name; the purls are distinct and sorted.
 */
export async function vexEntries(
  db: Executor,
  projectId: string,
  target: DependencyTarget,
): Promise<VexEntry[]> {
  const column = target.kind === 'branch' ? sql`tv.branch_id` : sql`tv.version_id`;
  const id = target.kind === 'branch' ? target.branchId : target.versionId;
  const result = await db.execute<VexRow>(sql`
    WITH r AS (${scopedRows(sql`tv.project_id = ${projectId} AND ${column} = ${id}`)})
    SELECT vulnerability_id, package_name, purl, severity, title, primary_url, fixed_version,
           eff_status, d_id
      FROM r
     WHERE NOT ignored`);

  const groups = new Map<string, VexRow[]>();
  for (const row of result.rows) {
    const key = JSON.stringify([row.vulnerability_id, row.package_name]);
    const group = groups.get(key);
    if (group) group.push(row);
    else groups.set(key, [row]);
  }
  const decisions = await decisionsOf(
    db,
    [...groups.values()].flatMap((g) => (g[0]?.d_id ? [g[0].d_id] : [])),
  );
  const entries: VexEntry[] = [];
  for (const group of groups.values()) {
    const [head] = [...group].sort(
      (a, b) =>
        (RANK.get(a.severity) ?? SEVERITIES.length) - (RANK.get(b.severity) ?? SEVERITIES.length) ||
        compare(a.purl, b.purl),
    );
    if (!head) continue;
    const decision = head.d_id === null ? undefined : decisions.get(head.d_id);
    entries.push({
      vulnerabilityId: head.vulnerability_id,
      severity: head.severity,
      title: head.title,
      primaryUrl: head.primary_url,
      fixedVersion: head.fixed_version,
      packageName: head.package_name,
      purls: [...new Set(group.map((r) => r.purl))].sort(compare),
      status: head.eff_status,
      reason: decision?.reason ?? null,
      comment: decision?.comment ?? null,
      decidedAt: decision ? new Date(decision.decidedAt) : null,
      decidedBy: decision?.decidedBy?.name ?? null,
    });
  }
  return entries.sort(
    (a, b) =>
      compare(a.vulnerabilityId, b.vulnerabilityId) || compare(a.packageName, b.packageName),
  );
}

/** Whether the target has had a vulnerability check (an untracked version keeps its row). */
export async function targetChecked(db: Executor, target: DependencyTarget): Promise<boolean> {
  const [row] = await db
    .select({ projectId: vulnerabilityTargetChecks.projectId })
    .from(vulnerabilityTargetChecks)
    .where(
      target.kind === 'branch'
        ? eq(vulnerabilityTargetChecks.branchId, target.branchId)
        : eq(vulnerabilityTargetChecks.versionId, target.versionId),
    )
    .limit(1);
  return row !== undefined;
}

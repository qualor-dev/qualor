import { eq } from 'drizzle-orm';
import type { Executor } from '../src/db/client';
import {
  analyses,
  branchDependencies,
  projectVersions,
  targetVulnerabilities,
  vulnerabilityMatches,
  vulnerabilityTargetChecks,
} from '../src/db/schema';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
type TargetKey = { branchId: string } | { versionId: string };

export const purlFor = (name: string, version: string, ecosystem = 'npm'): string =>
  `pkg:${ecosystem}/${name}@${version}`;

/**
 * A `vulnerability_matches` row for (purl, vulnerability), with Trivy's vendor ids (none unless
 * given); a second call replaces the first.
 */
export async function seedMatch(
  db: Executor,
  match: {
    purl: string;
    vulnerabilityId: string;
    severity?: Severity;
    title?: string | null;
    fixedVersion?: string | null;
    primaryUrl?: string | null;
    vendorIds?: string[];
  },
): Promise<void> {
  const values = {
    purl: match.purl,
    vulnerabilityId: match.vulnerabilityId,
    severity: match.severity ?? 'high',
    title: match.title ?? null,
    fixedVersion: match.fixedVersion ?? null,
    primaryUrl: match.primaryUrl ?? null,
    vendorIds: match.vendorIds ?? [],
  };
  await db
    .insert(vulnerabilityMatches)
    .values(values)
    .onConflictDoUpdate({
      target: [vulnerabilityMatches.purl, vulnerabilityMatches.vulnerabilityId],
      set: values,
    });
}

/**
 * A `target_vulnerabilities` row of a branch or a version, and the match it joins (severity
 * `high` unless given). `firstSeenAt` defaults to now.
 */
export async function seedTargetRow(
  db: Executor,
  row: TargetKey & {
    projectId: string;
    packageName: string;
    packageVersion?: string;
    ecosystem?: string;
    vulnerabilityId: string;
    severity?: Severity;
    title?: string | null;
    fixedVersion?: string | null;
    ignored?: boolean;
    firstSeenAt?: Date;
  },
): Promise<void> {
  const packageVersion = row.packageVersion ?? '1.0.0';
  const ecosystem = row.ecosystem ?? 'npm';
  const purl = purlFor(row.packageName, packageVersion, ecosystem);
  await seedMatch(db, {
    purl,
    vulnerabilityId: row.vulnerabilityId,
    ...(row.severity !== undefined && { severity: row.severity }),
    ...(row.title !== undefined && { title: row.title }),
    ...(row.fixedVersion !== undefined && { fixedVersion: row.fixedVersion }),
  });
  await db.insert(targetVulnerabilities).values({
    projectId: row.projectId,
    branchId: 'branchId' in row ? row.branchId : null,
    versionId: 'versionId' in row ? row.versionId : null,
    ecosystem,
    packageName: row.packageName,
    packageVersion,
    purl,
    vulnerabilityId: row.vulnerabilityId,
    ignored: row.ignored ?? false,
    ...(row.firstSeenAt !== undefined && { firstSeenAt: row.firstSeenAt }),
  });
}

/** A `vulnerability_target_checks` row: the target was re-checked, and "new" counts from the baseline. */
export async function seedCheck(
  db: Executor,
  check: TargetKey & { projectId: string; baselineAt: Date; checkedAt?: Date; basis?: string },
): Promise<void> {
  await db.insert(vulnerabilityTargetChecks).values({
    projectId: check.projectId,
    branchId: 'branchId' in check ? check.branchId : null,
    versionId: 'versionId' in check ? check.versionId : null,
    basis: check.basis ?? 'seed',
    baselineAt: check.baselineAt,
    checkedAt: check.checkedAt ?? check.baselineAt,
  });
}

/**
 * The branch has an empty dependency inventory: a `succeeded` analysis whose `trivy-licenses`
 * engine is `ok` (the licence pass ran and found nothing), and no `branch_dependencies` row.
 */
export async function seedEmptyInventory(
  db: Executor,
  target: { projectId: string; branchId: string },
): Promise<void> {
  await db.insert(analyses).values({
    projectId: target.projectId,
    branchId: target.branchId,
    status: 'succeeded',
    revision: 'a'.repeat(40),
    analysisDate: new Date(),
    baselineStatus: 'first_analysis',
    scannerVersion: '0.0.0-test',
    engines: [
      {
        id: 'trivy-licenses',
        kind: 'builtin',
        version: null,
        status: 'ok',
        reason: null,
        durationMs: 1,
      },
    ],
  });
}

/**
 * The target has a dependency inventory: a branch gets an analysis and one `branch_dependencies`
 * row, a version gets `has_inventory`. A second call changes nothing.
 */
export async function seedInventory(
  db: Executor,
  target: TargetKey & { projectId: string },
): Promise<void> {
  if ('versionId' in target) {
    await db
      .update(projectVersions)
      .set({ hasInventory: true })
      .where(eq(projectVersions.id, target.versionId));
    return;
  }
  const have = await db
    .select({ name: branchDependencies.name })
    .from(branchDependencies)
    .where(eq(branchDependencies.branchId, target.branchId))
    .limit(1);
  if (have.length > 0) return;
  const analysis = await db
    .insert(analyses)
    .values({ projectId: target.projectId, branchId: target.branchId, status: 'queued' })
    .returning({ id: analyses.id });
  await db.insert(branchDependencies).values({
    branchId: target.branchId,
    path: 'package.json',
    ecosystem: 'npm',
    name: 'lodash',
    version: '1.0.0',
    licenses: [],
    analysisId: analysis[0]!.id,
  });
}

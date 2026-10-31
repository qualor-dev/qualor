import type { Executor } from '../src/db/client';
import {
  targetVulnerabilities,
  vulnerabilityMatches,
  vulnerabilityTargetChecks,
} from '../src/db/schema';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
type TargetKey = { branchId: string } | { versionId: string };

export const purlFor = (name: string, version: string, ecosystem = 'npm'): string =>
  `pkg:${ecosystem}/${name}@${version}`;

/** A `vulnerability_matches` row for (purl, vulnerability); a second call replaces the first. */
export async function seedMatch(
  db: Executor,
  match: {
    purl: string;
    vulnerabilityId: string;
    severity?: Severity;
    title?: string | null;
    fixedVersion?: string | null;
    primaryUrl?: string | null;
  },
): Promise<void> {
  const values = {
    purl: match.purl,
    vulnerabilityId: match.vulnerabilityId,
    severity: match.severity ?? 'high',
    title: match.title ?? null,
    fixedVersion: match.fixedVersion ?? null,
    primaryUrl: match.primaryUrl ?? null,
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

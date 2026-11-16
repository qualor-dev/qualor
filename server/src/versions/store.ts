import { and, eq, sql, type SQLWrapper } from 'drizzle-orm';
import type { DependencyIgnore, SbomDistribution } from '@qualor/shared';
import type { Executor } from '../db/client';
import {
  projectVersions,
  versionDependencies,
  type ProjectVersionRow,
  type VersionSource,
} from '../db/schema';
import { insertDependencyRows, type VersionDependencyEntry } from '../measures/store';

export type { VersionDependencyEntry } from '../measures/store';

export interface UpsertVersionInput {
  projectId: string;
  label: string;
  source: VersionSource;
  tag: string | null;
  /** Null only for an uploaded SBOM (`source: 'sbom'`), which has no analysis. */
  analysisId: string | null;
  analyzedAt: Date;
  /**
   * The report's dependency inventory and `.trivyignore` ids (null when it carried none). Left
   * out when the report carried no inventory: an existing version then keeps its packages and its
   * ids, and its analysis and date unless a higher-ranked write takes it over.
   */
  inventory?: {
    dependencies: readonly VersionDependencyEntry[];
    ignores: DependencyIgnore[] | null;
  };
  /** An uploaded SBOM's origin and distribution; stored with `source: 'sbom'` only. */
  sbom?: { format: string; subject: string | null; distribution: SbomDistribution | null };
}

/** The version as written, and the source it had before (null: this write created it). */
export interface UpsertVersionResult {
  version: ProjectVersionRow;
  previous: VersionSource | null;
}

/**
 * Precedence between the sources of a version (spec §6.6): a tag scan is the release, an uploaded
 * SBOM is the user's explicit act, and a branch's `project.version` only a hint.
 */
const RANK: Record<VersionSource, number> = { tag: 3, sbom: 2, label: 1 };

/** {@link RANK} in SQL, for the source column or `excluded.source`. */
const rankOf = (source: SQLWrapper) =>
  sql`(CASE ${source} WHEN 'tag' THEN 3 WHEN 'sbom' THEN 2 ELSE 1 END)`;

/**
 * Creates the version of `label`, or points the existing one at this write (its source and tag
 * follow, so a tag scan turns a version taken from a label or an SBOM into a tag version). With an
 * inventory, the version's packages and `.trivyignore` ids are replaced by the write's. The
 * `tracking` override is the user's and stays. An SBOM write stores its origin and distribution;
 * any other write clears them, with or without an inventory (ruling R5).
 *
 * Precedence is tag > sbom > label. A lower-ranked write meeting a higher-ranked version changes
 * nothing and returns `'kept'` (a label write) or `'taken'` (an SBOM write); a higher-ranked write
 * takes the version over.
 *
 * Returns `'stale'`, changing nothing, when a write of the version's own source (tag or label)
 * was analysed earlier than the stored one: an older scan never replaces a newer inventory. A
 * takeover is never stale, and neither is an SBOM write: the upload is the user's act, dated by
 * the server (ruling R5).
 *
 * The overloads say what each source can meet: a tag write is never `'kept'` or `'taken'`, an SBOM
 * write never `'stale'` or `'kept'`.
 */
export async function upsertVersion(
  tx: Executor,
  input: UpsertVersionInput & { source: 'tag' },
): Promise<UpsertVersionResult | 'stale'>;
export async function upsertVersion(
  tx: Executor,
  input: UpsertVersionInput & { source: 'sbom' },
): Promise<UpsertVersionResult | 'taken'>;
export async function upsertVersion(
  tx: Executor,
  input: UpsertVersionInput,
): Promise<UpsertVersionResult | 'stale' | 'kept' | 'taken'>;
export async function upsertVersion(
  tx: Executor,
  input: UpsertVersionInput,
): Promise<UpsertVersionResult | 'stale' | 'kept' | 'taken'> {
  return upsertOnce(tx, input, false);
}

/**
 * {@link upsertVersion}; `reread`: this is the second read, after an upsert that returned no row.
 * That happens once, when a concurrent writer created the version after the first read; the second
 * read locks it, so a second miss is an error, never a loop.
 */
async function upsertOnce(
  tx: Executor,
  input: UpsertVersionInput,
  reread: boolean,
): Promise<UpsertVersionResult | 'stale' | 'kept' | 'taken'> {
  // Locked: the version judged here is the one the write below meets.
  const [existing] = await tx
    .select({ analyzedAt: projectVersions.analyzedAt, source: projectVersions.source })
    .from(projectVersions)
    .where(
      and(eq(projectVersions.projectId, input.projectId), eq(projectVersions.label, input.label)),
    )
    .for('no key update');
  if (existing && RANK[existing.source] > RANK[input.source]) {
    return input.source === 'sbom' ? 'taken' : 'kept';
  }
  const takesOver = existing !== undefined && RANK[input.source] > RANK[existing.source];
  if (
    existing?.source === input.source &&
    input.source !== 'sbom' &&
    existing.analyzedAt.getTime() > input.analyzedAt.getTime()
  ) {
    return 'stale';
  }
  const { inventory } = input;
  const sbom = input.source === 'sbom' ? input.sbom : undefined;
  const owner = {
    source: input.source,
    tag: input.tag,
    osFamily: sbom?.distribution?.family ?? null,
    osVersion: sbom?.distribution?.version ?? null,
    sbomFormat: sbom?.format ?? null,
    sbomSubject: sbom?.subject ?? null,
  };
  const snapshot = {
    analysisId: input.analysisId,
    analyzedAt: input.analyzedAt,
    dependencyIgnores: inventory?.ignores ?? null,
    // Even an empty inventory counts: the version was scanned and has no packages.
    ...(inventory && { hasInventory: true }),
  };
  const [version] = await tx
    .insert(projectVersions)
    .values({ projectId: input.projectId, label: input.label, ...owner, ...snapshot })
    .onConflictDoUpdate({
      target: [projectVersions.projectId, projectVersions.label],
      set: {
        ...owner,
        // Without an inventory a takeover still dates the version by its write; the version
        // keeps its packages and ids, and so its has_inventory.
        ...(takesOver && { analysisId: input.analysisId, analyzedAt: input.analyzedAt }),
        ...(inventory && snapshot),
        updatedAt: sql`now()`,
      },
      // Under the row's lock. The version judged above passes the precedence rule again. One
      // that a concurrent writer created and committed after the read is left as it is (though
      // locked now) and judged below, so that no rank, staleness or previous source is missed.
      setWhere: existing
        ? sql`${rankOf(projectVersions.source)} <= ${rankOf(sql`excluded.source`)}`
        : sql`false`,
    })
    .returning();
  if (version === undefined) {
    if (reread) {
      throw new Error(
        `no row for version ${input.label} of project ${input.projectId} after a second read`,
      );
    }
    return upsertOnce(tx, input, true);
  }
  if (inventory) {
    // Duplicates merged as for a branch.
    await tx.delete(versionDependencies).where(eq(versionDependencies.versionId, version.id));
    await insertDependencyRows(
      tx,
      'version_dependencies',
      version.id,
      input.analysisId,
      inventory.dependencies,
    );
  }
  return { version, previous: existing?.source ?? null };
}

import { and, eq, sql } from 'drizzle-orm';
import type { DependencyEntry, DependencyIgnore } from '@qualor/shared';
import type { Executor } from '../db/client';
import { projectVersions, versionDependencies, type ProjectVersionRow } from '../db/schema';
import { insertDependencyRows } from '../measures/store';

export interface UpsertVersionInput {
  projectId: string;
  label: string;
  source: 'tag' | 'label';
  tag: string | null;
  analysisId: string;
  analyzedAt: Date;
  /**
   * The report's dependency inventory and `.trivyignore` ids (null when it carried none). Left
   * out when the report carried no inventory: an existing version then keeps its packages, its
   * ids, its analysis and its date.
   */
  inventory?: { dependencies: readonly DependencyEntry[]; ignores: DependencyIgnore[] | null };
}

/**
 * Creates the version of `label`, or points the existing one at this analysis (its source and tag
 * follow, so a tag scan turns a version taken from a label into a tag version). With an inventory,
 * the version's packages and `.trivyignore` ids are replaced by the analysis's. The `tracking`
 * override is the user's and stays.
 *
 * Returns `'kept'`, changing nothing, when a `label` write meets a version a tag scan made: the
 * tag is the release and a branch's `project.version` never replaces it.
 *
 * Returns `'stale'`, changing nothing, when the stored version was analysed later than
 * `analyzedAt`: an older scan never replaces a newer inventory. A tag scan of a version taken from
 * a label is never stale: the tag is the release, whenever its job ran.
 */
export async function upsertVersion(
  tx: Executor,
  input: UpsertVersionInput,
): Promise<ProjectVersionRow | 'stale' | 'kept'> {
  const [existing] = await tx
    .select({ analyzedAt: projectVersions.analyzedAt, source: projectVersions.source })
    .from(projectVersions)
    .where(
      and(eq(projectVersions.projectId, input.projectId), eq(projectVersions.label, input.label)),
    );
  if (existing?.source === 'tag' && input.source === 'label') return 'kept';
  const takesOver = input.source === 'tag' && existing?.source === 'label';
  if (existing && !takesOver && existing.analyzedAt.getTime() > input.analyzedAt.getTime()) {
    return 'stale';
  }
  const { inventory } = input;
  const owner = { source: input.source, tag: input.tag };
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
      set: { ...owner, ...(inventory ? snapshot : {}), updatedAt: sql`now()` },
      // The 'kept' rule again, under the row's lock: a tag scan's version that committed after
      // the read above is not replaced either.
      setWhere: sql`${projectVersions.source} <> 'tag' OR excluded.source = 'tag'`,
    })
    .returning();
  if (version === undefined) return 'kept';
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
  return version;
}

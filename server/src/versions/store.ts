import { and, eq, sql } from 'drizzle-orm';
import type { DependencyEntry } from '@qualor/shared';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import { projectVersions, versionDependencies, type ProjectVersionRow } from '../db/schema';
import { insertDependencyRows } from '../measures/store';

export interface UpsertVersionInput {
  projectId: string;
  label: string;
  source: 'tag' | 'label';
  tag: string | null;
  analysisId: string;
  analyzedAt: Date;
}

/**
 * Creates the version of `label`, or points the existing one at this analysis (its source and tag
 * follow, so a tag scan turns a version taken from a label into a tag version). The `tracking`
 * override is the user's and stays. Returns `'stale'`, changing nothing, when the stored version
 * was analysed later than `analyzedAt`: an older scan never replaces a newer inventory.
 */
export async function upsertVersion(
  tx: Executor,
  input: UpsertVersionInput,
): Promise<ProjectVersionRow | 'stale'> {
  const [existing] = await tx
    .select({ analyzedAt: projectVersions.analyzedAt })
    .from(projectVersions)
    .where(
      and(eq(projectVersions.projectId, input.projectId), eq(projectVersions.label, input.label)),
    );
  if (existing && existing.analyzedAt.getTime() > input.analyzedAt.getTime()) return 'stale';
  const fields = {
    source: input.source,
    tag: input.tag,
    analysisId: input.analysisId,
    analyzedAt: input.analyzedAt,
  };
  return first(
    await tx
      .insert(projectVersions)
      .values({ projectId: input.projectId, label: input.label, ...fields })
      .onConflictDoUpdate({
        target: [projectVersions.projectId, projectVersions.label],
        set: { ...fields, updatedAt: sql`now()` },
      })
      .returning(),
  );
}

/** The inventory of a version, replaced by the analysis's (duplicates merged as for a branch). */
export async function replaceVersionDependencies(
  tx: Executor,
  versionId: string,
  analysisId: string,
  entries: readonly DependencyEntry[],
): Promise<void> {
  await tx.delete(versionDependencies).where(eq(versionDependencies.versionId, versionId));
  await insertDependencyRows(tx, 'version_dependencies', versionId, analysisId, entries);
}

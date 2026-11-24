import { addedLines } from '../line-diff';
import type { AzureChange, AzureDevOpsClient, AzureIteration } from './client';

/** Files whose two versions one job reads to find the added lines: the rest are unplaced. */
export const MAX_AZURE_DIFF_FILES = 40;

/** The change that holds `path`, unless the file was deleted. */
export const changeOf = (changes: readonly AzureChange[], path: string): AzureChange | null => {
  const change = changes.find((c) => c.path === path);
  return change === undefined || change.changeType.toLowerCase().includes('delete') ? null : change;
};

/**
 * The added lines (line number to text) of each of `paths` that the pull request changed, at most
 * {@link MAX_AZURE_DIFF_FILES} files: the file at the head against the file at the common commit
 * (the original path of a renamed one; none for an added file). A path missing from the result has
 * no place for a comment: deleted, binary, too large or missing, not in the changes, too different
 * to diff, or beyond the bound.
 */
export async function azureAddedLines(
  client: AzureDevOpsClient,
  repositoryId: string,
  analysed: AzureIteration,
  changes: readonly AzureChange[],
  paths: readonly string[],
): Promise<Map<string, ReadonlyMap<number, string>>> {
  const places = new Map<string, ReadonlyMap<number, string>>();
  for (const path of paths.slice(0, MAX_AZURE_DIFF_FILES)) {
    const change = changeOf(changes, path);
    if (change === null) continue;
    const head = await client.fileText(repositoryId, path, analysed.sourceRefCommit);
    if ('skipped' in head) continue;
    let base: string | null = null;
    if (!change.changeType.toLowerCase().includes('add')) {
      const original = await client.fileText(
        repositoryId,
        change.originalPath ?? path,
        analysed.commonRefCommit,
      );
      if ('skipped' in original) continue;
      base = original.text;
    }
    const added = addedLines(base, head.text);
    if (added !== null) places.set(path, added);
  }
  return places;
}

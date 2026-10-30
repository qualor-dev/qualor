import { eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { vulndbDatasets, type VulndbDatasetRow } from '../db/schema';
import type { VulndbState } from './state';

/** A `vulndb_datasets` row. */
export type DatasetRow = VulndbDatasetRow;

/** The dataset the state names as current, or null. */
export async function currentDataset(
  db: Executor,
  state: Pick<VulndbState, 'currentDatasetId'>,
): Promise<DatasetRow | null> {
  if (state.currentDatasetId === null) return null;
  const [row] = await db
    .select()
    .from(vulndbDatasets)
    .where(eq(vulndbDatasets.id, state.currentDatasetId));
  return row ?? null;
}

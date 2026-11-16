import type { SbomDistribution } from '@qualor/shared';
import type { ProjectVersionRow } from '../db/schema';

/** The operating system of an image SBOM version, null when the SBOM named none. */
export function distributionOf(
  row: Pick<ProjectVersionRow, 'osFamily' | 'osVersion'>,
): SbomDistribution | null {
  return row.osFamily === null || row.osVersion === null
    ? null
    : { family: row.osFamily, version: row.osVersion };
}

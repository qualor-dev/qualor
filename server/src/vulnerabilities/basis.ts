import { sql, type SQL } from 'drizzle-orm';

/**
 * What a re-check records as a target's basis (`vulnerability_target_checks.basis`), in SQL over a
 * `branches` row: its last analysis, empty when it has none.
 */
export function branchBasis(branch: string): SQL {
  return sql`coalesce(${sql.identifier(branch)}.last_analysis_id::text, '')`;
}

/**
 * {@link branchBasis} of a `project_versions` row: its analysis time (an SBOM's upload time), in
 * UTC to the millisecond, the same text every run.
 */
export function versionBasis(version: string): SQL {
  return sql`coalesce(to_char(${sql.identifier(version)}.analyzed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), '')`;
}

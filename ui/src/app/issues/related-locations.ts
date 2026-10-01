/** The report's bound on secondary locations (report-format.md, REPORT_BOUNDS.secondaryLocations). */
const MAX_RELATED = 20;

/** One related ("secondary") location of an issue, as the issue page shows it (spec §6). */
export interface RelatedLocation {
  path: string;
  startLine: number;
  endLine: number | null;
  message: string | null;
}

function lineNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1;
}

/**
 * The issue's `secondaryLocations`, read defensively like `readSnippet`: an older server or a
 * hand-made report may carry anything there, so a malformed entry is dropped, never shown.
 */
export function readRelatedLocations(raw: unknown): RelatedLocation[] {
  if (!Array.isArray(raw)) return [];
  const out: RelatedLocation[] = [];
  for (const entry of raw) {
    if (out.length >= MAX_RELATED) break;
    const location = readRelatedLocation(entry);
    if (location) out.push(location);
  }
  return out;
}

function readRelatedLocation(entry: unknown): RelatedLocation | null {
  if (typeof entry !== 'object' || entry === null) return null;
  const e = entry as Record<string, unknown>;
  if (typeof e['path'] !== 'string' || e['path'] === '' || !lineNumber(e['startLine'])) return null;
  const end = e['endLine'];
  if (end !== undefined && (!lineNumber(end) || end < e['startLine'])) return null;
  return {
    path: e['path'],
    startLine: e['startLine'],
    endLine: end === undefined ? null : end,
    message: typeof e['message'] === 'string' && e['message'] !== '' ? e['message'] : null,
  };
}

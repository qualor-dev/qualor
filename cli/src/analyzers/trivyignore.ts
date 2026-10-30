import { REPORT_BOUNDS, type DependencyIgnore } from '@qualor/shared';

const EXPIRY = /(?:^|\s)exp:(\d{4}-\d{2}-\d{2})(?=\s|$)/;

/** A calendar date `YYYY-MM-DD` that exists (2026-02-30 does not). */
function validDate(text: string): boolean {
  const d = new Date(`${text}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(text);
}

/**
 * The vulnerability ids of a `.trivyignore`, for the report's `dependencyIgnores`. The id is the
 * first token of a line; `exp:YYYY-MM-DD` anywhere on it sets `expiresAt` (an invalid date is
 * dropped). A repeated id is kept once with its latest valid expiry. Ids over the report bound are
 * skipped; entries past `REPORT_BOUNDS.dependencyIgnores` are cut (`truncated`).
 */
export function parseTrivyIgnore(text: string): {
  entries: DependencyIgnore[];
  truncated: boolean;
} {
  const byId = new Map<string, DependencyIgnore>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const id = line.split(/\s+/)[0];
    if (id === undefined || id.length > REPORT_BOUNDS.ruleIdChars) continue;
    const date = EXPIRY.exec(line)?.[1];
    const expiresAt = date !== undefined && validDate(date) ? date : undefined;
    const known = byId.get(id);
    if (known === undefined) {
      byId.set(id, expiresAt === undefined ? { id } : { id, expiresAt });
    } else if (
      expiresAt !== undefined &&
      (known.expiresAt === undefined || expiresAt > known.expiresAt)
    ) {
      known.expiresAt = expiresAt;
    }
  }
  const all = [...byId.values()];
  const max = REPORT_BOUNDS.dependencyIgnores;
  return { entries: all.slice(0, max), truncated: all.length > max };
}

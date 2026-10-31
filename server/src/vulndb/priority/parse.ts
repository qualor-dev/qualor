import { promisify } from 'node:util';
import { gunzip } from 'node:zlib';
import { z } from 'zod';

const gunzipAsync = promisify(gunzip);

/**
 * A priority file (KEV, EPSS) is at most this many bytes as downloaded or uploaded. The real files
 * are 1.5 to 12 MB; the caps keep the worst-case buffers within a small deployment's memory.
 */
export const PRIORITY_FILE_MAX_BYTES = 32 * 1024 * 1024;
/** ...and an EPSS file at most this many bytes inflated (the real one is about 12 MB). */
export const PRIORITY_DATA_MAX_BYTES = 64 * 1024 * 1024;
/**
 * A KEV catalog is at most this many bytes inflated (the real one is about 1.5 MB). `JSON.parse`
 * builds every value at once, so this cap bounds its heap: 8 MiB of `{},` is about 180 MB.
 */
export const KEV_DATA_MAX_BYTES = 8 * 1024 * 1024;
/** At most this many entries in a KEV catalog (the real one has about 1 500). */
export const KEV_MAX_ENTRIES = 100_000;
/**
 * At most this many lines in an EPSS file, blank and comment lines included (the real one has
 * about 300 000).
 */
export const EPSS_MAX_LINES = 1_000_000;
/**
 * PostgreSQL's `real` refuses a non-zero value below about 1.2e-38, so a score or percentile below
 * this one is skipped instead of failing the whole file.
 */
const REAL_MIN = 1e-37;

/** Test seam; production uses the constants above. */
export interface PriorityLimits {
  maxDataBytes?: number;
  /** KEV entries. */
  maxEntries?: number;
  /** EPSS lines. */
  maxLines?: number;
}

export type PriorityProblem = {
  problem: { code: 'INVALID_DATA' | 'TOO_LARGE'; message: string };
};

export interface KevEntry {
  vulnerabilityId: string;
  /** YYYY-MM-DD */
  dateAdded: string;
  ransomware: boolean;
}

export interface KevFile {
  catalogVersion: string;
  releasedAt: Date;
  entries: KevEntry[];
  skipped: number;
}

/** Column arrays, which feed `unnest` directly. */
export interface EpssFile {
  scoreDate: Date | null;
  modelVersion: string | null;
  ids: string[];
  scores: number[];
  percentiles: number[];
  skipped: number;
}

const CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,19}$/;

function invalid(message: string): PriorityProblem {
  return { problem: { code: 'INVALID_DATA', message } };
}

function tooLarge(message: string): PriorityProblem {
  return { problem: { code: 'TOO_LARGE', message } };
}

/** Whether `YYYY-MM-DD` names a real calendar day. */
function isCalendarDate(value: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (m === null) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(Date.UTC(y, mo - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === mo - 1 && date.getUTCDate() === d;
}

/**
 * A date-time with a real calendar day and an offset of `Z`, `±HH:MM` or `±HHMM` (older EPSS
 * files), as a Date; null if it is not one.
 */
function parseDateTime(value: string): Date | null {
  const m = /^((\d{4}-\d{2}-\d{2})T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)(Z|([+-]\d{2}):?(\d{2}))$/.exec(
    value,
  );
  if (m === null || !isCalendarDate(m[2] as string)) return null;
  const offset = m[3] === 'Z' ? 'Z' : `${m[4] as string}:${m[5] as string}`;
  const time = Date.parse(`${m[1] as string}${offset}`);
  return Number.isNaN(time) ? null : new Date(time);
}

/** The text of a file: inflated if it is gzip, bounded. */
async function readText(body: Buffer, maxBytes: number): Promise<string | PriorityProblem> {
  let raw = body;
  if (body.length >= 2 && body[0] === 0x1f && body[1] === 0x8b) {
    try {
      raw = await gunzipAsync(body, { maxOutputLength: maxBytes });
    } catch (err) {
      if (err instanceof RangeError || (err as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE') {
        return tooLarge(`The file is larger than ${maxBytes} bytes when inflated.`);
      }
      return invalid('The file is not valid gzip.');
    }
  }
  if (raw.length > maxBytes) return tooLarge(`The file is larger than ${maxBytes} bytes.`);
  const text = raw.toString('utf8');
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

const kevTop = z.object({
  catalogVersion: z.string().min(1),
  dateReleased: z.string(),
  vulnerabilities: z.array(z.unknown()),
});

const kevEntry = z.object({
  cveID: z.string().regex(CVE_ID),
  dateAdded: z.string().refine(isCalendarDate),
  knownRansomwareCampaignUse: z.unknown().optional(),
});

export async function parseKev(
  body: Buffer,
  limits: PriorityLimits = {},
): Promise<KevFile | PriorityProblem> {
  try {
    const text = await readText(body, limits.maxDataBytes ?? KEV_DATA_MAX_BYTES);
    if (typeof text !== 'string') return text;
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      return invalid('The KEV catalog is not valid JSON.');
    }
    const top = kevTop.safeParse(json);
    if (!top.success) return invalid('The KEV catalog lacks its version, date or entries.');
    const releasedAt = parseDateTime(top.data.dateReleased);
    if (releasedAt === null) return invalid('The KEV catalog has no valid release date.');
    const maxEntries = limits.maxEntries ?? KEV_MAX_ENTRIES;
    if (top.data.vulnerabilities.length > maxEntries) {
      return tooLarge(`The KEV catalog has more than ${maxEntries} entries.`);
    }
    const entries: KevEntry[] = [];
    const seen = new Set<string>();
    let skipped = 0;
    for (const item of top.data.vulnerabilities) {
      const parsed = kevEntry.safeParse(item);
      if (!parsed.success) {
        skipped++;
        continue;
      }
      const id = parsed.data.cveID;
      if (seen.has(id)) continue;
      seen.add(id);
      entries.push({
        vulnerabilityId: id,
        dateAdded: parsed.data.dateAdded,
        ransomware: parsed.data.knownRansomwareCampaignUse === 'Known',
      });
    }
    if (entries.length === 0) return invalid('The KEV catalog has no valid entry.');
    return { catalogVersion: top.data.catalogVersion, releasedAt, entries, skipped };
  } catch {
    return invalid('The KEV catalog could not be read.');
  }
}

/** A decimal number in [0, 1], or null. */
function unit(value: string | undefined): number | null {
  // A long cell is refused before the regex runs, so a long digit run cannot backtrack.
  if (value === undefined || value.length > 32) return null;
  if (!/^[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$/.test(value)) return null;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 1) return null;
  return n !== 0 && n < REAL_MIN ? null : n;
}

export async function parseEpss(
  body: Buffer,
  limits: PriorityLimits = {},
): Promise<EpssFile | PriorityProblem> {
  try {
    const text = await readText(body, limits.maxDataBytes ?? PRIORITY_DATA_MAX_BYTES);
    if (typeof text !== 'string') return text;
    const maxLines = limits.maxLines ?? EPSS_MAX_LINES;
    let scoreDate: Date | null = null;
    let modelVersion: string | null = null;
    let headerSeen = false;
    const ids: string[] = [];
    const scores: number[] = [];
    const percentiles: number[] = [];
    let skipped = 0;
    const seen = new Set<string>();
    let lines = 0;
    // One line at a time, never `split('\n')`: 64 MiB of newlines would be a 67M-element array.
    // Every split below has a limit for the same reason, so a long line costs no more than its text.
    for (let start = 0; start < text.length;) {
      const newline = text.indexOf('\n', start);
      const end = newline === -1 ? text.length : newline;
      let line = text.slice(start, end);
      start = end + 1;
      if (++lines > maxLines) return tooLarge(`The EPSS file has more than ${maxLines} lines.`);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      if (line.trim() === '') continue;
      if (!headerSeen) {
        if (line.startsWith('#')) {
          for (const part of line.slice(1).split(',', 8)) {
            const colon = part.indexOf(':');
            if (colon === -1) continue;
            const key = part.slice(0, colon).trim();
            const value = part.slice(colon + 1).trim();
            if (key === 'model_version' && value !== '') modelVersion = value;
            if (key === 'score_date') scoreDate = parseDateTime(value);
          }
          continue;
        }
        const columns = line
          .split(',', 4)
          .map((c) => c.trim())
          .join(',')
          .toLowerCase();
        if (columns !== 'cve,epss,percentile') {
          return invalid('The EPSS file does not have the columns cve, epss, percentile.');
        }
        headerSeen = true;
        continue;
      }
      // A fourth cell makes the row invalid, so nothing past it is split.
      const cells = line.split(',', 4).map((c) => c.trim());
      const score = cells.length === 3 ? unit(cells[1]) : null;
      const percentile = cells.length === 3 ? unit(cells[2]) : null;
      const id = cells[0] ?? '';
      if (score === null || percentile === null || !CVE_ID.test(id) || seen.has(id)) {
        skipped++;
        continue;
      }
      seen.add(id);
      ids.push(id);
      scores.push(score);
      percentiles.push(percentile);
    }
    if (!headerSeen) return invalid('The EPSS file has no header.');
    if (ids.length === 0) return invalid('The EPSS file has no valid row.');
    return { scoreDate, modelVersion, ids, scores, percentiles, skipped };
  } catch {
    return invalid('The EPSS file could not be read.');
  }
}

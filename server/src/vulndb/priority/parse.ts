import { promisify } from 'node:util';
import { gunzip } from 'node:zlib';
import { z } from 'zod';

const gunzipAsync = promisify(gunzip);

/** A priority file (KEV, EPSS) is at most this many bytes as downloaded or uploaded. */
export const PRIORITY_FILE_MAX_BYTES = 64 * 1024 * 1024;
/** ...and at most this many bytes inflated. */
export const PRIORITY_DATA_MAX_BYTES = 256 * 1024 * 1024;
/** At most this many entries (KEV) or rows (EPSS) in one file. */
export const EPSS_MAX_ROWS = 2_000_000;

export interface PriorityLimits {
  maxDataBytes?: number;
  maxRows?: number;
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

/** A date-time with a real calendar day, as a Date; null if it is not one. */
function parseDateTime(value: string): Date | null {
  const m = /^(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (m === null || !isCalendarDate(m[1] as string)) return null;
  const time = Date.parse(value);
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
    const text = await readText(body, limits.maxDataBytes ?? PRIORITY_DATA_MAX_BYTES);
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
    const maxRows = limits.maxRows ?? EPSS_MAX_ROWS;
    if (top.data.vulnerabilities.length > maxRows) {
      return tooLarge(`The KEV catalog has more than ${maxRows} entries.`);
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
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : null;
}

export async function parseEpss(
  body: Buffer,
  limits: PriorityLimits = {},
): Promise<EpssFile | PriorityProblem> {
  try {
    const text = await readText(body, limits.maxDataBytes ?? PRIORITY_DATA_MAX_BYTES);
    if (typeof text !== 'string') return text;
    const maxRows = limits.maxRows ?? EPSS_MAX_ROWS;
    let scoreDate: Date | null = null;
    let modelVersion: string | null = null;
    let headerSeen = false;
    const ids: string[] = [];
    const scores: number[] = [];
    const percentiles: number[] = [];
    let skipped = 0;
    const seen = new Set<string>();
    let rows = 0;
    for (let line of text.split('\n')) {
      if (line.endsWith('\r')) line = line.slice(0, -1);
      if (line.trim() === '') continue;
      if (!headerSeen) {
        if (line.startsWith('#')) {
          for (const part of line.slice(1).split(',')) {
            const [key, ...rest] = part.split(':');
            const value = rest.join(':').trim();
            if (key?.trim() === 'model_version' && value !== '') modelVersion = value;
            if (key?.trim() === 'score_date') scoreDate = parseDateTime(value);
          }
          continue;
        }
        const columns = line
          .split(',')
          .map((c) => c.trim())
          .join(',')
          .toLowerCase();
        if (columns !== 'cve,epss,percentile') {
          return invalid('The EPSS file does not have the columns cve, epss, percentile.');
        }
        headerSeen = true;
        continue;
      }
      if (++rows > maxRows) return tooLarge(`The EPSS file has more than ${maxRows} rows.`);
      const cells = line.split(',').map((c) => c.trim());
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

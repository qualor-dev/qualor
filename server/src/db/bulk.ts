import { sql, type SQL } from 'drizzle-orm';

/** Defaults sized for one statement: a few MiB of JSON keeps a single bind value small. */
export const BULK_MAX_ROWS = 5_000;
export const BULK_MAX_BYTES = 4 * 1024 * 1024;

/** Postgres `text` and `jsonb` both reject U+0000; report text (a snippet of a binary-ish file,
 *  a message) may contain it. Every string written through {@link jsonChunks} loses it. */
function withoutNul(_key: string, value: unknown): unknown {
  return typeof value === 'string' && value.includes('\u0000')
    ? value.replaceAll('\u0000', '')
    : value;
}

/**
 * Splits rows into JSON arrays of at most `maxRows` rows and (roughly) `maxBytes` UTF-16 code
 * units each — a single row larger than `maxBytes` still gets its own chunk. Each chunk is bound
 * as ONE parameter and expanded server-side with `jsonb_to_recordset`, so a 100k-row write is a
 * few dozen statements instead of 100k round trips, and never hits the 65 535-parameter limit.
 *
 * A generator, not an eagerly-built array (U5 fix round 1, #5): callers already iterate with
 * `for (const chunk of jsonChunks(rows)) { await tx.execute(...) }`, so yielding each chunk as
 * soon as it is complete lets that chunk be sent (and garbage-collected) before the next one is
 * even built, bounding peak memory to about one chunk instead of every chunk a huge row set would
 * produce.
 */
export function* jsonChunks(
  rows: Iterable<unknown>,
  options: { maxRows?: number; maxBytes?: number } = {},
): Generator<string> {
  const maxRows = options.maxRows ?? BULK_MAX_ROWS;
  const maxBytes = options.maxBytes ?? BULK_MAX_BYTES;
  let current: string[] = [];
  let size = 2;
  for (const row of rows) {
    const json = JSON.stringify(row, withoutNul);
    if (current.length > 0 && (current.length >= maxRows || size + json.length + 1 > maxBytes)) {
      yield `[${current.join(',')}]`;
      current = [];
      size = 2;
    }
    current.push(json);
    size += json.length + 1;
  }
  if (current.length > 0) yield `[${current.join(',')}]`;
}

/** `(SELECT … FROM jsonb_array_elements_text($1))`: an IN-list of any length as one parameter. */
export function textList(values: readonly string[]): SQL {
  return sql`(SELECT jsonb_array_elements_text(${JSON.stringify(values, withoutNul)}::jsonb))`;
}

/** {@link textList} for uuid columns. */
export function uuidList(values: readonly string[]): SQL {
  return sql`(SELECT jsonb_array_elements_text(${JSON.stringify(values)}::jsonb)::uuid)`;
}

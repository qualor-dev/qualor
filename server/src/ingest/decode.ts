import { gunzipSync } from 'node:zlib';
import { REPORT_SCHEMA_VERSION, reportSchema, type Report } from '@qualor/shared';
import type { UploadLimits } from '../config';
import type { AnalysisError } from '../db/schema';

export const MAX_REPORTED_ERRORS = 100;

export type DecodeResult = { ok: true; report: Report } | { ok: false; error: AnalysisError };

/**
 * The minimal logger `decodeStoredReport` needs, structurally compatible with `ProcessLogger`
 * (`ingest/process.ts`) and Fastify's own logger — a caller with either can pass it straight
 * through with no adapter. Optional: omitting it (as every existing test does) just skips logging.
 */
export interface DecodeLogger {
  debug(mergingObject: Record<string, unknown>, msg: string): void;
  warn(mergingObject: Record<string, unknown>, msg: string): void;
}

/**
 * `gunzipSync`'s own `maxOutputLength` guard throws `ERR_BUFFER_TOO_LARGE`. Ruling S13 #3:
 * defensively treat V8's own string-length ceiling (`ERR_STRING_TOO_LONG`) the same way — on some
 * Node builds/architectures `buffer.constants.MAX_STRING_LENGTH` sits below the configured 500 MiB
 * decompressed-bytes cap, so a buffer that passed the byte check can still fail to become a JS
 * string. Either way this is "the report is too large", never "malformed".
 */
export function isDecodedTooLarge(err: unknown): boolean {
  const code =
    typeof err === 'object' && err !== null ? (err as { code?: unknown }).code : undefined;
  return code === 'ERR_BUFFER_TOO_LARGE' || code === 'ERR_STRING_TOO_LONG';
}

/**
 * Well past any nesting the report schema permits (a handful of levels: `findings[].location`,
 * `engines[].rules`, …): a legitimate report never comes close. `JSON.parse` itself will accept
 * far deeper input than this, so {@link stripNulDeep} must refuse it explicitly rather than walk
 * it and find out the hard way.
 */
export const MAX_JSON_DEPTH = 64;

/** Internal to this module: {@link stripNulDeep} raises it for nesting past {@link MAX_JSON_DEPTH};
 *  `decodeStoredReport` turns it into `REPORT_INVALID`, the same deterministic-rejection path as a
 *  schema violation, instead of letting it escape as a retried, non-deterministic failure. */
class JsonTooDeepError extends Error {
  constructor() {
    super('nesting exceeds MAX_JSON_DEPTH');
    // A bare `class X extends Error {}` inherits `.name === 'Error'` from Error.prototype, not its
    // own class name — set explicitly so the type survives into logs and `instanceof` isn't the
    // only way to tell this apart from an ordinary parse failure.
    this.name = 'JsonTooDeepError';
  }
}

/** Internal to this module: raised only by {@link stripNulDeep}'s own defensive assertions — a bug
 *  in this module, never a malformed report. `decodeStoredReport` still turns it into
 *  `REPORT_INVALID` rather than let it escape (retrying can't fix a bug either), but logs it at
 *  `warn` instead of `debug` so it doesn't go unnoticed the way a routine bad report should. */
class StripNulInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StripNulInvariantError';
  }
}

function stripNulString(value: string): string {
  return value.includes('\u0000') ? value.replaceAll('\u0000', '') : value;
}

interface ArrayFrame {
  readonly kind: 'array';
  readonly source: readonly unknown[];
  result: unknown[] | null;
  index: number;
}

interface ObjectFrame {
  readonly kind: 'object';
  readonly source: Readonly<Record<string, unknown>>;
  readonly keys: readonly string[];
  result: Record<string, unknown> | null;
  index: number;
  /** The clean key for the child one level down, currently being walked (its own descendants may
   *  push further frames before it resolves); read back once that child's frame is popped. */
  pendingKey: string | null;
}

type Frame = ArrayFrame | ObjectFrame;

function frameFor(value: object): Frame {
  if (Array.isArray(value)) return { kind: 'array', source: value, result: null, index: 0 };
  const source = value as Record<string, unknown>;
  return {
    kind: 'object',
    source,
    keys: Object.keys(source),
    result: null,
    index: 0,
    pendingKey: null,
  };
}

function ensureArrayResult(frame: ArrayFrame, uptoExclusive: number): void {
  frame.result ??= frame.source.slice(0, uptoExclusive);
}

/**
 * `copy[key] = value` looks up `key` on `copy`'s prototype chain first: for the one key literally
 * named `"__proto__"` — an ordinary own property on any object `JSON.parse` builds, and one
 * `properties`/`partialFingerprints` (arbitrary-keyed records) can legitimately carry — that finds
 * `Object.prototype`'s inherited `__proto__` *accessor*, not a plain own slot on `copy`. Its setter
 * then either replaces `copy`'s actual prototype (an object/`null` value) or silently drops the
 * assignment (any other value), instead of ever creating an own `"__proto__"` property — a classic
 * prototype-pollution footgun. `Object.defineProperty` bypasses inherited accessors entirely and
 * always defines a genuine own data property, whatever the key.
 */
function setOwn(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

function ensureObjectResult(frame: ObjectFrame, uptoExclusive: number): void {
  if (frame.result) return;
  const copy: Record<string, unknown> = {};
  for (let j = 0; j < uptoExclusive; j += 1) {
    const k = frame.keys[j];
    if (k !== undefined) setOwn(copy, k, frame.source[k]);
  }
  frame.result = copy;
}

/**
 * Ruling U4: Postgres `text` and `jsonb` both reject U+0000 (`db/bulk.ts`'s `withoutNul`, kept as
 * defence in depth for values built server-side). A report is untrusted input and any string in
 * it — a rule id, a message, a path, even a `properties`/`partialFingerprints` key — may carry
 * one. Stripped too late (e.g. only at the point each stage writes), two stages can derive
 * different keys for what should be the same value (a rule upserted as `"eslint:ab"` but looked
 * up as `"eslint:a\0b"`), wedging ingestion. Stripping it here, once, right after `JSON.parse` and
 * before schema validation, means every stage — and the validation itself (path/length/key-count
 * checks) — sees the exact string that will end up stored. Object keys are walked too, not just
 * values: `properties` and `partialFingerprints` are user-defined records, so a NUL can arrive as
 * a key. Two distinct keys that collide once stripped resolve last-wins, in report order — the
 * same rule `JSON.parse` itself uses for two literally identical keys in the source text (later
 * assignment overwrites the value in place; the key keeps the *earlier* one's position). A key
 * literally `"__proto__"` (which `JSON.parse` itself makes an ordinary own property, never the
 * object's prototype) is written back the same way, via {@link setOwn}: every clone is built with
 * `Object.defineProperty`, never `obj[key] = value`, so it can never pollute the clone's prototype.
 *
 * Walked with an explicit stack, not native recursion, and depth-limited at {@link MAX_JSON_DEPTH}:
 * `JSON.parse` accepts JSON nested far deeper than any real report ever is, and a recursive walk
 * with no limit of its own would overflow the call stack on that input instead of rejecting it.
 * Only containers with something changed beneath them are ever cloned; a subtree with no NUL
 * anywhere (the common case — most reports have none at all, in which case the whole tree, and
 * every value in it, is returned by reference with no copy at all) comes back as the same
 * reference it went in as.
 */
export function stripNulDeep(root: unknown): unknown {
  if (typeof root === 'string') return stripNulString(root);
  if (root === null || typeof root !== 'object') return root;

  const stack: Frame[] = [frameFor(root)];
  // The just-finished value of the frame most recently popped, waiting to be filed into whichever
  // frame is now on top of the stack (its parent) — null when the top frame should instead advance
  // to its own next entry.
  let pendingChild: { value: unknown } | null = null;

  for (;;) {
    const frame = stack[stack.length - 1];
    if (!frame) throw new StripNulInvariantError('stripNulDeep: stack unexpectedly empty');

    if (pendingChild) {
      const { value: child } = pendingChild;
      pendingChild = null;
      const i = frame.index - 1;
      if (frame.kind === 'array') {
        if (child !== frame.source[i]) ensureArrayResult(frame, i);
        frame.result?.push(child);
      } else {
        const key = frame.keys[i];
        const cleanKey = frame.pendingKey;
        if (key === undefined || cleanKey === null) {
          throw new StripNulInvariantError('stripNulDeep: missing key for a pending child');
        }
        frame.pendingKey = null;
        if (cleanKey !== key || child !== frame.source[key]) ensureObjectResult(frame, i);
        if (frame.result) setOwn(frame.result, cleanKey, child);
      }
      continue;
    }

    if (frame.kind === 'array') {
      if (frame.index >= frame.source.length) {
        const finished = frame.result ?? frame.source;
        stack.pop();
        if (stack.length === 0) return finished;
        pendingChild = { value: finished };
        continue;
      }
      const i = frame.index;
      frame.index += 1;
      const value = frame.source[i];
      if (typeof value === 'string') {
        const cleaned = stripNulString(value);
        if (cleaned !== value) ensureArrayResult(frame, i);
        frame.result?.push(cleaned);
      } else if (value !== null && typeof value === 'object') {
        if (stack.length >= MAX_JSON_DEPTH) throw new JsonTooDeepError();
        stack.push(frameFor(value));
      } else {
        frame.result?.push(value);
      }
      continue;
    }

    // Object frame.
    if (frame.index >= frame.keys.length) {
      const finished = frame.result ?? frame.source;
      stack.pop();
      if (stack.length === 0) return finished;
      pendingChild = { value: finished };
      continue;
    }
    const i = frame.index;
    frame.index += 1;
    const key = frame.keys[i];
    if (key === undefined) continue; // Unreachable: i < frame.keys.length, just checked above.
    const cleanKey = stripNulString(key);
    const value = frame.source[key];
    if (typeof value === 'string') {
      const cleanedValue = stripNulString(value);
      if (cleanKey !== key || cleanedValue !== value) ensureObjectResult(frame, i);
      if (frame.result) setOwn(frame.result, cleanKey, cleanedValue);
    } else if (value !== null && typeof value === 'object') {
      if (stack.length >= MAX_JSON_DEPTH) throw new JsonTooDeepError();
      frame.pendingKey = cleanKey;
      stack.push(frameFor(value));
    } else {
      if (cleanKey !== key) ensureObjectResult(frame, i);
      if (frame.result) setOwn(frame.result, cleanKey, value);
    }
  }
}

/**
 * Decompresses and validates a stored report. The upload endpoint already bounded the
 * compressed/decompressed sizes while streaming, but this runs against the bytes actually
 * persisted in `analysis_reports`, so it re-checks `maxDecompressedBytes` itself rather than
 * trusting that whatever is in the row is safe to inflate without limit.
 */
export function decodeStoredReport(
  body: Buffer,
  limits: UploadLimits,
  logger?: DecodeLogger,
): DecodeResult {
  let text: string;
  try {
    // Ruling S13 #3: hold the (up to maxDecompressedBytes) inflated buffer only long enough to
    // convert it to a string, then drop the reference immediately rather than keeping it alive
    // for the rest of this function's scope. `stripNulDeep` below returns the parsed JSON by
    // reference (no copy at all) unless it actually finds a NUL somewhere, so a slot's peak
    // memory is ordinarily buffer + string + parsed JSON + the validated zod copy, not one more
    // full copy on top of that — each intermediate should still be released as soon as possible.
    let decompressed: Buffer | null = gunzipSync(body, {
      maxOutputLength: limits.maxDecompressedBytes,
    });
    try {
      text = decompressed.toString('utf8');
    } finally {
      decompressed = null;
    }
  } catch (err) {
    return {
      ok: false,
      error: isDecodedTooLarge(err)
        ? { code: 'REPORT_TOO_LARGE', message: 'The report inflates past the configured limit' }
        : { code: 'REPORT_INVALID', message: 'The report could not be decompressed' },
    };
  }
  // From here on, everything operates on untrusted, attacker-shaped input (JSON.parse accepts
  // JSON nested far deeper, or shaped far more pathologically, than a real report ever is); a bug
  // anywhere in this stretch — not just the depth guard it is written against — must fail this one
  // report as REPORT_INVALID rather than escape and have the caller treat it as a transient,
  // retriable error.
  try {
    const json = stripNulDeep(JSON.parse(text));
    if (
      typeof json === 'object' &&
      json !== null &&
      'schemaVersion' in json &&
      (json as { schemaVersion?: unknown }).schemaVersion !== REPORT_SCHEMA_VERSION
    ) {
      return {
        ok: false,
        error: {
          code: 'REPORT_INVALID',
          message: `Unsupported schemaVersion; this server accepts ${REPORT_SCHEMA_VERSION}..${REPORT_SCHEMA_VERSION}`,
          errors: [{ path: 'schemaVersion', message: 'Unsupported schemaVersion' }],
        },
      };
    }
    const parsed = reportSchema.safeParse(json);
    if (!parsed.success) {
      return {
        ok: false,
        error: {
          code: 'REPORT_INVALID',
          message: 'The report does not match the report schema',
          errors: parsed.error.issues.slice(0, MAX_REPORTED_ERRORS).map((issue) => ({
            path: issue.path.map(String).join('.'),
            message: issue.message,
          })),
        },
      };
    }
    return { ok: true, report: parsed.data };
  } catch (err) {
    // Never log report content — only the error's own type, never any text derived from the
    // report — so a hostile or malformed report can't smuggle anything into the server's logs.
    const errorType = err instanceof Error ? err.name : typeof err;
    if (err instanceof StripNulInvariantError) {
      logger?.warn(
        { errorType },
        'decodeStoredReport: an internal invariant was violated while stripping U+0000 from a report; this is a bug in the server, not the report',
      );
    } else {
      logger?.debug(
        { errorType },
        'decodeStoredReport: rejecting a report that failed to parse or was nested too deeply',
      );
    }
    return {
      ok: false,
      error: {
        code: 'REPORT_INVALID',
        message:
          err instanceof JsonTooDeepError
            ? 'The report is nested too deeply'
            : 'The report is not valid JSON',
      },
    };
  }
}

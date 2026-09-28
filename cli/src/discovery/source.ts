import { createHash } from 'node:crypto';
import { closeSync, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { splitSourceLines } from '@qualor/shared';
import { MAX_ANALYZED_BYTES } from './discover';

export interface SourceText {
  /** SHA-256 of the raw bytes (report-format §6). */
  sha256: string;
  /** Decoded text without a leading BOM; null for a file too large to analyse (streamed). */
  text: string | null;
  /** Line count per `splitSourceLines`. */
  lines: number;
  encoding: 'utf-8' | 'latin1';
}

const utf8 = new TextDecoder('utf-8', { fatal: true });
const latin1 = new TextDecoder('latin1');

/** Ruling C20: invalid UTF-8 falls back to Latin-1 so every byte still maps to one character. */
function decodeSource(bytes: Uint8Array): {
  text: string;
  encoding: SourceText['encoding'];
} {
  try {
    return { text: utf8.decode(bytes), encoding: 'utf-8' };
  } catch {
    return { text: latin1.decode(bytes), encoding: 'latin1' };
  }
}

export interface ReadSourceOptions {
  /** Files larger than this are streamed: hashed and line-counted, never decoded. */
  maxInMemoryBytes?: number;
  /** Read size of the streaming path (tests use tiny chunks to cover chunk boundaries). */
  chunkBytes?: number;
}

const STREAM_CHUNK_BYTES = 64 * 1024;
const LF = 0x0a;
const UTF8_BOM = [0xef, 0xbb, 0xbf] as const;

/**
 * Hashes and counts the lines of a file in fixed-size chunks, so a huge minified bundle or data
 * file in scope never has to fit in memory. The line count follows `splitSourceLines` exactly:
 * in both UTF-8 and Latin-1 an LF byte is always a line feed, a CR before it does not change
 * the count, a final LF does not start a new line, and a UTF-8 BOM (only when the whole file
 * is valid UTF-8) is not content. UTF-8 validity is checked with a streaming decoder whose output
 * is discarded.
 */
function streamSource(fd: number, chunkBytes: number): SourceText {
  const hash = createHash('sha256');
  const validator = new TextDecoder('utf-8', { fatal: true });
  let valid = true;
  const buf = Buffer.alloc(Math.max(1, chunkBytes));
  let total = 0;
  let newlines = 0;
  let last = -1;
  const head: number[] = [];
  for (;;) {
    const n = readSync(fd, buf, 0, buf.length, null);
    if (n === 0) break;
    const chunk = buf.subarray(0, n);
    hash.update(chunk);
    for (let i = 0; i < n; i++) {
      const b = chunk[i] ?? 0;
      if (b === LF) newlines++;
      if (head.length < UTF8_BOM.length) head.push(b);
    }
    if (valid) {
      try {
        validator.decode(chunk, { stream: true });
      } catch {
        valid = false;
      }
    }
    total += n;
    last = chunk[n - 1] ?? -1;
  }
  if (valid) {
    try {
      validator.decode();
    } catch {
      valid = false;
    }
  }
  const bom = valid && UTF8_BOM.every((b, i) => head[i] === b);
  const bodyBytes = total - (bom ? UTF8_BOM.length : 0);
  return {
    sha256: hash.digest('hex'),
    text: null,
    lines: bodyBytes === 0 ? 0 : newlines + (last === LF ? 0 : 1),
    encoding: valid ? 'utf-8' : 'latin1',
  };
}

/**
 * Reads a file once: the SHA-256 of its raw bytes, its line count and, for files up to
 * `maxInMemoryBytes` (default 1 MiB, the metrics/duplication limit), its decoded text. Larger
 * files take the streaming path and come back with `text: null`.
 */
export function readSource(absPath: string, o: ReadSourceOptions = {}): SourceText {
  const fd = openSync(absPath, 'r');
  try {
    if (fstatSync(fd).size > (o.maxInMemoryBytes ?? MAX_ANALYZED_BYTES)) {
      return streamSource(fd, o.chunkBytes ?? STREAM_CHUNK_BYTES);
    }
    const bytes = readFileSync(fd);
    const { text, encoding } = decodeSource(bytes);
    return {
      sha256: createHash('sha256').update(bytes).digest('hex'),
      text,
      lines: splitSourceLines(text).length,
      encoding,
    };
  } finally {
    closeSync(fd);
  }
}

/** `readLines` for the SARIF normaliser: null when the file cannot be read. */
export function readSourceLines(absPath: string): string[] | null {
  try {
    const { text } = readSource(absPath);
    return text === null ? null : splitSourceLines(text);
  } catch {
    return null;
  }
}

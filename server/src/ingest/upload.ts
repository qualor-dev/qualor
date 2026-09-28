import type { Readable } from 'node:stream';
import { createGunzip } from 'node:zlib';
import type { UploadLimits } from '../config';
import { ProblemError } from '../http/problem';

export function reportTooLarge(which: 'compressed' | 'decompressed', limit: number): ProblemError {
  return new ProblemError(413, 'REPORT_TOO_LARGE', 'The report is too large', {
    detail: `The ${which} report exceeds ${limit} bytes`,
  });
}

function invalidGzip(message: string): ProblemError {
  return new ProblemError(422, 'REPORT_INVALID', 'The report is not a valid gzip stream', {
    errors: [{ path: 'body', message }],
  });
}

function isZlibError(err: unknown): boolean {
  const code =
    typeof err === 'object' && err !== null ? (err as { code?: unknown }).code : undefined;
  return typeof code === 'string' && code.startsWith('Z_');
}

/** Node's names for "the client went away mid-request" — not a server fault, never a 500. */
const ABORT_ERROR_CODES = new Set([
  'ECONNRESET',
  'ECONNABORTED',
  'ERR_STREAM_PREMATURE_CLOSE',
  'EPIPE',
  'ABORT_ERR',
]);

function isClientAbort(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const code = (err as { code?: unknown }).code;
  const name = (err as { name?: unknown }).name;
  return (typeof code === 'string' && ABORT_ERROR_CODES.has(code)) || name === 'AbortError';
}

/** S11 (minor): the CLI/client disconnecting mid-upload is routine, not an internal error. */
export function clientAborted(): ProblemError {
  return new ProblemError(499, 'CLIENT_ABORTED', 'The client closed the connection');
}

export interface UploadedReport {
  body: Buffer;
  decompressedBytes: number;
}

/**
 * Reads a gzip request body and enforces both limits while streaming. Compressed bytes are kept
 * (at most maxCompressedBytes) for storage; inflated bytes are only counted and dropped, so a gzip
 * bomb costs at most the limit plus one chunk before it is rejected, and an oversized body stops
 * being read as soon as it crosses the limit.
 *
 * `source` (the incoming HTTP request stream in production) is deliberately never destroyed here:
 * doing so tears down the response too, in real HTTP/1.1 pipelining and — critically — under the
 * `light-my-request`-based test harness, whose mock request/response are wired so that the
 * request erroring or closing before the response has finished aborts the response object it is
 * still writing. Once we reject, we just stop listening to `source`; whatever it still has
 * buffered is left for the platform to reclaim once the response completes and the connection is
 * torn down, exactly like Fastify's own built-in "body too large" handling.
 */
export async function readGzipUpload(
  source: Readable,
  limits: UploadLimits,
): Promise<UploadedReport> {
  const gunzip = createGunzip();
  const chunks: Buffer[] = [];
  let compressed = 0;
  let decompressed = 0;

  await new Promise<void>((resolve, reject) => {
    let settled = false;

    const cleanup = (): void => {
      source.off('data', onSourceData);
      source.off('error', onSourceError);
      source.off('end', onSourceEnd);
      gunzip.off('data', onGunzipData);
      gunzip.off('drain', onGunzipDrain);
      gunzip.off('error', onGunzipError);
      gunzip.off('end', onGunzipEnd);
    };
    const fail = (err: unknown): void => {
      if (settled) return;
      settled = true;
      cleanup();
      source.pause();
      gunzip.destroy();
      reject(err);
    };
    const succeed = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };

    function onSourceData(chunk: Buffer): void {
      compressed += chunk.length;
      if (compressed > limits.maxCompressedBytes) {
        fail(reportTooLarge('compressed', limits.maxCompressedBytes));
        return;
      }
      chunks.push(chunk);
      if (!gunzip.write(chunk)) source.pause();
    }
    function onSourceError(err: unknown): void {
      fail(isClientAbort(err) ? clientAborted() : err);
    }
    function onSourceEnd(): void {
      gunzip.end();
    }
    function onGunzipDrain(): void {
      source.resume();
    }
    function onGunzipData(chunk: Buffer): void {
      decompressed += chunk.length;
      if (decompressed > limits.maxDecompressedBytes) {
        fail(reportTooLarge('decompressed', limits.maxDecompressedBytes));
      }
    }
    function onGunzipError(err: unknown): void {
      fail(
        isZlibError(err)
          ? invalidGzip(compressed === 0 ? 'Empty body' : 'Not valid gzip data')
          : err,
      );
    }
    function onGunzipEnd(): void {
      succeed();
    }

    source.on('data', onSourceData);
    source.on('error', onSourceError);
    source.on('end', onSourceEnd);
    gunzip.on('drain', onGunzipDrain);
    gunzip.on('data', onGunzipData);
    gunzip.on('error', onGunzipError);
    gunzip.on('end', onGunzipEnd);
  });

  if (compressed === 0) throw invalidGzip('Empty body');
  return { body: Buffer.concat(chunks, compressed), decompressedBytes: decompressed };
}

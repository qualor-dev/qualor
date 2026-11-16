/**
 * Reading an uploaded SBOM (0.16, spec §6.1, §6.6): the body as sent, gunzipped when it says so,
 * into the text `parseSbom` reads; the version label; and the inventory entries a version stores.
 */
import { promisify } from 'node:util';
import { gunzip } from 'node:zlib';
import type { SbomEntry } from '@qualor/shared';
import { ProblemError } from '../http/problem';
import { clientAborted, isClientAbort } from '../ingest/upload';
import type { VersionDependencyEntry } from '../versions/store';

const gunzipAsync = promisify(gunzip);

/** An SBOM is at most this many bytes as sent: the cap of the KEV and EPSS files. */
export const SBOM_BODY_MAX_BYTES = 32 * 1024 * 1024;
/** ...and at most this many bytes of text, inflated. */
export const SBOM_TEXT_MAX_BYTES = 64 * 1024 * 1024;
/** The longest version label (`project_versions_label_check`, as a tag scan's). */
export const VERSION_LABEL_MAX_CHARS = 100;

const GZIP_MAGIC = [0x1f, 0x8b] as const;

export function sbomTooLarge(detail: string): ProblemError {
  return new ProblemError(413, 'SBOM_TOO_LARGE', 'The SBOM is too large', { detail });
}

function sbomInvalid(detail: string): ProblemError {
  return new ProblemError(422, 'SBOM_INVALID', 'The SBOM cannot be read', { detail });
}

function labelInvalid(detail: string): ProblemError {
  return new ProblemError(422, 'VERSION_LABEL_INVALID', 'The version label is not valid', {
    detail,
  });
}

/**
 * The text of an uploaded SBOM. The body is counted while it is read and refused as soon as it
 * passes `maxBodyBytes`; gzip is inflated with `maxOutputLength`, so a gzip bomb stops at
 * `maxTextBytes` (as the KEV and EPSS files, `vulndb/priority/parse.ts`). The text must be UTF-8;
 * a leading byte order mark is dropped.
 *
 * Refusals: 413 `SBOM_TOO_LARGE` over either cap, 422 `SBOM_INVALID` for bad gzip or text that is
 * not UTF-8, 499 `CLIENT_ABORTED` when the client goes away mid-body.
 */
export async function readSbomText(
  body: AsyncIterable<Buffer>,
  o: { gzip: boolean; maxBodyBytes?: number; maxTextBytes?: number },
): Promise<string> {
  const maxBodyBytes = o.maxBodyBytes ?? SBOM_BODY_MAX_BYTES;
  const maxTextBytes = o.maxTextBytes ?? SBOM_TEXT_MAX_BYTES;
  const sent = await readBody(body, maxBodyBytes);
  const bytes = o.gzip ? await inflate(sent, maxTextBytes) : sent;
  if (bytes.length > maxTextBytes) {
    throw sbomTooLarge(`The SBOM is larger than ${maxTextBytes} bytes.`);
  }
  try {
    // `fatal`: bytes that are not UTF-8 throw instead of turning into U+FFFD. The decoder drops a
    // leading byte order mark (`ignoreBOM` is false).
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    const zipped = !o.gzip && bytes[0] === GZIP_MAGIC[0] && bytes[1] === GZIP_MAGIC[1];
    throw sbomInvalid(
      zipped
        ? 'The body is gzip. Send it with Content-Encoding: gzip, or send the plain JSON.'
        : 'The SBOM is not UTF-8 text.',
    );
  }
}

/** The body, at most `maxBytes`. */
async function readBody(body: AsyncIterable<Buffer>, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of body) {
      total += chunk.length;
      if (total > maxBytes) throw sbomTooLarge(`The body is larger than ${maxBytes} bytes.`);
      chunks.push(chunk);
    }
  } catch (err) {
    // The client hanging up is routine, not a server fault.
    throw isClientAbort(err) ? clientAborted() : err;
  }
  return Buffer.concat(chunks, total);
}

async function inflate(sent: Buffer, maxBytes: number): Promise<Buffer> {
  try {
    return await gunzipAsync(sent, { maxOutputLength: maxBytes });
  } catch (err) {
    if (err instanceof RangeError || (err as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE') {
      throw sbomTooLarge(`The SBOM is larger than ${maxBytes} bytes when inflated.`);
    }
    throw sbomInvalid('The body is not valid gzip data, as its Content-Encoding: gzip says.');
  }
}

/**
 * The version label of an upload (spec §6.6, ruling R4): the trimmed `?version=`, 1 to 100
 * characters; only an absent one falls back to the SBOM's own version (CycloneDX
 * `metadata.component.version`, SPDX `versionInfo`). Refusals are 422 `VERSION_LABEL_INVALID`.
 */
export function sbomLabel(query: string | undefined, subjectVersion: string | null): string {
  if (query !== undefined) {
    const label = query.trim();
    if (label === '') {
      throw labelInvalid(
        "The version is blank. Give a label of 1 to 100 characters, or leave the parameter out to use the SBOM's own version.",
      );
    }
    if (label.length > VERSION_LABEL_MAX_CHARS) {
      throw labelInvalid(`The version is longer than ${VERSION_LABEL_MAX_CHARS} characters.`);
    }
    return label;
  }
  const label = subjectVersion?.trim() ?? '';
  if (label === '') {
    throw labelInvalid(
      'The SBOM names no version of what it describes (CycloneDX metadata.component.version, SPDX versionInfo). Give one with ?version=.',
    );
  }
  if (label.length > VERSION_LABEL_MAX_CHARS) {
    throw labelInvalid(
      `The SBOM's own version is longer than ${VERSION_LABEL_MAX_CHARS} characters. Give one with ?version=.`,
    );
  }
  return label;
}

/**
 * The entries a version stores: an unknown `direct` is left out, the source package an OS package
 * was built from becomes `sourceName` and `sourceVersion`, and its arch and modularity label are
 * kept when the SBOM names them.
 */
export function toVersionEntries(entries: readonly SbomEntry[]): VersionDependencyEntry[] {
  return entries.map((e) => ({
    ecosystem: e.ecosystem,
    name: e.name,
    version: e.version,
    path: e.path,
    licenses: e.licenses,
    ...(e.direct !== null && { direct: e.direct }),
    ...(e.source !== null && { sourceName: e.source.name, sourceVersion: e.source.version }),
    ...(e.arch !== null && { arch: e.arch }),
    ...(e.modularityLabel !== null && { modularityLabel: e.modularityLabel }),
  }));
}

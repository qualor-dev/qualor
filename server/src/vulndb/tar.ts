import { pipeline } from 'node:stream/promises';
import { createGunzip } from 'node:zlib';

const BLOCK = 512;
/** A `keep` entry is read into memory: at most this big (metadata.json is a few hundred bytes). */
export const KEEP_MAX_BYTES = 1024 * 1024;

/** What is wrong with an archive: a short fixed text, safe to show to an administrator. */
export class TarError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TarError';
  }
}

/**
 * A regular file of the archive, handed to `onFile`:
 * - `keep`: its bytes, whole;
 * - `stream`: its bytes as they are decompressed, never buffered whole. `body` may be read once,
 *   while `onFile` runs (for example `await pipeline(entry.body, createWriteStream(path))`, which
 *   applies backpressure); what is left unread when `onFile` settles is skipped, and a read after
 *   that throws.
 */
export type TarEntry =
  | { want: 'keep'; name: string; size: number; data: Buffer }
  | { want: 'stream'; name: string; size: number; body: AsyncIterable<Buffer> };

export type TarWant = (name: string) => 'keep' | 'stream' | 'skip';
export type OnTarEntry = (entry: TarEntry) => Promise<void> | void;

/**
 * An entry's name as `want` sees it: without `.` and empty segments, and without a leading `db/`
 * directory, so `./db/trivy.db`, `db/trivy.db` and `trivy.db` are all `trivy.db`.
 */
export function normalName(raw: string): string {
  const parts = raw.split('/').filter((part) => part !== '' && part !== '.');
  if (parts.length > 1 && parts[0] === 'db') parts.shift();
  return parts.join('/');
}

/** zlib's own errors: the data is not gzip, or it is cut. */
function gzipError(err: unknown): TarError | null {
  const code = (err as { code?: unknown } | null)?.code;
  if (code === 'Z_BUF_ERROR') return new TarError('The archive ends early (the gzip data is cut)');
  if (typeof code === 'string' && code.startsWith('Z_')) {
    return new TarError('The file is not a gzip archive');
  }
  return null;
}

/**
 * The decompressed bytes of `chunks`, pulled as they are read: the source is read only as fast as
 * the reader takes the output. An error of the source is passed on as it is; one of zlib becomes
 * a {@link TarError}. Stopping early (`return()`) stops the source too.
 */
async function* inflate(chunks: AsyncIterable<Buffer>): AsyncGenerator<Buffer, void, undefined> {
  const gunzip = createGunzip();
  const pumped = pipeline(chunks, gunzip);
  // Its error reaches the reader through `gunzip`, which the pipeline destroys with it.
  pumped.catch(() => undefined);
  try {
    for await (const piece of gunzip as AsyncIterable<Buffer>) yield piece;
    await pumped;
  } catch (err) {
    throw gzipError(err) ?? err;
  } finally {
    gunzip.destroy();
  }
}

/** The decompressed stream, read by the byte. */
class Reader {
  private readonly pending: Buffer[] = [];
  private pendingBytes = 0;
  private ended = false;

  constructor(private readonly source: AsyncIterator<Buffer, void, undefined>) {}

  /** Pulls one more piece; false at the end of the data. */
  private async pull(): Promise<boolean> {
    if (this.ended) return false;
    const step = await this.source.next();
    if (step.done) {
      this.ended = true;
      return false;
    }
    if (step.value.length > 0) {
      this.pending.push(step.value);
      this.pendingBytes += step.value.length;
    }
    return true;
  }

  /** Exactly `n` bytes; null when the data ends before the first of them; else a short read throws. */
  async exactly(n: number): Promise<Buffer | null> {
    while (this.pendingBytes < n) {
      if (!(await this.pull())) {
        if (this.pendingBytes === 0) return null;
        throw new TarError('The archive ends early');
      }
    }
    const [only] = this.pending;
    // One piece is cut without a copy.
    const all = this.pending.length === 1 && only ? only : Buffer.concat(this.pending);
    this.pending.length = 0;
    const out = all.subarray(0, n);
    if (all.length > n) this.pending.push(all.subarray(n));
    this.pendingBytes -= n;
    return out;
  }

  /** At least one and at most `max` bytes, as they come; the end of the data throws. */
  async upTo(max: number): Promise<Buffer> {
    while (this.pendingBytes === 0) {
      if (!(await this.pull())) throw new TarError('The archive ends early');
    }
    const first = this.pending.shift();
    if (first === undefined) throw new TarError('The archive ends early');
    if (first.length > max) {
      this.pending.unshift(first.subarray(max));
      this.pendingBytes -= max;
      return first.subarray(0, max);
    }
    this.pendingBytes -= first.length;
    return first;
  }

  async skip(n: number): Promise<void> {
    let left = n;
    while (left > 0) left -= (await this.upTo(left)).length;
  }

  async close(): Promise<void> {
    await this.source.return?.();
  }
}

/** A NUL-ended text field of a header. */
function field(block: Buffer, offset: number, length: number): string {
  const raw = block.subarray(offset, offset + length);
  const nul = raw.indexOf(0);
  return raw.subarray(0, nul === -1 ? length : nul).toString('utf8');
}

/** An octal number field; null when it is not one (GNU base-256 included). */
function octalField(block: Buffer, offset: number, length: number): number | null {
  const text = field(block, offset, length).trim();
  if (!/^[0-7]{1,12}$/.test(text)) return null;
  return parseInt(text, 8);
}

/** The header checksum holds: the unsigned sum, or the signed one some old writers used. */
function checksumHolds(block: Buffer): boolean {
  const stored = octalField(block, 148, 8);
  if (stored === null) return false;
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < BLOCK; i++) {
    const byte = i >= 148 && i < 156 ? 0x20 : block.readUInt8(i);
    unsigned += byte;
    signed += byte > 127 ? byte - 256 : byte;
  }
  return stored === unsigned || stored === signed;
}

const OTHER_TYPES: Record<string, string> = {
  '1': 'a hard link',
  '2': 'a symbolic link',
  '3': 'a character device',
  '4': 'a block device',
  '6': 'a FIFO',
  L: 'a GNU long name',
  K: 'a GNU long link name',
};

interface Header {
  name: string;
  size: number;
  /** `skipped`: a directory or a pax header, passed over with its data. */
  type: 'file' | 'skipped';
}

/** A 512-byte header; null for the zero block that ends the archive. */
function parseHeader(block: Buffer): Header | null {
  if (block.every((byte) => byte === 0)) return null;
  if (!checksumHolds(block)) throw new TarError('The file is not a tar archive (bad header)');
  const magic = block.toString('latin1', 257, 263);
  if (magic !== 'ustar\0' && magic !== 'ustar ') {
    throw new TarError('The file is not a ustar tar archive');
  }
  const size = octalField(block, 124, 12);
  if (size === null) throw new TarError('An entry of the archive has no valid size');
  const flag = String.fromCharCode(block.readUInt8(156));
  let type: Header['type'];
  if (flag === '0' || flag === '\0' || flag === '7') type = 'file';
  // Directories, and pax extended (`x`) and global (`g`) headers, which carry times and owners
  // that this reader ignores. GNU long names and link names (`L`, `K`) are refused below.
  else if (flag === '5' || flag === 'x' || flag === 'g') type = 'skipped';
  else {
    const what = OTHER_TYPES[flag] ?? 'an entry of an unknown type';
    throw new TarError(`The archive holds ${what}; only plain files are allowed`);
  }
  // Only POSIX ustar has the prefix field; GNU tar keeps other data there.
  const prefix = magic === 'ustar\0' ? field(block, 345, 155) : '';
  const name = field(block, 0, 100);
  return { name: prefix === '' ? name : `${prefix}/${name}`, size, type };
}

/**
 * Reads a gzipped tar archive from `chunks`, in one pass, as the bytes arrive. Regular files
 * (ustar and GNU tar) are offered to `want` under their {@link normalName}; directories and pax
 * `x`/`g` headers are passed over; any other entry (a link, a device, a GNU long name) rejects
 * the archive. A
 * `keep` entry over {@link KEEP_MAX_BYTES} rejects it too. `onFile` is awaited for each wanted
 * entry, in archive order (see {@link TarEntry}). Rejects with a {@link TarError} for an archive
 * that is not valid, or with what `chunks` or `onFile` threw. Stops at the archive's end marker.
 */
export async function readTarGz(
  chunks: AsyncIterable<Buffer>,
  want: TarWant,
  onFile: OnTarEntry,
): Promise<void> {
  const reader = new Reader(inflate(chunks));
  try {
    for (;;) {
      const block = await reader.exactly(BLOCK);
      if (block === null) return;
      const header = parseHeader(block);
      if (header === null) return;
      const padding = (BLOCK - (header.size % BLOCK)) % BLOCK;
      const name = normalName(header.name);
      const wanted = header.type === 'file' ? want(name) : 'skip';
      let unread = header.size;
      if (wanted === 'keep') {
        if (header.size > KEEP_MAX_BYTES) throw new TarError(`${name} is larger than 1 MiB`);
        const data = Buffer.from((await reader.exactly(header.size)) ?? Buffer.alloc(0));
        if (data.length !== header.size) throw new TarError('The archive ends early');
        unread = 0;
        await onFile({ want: 'keep', name, size: header.size, data });
      } else if (wanted === 'stream') {
        let open = true;
        const body: AsyncIterable<Buffer> = {
          [Symbol.asyncIterator]: () => ({
            next: async (): Promise<IteratorResult<Buffer, undefined>> => {
              if (!open) throw new Error(`${name} was read after its onFile settled`);
              if (unread === 0) return { done: true, value: undefined };
              const piece = await reader.upTo(unread);
              unread -= piece.length;
              return { done: false, value: piece };
            },
            return: (): Promise<IteratorResult<Buffer, undefined>> =>
              Promise.resolve({ done: true, value: undefined }),
          }),
        };
        try {
          await onFile({ want: 'stream', name, size: header.size, body });
        } finally {
          open = false;
        }
      }
      await reader.skip(unread + padding);
    }
  } finally {
    await reader.close();
  }
}

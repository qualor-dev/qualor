import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip, createGzip, gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { ProblemError } from '../http/problem';
import { readGzipUpload, TransferSlots, type UploadProblems } from './upload';

const MiB = 1024 * 1024;
const DEFAULT_LIMITS = { maxCompressedBytes: 50 * MiB, maxDecompressedBytes: 500 * MiB };

/** A source that counts what it has handed out, with no read-ahead beyond one chunk. */
function counted(chunks: Iterable<Buffer>): { stream: Readable; produced(): number } {
  let produced = 0;
  const stream = Readable.from(
    (function* () {
      for (const chunk of chunks) {
        produced += chunk.length;
        yield chunk;
      }
    })(),
    { highWaterMark: 1 },
  );
  return { stream, produced: () => produced };
}

function* repeat(chunk: Buffer, times: number): Generator<Buffer> {
  for (let i = 0; i < times; i++) yield chunk;
}

function* slices(buffer: Buffer, size: number): Generator<Buffer> {
  for (let i = 0; i < buffer.length; i += size) yield buffer.subarray(i, i + size);
}

async function gzipStream(source: Readable): Promise<Buffer> {
  const parts: Buffer[] = [];
  await pipeline(source, createGzip({ level: 9 }), async (out: AsyncIterable<Buffer>) => {
    for await (const part of out) parts.push(part);
  });
  return Buffer.concat(parts);
}

describe('readGzipUpload (report-format.md §2)', () => {
  it('returns the compressed bytes and counts the inflated size', async () => {
    const json = Buffer.from(JSON.stringify({ hello: 'x'.repeat(1_000) }));
    const gz = gzipSync(json);
    const out = await readGzipUpload(Readable.from([gz]), DEFAULT_LIMITS);
    expect(out.body.equals(gz)).toBe(true);
    expect(out.decompressedBytes).toBe(json.length);
  });

  it('rejects a 51 MiB upload with 413 and stops reading it (api.md §6 criterion 4)', async () => {
    // Chunked fine enough (128 KiB, not 1 MiB) that the natural "one chunk of read-ahead"
    // backpressure allowance a correct streaming reader has is a small fraction of the 1 MiB
    // overshoot, not the whole of it — with 1 MiB chunks the single allowed extra chunk *is* the
    // entire excess over the limit, so the assertion below would be racy no matter how tightly
    // readGzipUpload stops.
    const CHUNK = 128 * 1024;
    const raw = counted(repeat(randomBytes(CHUNK), Math.ceil((51 * MiB) / CHUNK)));
    const gz = raw.stream.pipe(createGzip({ level: 0 }));
    await expect(readGzipUpload(gz, DEFAULT_LIMITS)).rejects.toMatchObject({
      status: 413,
      code: 'REPORT_TOO_LARGE',
    });
    expect(raw.produced()).toBeLessThan(51 * MiB);
  }, 60_000);

  it('rejects a 1 MiB gzip that inflates past 500 MiB with 413 (report-format.md §10.5)', async () => {
    const bomb = await gzipStream(Readable.from(repeat(Buffer.alloc(MiB), 1_024)));
    expect(bomb.length).toBeLessThan(1.5 * MiB);
    const source = counted(slices(bomb, 16 * 1024));
    await expect(readGzipUpload(source.stream, DEFAULT_LIMITS)).rejects.toMatchObject({
      status: 413,
      code: 'REPORT_TOO_LARGE',
    });
    expect(source.produced()).toBeLessThan(bomb.length * 0.75);
  }, 60_000);

  it('stops inflating a small bomb at a small limit', async () => {
    // How far the reader can get ahead is bounded by the gunzip stream's writable buffer, whose
    // default size depends on the Node version (16 KiB on some releases, 64 KiB on Node 22.x,
    // where it swallowed the whole 64 KiB bomb this test used to use). So the bomb is made much
    // larger than that buffer, and the bound is taken from the running Node itself: the ~1 KiB of
    // input that inflates past the 1 MiB limit, plus one gunzip write buffer, plus one chunk.
    const CHUNK = 1_024;
    const bomb = await gzipStream(Readable.from(repeat(Buffer.alloc(MiB), 256)));
    const readAhead = createGunzip().writableHighWaterMark;
    expect(bomb.length).toBeGreaterThan(3 * (readAhead + 2 * CHUNK));
    const source = counted(slices(bomb, CHUNK));
    await expect(
      readGzipUpload(source.stream, { maxCompressedBytes: MiB, maxDecompressedBytes: MiB }),
    ).rejects.toMatchObject({ status: 413 });
    expect(source.produced()).toBeLessThanOrEqual(readAhead + 2 * CHUNK);
    expect(source.produced()).toBeLessThan(bomb.length / 3);
  }, 30_000);

  it('rejects non-gzip, truncated and empty bodies with 422 REPORT_INVALID', async () => {
    const gz = gzipSync(Buffer.from('{"a":1}'));
    for (const body of [Buffer.from('{"a":1}'), gz.subarray(0, gz.length - 4), Buffer.alloc(0)]) {
      await expect(readGzipUpload(Readable.from([body]), DEFAULT_LIMITS)).rejects.toMatchObject({
        status: 422,
        code: 'REPORT_INVALID',
      });
    }
  });

  it('answers with the problems of the upload it reads, when the route names its own (6I-2)', async () => {
    const problems: UploadProblems = {
      tooLarge: (which, limit) => new ProblemError(413, 'SNAPSHOT_TOO_LARGE', `${which} ${limit}`),
      invalidGzip: (message) => new ProblemError(422, 'SNAPSHOT_INVALID', message),
    };
    const limits = { maxCompressedBytes: 1_000, maxDecompressedBytes: 2_000 };
    const cases: [Buffer, object][] = [
      [randomBytes(2_000), { status: 413, code: 'SNAPSHOT_TOO_LARGE', message: 'compressed 1000' }],
      [gzipSync(Buffer.alloc(4_000)), { status: 413, message: 'decompressed 2000' }],
      [
        Buffer.from('not gzip'),
        { status: 422, code: 'SNAPSHOT_INVALID', message: 'Not valid gzip data' },
      ],
      [Buffer.alloc(0), { status: 422, message: 'Empty body' }],
    ];
    for (const [body, problem] of cases) {
      await expect(readGzipUpload(Readable.from([body]), limits, problems)).rejects.toMatchObject(
        problem,
      );
    }
  });

  it('maps a source abort (S11 minor) to a quiet, non-500 CLIENT_ABORTED instead of the raw error', async () => {
    const source = new Readable({ read() {} });
    const upload = readGzipUpload(source, DEFAULT_LIMITS);
    const econnreset = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });
    source.emit('error', econnreset);
    await expect(upload).rejects.toMatchObject({ status: 499, code: 'CLIENT_ABORTED' });
    await expect(upload).rejects.not.toBe(econnreset);
  });
});

describe('TransferSlots (S11, 6I-2)', () => {
  /** What a take answers: null when it got a slot, else the problem it was refused with. */
  const refusal = (take: () => void): unknown => {
    try {
      take();
      return null;
    } catch (err) {
      return err;
    }
  };
  const BUSY = { status: 503, code: 'UPLOADS_BUSY', headers: { 'retry-after': '1' } };

  it('refuses a take when every slot is taken, with 503 UPLOADS_BUSY and Retry-After, until one is released', () => {
    const slots = new TransferSlots(2);
    expect(refusal(() => slots.take())).toBeNull();
    expect(refusal(() => slots.take())).toBeNull();
    expect(refusal(() => slots.take())).toMatchObject(BUSY);
    slots.release();
    expect(refusal(() => slots.take())).toBeNull();
  });

  it('keeps `reserve` slots free for the takes that reserve none', () => {
    const slots = new TransferSlots(2);
    // With a reserve of one, a take is allowed while a slot besides it stays free ...
    expect(refusal(() => slots.take({ reserve: 1 }))).toBeNull();
    // ... so a second one is refused, though a slot is free: it is the one kept ...
    expect(refusal(() => slots.take({ reserve: 1 }))).toMatchObject(BUSY);
    // ... which a plain take may use.
    expect(refusal(() => slots.take())).toBeNull();
    expect(refusal(() => slots.take())).toMatchObject(BUSY);
    expect(refusal(() => slots.take({ reserve: 1 }))).toMatchObject(BUSY);
    // Released slots are free again to both kinds of take.
    slots.release();
    slots.release();
    expect(refusal(() => slots.take({ reserve: 1 }))).toBeNull();
  });

  it('exposes how many slots there are, which tells whether one can be kept back', () => {
    expect(new TransferSlots(1).max).toBe(1);
    expect(new TransferSlots(4).max).toBe(4);
  });
});

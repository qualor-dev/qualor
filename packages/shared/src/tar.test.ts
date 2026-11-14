import { randomBytes } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { metadataJson, tar, tarGz, trivyArchive } from '../test/trivy-archive';
import { normalName, readTarGz, TarError, type TarEntry } from './tar';

/** The archive in pieces of `size` bytes, as a download or the stored chunks deliver it. */
async function* piecesOf(bytes: Buffer, size = 1_000): AsyncGenerator<Buffer> {
  for (let at = 0; at < bytes.length; at += size) {
    await Promise.resolve();
    yield bytes.subarray(at, at + size);
  }
}

interface Seen {
  name: string;
  want: TarEntry['want'];
  size: number;
  data: Buffer;
  pieces: number;
}

/** Reads the archive keeping metadata.json and streaming trivy.db; what onFile was handed. */
async function readAll(
  bytes: Buffer,
  want: (name: string) => 'keep' | 'stream' | 'skip' = (name) =>
    name === 'metadata.json' ? 'keep' : name === 'trivy.db' ? 'stream' : 'skip',
): Promise<Seen[]> {
  const seen: Seen[] = [];
  await readTarGz(piecesOf(bytes), want, async (entry) => {
    if (entry.want === 'keep') {
      seen.push({ name: entry.name, want: 'keep', size: entry.size, data: entry.data, pieces: 1 });
      return;
    }
    const parts: Buffer[] = [];
    for await (const part of entry.body) parts.push(Buffer.from(part));
    seen.push({
      name: entry.name,
      want: 'stream',
      size: entry.size,
      data: Buffer.concat(parts),
      pieces: parts.length,
    });
  });
  return seen;
}

async function rejection(action: Promise<unknown>): Promise<unknown> {
  return action.then(
    () => null,
    (err: unknown) => err,
  );
}

describe('normalName', () => {
  it.each([
    ['trivy.db', 'trivy.db'],
    ['./trivy.db', 'trivy.db'],
    ['db/trivy.db', 'trivy.db'],
    ['./db/trivy.db', 'trivy.db'],
    ['.//db/./metadata.json', 'metadata.json'],
    ['other/trivy.db', 'other/trivy.db'],
    ['db', 'db'],
  ])('%s → %s', (raw, normal) => {
    expect(normalName(raw)).toBe(normal);
  });
});

describe('readTarGz', () => {
  it('keeps metadata.json whole and streams trivy.db in pieces', async () => {
    const db = randomBytes(300_000);
    const seen = await readAll(trivyArchive({ db }));
    expect(seen.map((s) => [s.name, s.want, s.size])).toEqual([
      ['trivy.db', 'stream', db.length],
      ['metadata.json', 'keep', Buffer.byteLength(metadataJson())],
    ]);
    expect(seen[0]?.data.equals(db)).toBe(true);
    // Streamed as it is decompressed, never as one buffer.
    expect(seen[0]?.pieces).toBeGreaterThan(1);
    expect(seen[1]?.data.toString()).toBe(metadataJson());
  });

  it('finds ./db/trivy.db and ./db/metadata.json, skipping the directories', async () => {
    const seen = await readAll(trivyArchive({ layout: 'dotdb' }));
    expect(seen.map((s) => s.name)).toEqual(['trivy.db', 'metadata.json']);
  });

  it('joins the POSIX prefix to the name', async () => {
    const seen = await readAll(
      tarGz([{ name: 'metadata.json', prefix: 'db', data: metadataJson() }]),
    );
    expect(seen.map((s) => s.name)).toEqual(['metadata.json']);
  });

  it('never hands over a skipped entry, and finds what follows it', async () => {
    const seen = await readAll(
      tarGz([
        { name: 'README', data: 'x'.repeat(5_000) },
        { name: 'metadata.json', data: metadataJson() },
      ]),
    );
    expect(seen.map((s) => s.name)).toEqual(['metadata.json']);
  });

  it('skips what onFile leaves unread of a streamed entry', async () => {
    const names: string[] = [];
    await readTarGz(
      piecesOf(trivyArchive({ db: randomBytes(100_000) })),
      (name) => (name === 'trivy.db' ? 'stream' : 'keep'),
      (entry) => {
        names.push(entry.name);
      },
    );
    expect(names).toEqual(['trivy.db', 'metadata.json']);
  });

  it('refuses to read a streamed body once onFile has settled', async () => {
    let body: AsyncIterable<Buffer> | null = null;
    await readTarGz(
      piecesOf(trivyArchive()),
      (name) => (name === 'trivy.db' ? 'stream' : 'skip'),
      (entry) => {
        if (entry.want === 'stream') body = entry.body;
      },
    );
    expect(body).not.toBeNull();
    const late = body as unknown as AsyncIterable<Buffer>;
    await expect(late[Symbol.asyncIterator]().next()).rejects.toThrow(/after/);
  });

  it.each([
    ['a symbolic link', '2'],
    ['a hard link', '1'],
    ['a GNU long name', 'L'],
    ['a FIFO', '6'],
  ])('rejects an archive that holds %s', async (_what, type) => {
    const error = await rejection(
      readAll(
        tarGz([
          { name: 'link', type, data: type === 'L' ? 'payload' : '' },
          { name: 'metadata.json', data: metadataJson() },
        ]),
      ),
    );
    expect(error).toBeInstanceOf(TarError);
    expect((error as Error).message).toMatch(/only plain files/);
  });

  it.each([
    ['a pax extended header', 'x'],
    ['a pax global header', 'g'],
  ])('skips %s and reads the entries around it', async (_what, type) => {
    const seen = await readAll(
      tarGz([
        { name: 'PaxHeader', type, data: '30 mtime=1700000000.123456789\n' },
        { name: 'metadata.json', data: metadataJson() },
      ]),
    );
    expect(seen.map((s) => s.name)).toEqual(['metadata.json']);
    expect(seen[0]?.data.toString()).toBe(metadataJson());
  });

  /** One pax record, `<length> <keyword>=<value>\n`, its length counting itself. */
  const paxRecord = (keyword: string, value: string): string => {
    const body = ` ${keyword}=${value}\n`;
    let length = body.length + 1;
    while (`${length}${body}`.length !== length) length = `${length}${body}`.length;
    return `${length}${body}`;
  };

  it.each([
    ['an extended', 'size', 'x', '10'],
    ['an extended', 'path', 'x', 'evil.json'],
    ['a global', 'size', 'g', '10'],
    ['a global', 'path', 'g', 'evil.json'],
  ])('rejects %s pax header that sets %s (final review F9)', async (_what, key, type, value) => {
    const error = await rejection(
      readAll(
        tarGz([
          {
            name: 'PaxHeader',
            type,
            data: paxRecord('mtime', '1700000000.5') + paxRecord(key, value),
          },
          { name: 'metadata.json', data: metadataJson() },
        ]),
      ),
    );
    expect(error).toBeInstanceOf(TarError);
    expect((error as Error).message).toMatch(/pax header that sets the size or the name/);
  });

  it('rejects a pax header whose records are malformed (final review F9)', async () => {
    const error = await rejection(
      readAll(
        tarGz([
          { name: 'PaxHeader', type: 'x', data: '99 path=evil.json\n' },
          { name: 'metadata.json', data: metadataJson() },
        ]),
      ),
    );
    expect(error).toBeInstanceOf(TarError);
    expect((error as Error).message).toMatch(/malformed pax header/);
  });

  it('rejects a header whose checksum is wrong', async () => {
    const error = await rejection(
      readAll(tarGz([{ name: 'metadata.json', data: metadataJson(), badChecksum: true }])),
    );
    expect(error).toBeInstanceOf(TarError);
    expect((error as Error).message).toMatch(/not a tar archive/);
  });

  it('rejects data that is not gzip', async () => {
    const error = await rejection(readAll(tar([{ name: 'metadata.json', data: 'x' }])));
    expect(error).toBeInstanceOf(TarError);
    expect((error as Error).message).toMatch(/not a gzip/);
  });

  it('rejects gzip data that is cut', async () => {
    const whole = trivyArchive({ db: randomBytes(50_000) });
    const error = await rejection(readAll(whole.subarray(0, whole.length - 2_000)));
    expect(error).toBeInstanceOf(TarError);
    expect((error as Error).message).toMatch(/ends early/);
  });

  it('rejects a tar that ends inside an entry', async () => {
    const whole = tar([{ name: 'trivy.db', data: randomBytes(10_000) }]);
    const error = await rejection(readAll(gzipSync(whole.subarray(0, 4_096))));
    expect(error).toBeInstanceOf(TarError);
    expect((error as Error).message).toMatch(/ends early/);
  });

  it('rejects a kept entry over 1 MiB', async () => {
    const error = await rejection(
      readAll(tarGz([{ name: 'metadata.json', data: Buffer.alloc(1_048_577, 0x20) }])),
    );
    expect(error).toBeInstanceOf(TarError);
    expect((error as Error).message).toMatch(/metadata\.json is larger than 1 MiB/);
  });

  describe('limits', () => {
    const bomb = () =>
      tarGz([
        { name: 'trivy.db', data: Buffer.alloc(2 * 1024 * 1024) },
        { name: 'metadata.json', data: metadataJson() },
      ]);
    const read = (bytes: Buffer, limits: { maxBytes?: number; deadline?: number }) =>
      readTarGz(
        piecesOf(bytes),
        (name) => (name === 'trivy.db' ? 'stream' : 'skip'),
        async (entry) => {
          if (entry.want === 'stream') for await (const _ of entry.body) void _;
        },
        limits,
      );

    it('rejects an archive that inflates past maxBytes', async () => {
      const error = await rejection(read(bomb(), { maxBytes: 1024 * 1024 }));
      expect(error).toBeInstanceOf(TarError);
      expect((error as Error).message).toContain('more than 1048576 bytes');
      expect((error as TarError).limit).toBe('bytes');
    });

    it('reads an archive that inflates to just under maxBytes', async () => {
      const inflated = gunzipSync(bomb()).length;
      await expect(read(bomb(), { maxBytes: inflated })).resolves.toBeUndefined();
      const error = await rejection(read(bomb(), { maxBytes: inflated - 1 }));
      expect(error).toBeInstanceOf(TarError);
    });

    it('rejects an archive read past its deadline', async () => {
      const error = await rejection(read(bomb(), { deadline: Date.now() - 1 }));
      expect(error).toBeInstanceOf(TarError);
      expect((error as Error).message).toBe('The archive took too long to unpack');
      expect((error as TarError).limit).toBe('deadline');
    });

    it('names no limit for an archive that is not valid', async () => {
      const error = await rejection(read(Buffer.from('not gzip'), {}));
      expect(error).toBeInstanceOf(TarError);
      expect((error as TarError).limit).toBeNull();
    });
  });

  describe('the gzip trailer', () => {
    const DAMAGED = 'The gzip archive is damaged (checksum or length mismatch)';
    const readPieces = (bytes: Buffer) =>
      readTarGz(
        piecesOf(bytes, 1),
        (name) => (name === 'metadata.json' ? 'keep' : 'skip'),
        () => undefined,
      );

    it.each([
      ['CRC', 8],
      ['ISIZE', 1],
    ])('rejects a bad %s even when read byte by byte', async (_what, fromEnd) => {
      const bad = trivyArchive({ db: randomBytes(50_000) });
      bad[bad.length - fromEnd] = (bad[bad.length - fromEnd] ?? 0) ^ 0xff;
      const error = await rejection(readPieces(bad));
      expect(error).toBeInstanceOf(TarError);
      expect((error as Error).message).toBe(DAMAGED);
    });

    it('reads an archive followed by zero bytes', async () => {
      const good = trivyArchive({ db: randomBytes(1_000) });
      await expect(readPieces(Buffer.concat([good, Buffer.alloc(512)]))).resolves.toBeUndefined();
    });

    it('rejects an archive followed by junk', async () => {
      const good = trivyArchive({ db: randomBytes(1_000) });
      const error = await rejection(readPieces(Buffer.concat([good, Buffer.from('junk')])));
      expect(error).toBeInstanceOf(TarError);
    });
  });

  it('passes on what the chunks throw', async () => {
    const cut = new Error('the stream was cut');
    async function* broken(): AsyncGenerator<Buffer> {
      const whole = trivyArchive({ db: randomBytes(50_000) });
      yield whole.subarray(0, 10_000);
      throw cut;
    }
    const error = await rejection(
      readTarGz(
        broken(),
        () => 'stream',
        async (entry) => {
          if (entry.want === 'stream') for await (const _ of entry.body) void _;
        },
      ),
    );
    expect(error).toBe(cut);
  });

  it('passes on what onFile throws', async () => {
    const failed = new Error('disk full');
    const error = await rejection(
      readTarGz(
        piecesOf(trivyArchive()),
        () => 'stream',
        () => {
          throw failed;
        },
      ),
    );
    expect(error).toBe(failed);
  });

  it('reads an empty archive as no entries', async () => {
    expect(await readAll(tarGz([]))).toEqual([]);
  });
});

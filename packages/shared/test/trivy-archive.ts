import { gzipSync } from 'node:zlib';

/** One entry of a test tar: a regular file unless `type` says otherwise. */
export interface TarInput {
  name: string;
  data?: Buffer | string;
  /** The typeflag: `0` file (default), `5` directory, `2` symbolic link, `x` pax header, … */
  type?: string;
  /** POSIX ustar (`ustar\0` + `00`, default) or the GNU form (`ustar  \0`) GNU tar writes. */
  format?: 'posix' | 'gnu';
  /** The POSIX prefix field (joined to the name with `/`). */
  prefix?: string;
  /** Spoils the header checksum. */
  badChecksum?: boolean;
}

function put(block: Buffer, offset: number, length: number, text: string): void {
  block.write(text.slice(0, length), offset, length, 'latin1');
}

function octal(value: number, digits: number): string {
  return `${value.toString(8).padStart(digits, '0')}\0`;
}

/** One 512-byte ustar header. */
function header(entry: TarInput, size: number): Buffer {
  const block = Buffer.alloc(512);
  put(block, 0, 100, entry.name);
  put(block, 100, 8, '0000644\0');
  put(block, 108, 8, '0000000\0');
  put(block, 116, 8, '0000000\0');
  put(block, 124, 12, octal(size, 11));
  put(block, 136, 12, octal(1_761_800_000, 11));
  put(block, 148, 8, '        ');
  put(block, 156, 1, entry.type ?? '0');
  if (entry.format === 'gnu') {
    put(block, 257, 8, 'ustar  \0');
  } else {
    put(block, 257, 6, 'ustar\0');
    put(block, 263, 2, '00');
    if (entry.prefix !== undefined) put(block, 345, 155, entry.prefix);
  }
  put(block, 265, 32, 'runner');
  put(block, 297, 32, 'runner');
  let sum = 0;
  for (const byte of block) sum += byte;
  if (entry.badChecksum) sum += 1;
  put(block, 148, 8, `${sum.toString(8).padStart(6, '0')}\0 `);
  return block;
}

/** A tar archive of `entries`, ended by two zero blocks. */
export function tar(entries: readonly TarInput[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const data =
      typeof entry.data === 'string' ? Buffer.from(entry.data) : (entry.data ?? Buffer.alloc(0));
    parts.push(header(entry, data.length), data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad > 0) parts.push(Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

export function tarGz(entries: readonly TarInput[]): Buffer {
  return gzipSync(tar(entries), { level: 1 });
}

export const UPDATED_AT = '2026-10-30T19:07:50Z';

export function metadataJson(version = 2, updatedAt: unknown = UPDATED_AT): string {
  return JSON.stringify({
    Version: version,
    NextUpdate: '2026-10-31T01:07:50Z',
    UpdatedAt: updatedAt,
    DownloadedAt: '2026-10-30T20:00:00Z',
  });
}

export interface TrivyArchiveOptions {
  /** metadata.json's text; null leaves the file out. */
  metadata?: string | null;
  /** trivy.db's bytes; null leaves the file out. */
  db?: Buffer | null;
  /**
   * `flat`: `trivy.db`, `metadata.json` (the registry's layer, GNU tar); `dotdb`: `./`, `./db/`,
   * `./db/trivy.db`, `./db/metadata.json` (what `tar czf … -C cache ./db` makes).
   */
  layout?: 'flat' | 'dotdb';
}

/** A tiny Trivy database archive (`db.tar.gz`): trivy.db first, then metadata.json. */
export function trivyArchive(options: TrivyArchiveOptions = {}): Buffer {
  const metadata = options.metadata === undefined ? metadataJson() : options.metadata;
  const db = options.db === undefined ? Buffer.from('bolt database bytes') : options.db;
  const dot = options.layout === 'dotdb';
  const format = dot ? 'posix' : 'gnu';
  const entries: TarInput[] = dot
    ? [
        { name: './', type: '5', format },
        { name: './db/', type: '5', format },
      ]
    : [];
  if (db !== null) entries.push({ name: dot ? './db/trivy.db' : 'trivy.db', data: db, format });
  if (metadata !== null) {
    entries.push({ name: dot ? './db/metadata.json' : 'metadata.json', data: metadata, format });
  }
  return tarGz(entries);
}

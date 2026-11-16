import { closeSync, openSync, readSync } from 'node:fs';

/**
 * A read-only reader of a bbolt file (go.etcd.io/bbolt's format), as much as the checks of
 * trivy-db-filter.test.ts (0.16 debts D31-1) and trivy-db-fixture.test.ts (0.16 SBOM) need: the
 * top-level bucket names, and the entries and nested buckets of a bucket. It takes the meta page
 * with the higher transaction id and walks branch and leaf pages, inline buckets included.
 */
export interface BoltFile {
  /** The top-level buckets, in key order. */
  readonly topLevel: readonly string[];
  /**
   * The key/value entries of a top-level bucket (its nested buckets left out), or of the bucket
   * that `nested` names below it, one level per name.
   */
  entries(bucket: string, ...nested: string[]): Map<string, Buffer>;
  /** The nested buckets of a bucket named as for {@link entries}, in key order. */
  buckets(bucket: string, ...nested: string[]): string[];
  close(): void;
}

const PAGE_HEADER = 16;
const BUCKET_HEADER = 16;
const ELEMENT = 16;
const BRANCH_PAGE = 0x01;
const LEAF_PAGE = 0x02;
const BUCKET_LEAF = 0x01;
const MAGIC = 0xed0cdaed;
/** Offsets in a meta page, after its page header. */
const META = { magic: 0, pageSize: 8, root: 16, txid: 48, size: 64 } as const;

interface Element {
  key: Buffer;
  value: Buffer;
  bucket: boolean;
}

export function openBolt(file: string): BoltFile {
  const fd = openSync(file, 'r');
  const read = (offset: number, length: number): Buffer => {
    const buf = Buffer.alloc(length);
    const n = readSync(fd, buf, 0, length, offset);
    if (n !== length) throw new Error(`${file}: short read at ${offset}`);
    return buf;
  };
  try {
    const pageSize = read(PAGE_HEADER + META.pageSize, 4).readUInt32LE(0);
    const meta = [0, 1]
      .map((i) => read(i * pageSize + PAGE_HEADER, META.size))
      .filter((m) => m.readUInt32LE(META.magic) === MAGIC)
      .sort((a, b) => (a.readBigUInt64LE(META.txid) < b.readBigUInt64LE(META.txid) ? 1 : -1))[0];
    if (meta === undefined) throw new Error(`${file}: not a bbolt file`);

    const page = (id: bigint): Buffer => {
      const offset = Number(id) * pageSize;
      const overflow = read(offset, PAGE_HEADER).readUInt32LE(12);
      return read(offset, pageSize * (overflow + 1));
    };
    /** The leaf elements of the tree that starts at a page (a buffer that begins with its header). */
    const elements = function* (p: Buffer): Generator<Element> {
      const flags = p.readUInt16LE(8);
      const count = p.readUInt16LE(10);
      for (let i = 0; i < count; i++) {
        const at = PAGE_HEADER + i * ELEMENT;
        if (flags & LEAF_PAGE) {
          const pos = at + p.readUInt32LE(at + 4);
          const keySize = p.readUInt32LE(at + 8);
          const valueSize = p.readUInt32LE(at + 12);
          yield {
            key: p.subarray(pos, pos + keySize),
            value: p.subarray(pos + keySize, pos + keySize + valueSize),
            bucket: (p.readUInt32LE(at) & BUCKET_LEAF) !== 0,
          };
        } else if (flags & BRANCH_PAGE) {
          yield* elements(page(p.readBigUInt64LE(at + 8)));
        } else {
          throw new Error(`${file}: a page with flags ${flags} in a bucket's tree`);
        }
      }
    };
    // A bucket's value is its root page id and sequence; root 0 means an inline page follows.
    const bucketElements = (value: Buffer) => {
      const root = value.readBigUInt64LE(0);
      return elements(root === 0n ? value.subarray(BUCKET_HEADER) : page(root));
    };

    const top = [...elements(page(meta.readBigUInt64LE(META.root)))].filter((e) => e.bucket);
    /** The elements of the bucket at a path of names, the first one top-level. */
    const at = (path: readonly string[]): Element[] => {
      let level: Element[] = top;
      path.forEach((name, i) => {
        const found = level.find((e) => e.bucket && e.key.toString('utf8') === name);
        if (found === undefined)
          throw new Error(`${file}: no bucket ${path.slice(0, i + 1).join(' / ')}`);
        level = [...bucketElements(found.value)];
      });
      return level;
    };
    return {
      topLevel: top.map((e) => e.key.toString('utf8')),
      entries(bucket, ...nested) {
        const out = new Map<string, Buffer>();
        for (const e of at([bucket, ...nested]))
          if (!e.bucket) out.set(e.key.toString('utf8'), e.value);
        return out;
      },
      buckets: (bucket, ...nested) =>
        at([bucket, ...nested])
          .filter((e) => e.bucket)
          .map((e) => e.key.toString('utf8')),
      close: () => closeSync(fd),
    };
  } catch (err) {
    closeSync(fd);
    throw err;
  }
}

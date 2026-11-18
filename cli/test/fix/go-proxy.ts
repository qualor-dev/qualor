import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { crc32 } from 'node:zlib';

/**
 * R27: an offline Go module proxy for the Go adapter's tests. `writeGoProxy` lays the modules out
 * under `dir` as the GOPROXY protocol reads them (`<module>/@v/list`, `<version>.info`, `.mod`,
 * `.zip`) and returns its `file://` URL, for `GOPROXY=<url>` with `GOSUMDB=off`.
 */
export interface GoProxyModule {
  /** The module path, such as `example.com/qf`. */
  path: string;
  /** The version with its `v`, such as `v1.2.6` or a pseudo-version. */
  version: string;
  /** The module's `go.mod` text, served as `.mod` and put in the zip. */
  goMod: string;
  /** The module's other files (`qf.go`), by their path in the module. */
  files: Record<string, string>;
}

/** The proxy protocol's case encoding: each upper-case letter as `!` and its lower case. */
function escapeCase(text: string): string {
  return text.replaceAll(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

/** A pseudo-version's tail (`-yyyymmddhhmmss-abcdefabcdef`): proxies do not list those. */
const PSEUDO = /\d{14}-[0-9a-f]{12}(?:\+incompatible)?$/;
const INCOMPATIBLE = '+incompatible';

/** Every file of one zip entry is stored (method 0), named in UTF-8, dated 1980-01-01. */
const STORED = 0;
const UTF8_NAMES = 0x0800;
/** 1980-01-01 (year 0 from 1980, month 1, day 1), the first date a zip can hold. */
const DOS_DATE = 0x21;

function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
}

/** The fields a local header and a central directory entry share, from "version needed" on. */
function commonFields(name: Buffer, data: Buffer, crc: number): Buffer {
  return Buffer.concat([
    u16(20),
    u16(UTF8_NAMES),
    u16(STORED),
    u16(0),
    u16(DOS_DATE),
    u32(crc),
    u32(data.length),
    u32(data.length),
    u16(name.length),
    u16(0),
  ]);
}

/** A zip archive of `entries` (name → text), stored without compression. */
export function storedZip(entries: Record<string, string>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [entryName, text] of Object.entries(entries)) {
    const name = Buffer.from(entryName, 'utf8');
    const data = Buffer.from(text, 'utf8');
    const common = commonFields(name, data, crc32(data));
    const local = Buffer.concat([u32(0x04034b50), common, name, data]);
    centrals.push(
      Buffer.concat([
        u32(0x02014b50),
        u16(20),
        common,
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(offset),
        name,
      ]),
    );
    locals.push(local);
    offset += local.length;
  }
  const central = Buffer.concat(centrals);
  const end = Buffer.concat([
    u32(0x06054b50),
    u16(0),
    u16(0),
    u16(centrals.length),
    u16(centrals.length),
    u32(central.length),
    u32(offset),
    u16(0),
  ]);
  return Buffer.concat([...locals, central, end]);
}

/**
 * Writes the modules under `dir` as a GOPROXY tree and returns its `file://` URL. Each module
 * version gets its `.info` (`{"Version", "Time"}`), its `.mod` (`goMod`) and its `.zip` (`go.mod`,
 * except for a `+incompatible` version, and `files` under `<path>@<version>/`); each module's
 * `@v/list` names its versions that are not pseudo-versions, as a real proxy does.
 */
export function writeGoProxy(
  dir: string,
  modules: { path: string; version: string; goMod: string; files: Record<string, string> }[],
): string {
  const lists = new Map<string, string[]>();
  for (const m of modules) {
    const at = path.join(dir, ...escapeCase(m.path).split('/'), '@v');
    mkdirSync(at, { recursive: true });
    const base = path.join(at, escapeCase(m.version));
    const info = { Version: m.version, Time: '2026-01-01T00:00:00Z' };
    writeFileSync(`${base}.info`, `${JSON.stringify(info)}\n`);
    writeFileSync(`${base}.mod`, m.goMod);
    const prefix = `${m.path}@${m.version}/`;
    // A `+incompatible` version is one without a go.mod; the proxy serves a made-up `.mod`.
    const zipEntries: Record<string, string> = m.version.endsWith(INCOMPATIBLE)
      ? {}
      : { [`${prefix}go.mod`]: m.goMod };
    for (const [file, text] of Object.entries(m.files)) zipEntries[`${prefix}${file}`] = text;
    writeFileSync(`${base}.zip`, storedZip(zipEntries));
    const listed = lists.get(at) ?? [];
    if (!PSEUDO.test(m.version)) listed.push(m.version);
    lists.set(at, listed);
  }
  for (const [at, versions] of lists) {
    writeFileSync(path.join(at, 'list'), versions.map((v) => `${v}\n`).join(''));
  }
  return pathToFileURL(dir).href;
}

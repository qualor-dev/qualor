import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { BUN_VERSION, RELEASE_TARGETS, type ReleaseTarget } from '../../cli/scripts/targets';
import { REPO_ROOT } from '../deploy/stack';

/**
 * Ruling R-MAC (release.md §4), extended in the fix wave to every target: bun 1.3.13 fails to
 * extract the macOS runtimes it downloads for itself on a Windows host, and a runtime bun fetches
 * for itself is checked by nothing of ours. So the release pins the runtime of every release
 * target, linux-x64 included (tools/release/bun-runtimes.json: the npm registry's SHA-512
 * integrity and our own SHA-256), downloads them over https, checks both hashes before unpacking,
 * extracts the executable itself, and passes it to `bun build --compile-executable-path`. Every
 * host then builds all five targets the same way, from runtimes nobody but us chose.
 */
export interface RuntimePin {
  package: string;
  url: string;
  integrity: string;
  sha256: string;
  /** The executable inside the tarball; `package/bin/bun` unless set (Windows: `bun.exe`). */
  entry?: string;
}
export interface RuntimePins {
  version: string;
  runtimes: Partial<Record<ReleaseTarget, RuntimePin>>;
}

export const RUNTIME_PINS_FILE = path.join(REPO_ROOT, 'tools', 'release', 'bun-runtimes.json');
export const RUNTIMES_DIR = path.join(REPO_ROOT, '.tmp', 'bun-runtimes');
/** The file inside an npm package tarball that is the runtime, unless its pin names another. */
const RUNTIME_ENTRY = 'package/bin/bun';

export function loadRuntimePins(file = RUNTIME_PINS_FILE): RuntimePins {
  const pins = JSON.parse(readFileSync(file, 'utf8')) as RuntimePins;
  if (pins.version !== BUN_VERSION) {
    throw new Error(`${file} pins bun ${pins.version}, but BUN_VERSION is ${BUN_VERSION}`);
  }
  for (const target of Object.keys(RELEASE_TARGETS) as ReleaseTarget[]) {
    if (pins.runtimes[target] === undefined) {
      throw new Error(`${file} pins no Bun runtime for ${target}`);
    }
  }
  return pins;
}

/** Throws unless the tarball matches both of its pins. */
export function checkRuntime(data: Uint8Array, pin: RuntimePin): void {
  const sha512 = `sha512-${createHash('sha512').update(data).digest('base64')}`;
  const sha256 = createHash('sha256').update(data).digest('hex');
  if (sha512 !== pin.integrity || sha256 !== pin.sha256) {
    throw new Error(
      `${pin.url}: checksum mismatch (sha512 ${sha512}, sha256 ${sha256}); expected ${pin.integrity} and ${pin.sha256}`,
    );
  }
}

function field(block: Uint8Array, offset: number, length: number): string {
  const raw = Buffer.from(block.subarray(offset, offset + length)).toString('utf8');
  const nul = raw.indexOf('\0');
  return nul === -1 ? raw : raw.slice(0, nul);
}

/** One regular file from a gzipped tar (ustar, with pax and GNU long names), or an error. */
export function extractFromTgz(tgz: Uint8Array, name: string): Buffer {
  const tar = gunzipSync(tgz);
  let offset = 0;
  let longName: string | undefined;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const size = parseInt(field(header, 124, 12).trim() || '0', 8);
    if (!Number.isFinite(size) || size < 0) throw new Error('corrupt tar header');
    const type = String.fromCharCode(header[156] ?? 0);
    const body = tar.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x' || type === 'L') {
      // pax extended header (`<len> path=<name>\n`) or GNU long name: applies to the next entry.
      const text = body.toString('utf8');
      longName =
        type === 'L' ? text.replace(/\0+$/, '') : /(?:^|\n)\d+ path=([^\n]*)\n/.exec(text)?.[1];
      continue;
    }
    if (type === 'g') continue;
    const prefix = field(header, 345, 155);
    const entry =
      longName ?? (prefix ? `${prefix}/${field(header, 0, 100)}` : field(header, 0, 100));
    longName = undefined;
    if (entry === name && (type === '0' || type === '\0')) return Buffer.from(body);
  }
  throw new Error(`${name} is not in the tarball`);
}

export type Download = (url: string) => Promise<Uint8Array>;

export const httpsDownload: Download = async (url) => {
  if (!url.startsWith('https://')) throw new Error(`not https: ${url}`);
  const response = await fetch(url, { redirect: 'error' });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
};

/**
 * The runtime executable for `target`. An unpinned target is refused: bun would otherwise
 * download a runtime nothing checks. A cached tarball is used only while it still matches its pins.
 */
export async function bunRuntime(
  target: ReleaseTarget,
  o: { pins?: RuntimePins; dir?: string; download?: Download } = {},
): Promise<string> {
  const pins = o.pins ?? loadRuntimePins();
  const pin = pins.runtimes[target];
  if (pin === undefined) throw new Error(`no pinned Bun runtime for ${target}`);
  const dir = o.dir ?? RUNTIMES_DIR;
  const base = `${pin.package.replace(/^@/, '').replace('/', '-')}-${pins.version}`;
  const tarball = path.join(dir, `${base}.tgz`);
  mkdirSync(dir, { recursive: true });
  let data = existsSync(tarball) ? readFileSync(tarball) : undefined;
  try {
    if (data !== undefined) checkRuntime(data, pin);
  } catch {
    data = undefined;
    rmSync(tarball, { force: true });
  }
  if (data === undefined) {
    const fetched = await (o.download ?? httpsDownload)(pin.url);
    checkRuntime(fetched, pin);
    writeFileSync(tarball, fetched);
    data = Buffer.from(fetched);
  }
  const entry = pin.entry ?? RUNTIME_ENTRY;
  const exe = path.join(dir, base, path.posix.basename(entry));
  mkdirSync(path.dirname(exe), { recursive: true });
  writeFileSync(exe, extractFromTgz(data, entry));
  chmodSync(exe, 0o755);
  return exe;
}

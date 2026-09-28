import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import { BUN_VERSION, bunReleaseArgs, RELEASE_TARGETS } from '../../cli/scripts/targets';
import {
  bunRuntime,
  checkRuntime,
  extractFromTgz,
  loadRuntimePins,
  type RuntimePin,
  type RuntimePins,
} from './runtimes';

/** A minimal ustar archive: each entry a 512-byte header plus its padded body. */
function tar(entries: { name: string; body: string; type?: string; prefix?: string }[]): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const header = Buffer.alloc(512);
    header.write(e.name, 0, 100, 'utf8');
    header.write('0000755\0', 100);
    header.write(`${Buffer.byteLength(e.body).toString(8).padStart(11, '0')}\0`, 124);
    header.write(e.type ?? '0', 156);
    header.write('ustar\0', 257);
    if (e.prefix) header.write(e.prefix, 345, 155, 'utf8');
    blocks.push(header);
    const body = Buffer.from(e.body);
    blocks.push(Buffer.concat([body, Buffer.alloc((512 - (body.length % 512)) % 512)]));
  }
  return Buffer.concat([...blocks, Buffer.alloc(1024)]);
}

function pinFor(data: Buffer): RuntimePin {
  return {
    package: '@oven/bun-darwin-x64',
    url: 'https://registry.example/bun-darwin-x64.tgz',
    integrity: `sha512-${createHash('sha512').update(data).digest('base64')}`,
    sha256: createHash('sha256').update(data).digest('hex'),
  };
}

let dir = '';
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe('the pinned Bun runtimes (ruling R-MAC, release.md §4)', () => {
  it('pins the runtime of every release target at BUN_VERSION from the npm registry by SHA-512 and SHA-256', () => {
    const pins = loadRuntimePins();
    expect(pins.version).toBe(BUN_VERSION);
    expect(Object.keys(pins.runtimes).sort()).toEqual(Object.keys(RELEASE_TARGETS).sort());
    const packages = {
      'linux-x64': 'bun-linux-x64',
      'linux-arm64': 'bun-linux-aarch64',
      'darwin-x64': 'bun-darwin-x64',
      'darwin-arm64': 'bun-darwin-aarch64',
      'windows-x64': 'bun-windows-x64',
    };
    for (const [target, name] of Object.entries(packages)) {
      const pin = pins.runtimes[target as keyof typeof packages];
      expect(pin?.entry ?? 'package/bin/bun').toBe(
        target.startsWith('windows-') ? 'package/bin/bun.exe' : 'package/bin/bun',
      );
      expect(pin?.package).toBe(`@oven/${name}`);
      expect(pin?.url).toBe(
        `https://registry.npmjs.org/@oven/${name}/-/${name}-${BUN_VERSION}.tgz`,
      );
      expect(pin?.integrity).toMatch(/^sha512-[A-Za-z0-9+/]{86}==$/);
      expect(pin?.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('passes the runtime to bun with --compile-executable-path, and only when there is one', () => {
    expect(bunReleaseArgs('darwin-x64', '/out/q', '/rt/bun')).toContain(
      '--compile-executable-path=/rt/bun',
    );
    expect(bunReleaseArgs('darwin-x64', '/out/q').join(' ')).not.toContain('executable-path');
  });
});

describe('checkRuntime and extractFromTgz', () => {
  const tgz = gzipSync(
    tar([
      { name: 'package/package.json', body: '{}' },
      { name: 'package/bin/bun', body: 'RUNTIME' },
    ]),
  );

  it('accepts a tarball matching both pins and refuses one that matches only one', () => {
    const pin = pinFor(tgz);
    expect(() => checkRuntime(tgz, pin)).not.toThrow();
    expect(() => checkRuntime(tgz, { ...pin, sha256: '0'.repeat(64) })).toThrow(
      /checksum mismatch/,
    );
    expect(() => checkRuntime(tgz, { ...pin, integrity: 'sha512-AAAA' })).toThrow(
      /checksum mismatch/,
    );
  });

  it('extracts one regular file, by its plain, prefixed or pax name', () => {
    expect(extractFromTgz(tgz, 'package/bin/bun').toString()).toBe('RUNTIME');
    const prefixed = gzipSync(tar([{ name: 'bun', prefix: 'package/bin', body: 'P' }]));
    expect(extractFromTgz(prefixed, 'package/bin/bun').toString()).toBe('P');
    const pax = gzipSync(
      tar([
        { name: 'PaxHeader', type: 'x', body: '24 path=package/bin/bun\n' },
        { name: 'truncated', body: 'X' },
      ]),
    );
    expect(extractFromTgz(pax, 'package/bin/bun').toString()).toBe('X');
    expect(() => extractFromTgz(tgz, 'package/bin/node')).toThrow(/not in the tarball/);
  });
});

describe('bunRuntime', () => {
  const tgz = gzipSync(tar([{ name: 'package/bin/bun', body: 'RUNTIME' }]));
  const pins = (data: Buffer): RuntimePins => ({
    version: BUN_VERSION,
    runtimes: { 'darwin-x64': pinFor(data) },
  });

  it('downloads, checks and extracts a pinned runtime, then reuses the checked tarball', async () => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-runtimes-'));
    const urls: string[] = [];
    const download = async (url: string) => {
      urls.push(url);
      return tgz;
    };
    const exe = await bunRuntime('darwin-x64', { pins: pins(tgz), dir, download });
    expect(readFileSync(exe, 'utf8')).toBe('RUNTIME');
    await bunRuntime('darwin-x64', { pins: pins(tgz), dir, download });
    expect(urls).toEqual(['https://registry.example/bun-darwin-x64.tgz']);
  });

  it('refuses a download that does not match, and writes nothing', async () => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-runtimes-'));
    const other = gzipSync(tar([{ name: 'package/bin/bun', body: 'EVIL' }]));
    await expect(
      bunRuntime('darwin-x64', { pins: pins(tgz), dir, download: async () => other }),
    ).rejects.toThrow(/checksum mismatch/);
    expect(existsSync(path.join(dir, `oven-bun-darwin-x64-${BUN_VERSION}.tgz`))).toBe(false);
    expect(existsSync(path.join(dir, `oven-bun-darwin-x64-${BUN_VERSION}`))).toBe(false);
  });

  it('downloads again when the cached tarball no longer matches', async () => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-runtimes-'));
    writeFileSync(path.join(dir, `oven-bun-darwin-x64-${BUN_VERSION}.tgz`), 'CHANGED');
    let calls = 0;
    const exe = await bunRuntime('darwin-x64', {
      pins: pins(tgz),
      dir,
      download: async () => {
        calls += 1;
        return tgz;
      },
    });
    expect(calls).toBe(1);
    expect(readFileSync(exe, 'utf8')).toBe('RUNTIME');
  });

  it('refuses an unpinned target instead of leaving the download to bun', async () => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-runtimes-'));
    await expect(bunRuntime('linux-x64', { pins: pins(tgz), dir })).rejects.toThrow(
      'no pinned Bun runtime for linux-x64',
    );
  });

  it('extracts the runtime a pin names, bun.exe for Windows', async () => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-runtimes-'));
    const win = gzipSync(tar([{ name: 'package/bin/bun.exe', body: 'PE' }]));
    const exe = await bunRuntime('windows-x64', {
      pins: {
        version: BUN_VERSION,
        runtimes: { 'windows-x64': { ...pinFor(win), entry: 'package/bin/bun.exe' } },
      },
      dir,
      download: async () => win,
    });
    expect(path.basename(exe)).toBe('bun.exe');
    expect(readFileSync(exe, 'utf8')).toBe('PE');
  });

  it('refuses a pins file without every release target', () => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-runtimes-'));
    const file = path.join(dir, 'pins.json');
    const all = loadRuntimePins();
    const rest = Object.fromEntries(
      Object.entries(all.runtimes).filter(([target]) => target !== 'linux-arm64'),
    );
    writeFileSync(file, JSON.stringify({ ...all, runtimes: rest }));
    expect(() => loadRuntimePins(file)).toThrow(`${file} pins no Bun runtime for linux-arm64`);
  });
});

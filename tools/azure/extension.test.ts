import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../deploy/stack';
import { VERSION } from '../../server/src/index';

/** The manifest holds numbers only: a pre-release VERSION packs as its x.y.z. */
const PACKED = VERSION.split('-')[0] ?? VERSION;
const EXTENSION = path.join(REPO_ROOT, 'integrations', 'azure-devops', 'extension');

/** The entries of a zip, read through its central directory (no zip dependency in the repo). */
function zipEntries(file: string): Map<string, Buffer> {
  const zip = readFileSync(file);
  const end = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (end < 0) throw new Error('not a zip file');
  const count = zip.readUInt16LE(end + 10);
  let at = zip.readUInt32LE(end + 16);
  const out = new Map<string, Buffer>();
  for (let i = 0; i < count; i += 1) {
    const method = zip.readUInt16LE(at + 10);
    const size = zip.readUInt32LE(at + 20);
    const nameLength = zip.readUInt16LE(at + 28);
    const extra = zip.readUInt16LE(at + 30);
    const comment = zip.readUInt16LE(at + 32);
    const local = zip.readUInt32LE(at + 42);
    const name = zip.toString('utf8', at + 46, at + 46 + nameLength);
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    const data = zip.subarray(start, start + size);
    out.set(name, method === 8 ? inflateRawSync(data) : Buffer.from(data));
    at += 46 + nameLength + extra + comment;
  }
  return out;
}

function text(entries: Map<string, Buffer>, name: string): string {
  const data = entries.get(name);
  if (!data) throw new Error(`${name} is not in the VSIX`);
  return data.toString('utf8');
}

function pack(out: string, ...extra: string[]): string {
  execFileSync(process.execPath, ['--import', 'tsx', path.join('scripts', 'build.ts')], {
    cwd: EXTENSION,
    stdio: 'pipe',
  });
  execFileSync(
    process.execPath,
    ['--import', 'tsx', path.join('scripts', 'package.ts'), '--output-path', out, ...extra],
    { cwd: EXTENSION, stdio: 'pipe' },
  );
  const vsix = readdirSync(out).filter((f) => f.endsWith('.vsix'));
  expect(vsix).toHaveLength(1);
  return path.join(out, vsix[0] ?? '');
}

describe('the extension package (VSIX)', () => {
  let dir = '';
  let vsix = '';
  let dev = '';
  beforeAll(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'qualor-vsix-'));
    vsix = pack(path.join(dir, 'public'));
    dev = pack(path.join(dir, 'dev'), '--overrides-file', 'dev-overrides.json');
  }, 120_000);
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('is named after the extension id and the Qualor version', () => {
    expect(path.basename(vsix)).toBe(`qualor.qualor-${PACKED}.vsix`);
  });

  it('holds the manifests, the task and the icon', () => {
    const names = [...zipEntries(vsix).keys()];
    for (const n of [
      'extension.vsixmanifest',
      'extension.vsomanifest',
      'tasks/qualor/task.json',
      'tasks/qualor/index.js',
      'images/icon.png',
    ]) {
      expect(names, n).toContain(n);
    }
  });

  it('names publisher qualor, id qualor, the version and the Services target', () => {
    const entries = zipEntries(vsix);
    const manifest = text(entries, 'extension.vsixmanifest');
    expect(manifest).toMatch(
      new RegExp(`<Identity [^>]*Id="qualor" Publisher="qualor" Version="${PACKED}"`),
    );
    expect(manifest).toContain('<InstallationTarget Id="Microsoft.VisualStudio.Services"/>');
    expect(manifest).toContain('<Categories>Azure Pipelines</Categories>');
    const task = JSON.parse(text(entries, 'tasks/qualor/task.json')) as {
      version: { Major: number; Minor: number; Patch: number };
    };
    const [major, minor, patch] = PACKED.split('.').map(Number);
    expect(task.version).toEqual({ Major: major, Minor: minor, Patch: patch });
  });

  it('ships the licence notices of the bundled packages', () => {
    const notices = text(zipEntries(vsix), 'tasks/qualor/THIRD-PARTY-NOTICES');
    expect(notices).toContain('azure-pipelines-task-lib');
    expect(notices).toMatch(/Permission is hereby granted/);
    expect(notices).toMatch(/minimatch \S+ \(ISC\)/);
    expect(notices).toMatch(/semver \S+ \(ISC\)/);
    expect(notices).toMatch(/Permission to use, copy, modify, and\/or distribute this software/);
  });

  it('builds a dev variant under another id for a bench install', () => {
    expect(path.basename(dev)).toBe(`qualor.qualor-dev-${PACKED}.vsix`);
    const manifest = text(zipEntries(dev), 'extension.vsixmanifest');
    expect(manifest).toContain(`Id="qualor-dev" Publisher="qualor" Version="${PACKED}"`);
    expect(manifest).toContain('<DisplayName>Qualor (dev)</DisplayName>');
    expect(manifest).not.toContain('Microsoft.VisualStudio.Services.Public');
  });
});

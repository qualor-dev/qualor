import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { zipStore } from '../../server/src/support/zip';
import { parseVersion } from './version';
import { EXTENSION_DIR, readVsix, vsixName, vsixProblems, zipEntries } from './vsix';

/** A VSIX as tfx lays one out, with the identity and the task version given. */
function vsix(o: { id?: string; publisher?: string; version: string; task?: string }): Buffer {
  const [major, minor, patch] = (o.task ?? o.version).split('.').map(Number);
  const manifest =
    '<?xml version="1.0" encoding="utf-8"?>\n<PackageManifest Version="2.0.0">\n  <Metadata>\n' +
    `    <Identity Language="en-US" Id="${o.id ?? 'qualor'}" Publisher="${o.publisher ?? 'qualor'}" Version="${o.version}"/>\n` +
    '  </Metadata>\n</PackageManifest>\n';
  const task = JSON.stringify({
    name: 'Qualor',
    version: { Major: major, Minor: minor, Patch: patch },
  });
  return zipStore([
    { name: '[Content_Types].xml', data: Buffer.from('<Types/>') },
    { name: 'extension.vsixmanifest', data: Buffer.from(manifest) },
    { name: 'tasks/qualor/task.json', data: Buffer.from(task) },
  ]);
}

let dir = '';
afterEach(() => rmSync(dir, { recursive: true, force: true }));
const out = (): string => (dir = mkdtempSync(path.join(tmpdir(), 'qualor-vsix-')));

describe('the Azure DevOps extension in the release (Azure sub-plan 3 ruling 14)', () => {
  const v = parseVersion('2.7.1');

  it('is the VSIX tfx names after the extension and its numbers-only version', () => {
    expect(vsixName(v)).toBe('qualor.qualor-2.7.1.vsix');
    expect(vsixName(parseVersion('2.8.0-rc.1'))).toBe('qualor.qualor-2.8.0.vsix');
    expect(EXTENSION_DIR).toBe('azure-devops');
  });

  it('reads the entries of a zip by its central directory', () => {
    const entries = zipEntries(vsix({ version: '2.7.1' }));
    expect([...entries.keys()]).toEqual([
      '[Content_Types].xml',
      'extension.vsixmanifest',
      'tasks/qualor/task.json',
    ]);
    expect(entries.get('[Content_Types].xml')?.toString()).toBe('<Types/>');
    expect(() => zipEntries(Buffer.from('not a zip'))).toThrow(/not a zip file/);
  });

  it('accepts the extension qualor.qualor of this version, task included', () => {
    expect(vsixProblems(vsix({ version: '2.7.1' }), v)).toEqual([]);
    // A pre-release packs its x.y.z: the Marketplace takes numbers only.
    expect(vsixProblems(vsix({ version: '2.8.0' }), parseVersion('2.8.0-rc.1'))).toEqual([]);
  });

  it('refuses a VSIX of another version, a stale task, the dev extension and a non-zip', () => {
    expect(vsixProblems(vsix({ version: '2.6.3' }), v)).toEqual([
      'its version (vss-extension.json) is 2.6.3, not 2.7.1',
      'its task (task.json) is 2.6.3, not 2.7.1',
    ]);
    expect(vsixProblems(vsix({ version: '2.7.1', task: '2.6.3' }), v)).toEqual([
      'its task (task.json) is 2.6.3, not 2.7.1',
    ]);
    expect(vsixProblems(vsix({ id: 'qualor-dev', version: '2.7.1' }), v)).toEqual([
      'it is the extension qualor.qualor-dev, not qualor.qualor: build it without --overrides-file',
    ]);
    expect(vsixProblems(Buffer.from('PK nothing'), v)).toEqual(['not a zip file']);
    const empty = zipStore([{ name: 'x', data: Buffer.from('') }]);
    expect(vsixProblems(empty, v)).toEqual([
      'no extension.vsixmanifest in it',
      'no tasks/qualor/task.json in it',
    ]);
  });

  it('fails the dry run when the VSIX is missing or of another version', () => {
    const from = out();
    expect(() => readVsix(v, from)).toThrow(
      `${path.join(from, 'qualor.qualor-2.7.1.vsix')} is missing: run pnpm extension:package`,
    );
    // An old build under this version's name (or renamed to it) is refused, problems named.
    writeFileSync(path.join(from, 'qualor.qualor-2.7.1.vsix'), vsix({ version: '2.6.3' }));
    expect(() => readVsix(v, from)).toThrow(
      /qualor\.qualor-2\.7\.1\.vsix: its version \(vss-extension\.json\) is 2\.6\.3, not 2\.7\.1[\s\S]*run pnpm extension:package/,
    );
  });

  it('returns the bytes it checked, for the dry run to write unchanged', () => {
    const from = out();
    const file = path.join(from, 'qualor.qualor-2.7.1.vsix');
    writeFileSync(file, vsix({ version: '2.7.1' }));
    const read = readVsix(v, from);
    expect(read.name).toBe('qualor.qualor-2.7.1.vsix');
    expect(read.version).toBe('2.7.1');
    expect(read.data.equals(readFileSync(file))).toBe(true);
  });
});

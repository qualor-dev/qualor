import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ENTERPRISE_PROBE } from './checks';

const posix = process.platform !== 'win32';
const OWNER = String(process.getuid?.() ?? 0);
const GOOD =
  "export default { name: 'qualor-enterprise', apiVersion: 1, features: ['llm.fix-quota'], register() {} };\n";

let dir = '';
afterEach(() => {
  if (dir !== '') rmSync(dir, { recursive: true, force: true });
  dir = '';
});

/** A plugin directory like /app/enterprise: an ESM manifest and plugin.js. */
function pluginDir(source: string): string {
  dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-probe-'));
  const sub = path.join(dir, 'enterprise');
  mkdirSync(sub);
  writeFileSync(path.join(sub, 'package.json'), '{"type":"module"}\n');
  writeFileSync(path.join(sub, 'plugin.js'), source);
  if (posix) {
    chmodSync(sub, 0o755);
    chmodSync(path.join(sub, 'plugin.js'), 0o644);
  }
  return path.join(sub, 'plugin.js');
}

function probe(file: string, owner = OWNER): { code: number | null; problems: string[] } {
  const r = spawnSync(
    process.execPath,
    ['--input-type=module', '-e', ENTERPRISE_PROBE, file, owner],
    { encoding: 'utf8' },
  );
  return { code: r.status, problems: JSON.parse(r.stdout || '[]') as string[] };
}

/** On Windows owner and mode mean nothing (every file reads as writable): only the import rows count there. */
const importProblems = (problems: string[]) =>
  posix ? problems : problems.filter((p) => !/owned by|writable/.test(p));

describe('the enterprise plugin probe of the smoke test (enterprise.md §14.1)', () => {
  it('passes a root-owned, read-only plugin that declares qualor-enterprise with llm.fix-quota', () => {
    const r = probe(pluginDir(GOOD));
    expect(importProblems(r.problems)).toEqual([]);
    if (posix) expect(r.code).toBe(0);
  });

  it.each([
    [
      "export default { name: 'other', apiVersion: 1, features: ['llm.fix-quota'], register() {} };",
      'name is "other"',
    ],
    [
      "export default { name: 'qualor-enterprise', apiVersion: 2, features: ['llm.fix-quota'], register() {} };",
      'apiVersion is 2',
    ],
    [
      "export default { name: 'qualor-enterprise', apiVersion: 1, features: [], register() {} };",
      'features are []',
    ],
    [
      "export default { name: 'qualor-enterprise', apiVersion: 1, features: ['llm.fix-quota'] };",
      'register is not a function',
    ],
    ["throw new Error('boom');", 'import failed: boom'],
  ])('refuses %s', (source, problem) => {
    const r = probe(pluginDir(source));
    expect(r.code).toBe(1);
    expect(importProblems(r.problems)).toEqual([problem]);
  });

  it('refuses a missing file', () => {
    const file = pluginDir(GOOD);
    const r = probe(`${file}.missing`);
    expect(r.code).toBe(1);
    expect(r.problems[0]).toMatch(/ENOENT$/);
  });

  it.skipIf(!posix)('refuses a group- or world-writable file or directory', () => {
    const file = pluginDir(GOOD);
    chmodSync(file, 0o664);
    expect(probe(file).problems).toEqual([`${file} is group- or world-writable (mode 664)`]);
    chmodSync(file, 0o644);
    chmodSync(path.dirname(file), 0o757);
    expect(probe(file).problems).toEqual([
      `${path.dirname(file)} is group- or world-writable (mode 757)`,
    ]);
  });

  it.skipIf(!posix)('refuses a file owned by another user', () => {
    const file = pluginDir(GOOD);
    const other = String(Number(OWNER) + 1);
    expect(probe(file, other).problems).toEqual([
      `${file} is owned by uid ${OWNER}, not ${other}`,
      `${path.dirname(file)} is owned by uid ${OWNER}, not ${other}`,
    ]);
  });
});

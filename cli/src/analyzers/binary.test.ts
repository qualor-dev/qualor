import { chmodSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { findRepoBinary, isInside, real, resolveBinary, staysInside, within } from './binary';

const tmp = useTempDirs();
const exe = process.platform === 'win32' ? '.exe' : '';
const delimiter = process.platform === 'win32' ? ';' : ':';

function tool(dir: string, rel: string): string {
  writeTree(dir, { [rel]: '#!/bin/sh\n' });
  const abs = path.join(dir, ...rel.split('/'));
  chmodSync(abs, 0o755);
  return abs;
}

/** Null, or a system copy (the scanner image ships gitleaks): never anything under `root`. */
const fromSystem = (root: string, resolved: string | null) =>
  resolved === null || !within(root, resolved);

const pathEnv = (...dirs: string[]) => {
  const value = dirs.join(delimiter);
  return { PATH: value, Path: value };
};

describe('resolveBinary', () => {
  it('resolves from PATH (ruling V3: never from the project node_modules/.bin)', () => {
    const root = tmp();
    const bin = tmp();
    tool(root, `node_modules/.bin/eslint${exe}`);
    const global = tool(bin, `eslint${exe}`);
    const onPath = tool(bin, `pmd${exe}`);
    const env = pathEnv(bin);
    expect(resolveBinary('eslint', { root, env })).toBe(global);
    expect(resolveBinary('pmd', { root, env })).toBe(onPath);
    expect(resolveBinary('no-such-tool', { root, env })).toBeNull();
  });

  it('ignores Windows .cmd shims and, on POSIX, non-executable files', () => {
    const bin = tmp();
    writeTree(bin, { 'eslint.cmd': '@echo off\n', semgrep: 'x' });
    chmodSync(path.join(bin, 'semgrep'), 0o644);
    const env = pathEnv(bin);
    expect(resolveBinary('eslint', { root: tmp(), env, platform: 'win32' })).toBeNull();
    expect(resolveBinary('semgrep', { root: tmp(), env, platform: 'linux' })).toBeNull();
  });

  it('never returns a binary inside the repository, whatever PATH says (fix round 1)', () => {
    const root = tmp();
    const system = tmp();
    tool(root, `node_modules/.bin/eslint${exe}`);
    tool(root, `eslint${exe}`);
    tool(root, `tools/eslint${exe}`);
    const repoDirs = [
      path.join(root, 'node_modules', '.bin'),
      root,
      path.join(root, 'tools'),
      '.',
      'tools',
    ];
    expect(resolveBinary('eslint', { root, env: pathEnv(...repoDirs) })).toBeNull();
    const global = tool(system, `eslint${exe}`);
    expect(resolveBinary('eslint', { root, env: pathEnv(...repoDirs, system) })).toBe(global);
  });

  it('refuses a planted analyzer binary of any built-in tool (ruling V3)', () => {
    const root = tmp();
    const planted = tool(root, `node_modules/.bin/gitleaks${exe}`);
    const env = pathEnv(path.join(root, 'node_modules', '.bin'));
    expect(resolveBinary('gitleaks', { root, env })).not.toBe(planted);
    expect(fromSystem(root, resolveBinary('gitleaks', { root, env }))).toBe(true);
    expect(fromSystem(root, resolveBinary('gitleaks', { root, env: {} }))).toBe(true);
    // ...but it can be named in a skip reason.
    expect(findRepoBinary('gitleaks', { root, env: {} })).toBe(planted);
    expect(findRepoBinary('gitleaks', { root: tmp(), env: {} })).toBeNull();
  });
});

describe('path containment (fix round 2)', () => {
  it('treats <root>/..name as inside and <root>/../name as outside', () => {
    const root = path.resolve('/work/repo');
    expect(within(root, root)).toBe(true);
    expect(within(root, path.join(root, '..planted', 'eslint'))).toBe(true);
    expect(within(root, path.join(root, '..'))).toBe(false);
    expect(within(root, path.resolve(root, '..', 'other'))).toBe(false);
    expect(within(root, path.resolve('/elsewhere'))).toBe(false);
  });

  it('refuses a planted binary in a <root>/..name directory on PATH', () => {
    const root = tmp();
    tool(root, `..planted/gitleaks${exe}`);
    const resolved = resolveBinary('gitleaks', {
      root,
      env: pathEnv(path.join(root, '..planted')),
    });
    expect(resolved).not.toBe(path.join(root, '..planted', `gitleaks${exe}`));
    expect(fromSystem(root, resolved)).toBe(true);
    expect(staysInside(root, path.join(root, '..planted', 'x'))).toBe(true);
  });
});

describe('real paths of missing entries (fix round 1 of tasks 3-4)', () => {
  it('resolves a missing path through the real path of its longest existing prefix', () => {
    const root = tmp();
    const outside = tmp();
    symlinkSync(root, path.join(outside, 'link'), 'junction');
    const missing = path.join(outside, 'link', 'not', 'yet', 'bin');
    expect(real(missing)).toBe(path.join(root, 'not', 'yet', 'bin'));
    expect(isInside(root, missing)).toBe(true);
    expect(real(path.join(outside, 'nothing'))).toBe(path.join(outside, 'nothing'));
  });
});

import { describe, expect, it } from 'vitest';
import {
  familyFiles,
  familyTools,
  FIX_LOCKFILE_TOOLS,
  missingTools,
  servedFamilies,
} from './tools';

const all = (tool: string) => `/usr/bin/${tool}`;
const without =
  (...missing: string[]) =>
  (tool: string) =>
    missing.includes(tool) ? null : `/usr/bin/${tool}`;

describe('FIX_LOCKFILE_TOOLS (B7)', () => {
  it('names the package manager of each lockfile, go.mod and pom.xml', () => {
    expect(FIX_LOCKFILE_TOOLS).toEqual({
      'package-lock.json': 'npm',
      'npm-shrinkwrap.json': 'npm',
      'pnpm-lock.yaml': 'pnpm',
      'yarn.lock': 'yarn',
      'go.mod': 'go',
      'pom.xml': 'mvn',
      'uv.lock': 'uv',
      'poetry.lock': 'poetry',
    });
  });
});

describe('familyFiles', () => {
  it('groups the manifests and lockfiles of each family, nested paths included', () => {
    const files = familyFiles([
      'README.md',
      'package.json',
      'package-lock.json',
      'apps/web/package.json',
      'apps/web/npm-shrinkwrap.json',
      'apps/api/pnpm-lock.yaml',
      'svc/a/go.mod',
      'svc/a/go.sum',
      'backend/pom.xml',
      'tools/py/pyproject.toml',
      'src/package.json.bak',
      'docs/yarn.lock.md',
    ]);
    expect([...files.keys()]).toEqual(['js', 'go', 'maven', 'python']);
    expect(files.get('js')).toEqual([
      'package.json',
      'package-lock.json',
      'apps/web/package.json',
      'apps/web/npm-shrinkwrap.json',
      'apps/api/pnpm-lock.yaml',
    ]);
    expect(files.get('go')).toEqual(['svc/a/go.mod', 'svc/a/go.sum']);
    expect(files.get('maven')).toEqual(['backend/pom.xml']);
    expect(files.get('python')).toEqual(['tools/py/pyproject.toml']);
  });

  it('has no entry for a family without files', () => {
    expect(familyFiles(['README.md', 'src/main.ts']).size).toBe(0);
  });
});

describe('familyTools and missingTools', () => {
  it('names each tool the files need once, sorted; npm-shrinkwrap.json needs npm', () => {
    expect(
      familyTools(['a/npm-shrinkwrap.json', 'b/package-lock.json', 'yarn.lock', 'package.json']),
    ).toEqual(['npm', 'yarn']);
    expect(familyTools(['package.json', 'pyproject.toml'])).toEqual([]);
  });

  it('lists the tools that do not resolve', () => {
    expect(missingTools(['yarn.lock', 'package-lock.json'], without('yarn'))).toEqual(['yarn']);
    expect(missingTools(['yarn.lock', 'package-lock.json'], all)).toEqual([]);
  });
});

describe('servedFamilies (B7, ruling F6)', () => {
  it('serves a family whose every lockfile tool resolves, nested and shrinkwrap lockfiles too', () => {
    const files = familyFiles([
      'apps/web/package.json',
      'apps/web/npm-shrinkwrap.json',
      'svc/go.mod',
      'svc/go.sum',
    ]);
    expect(servedFamilies(files, all)).toEqual(['js', 'go']);
    expect(servedFamilies(files, without('npm'))).toEqual(['go']);
    expect(servedFamilies(files, without('go'))).toEqual(['js']);
  });

  it('does not serve a family when one of its tools is missing', () => {
    const files = familyFiles(['package.json', 'package-lock.json', 'web/yarn.lock']);
    expect(servedFamilies(files, without('yarn'))).toEqual([]);
    expect(servedFamilies(files, all)).toEqual(['js']);
  });

  it('does not serve a family with a manifest but no lockfile', () => {
    const files = familyFiles(['package.json', 'pyproject.toml', 'apps/package.json']);
    expect(files.get('js')).toEqual(['package.json', 'apps/package.json']);
    expect(servedFamilies(files, all)).toEqual([]);
  });

  it('serves Maven through pom.xml, which has no lockfile', () => {
    expect(servedFamilies(familyFiles(['pom.xml', 'core/pom.xml']), all)).toEqual(['maven']);
    expect(servedFamilies(familyFiles(['pom.xml']), without('mvn'))).toEqual([]);
  });

  it('serves Python through uv.lock or poetry.lock and needs both tools when both are there', () => {
    const files = familyFiles([
      'a/pyproject.toml',
      'a/uv.lock',
      'b/pyproject.toml',
      'b/poetry.lock',
    ]);
    expect(servedFamilies(files, all)).toEqual(['python']);
    expect(servedFamilies(files, without('poetry'))).toEqual([]);
  });
});

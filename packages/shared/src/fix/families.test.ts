import { describe, expect, it } from 'vitest';
import {
  FIX_ECOSYSTEM_FAMILY,
  FIX_FAILURE_CODES,
  FIX_FAMILIES,
  FIX_FILES,
  FIX_LIMITS,
  NO_FIX_REASONS,
  ecosystemsOf,
  familyOfEcosystem,
  fixFileKind,
  fixPathProblem,
} from './families';

describe('families (B7)', () => {
  it('maps the seven Trivy types to their family', () => {
    expect(familyOfEcosystem('npm')).toBe('js');
    expect(familyOfEcosystem('pnpm')).toBe('js');
    expect(familyOfEcosystem('yarn')).toBe('js');
    expect(familyOfEcosystem('gomod')).toBe('go');
    expect(familyOfEcosystem('pom')).toBe('maven');
    expect(familyOfEcosystem('uv')).toBe('python');
    expect(familyOfEcosystem('poetry')).toBe('python');
    expect(Object.keys(FIX_ECOSYSTEM_FAMILY)).toHaveLength(7);
  });

  it('has no family for any other type', () => {
    expect(familyOfEcosystem('gradle')).toBeNull();
    expect(familyOfEcosystem('pip')).toBeNull();
    expect(familyOfEcosystem('toString')).toBeNull();
    expect(familyOfEcosystem('__proto__')).toBeNull();
    expect(familyOfEcosystem('')).toBeNull();
  });

  it('lists the ecosystems of each family', () => {
    expect(ecosystemsOf('js')).toEqual(['npm', 'pnpm', 'yarn']);
    expect(ecosystemsOf('go')).toEqual(['gomod']);
    expect(ecosystemsOf('maven')).toEqual(['pom']);
    expect(ecosystemsOf('python')).toEqual(['uv', 'poetry']);
    expect(FIX_FAMILIES).toEqual(['js', 'go', 'maven', 'python']);
  });

  it('names the manifests and lockfiles of each family', () => {
    expect(FIX_FILES.js).toEqual({
      manifests: ['package.json', 'pnpm-workspace.yaml'],
      lockfiles: ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'],
    });
    expect(FIX_FILES.go).toEqual({ manifests: ['go.mod'], lockfiles: ['go.sum'] });
    expect(FIX_FILES.maven).toEqual({ manifests: ['pom.xml'], lockfiles: [] });
    expect(FIX_FILES.python).toEqual({
      manifests: ['pyproject.toml'],
      lockfiles: ['uv.lock', 'poetry.lock'],
    });
    expect(Object.isFrozen(FIX_FILES)).toBe(true);
    expect(Object.isFrozen(FIX_FILES.js.lockfiles)).toBe(true);
  });

  it('tells a manifest from a lockfile by basename', () => {
    expect(fixFileKind('js', 'packages/a/package.json')).toBe('manifest');
    expect(fixFileKind('js', 'pnpm-workspace.yaml')).toBe('manifest');
    expect(fixFileKind('js', 'web/yarn.lock')).toBe('lockfile');
    expect(fixFileKind('go', 'svc/go.sum')).toBe('lockfile');
    expect(fixFileKind('maven', 'core/pom.xml')).toBe('manifest');
    expect(fixFileKind('python', 'uv.lock')).toBe('lockfile');
    expect(fixFileKind('js', 'go.mod')).toBeNull();
    expect(fixFileKind('python', 'requirements.txt')).toBeNull();
    expect(fixFileKind('js', 'Package.json')).toBeNull();
  });
});

describe('fixPathProblem', () => {
  it('accepts a relative, normalised path to a file of the family', () => {
    expect(fixPathProblem('js', 'packages/a/package.json')).toBeNull();
    expect(fixPathProblem('js', 'package-lock.json')).toBeNull();
    expect(fixPathProblem('go', 'services/api/go.mod')).toBeNull();
    expect(fixPathProblem('python', '.config/pyproject.toml')).toBeNull();
  });

  it.each([
    ['../.github/workflows/x.yml'],
    ['../package.json'],
    ['/package.json'],
    ['C:/package.json'],
    ['a/./package.json'],
    ['a\\package.json'],
    ['.git/package.json'],
    ['x/.git/yarn.lock'],
    ['x/.GIT/yarn.lock'],
    ['a//package.json'],
    ['a/package.json/'],
    [''],
    ['go.mod'],
    ['a/package.json.bak'],
    [`${'a/'.repeat(512)}package.json`],
  ])('refuses %j for js', (path) => {
    expect(fixPathProblem('js', path)).toEqual(expect.any(String));
  });

  it('names the first failing rule with a fixed text', () => {
    expect(fixPathProblem('js', '')).toBe('empty path');
    expect(fixPathProblem('js', `${'a/'.repeat(512)}package.json`)).toBe(
      'path longer than 1024 characters',
    );
    expect(fixPathProblem('js', '/package.json')).toBe('absolute path');
    expect(fixPathProblem('js', 'C:/package.json')).toBe('absolute path');
    expect(fixPathProblem('js', 'a\\package.json')).toBe('backslash in path');
    expect(fixPathProblem('js', 'a//package.json')).toBe('empty path segment');
    expect(fixPathProblem('js', 'a/./package.json')).toBe('"." or ".." path segment');
    expect(fixPathProblem('js', '../.github/workflows/x.yml')).toBe('"." or ".." path segment');
    expect(fixPathProblem('js', 'x/.git/yarn.lock')).toBe('path under .git');
    expect(fixPathProblem('js', 'go.mod')).toBe('not a js manifest or lockfile');
  });
});

describe('fix constants', () => {
  it('holds the limits, failure codes and no-fix reasons', () => {
    expect(FIX_LIMITS).toEqual({
      maxFiles: 50,
      maxTotalBytes: 32 * 1024 * 1024,
      messageBytes: 2048,
      leaseMinutes: 30,
      perFixMinutes: 10,
      defaultMaxOpen: 5,
      maxOpen: 20,
      claimMax: 10,
    });
    expect(FIX_FAILURE_CODES).toEqual([
      'manifest_unsupported',
      'missing_tool',
      'package_manager',
      'verify_failed',
      'unplanned_change',
      'timeout',
      'upload_refused',
      'scm_permission',
      'scm_refused',
      'scm_unavailable',
      'scm_not_bound',
      'fixes_disabled',
    ]);
    expect(NO_FIX_REASONS).toEqual([
      'no_fixed_version',
      'declined',
      'several_lines',
      'not_installed',
      'unresolvable',
    ]);
  });
});

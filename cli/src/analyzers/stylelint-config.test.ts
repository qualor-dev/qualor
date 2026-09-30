import { execFileSync } from 'node:child_process';
import { readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import {
  QUALOR_DEFAULT_STYLELINT,
  resolveStylelintConfig,
  STYLELINT_CONFIG_FILES,
} from './stylelint-config';

const tmp = useTempDirs();
const posix = process.platform !== 'win32';
const repo = (files: Record<string, string>) => {
  const root = tmp();
  writeTree(root, files);
  return root;
};
const SCSS = { files: ['**/*.scss'], customSyntax: 'postcss-scss' };
const skip = (r: ReturnType<typeof resolveStylelintConfig>) => ('skip' in r ? r.skip : '');

describe('resolveStylelintConfig (config.md §6, plan 8D)', () => {
  it("uses Qualor's default without a configuration", () => {
    expect(resolveStylelintConfig(repo({ 'a.css': '' }), null)).toEqual({
      config: QUALOR_DEFAULT_STYLELINT,
      source: 'qualor-default',
      ignoreFile: null,
    });
    expect(QUALOR_DEFAULT_STYLELINT).toEqual({
      extends: ['stylelint-config-recommended'],
      overrides: [{ files: ['**/*.scss'], extends: ['stylelint-config-recommended-scss'] }],
    });
  });

  it('reads a JSON config that extends a bundled config, and parses SCSS with postcss-scss', () => {
    const root = repo({
      '.stylelintrc.json': JSON.stringify({
        extends: 'stylelint-config-standard',
        rules: { 'color-hex-length': 'long' },
        ignoreFiles: ['legacy/**'],
      }),
    });
    expect(resolveStylelintConfig(root, null)).toEqual({
      config: {
        extends: 'stylelint-config-standard',
        rules: { 'color-hex-length': 'long' },
        ignoreFiles: ['legacy/**'],
        overrides: [SCSS],
      },
      source: '.stylelintrc.json',
      ignoreFile: null,
    });
  });

  it('adds no SCSS override when the config already sets an SCSS syntax', () => {
    const root = repo({
      '.stylelintrc.yml': 'extends:\n  - stylelint-config-standard-scss\n',
    });
    const r = resolveStylelintConfig(root, null);
    expect(r).toMatchObject({ source: '.stylelintrc.yml' });
    expect('config' in r ? r.config : null).toEqual({
      extends: ['stylelint-config-standard-scss'],
    });
  });

  it("follows stylelint's own search order at the root: package.json first, then .stylelintrc…", () => {
    const root = repo({
      'package.json': JSON.stringify({
        name: 'x',
        stylelint: { rules: { 'block-no-empty': true } },
      }),
      '.stylelintrc.json': '{ "rules": {} }',
    });
    expect(resolveStylelintConfig(root, null)).toMatchObject({
      source: 'package.json "stylelint"',
    });
    const noKey = repo({
      'package.json': '{ "name": "x" }',
      '.stylelintrc': 'rules:\n  block-no-empty: true\n',
    });
    expect(resolveStylelintConfig(noKey, null)).toMatchObject({ source: '.stylelintrc' });
    expect(STYLELINT_CONFIG_FILES[0]).toBe('package.json');
    expect(STYLELINT_CONFIG_FILES.indexOf('.stylelintrc.yml')).toBeLessThan(
      STYLELINT_CONFIG_FILES.indexOf('.stylelintrc.js'),
    );
    expect(STYLELINT_CONFIG_FILES.at(-1)).toBe('stylelint.config.mjs');
  });

  it('never runs an executable config: it skips with the file and the escape hatch', () => {
    for (const file of [
      'stylelint.config.js',
      'stylelint.config.mjs',
      '.stylelintrc.cjs',
      '.config/stylelintrc.ts',
    ]) {
      const reason = skip(resolveStylelintConfig(repo({ [file]: 'throw new Error("ran")' }), null));
      expect(reason, file).toContain(
        `${file} is executable configuration, which Qualor never runs`,
      );
      expect(reason, file).toContain('analyzers.stylelint.configFile: qualor-default');
    }
  });

  it('prefers an earlier JSON config over a later executable one, as stylelint does', () => {
    const root = repo({ '.stylelintrc.json': '{ "rules": {} }', 'stylelint.config.js': 'x' });
    expect(resolveStylelintConfig(root, null)).toMatchObject({ source: '.stylelintrc.json' });
  });

  it('configFile: qualor-default is the way out of an executable or unusable config', () => {
    const root = repo({ 'stylelint.config.js': 'x' });
    expect(resolveStylelintConfig(root, 'qualor-default')).toMatchObject({
      config: QUALOR_DEFAULT_STYLELINT,
    });
  });

  it.each([
    [
      { extends: '@acme/stylelint-config' },
      'extends "@acme/stylelint-config" is not one of the packages Qualor bundles',
    ],
    [
      { extends: ['./base.json'] },
      'extends "./base.json" is not one of the packages Qualor bundles',
    ],
    [{ extends: [{ rules: {} }] }, 'extends must be a package name or a list of them'],
    [
      { plugins: ['stylelint-order'] },
      'plugins "stylelint-order" is not one of the packages Qualor bundles',
    ],
    [
      { customSyntax: 'postcss-less' },
      'customSyntax "postcss-less" is not one of the packages Qualor bundles',
    ],
    [{ processors: ['x'] }, 'sets "processors", which Qualor does not support'],
    [{ referenceFiles: ['a.css'] }, 'sets "referenceFiles", which Qualor does not support'],
    [{ overrides: [{ rules: {} }] }, 'overrides[0] has no "files" globs'],
    [
      { overrides: [{ files: ['*.css'], plugins: ['evil'] }] },
      'plugins "evil" is not one of the packages Qualor bundles',
    ],
    [{ rules: [] }, 'rules must be an object'],
    [{ banana: 1 }, 'sets "banana", which Qualor does not support'],
  ])('refuses %j (never runs part of a config)', (config, message) => {
    const reason = skip(
      resolveStylelintConfig(repo({ '.stylelintrc.json': JSON.stringify(config) }), null),
    );
    expect(reason).toContain(message);
    expect(reason).toContain('configFile: qualor-default');
  });

  it('drops fix, cache, allowEmptyInput and $schema (Qualor never writes to the checkout)', () => {
    const root = repo({
      '.stylelintrc.json': JSON.stringify({
        $schema: 'x',
        fix: true,
        cache: true,
        allowEmptyInput: false,
        rules: {},
      }),
    });
    expect(resolveStylelintConfig(root, null)).toMatchObject({
      config: { rules: {}, overrides: [SCSS] },
    });
    const r = resolveStylelintConfig(root, null);
    expect('config' in r && Object.keys(r.config).sort()).toEqual(['overrides', 'rules']);
  });

  it('reads configFile from the repository and refuses an executable one', () => {
    const root = repo({
      'config/lint.yml': 'rules:\n  block-no-empty: true\n',
      'config/lint.js': 'x',
    });
    expect(resolveStylelintConfig(root, 'config/lint.yml')).toMatchObject({
      source: 'config/lint.yml',
    });
    expect(skip(resolveStylelintConfig(root, 'config/lint.js'))).toContain(
      'config/lint.js is executable configuration',
    );
    expect(skip(resolveStylelintConfig(root, 'config/missing.json'))).toContain(
      'config/missing.json cannot be read',
    );
  });

  it('skips on a config that is not valid JSON or YAML', () => {
    expect(skip(resolveStylelintConfig(repo({ '.stylelintrc.json': '{ nope' }), null))).toContain(
      '.stylelintrc.json is not valid JSON',
    );
    expect(skip(resolveStylelintConfig(repo({ '.stylelintrc': 'a: [' }), null))).toContain(
      '.stylelintrc is not valid YAML or JSON',
    );
  });

  it('honours a root .stylelintignore and refuses a large one', () => {
    const root = repo({ '.stylelintignore': 'vendor/\n' });
    expect(resolveStylelintConfig(root, null)).toMatchObject({
      ignoreFile: path.join(root, '.stylelintignore'),
    });
    writeFileSync(path.join(root, '.stylelintignore'), 'x'.repeat(1024 * 1024 + 1));
    expect(skip(resolveStylelintConfig(root, null))).toContain(
      '.stylelintignore is larger than 1 MiB',
    );
  });

  it.runIf(posix)('never reads a config that links out of the repository, or a FIFO', () => {
    const outside = path.join(tmp(), 'outside.json');
    writeFileSync(outside, '{ "rules": {} }');
    const root = repo({});
    symlinkSync(outside, path.join(root, '.stylelintrc.json'));
    expect(skip(resolveStylelintConfig(root, null))).toContain(
      '.stylelintrc.json is outside the repository',
    );
    const fifo = repo({});
    execFileSync('mkfifo', [path.join(fifo, '.stylelintrc.json')]);
    expect(skip(resolveStylelintConfig(fifo, null))).toContain(
      '.stylelintrc.json is not a regular file',
    );
  });

  it('skips a config over 1 MiB', () => {
    const root = repo({
      '.stylelintrc.json': `{ "rules": {}, "x": "${'a'.repeat(1024 * 1024)}" }`,
    });
    expect(skip(resolveStylelintConfig(root, null))).toContain(
      '.stylelintrc.json is larger than 1 MiB',
    );
  });
});

describe('resolveStylelintConfig never loads or runs anything from the checkout (config.md §6)', () => {
  /** A module that leaves a marker file when anything requires or imports it. */
  const marker = (root: string, name: string) =>
    `require('node:fs').writeFileSync(${JSON.stringify(path.join(root, `${name}.ran`))}, 'ran');\nmodule.exports = {};\n`;
  const ran = (root: string) =>
    readdirSync(root, { recursive: true })
      .map(String)
      .filter((f) => f.endsWith('.ran'));

  it('refuses a config naming planted packages, paths or executable files, and none of them runs', () => {
    const root = tmp();
    writeTree(root, {
      'stylelint.config.js': marker(root, 'config'),
      '.stylelintrc.cjs': marker(root, 'rc'),
      'node_modules/stylelint-config-standard/index.js': marker(root, 'bundled-name'),
      'node_modules/stylelint-config-standard/package.json':
        '{ "name": "stylelint-config-standard", "main": "index.js" }',
      'node_modules/stylelint-order/index.js': marker(root, 'plugin'),
      'node_modules/postcss-less/index.js': marker(root, 'syntax'),
      'base.js': marker(root, 'base'),
      'postcss.config.js': marker(root, 'postcss'),
    });
    const configs: Record<string, unknown>[] = [
      { extends: ['./base.js'] },
      { extends: path.join(root, 'base.js') },
      { extends: 'stylelint-config-standard/index.js' },
      { plugins: ['stylelint-order'] },
      { plugins: [path.join(root, 'node_modules/stylelint-order/index.js')] },
      { plugins: 'stylelint-scss/../../base.js' },
      { customSyntax: 'postcss-less' },
      { customSyntax: './node_modules/postcss-less/index.js' },
      { customSyntax: { parse: 'x' } },
      { overrides: [{ files: ['*.css'], extends: ['./base.js'] }] },
      { overrides: [{ files: ['*.css'], customSyntax: 'postcss-less' }] },
      { overrides: [{ files: ['*.css'], processors: ['./base.js'] }] },
      {
        overrides: [
          { files: ['*.css'], overrides: [{ files: ['*.css'], plugins: ['./base.js'] }] },
        ],
      },
      { processors: [['./base.js', {}]] },
      { formatter: './base.js' },
      { configBasedir: root },
    ];
    for (const config of configs) {
      writeFileSync(path.join(root, '.stylelintrc.json'), JSON.stringify(config));
      const reason = skip(resolveStylelintConfig(root, null));
      expect(reason, JSON.stringify(config)).toContain('.stylelintrc.json');
      expect(reason, JSON.stringify(config)).toContain('configFile: qualor-default');
    }
    for (const file of [
      'stylelint.config.js',
      '.stylelintrc.cjs',
      'base.js',
      'postcss.config.js',
    ]) {
      expect(skip(resolveStylelintConfig(root, file))).toContain(
        `${file} is executable configuration`,
      );
    }
    // A bundled name is passed on as a name, for the pass to map to its own copy; never resolved here.
    writeFileSync(
      path.join(root, '.stylelintrc.json'),
      '{ "extends": "stylelint-config-standard" }',
    );
    expect(resolveStylelintConfig(root, null)).toMatchObject({
      config: { extends: 'stylelint-config-standard' },
    });
    expect(ran(root)).toEqual([]);
  });

  it.each([
    ['/etc/**'],
    ['C:\\Windows\\**'],
    ['c:/x/**'],
    ['../outside/**'],
    ['src/../../outside/**'],
    ['!../outside/**'],
  ])('refuses ignoreFiles %s, which points outside the repository', (glob) => {
    const root = repo({ '.stylelintrc.json': JSON.stringify({ ignoreFiles: [glob] }) });
    expect(skip(resolveStylelintConfig(root, null))).toContain(
      `ignoreFiles "${glob}" is outside the repository`,
    );
    const one = repo({ '.stylelintrc.json': JSON.stringify({ ignoreFiles: glob }) });
    expect(skip(resolveStylelintConfig(one, null))).toContain(
      `ignoreFiles "${glob}" is outside the repository`,
    );
  });

  it('refuses YAML tags, alias bombs and several documents', () => {
    for (const text of [
      'rules: !!js/function "function () {}"\n',
      'rules:\n  block-no-empty: !custom true\n',
      'rules: {}\n---\nrules: {}\n',
      'rules: {}\nrules: {}\n',
    ]) {
      expect(
        skip(resolveStylelintConfig(repo({ '.stylelintrc.yml': text }), null)),
        text,
      ).toContain('.stylelintrc.yml is not valid YAML or JSON');
    }
    const letter = (i: number) => String.fromCharCode(97 + i);
    const bomb = ['a: &a [x, x, x, x, x, x, x, x, x, x]'];
    for (let i = 1; i < 10; i++)
      bomb.push(
        `${letter(i)}: &${letter(i)} [${Array(10)
          .fill(`*${letter(i - 1)}`)
          .join(', ')}]`,
      );
    const root = repo({ '.stylelintrc.yaml': `${bomb.join('\n')}\n` });
    expect(skip(resolveStylelintConfig(root, null))).toContain(
      '.stylelintrc.yaml is not valid YAML or JSON',
    );
  });

  it('keeps __proto__ a plain, refused key', () => {
    for (const text of ['{ "__proto__": { "polluted": 1 } }', '__proto__:\n  polluted: 1\n']) {
      expect(skip(resolveStylelintConfig(repo({ '.stylelintrc': text }), null))).toContain(
        'sets "__proto__", which Qualor does not support',
      );
    }
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('refuses a configFile outside the repository', () => {
    const outside = tmp();
    writeFileSync(path.join(outside, 'lint.json'), '{ "rules": {} }');
    const root = repo({});
    expect(skip(resolveStylelintConfig(root, path.join(outside, 'lint.json')))).toContain(
      'is outside the repository',
    );
    expect(skip(resolveStylelintConfig(root, `../${path.basename(outside)}/lint.json`))).toContain(
      'is outside the repository',
    );
  });

  it.runIf(posix)('never reads a .stylelintignore that links out of the repository', () => {
    const outside = path.join(tmp(), 'ignore');
    writeFileSync(outside, 'x\n');
    const root = repo({});
    symlinkSync(outside, path.join(root, '.stylelintignore'));
    expect(skip(resolveStylelintConfig(root, 'qualor-default'))).toContain(
      '.stylelintignore is outside the repository',
    );
  });

  it('refuses a package.json "stylelint" key that names anything unbundled', () => {
    const root = repo({
      'package.json': JSON.stringify({ stylelint: { extends: ['./base.json'] } }),
    });
    expect(skip(resolveStylelintConfig(root, null))).toContain(
      'package.json "stylelint" extends "./base.json"',
    );
  });
});

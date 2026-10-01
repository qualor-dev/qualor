import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { canCreateFileSymlinks } from '../../test/symlinks';
import { useTempDirs, writeTree } from '../../test/tmp';
import {
  copyDependencies,
  DEPENDENCIES_NOT_INSTALLED,
  DEPENDENCIES_TOO_LARGE,
  MAX_DEPENDENCY_BYTES,
  MAX_DEPENDENCY_FILES,
  phpDependencies,
} from './phpstan-deps';

const tmp = useTempDirs();
const composer = (o: object) => JSON.stringify(o);
const CAN_SYMLINK_FILES = canCreateFileSymlinks();

describe('phpDependencies (config.md §6, plan 9A decision 2)', () => {
  it('runs without dependencies when there is no composer.json, or nothing is required', () => {
    expect(phpDependencies(tmp())).toEqual({ kind: 'none' });
    const root = tmp();
    writeTree(root, {
      'composer.json': composer({
        require: { php: '>=8.1', 'ext-json': '*' },
        'require-dev': { 'phpunit/phpunit': '^11' },
      }),
    });
    expect(phpDependencies(root)).toEqual({ kind: 'none' });
  });

  it('is skipped when packages are required but not installed', () => {
    const root = tmp();
    writeTree(root, { 'composer.json': composer({ require: { 'acme/lib': '^1' } }) });
    expect(phpDependencies(root)).toEqual({ kind: 'skip', reason: DEPENDENCIES_NOT_INSTALLED });
    expect(DEPENDENCIES_NOT_INSTALLED).toBe(
      'PHP dependencies are not installed (composer.json requires packages; run composer install before the scan; Qualor reads vendor/, never runs it)',
    );
  });

  it('finds installed dependencies in vendor/ or in config.vendor-dir', () => {
    const root = tmp();
    writeTree(root, {
      'composer.json': composer({ require: { 'acme/lib': '^1' } }),
      'vendor/composer/installed.json': '{"packages":[]}',
    });
    expect(phpDependencies(root)).toEqual({
      kind: 'installed',
      vendorDir: 'vendor',
      requiresPackages: true,
    });
    const custom = tmp();
    writeTree(custom, {
      'composer.json': composer({ config: { 'vendor-dir': 'lib/vendor/' } }),
      'lib/vendor/composer/installed.json': '{}',
    });
    expect(phpDependencies(custom)).toEqual({
      kind: 'installed',
      vendorDir: 'lib/vendor',
      requiresPackages: false,
    });
  });

  it('skips with a reason for a composer.json it cannot use', () => {
    const cases: [string, string][] = [
      ['{', 'composer.json is not valid JSON'],
      ['[]', 'composer.json is not a JSON object'],
      [
        composer({ config: { 'vendor-dir': '../outside' } }),
        'composer.json config.vendor-dir must be a relative path inside the repository',
      ],
      [
        composer({ config: { 'vendor-dir': '/abs' } }),
        'composer.json config.vendor-dir must be a relative path inside the repository',
      ],
      [
        composer({ config: { 'vendor-dir': '{$home}/v' } }),
        'composer.json config.vendor-dir must be a relative path inside the repository',
      ],
      [
        composer({ config: { 'vendor-dir': 3 } }),
        'composer.json config.vendor-dir must be a relative path inside the repository',
      ],
    ];
    for (const [text, reason] of cases) {
      const root = tmp();
      writeTree(root, { 'composer.json': text });
      expect(phpDependencies(root), text).toEqual({ kind: 'skip', reason });
    }
    const big = tmp();
    writeTree(big, { 'composer.json': `{"x":"${'a'.repeat(1024 * 1024)}"}` });
    expect(phpDependencies(big)).toEqual({
      kind: 'skip',
      reason: 'composer.json is larger than 1 MiB',
    });
  });

  // Skipped (and shown as skipped) where file symlinks cannot be made; Task 9 Step 2 runs it in the toolbox.
  it.skipIf(!CAN_SYMLINK_FILES)(
    'never reads a composer.json or an installed.json through a link out of the repository',
    () => {
      const root = tmp();
      const outside = tmp();
      writeFileSync(path.join(outside, 'composer.json'), composer({ require: { 'a/b': '1' } }));
      symlinkSync(path.join(outside, 'composer.json'), path.join(root, 'composer.json'), 'file');
      expect(phpDependencies(root)).toEqual({
        kind: 'skip',
        reason: 'composer.json is outside the repository',
      });
      const linked = tmp();
      mkdirSync(path.join(outside, 'v', 'composer'), { recursive: true });
      writeFileSync(path.join(outside, 'v', 'composer', 'installed.json'), '{}');
      writeTree(linked, { 'composer.json': composer({ require: { 'a/b': '1' } }) });
      symlinkSync(path.join(outside, 'v'), path.join(linked, 'vendor'), 'dir');
      expect(phpDependencies(linked)).toEqual({ kind: 'skip', reason: DEPENDENCIES_NOT_INSTALLED });
    },
  );
});

describe('copyDependencies', () => {
  it("copies the dependencies' .php files, never Composer's autoloader, composer/ or bin/", () => {
    const root = tmp();
    writeTree(root, {
      'vendor/autoload.php': '<?php // autoload',
      'vendor/composer/autoload_real.php': '<?php // composer',
      'vendor/bin/tool.php': '<?php // proxy',
      'vendor/acme/lib/src/Thing.php': '<?php class Thing {}',
      'vendor/acme/lib/src/functions.php': '<?php function f() {}',
      'vendor/acme/lib/README.md': 'x',
      'vendor/acme/lib/composer/inner.php':
        '<?php // kept: only the top-level composer/ is Composer’s',
    });
    const target = tmp();
    const r = copyDependencies(root, 'vendor', target);
    expect(r).toEqual({ files: 3, skipped: 0, truncated: false, tooLarge: false });
    expect(readFileSync(path.join(target, 'vendor/acme/lib/src/Thing.php'), 'utf8')).toBe(
      '<?php class Thing {}',
    );
    for (const absent of [
      'vendor/autoload.php',
      'vendor/composer',
      'vendor/bin',
      'vendor/acme/lib/README.md',
    ]) {
      expect(existsSync(path.join(target, absent)), absent).toBe(false);
    }
    expect(existsSync(path.join(target, 'vendor/acme/lib/composer/inner.php'))).toBe(true);
  });

  it('leaves out autoload.php, composer/ and bin/ whatever their case (ruling A9-15)', () => {
    const root = tmp();
    writeTree(root, {
      'vendor/Autoload.PHP.php': '<?php // kept: another name',
      'vendor/AUTOLOAD.php': '<?php // autoload',
      'vendor/Composer/autoload_real.php': '<?php // composer',
      'vendor/BIN/tool.php': '<?php // proxy',
      'vendor/acme/lib/src/Thing.php': '<?php class Thing {}',
    });
    const target = tmp();
    expect(copyDependencies(root, 'vendor', target)).toEqual({
      files: 2,
      skipped: 0,
      truncated: false,
      tooLarge: false,
    });
    for (const absent of ['vendor/AUTOLOAD.php', 'vendor/Composer', 'vendor/BIN']) {
      expect(existsSync(path.join(target, absent)), absent).toBe(false);
    }
  });

  it('stops at the limit', () => {
    const root = tmp();
    writeTree(root, {
      'vendor/a/b/x.php': '<?php',
      'vendor/a/b/y.php': '<?php',
      'vendor/a/b/z.php': '<?php',
    });
    expect(copyDependencies(root, 'vendor', tmp())).toEqual({
      files: 3,
      skipped: 0,
      truncated: false,
      tooLarge: false,
    });
    expect(copyDependencies(root, 'vendor', tmp(), 2)).toMatchObject({ files: 2, truncated: true });
  });

  it('gives up and removes the partial copy past the total size cap (ruling A9-14)', () => {
    expect(MAX_DEPENDENCY_BYTES).toBe(1024 * 1024 * 1024);
    expect(DEPENDENCIES_TOO_LARGE).toBe(
      'PHP dependencies are larger than 1 GiB (the .php files below vendor/); PHPStan is skipped rather than run with part of them',
    );
    const root = tmp();
    writeTree(root, {
      'vendor/a/b/x.php': '<?php // 10 bytes',
      'vendor/a/b/y.php': '<?php // 10 bytes',
      'vendor/a/b/z.php': '<?php // 10 bytes',
    });
    const size = '<?php // 10 bytes'.length;
    expect(copyDependencies(root, 'vendor', tmp(), MAX_DEPENDENCY_FILES, 3 * size)).toEqual({
      files: 3,
      skipped: 0,
      truncated: false,
      tooLarge: false,
    });
    const target = tmp();
    writeTree(target, { 'phpstan.neon': 'kept' });
    expect(copyDependencies(root, 'vendor', target, MAX_DEPENDENCY_FILES, 3 * size - 1)).toEqual({
      files: 0,
      skipped: 0,
      truncated: false,
      tooLarge: true,
    });
    expect(existsSync(path.join(target, 'vendor'))).toBe(false);
    expect(existsSync(path.join(target, 'phpstan.neon'))).toBe(true);
  });

  it.skipIf(!CAN_SYMLINK_FILES)('follows no file or directory link', () => {
    const root = tmp();
    const outside = tmp();
    writeFileSync(path.join(outside, 'secret.php'), '<?php // outside');
    mkdirSync(path.join(outside, 'pkg'));
    writeFileSync(path.join(outside, 'pkg', 'a.php'), '<?php // outside');
    writeTree(root, { 'vendor/a/b/x.php': '<?php' });
    symlinkSync(path.join(outside, 'secret.php'), path.join(root, 'vendor/a/b/link.php'), 'file');
    symlinkSync(path.join(outside, 'pkg'), path.join(root, 'vendor/a/linked'), 'dir');
    const target = tmp();
    expect(copyDependencies(root, 'vendor', target)).toEqual({
      files: 1,
      skipped: 0,
      truncated: false,
      tooLarge: false,
    });
    expect(existsSync(path.join(target, 'vendor/a/b/link.php'))).toBe(false);
    expect(existsSync(path.join(target, 'vendor/a/linked'))).toBe(false);
  });
});

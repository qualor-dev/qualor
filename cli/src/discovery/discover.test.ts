import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseConfig, type QualorConfigInput } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { discoverFiles, isBinaryFile } from './discover';

const tmp = useTempDirs();

/**
 * A *file* symlink (unlike a directory junction) needs Developer Mode or elevation on Windows.
 * Probing once lets the file-symlink tests below run wherever the platform actually allows it
 * (every POSIX CI runner, and Windows in Developer Mode) and skip only where it does not,
 * instead of assuming based on `process.platform` alone.
 */
function canCreateFileSymlinks(): boolean {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-symlink-check-'));
  try {
    const target = path.join(dir, 'target.txt');
    writeFileSync(target, 'x');
    symlinkSync(target, path.join(dir, 'link.txt'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const CAN_SYMLINK_FILES = canCreateFileSymlinks();

function tree(root: string): void {
  writeTree(root, {
    'src/a.ts': 'export const a = 1;\n',
    'src/a.test.ts': "import { a } from './a';\n",
    'src/view.tsx': 'export const V = () => <b />;\n',
    'src/util.js': 'module.exports = 1;\n',
    'src/Main.java': 'class Main {}\n',
    'src/test/java/MainTest.java': 'class MainTest {}\n',
    'src/legacy.spec.ts': 'export {};\n',
    'README.md': '# app\n',
    'node_modules/x/index.js': 'x\n',
    'dist/out.js': 'x\n',
    'build/gen.ts': 'x\n',
    'target/classes/A.java': 'x\n',
    'coverage/lcov.info': 'TN:\n',
    'vendor/v.js': 'x\n',
    'app.min.js': 'x\n',
    '.hidden/h.ts': 'x\n',
    '.gitignore': 'ignored/\n/coverage/\n',
    'ignored/i.ts': 'x\n',
    'src/.gitignore': '*.gen.ts\n!keep.gen.ts\n',
    'src/x.gen.ts': 'x\n',
    'src/keep.gen.ts': 'x\n',
    'generated/g.ts': 'x\n',
    'src/bin.dat': new Uint8Array([1, 2, 0, 3]),
    'src/big.ts': `export const s = '${'x'.repeat(1_100_000)}';\n`,
    // Decomposed (NFD) on disk; the report path must be NFC.
    'dir with space/ü.ts': 'export {};\n',
  });
}

function config(extra: Partial<QualorConfigInput> = {}) {
  return parseConfig({
    version: 1,
    sources: { exclude: ['generated/**'] },
    tests: { exclude: ['**/legacy.spec.ts'] },
    ...extra,
  });
}

describe('discoverFiles', () => {
  it('applies includes, built-in and user excludes, nested .gitignore files and test globs', () => {
    const root = tmp();
    tree(root);
    const warnings = new Warnings();
    const files = discoverFiles({ root, config: config(), warnings, log: silentLogger });
    expect(files.map((f) => [f.path, f.language, f.grammar, f.kind])).toEqual([
      ['README.md', 'other', null, 'main'],
      ['dir with space/ü.ts', 'typescript', 'typescript', 'main'],
      ['src/Main.java', 'java', 'java', 'main'],
      ['src/a.test.ts', 'typescript', 'typescript', 'test'],
      ['src/a.ts', 'typescript', 'typescript', 'main'],
      ['src/big.ts', 'typescript', 'typescript', 'main'],
      ['src/keep.gen.ts', 'typescript', 'typescript', 'main'],
      ['src/legacy.spec.ts', 'typescript', 'typescript', 'main'],
      ['src/test/java/MainTest.java', 'java', 'java', 'test'],
      ['src/util.js', 'javascript', 'javascript', 'main'],
      ['src/view.tsx', 'typescript', 'tsx', 'main'],
    ]);
    const big = files.find((f) => f.path === 'src/big.ts');
    expect(big?.size).toBeGreaterThan(1_048_576);
    expect(big?.absPath).toBe(path.join(root, 'src', 'big.ts'));
  });

  it('scans a source directory named coverage; a gitignored coverage output is not scanned', () => {
    // Ruling Q3 (plan 1G): `coverage` is no built-in exclude; generated output goes through .gitignore.
    const root = tmp();
    writeTree(root, {
      '.gitignore': '/coverage/\n',
      'src/coverage/lcov.ts': 'export const lcov = 1;\n',
      'coverage/lcov.info': 'TN:\n',
      'coverage/prettify.js': 'x\n',
    });
    const files = discoverFiles({
      root,
      config: config(),
      warnings: new Warnings(),
      log: silentLogger,
    });
    expect(files.map((f) => [f.path, f.language, f.kind])).toEqual([
      ['src/coverage/lcov.ts', 'typescript', 'main'],
    ]);
  });

  it('includes gitignored files when useGitignore is false', () => {
    const root = tmp();
    tree(root);
    const files = discoverFiles({
      root,
      config: config({ sources: { useGitignore: false, exclude: ['generated/**'] } }),
      warnings: new Warnings(),
      log: silentLogger,
    });
    const paths = files.map((f) => f.path);
    expect(paths).toContain('ignored/i.ts');
    expect(paths).toContain('src/x.gen.ts');
  });

  it('never follows a symlink or junction, even one pointing outside the repo', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'secret.ts': 'export const s = 1;\n' });
    writeTree(root, { 'src/a.ts': 'export {};\n' });
    // A junction needs no privileges on Windows; on Linux the type argument is ignored.
    symlinkSync(outside, path.join(root, 'linked'), 'junction');
    const warnings = new Warnings();
    const files = discoverFiles({ root, config: config(), warnings, log: silentLogger });
    expect(files.map((f) => f.path)).toEqual(['src/a.ts']);
    expect(warnings.list()).toContainEqual(
      expect.objectContaining({ code: 'SYMLINK_SKIPPED', count: 1 }),
    );
  });

  it.skipIf(!CAN_SYMLINK_FILES)(
    'never follows a root .gitignore that is a symlink, so its rules have no effect, even pointing outside the repo',
    () => {
      const root = tmp();
      const outside = tmp();
      writeTree(outside, { 'rules.gitignore': 'excluded-by-symlink.ts\n' });
      writeTree(root, { 'src/a.ts': 'export {};\n', 'excluded-by-symlink.ts': 'export {};\n' });
      symlinkSync(path.join(outside, 'rules.gitignore'), path.join(root, '.gitignore'), 'file');
      const warnings = new Warnings();
      const files = discoverFiles({ root, config: config(), warnings, log: silentLogger });
      // If the symlink had been followed, `excluded-by-symlink.ts` would have been ignored.
      expect(files.map((f) => f.path)).toEqual(['excluded-by-symlink.ts', 'src/a.ts']);
      expect(warnings.list()).toContainEqual(expect.objectContaining({ code: 'SYMLINK_SKIPPED' }));
    },
  );

  it.skipIf(!CAN_SYMLINK_FILES)(
    'never follows a nested .gitignore that is a symlink, so its rules have no effect, even pointing outside the repo',
    () => {
      const root = tmp();
      const outside = tmp();
      writeTree(outside, { 'rules.gitignore': 'excluded-by-symlink.ts\n' });
      writeTree(root, { 'src/a.ts': 'export {};\n', 'src/excluded-by-symlink.ts': 'export {};\n' });
      symlinkSync(
        path.join(outside, 'rules.gitignore'),
        path.join(root, 'src', '.gitignore'),
        'file',
      );
      const warnings = new Warnings();
      const files = discoverFiles({ root, config: config(), warnings, log: silentLogger });
      expect(files.map((f) => f.path)).toEqual(['src/a.ts', 'src/excluded-by-symlink.ts']);
      expect(warnings.list()).toContainEqual(expect.objectContaining({ code: 'SYMLINK_SKIPPED' }));
    },
  );

  it.skipIf(process.platform === 'win32')(
    'skips a directory whose name contains a backslash on POSIX, without descending into it',
    () => {
      const root = tmp();
      writeTree(root, { 'foo\\bar/inside.ts': 'export {};\n', 'ok.ts': 'export {};\n' });
      const warnings = new Warnings();
      const files = discoverFiles({ root, config: config(), warnings, log: silentLogger });
      expect(files.map((f) => f.path)).toEqual(['ok.ts']);
      expect(warnings.list()).toContainEqual(expect.objectContaining({ code: 'PATH_UNSUPPORTED' }));
    },
  );

  it('marks files of languages outside an explicit list as other', () => {
    const root = tmp();
    writeTree(root, { 'a.ts': 'x\n', 'B.java': 'class B {}\n' });
    const files = discoverFiles({
      root,
      config: config({ languages: ['java'] }),
      warnings: new Warnings(),
      log: silentLogger,
    });
    expect(files.map((f) => [f.path, f.language, f.grammar])).toEqual([
      ['B.java', 'java', 'java'],
      ['a.ts', 'other', null],
    ]);
  });

  it('skips nested repositories and submodules (a .git directory or file below the root), with a warning', () => {
    const root = tmp();
    writeTree(root, {
      '.git/HEAD': 'ref: refs/heads/main\n',
      'src/a.ts': 'export const a = 1;\n',
      'vendor-repo/.git/HEAD': 'ref: refs/heads/main\n',
      'vendor-repo/lib.ts': 'export const v = 1;\n',
      'libs/sub/.git': 'gitdir: ../../.git/modules/sub\n',
      'libs/sub/index.ts': 'export const s = 1;\n',
      'libs/own.ts': 'export const o = 1;\n',
    });
    const warnings = new Warnings();
    const files = discoverFiles({ root, config: config(), warnings, log: silentLogger });
    expect(files.map((f) => f.path)).toEqual(['libs/own.ts', 'src/a.ts']);
    expect(warnings.list()).toEqual([
      expect.objectContaining({ code: 'NESTED_REPOSITORY_SKIPPED', count: 2 }),
    ]);
  });

  it('leaves Python virtual environments and caches out, and marks pytest files as tests (plan 8C)', () => {
    const root = tmp();
    writeTree(root, {
      'app/store.py': 'x = 1\n',
      'tests/test_store.py': 'def test_x():\n    pass\n',
      'app/store_test.py': 'x = 1\n',
      'conftest.py': 'x = 1\n',
      '.venv/lib/python3.12/site-packages/pkg/mod.py': 'x = 1\n',
      'venv/bin/tool.py': 'x = 1\n',
      'app/__pycache__/store.cpython-312.py': 'x = 1\n',
      '.tox/py312/x.py': 'x = 1\n',
    });
    const files = discoverFiles({
      root,
      config: config(),
      warnings: new Warnings(),
      log: silentLogger,
    });
    expect(files.map((f) => [f.path, f.language, f.kind]).sort()).toEqual([
      ['app/store.py', 'python', 'main'],
      ['app/store_test.py', 'python', 'test'],
      ['conftest.py', 'python', 'test'],
      ['tests/test_store.py', 'python', 'test'],
    ]);
  });

  it('leaves CocoaPods, Carthage and SwiftPM checkouts out (plan 8F)', () => {
    const root = tmp();
    writeTree(root, {
      'Sources/App/Store.swift': 'let a = 1\n',
      'Pods/Alamofire/Source/Session.swift': 'let a = 1\n',
      'Carthage/Checkouts/Kit/Kit.swift': 'let a = 1\n',
      '.build/checkouts/swift-nio/Sources/NIO.swift': 'let a = 1\n',
    });
    const files = discoverFiles({
      root,
      config: config(),
      warnings: new Warnings(),
      log: silentLogger,
    });
    expect(files.map((f) => [f.path, f.language])).toEqual([['Sources/App/Store.swift', 'swift']]);
  });

  it('excludes committed minified CSS like minified JS; keeps HTML, CSS and SCSS (config.md §3.1, plan 8D)', () => {
    const root = tmp();
    writeTree(root, {
      'static/css/bootstrap.min.css': '.a{color:red}\n',
      'src/a.css': '.a { color: red; }\n',
      'src/b.scss': '$x: 1;\n',
      'site/index.html': '<p>x</p>\n',
    });
    const files = discoverFiles({
      root,
      config: parseConfig({ version: 1 }),
      warnings: new Warnings(),
      log: silentLogger,
    });
    expect(files.map((f) => [f.path, f.language, f.grammar])).toEqual([
      ['site/index.html', 'html', 'html'],
      ['src/a.css', 'css', 'css'],
      ['src/b.scss', 'css', null],
    ]);
  });

  it('keeps an empty directory tree empty', () => {
    const root = tmp();
    mkdirSync(path.join(root, 'empty', 'deeper'), { recursive: true });
    expect(
      discoverFiles({ root, config: config(), warnings: new Warnings(), log: silentLogger }),
    ).toEqual([]);
  });
});

describe('isBinaryFile', () => {
  it('detects a NUL byte in the first 8 KiB only', () => {
    const root = tmp();
    const late = new Uint8Array(9_000).fill(0x61);
    late[8_500] = 0;
    writeTree(root, { 'a.bin': new Uint8Array([0x61, 0]), 'late.txt': late, 'b.txt': 'text' });
    expect(isBinaryFile(path.join(root, 'a.bin'))).toBe(true);
    expect(isBinaryFile(path.join(root, 'late.txt'))).toBe(false);
    expect(isBinaryFile(path.join(root, 'b.txt'))).toBe(false);
  });
});

import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { GO_KEPT_ENV, goEnv, goModuleCache, MAX_GO_MOD_BYTES, planGoModules } from './go-modules';

const tmp = useTempDirs();
const posix = process.platform !== 'win32';
const GO = '1.27.1';

/** In-scope files as discovery lists them: .go files are language go, everything else other. */
function scope(root: string, files: Record<string, string>): ScopeFile[] {
  writeTree(root, files);
  return Object.keys(files).map((p) => ({
    path: p,
    absPath: path.join(root, ...p.split('/')),
    language: p.endsWith('.go') ? 'go' : 'other',
    grammar: p.endsWith('.go') ? 'go' : null,
    kind: p.endsWith('_test.go') ? 'test' : 'main',
    size: 1,
  }));
}

describe('planGoModules (config.md §6, plan 9C)', () => {
  it('gives each Go file to the nearest module and counts the files outside every module', () => {
    const root = tmp();
    const files = scope(root, {
      'go.mod': 'module ex/root\n\ngo 1.24\n',
      'a.go': 'package root\n',
      'tools/go.mod': 'module ex/tools\n\ngo 1.24\n',
      'tools/t.go': 'package tools\n',
      'tools/sub/u.go': 'package sub\n',
      'docs/go.mod': 'module ex/docs\n\ngo 1.24\n',
    });
    expect(planGoModules(root, files, GO)).toEqual({
      modules: [
        { dir: root, rel: '', modulePath: 'ex/root', files: 1 },
        { dir: path.join(root, 'tools'), rel: 'tools', modulePath: 'ex/tools', files: 2 },
      ],
      skipped: [],
      outside: 0,
    });
    const loose = tmp();
    const looseFiles = scope(loose, {
      'lib/go.mod': 'module ex/lib\n\ngo 1.24\n',
      'lib/a.go': 'package lib\n',
      'cmd/b.go': 'package main\n',
    });
    expect(planGoModules(loose, looseFiles, GO)).toMatchObject({
      modules: [{ rel: 'lib' }],
      outside: 1,
    });
  });

  it('leaves out a module that needs a newer Go, names no module, cannot be parsed or is too big', () => {
    const root = tmp();
    const files = scope(root, {
      'new/go.mod': 'module ex/new\n\ngo 1.99\n',
      'new/a.go': 'package a\n',
      'nameless/go.mod': 'go 1.24\n',
      'nameless/a.go': 'package a\n',
      'broken/go.mod': 'module "ex\n',
      'broken/a.go': 'package a\n',
      'big/go.mod': `module ex/big\n// ${'x'.repeat(MAX_GO_MOD_BYTES)}\n`,
      'big/a.go': 'package a\n',
    });
    const plan = planGoModules(root, files, GO);
    expect(plan.modules).toEqual([]);
    expect(plan.skipped).toEqual([
      { rel: 'big', reason: 'big/go.mod is larger than 1 MiB' },
      { rel: 'broken', reason: 'broken/go.mod cannot be read: line 1 cannot be read' },
      { rel: 'nameless', reason: 'nameless/go.mod names no module' },
      {
        rel: 'new',
        reason:
          'new/go.mod needs Go 1.99, newer than this Go 1.27.1; Qualor never downloads a toolchain (GOTOOLCHAIN=local)',
      },
    ]);
  });

  it('leaves out a module that replaces a dependency with a directory outside the repository', () => {
    const root = tmp();
    const outside = tmp();
    const files = scope(root, {
      'a/go.mod': `module ex/a\n\ngo 1.24\n\nreplace ex/dep => ${JSON.stringify(outside)}\n`,
      'a/a.go': 'package a\n',
      'b/go.mod':
        'module ex/b\n\ngo 1.24\n\nreplace ex/dep => ../shared\nreplace ex/x v1.0.0 => ex/y v1.1.0\n',
      'b/b.go': 'package b\n',
      'shared/go.mod': 'module ex/dep\n\ngo 1.24\n',
      'c/go.mod': 'module ex/c\n\ngo 1.24\n\nreplace ex/dep => ../../elsewhere\n',
      'c/c.go': 'package c\n',
    });
    const plan = planGoModules(root, files, GO);
    expect(plan.modules.map((m) => m.rel)).toEqual(['b']);
    expect(plan.skipped.map((s) => s.rel)).toEqual(['a', 'c']);
    expect(plan.skipped[1]?.reason).toBe(
      'c/go.mod replaces ex/dep with ../../elsewhere, a directory outside the repository, which Qualor does not read',
    );
  });

  it.runIf(posix)(
    'leaves out a module with a link out of the repository, vendor included; links inside are fine',
    () => {
      const root = tmp();
      const outside = tmp();
      writeFileSync(path.join(outside, 'secret.go'), 'package x\n');
      const files = scope(root, {
        'a/go.mod': 'module ex/a\n\ngo 1.24\n',
        'a/a.go': 'package a\n',
        'b/go.mod': 'module ex/b\n\ngo 1.24\n',
        'b/b.go': 'package b\n',
        'c/go.mod': 'module ex/c\n\ngo 1.24\n',
        'c/c.go': 'package c\n',
        'c/inner/go.mod': 'module ex/c/inner\n\ngo 1.24\n',
        'c/inner/i.go': 'package inner\n',
      });
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, 'a', 'link.go'));
      mkdirSync(path.join(root, 'b', 'vendor', 'ex', 'dep'), { recursive: true });
      symlinkSync(outside, path.join(root, 'b', 'vendor', 'ex', 'dep', 'src'));
      symlinkSync(path.join(root, 'c', 'c.go'), path.join(root, 'c', 'alias.go'));
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, 'c', 'inner', 'out.go'));
      const plan = planGoModules(root, files, GO);
      // c keeps its link inside the repository; c/inner is its own module and holds the link out.
      expect(plan.modules.map((m) => m.rel)).toEqual(['c']);
      expect(plan.skipped).toEqual([
        {
          rel: 'a',
          reason: 'a/link.go is a symbolic link out of the repository, which Go would follow',
        },
        {
          rel: 'b',
          reason:
            'b/vendor/ex/dep/src is a symbolic link out of the repository, which Go would follow',
        },
        {
          rel: 'c/inner',
          reason: 'c/inner/out.go is a symbolic link out of the repository, which Go would follow',
        },
      ]);
    },
  );

  it.runIf(posix)(
    'follows a directory link inside the repository and walks a replaced directory, which go reads',
    () => {
      const root = tmp();
      const outside = tmp();
      writeFileSync(path.join(outside, 'secret.go'), 'package x\n');
      const files = scope(root, {
        // b vendors a package through a link into node_modules, which the walk itself skips.
        'b/go.mod': 'module ex/b\n\ngo 1.24\n',
        'b/b.go': 'package b\n',
        'node_modules/evil/ok.go': 'package evil\n',
        // c replaces a dependency with its own nested module, which holds a link out.
        'c/go.mod': 'module ex/c\n\ngo 1.24\n\nreplace ex/c/inner => ./inner\n',
        'c/c.go': 'package c\n',
        'c/inner/go.mod': 'module ex/c/inner\n\ngo 1.24\n',
        // d replaces a dependency with a directory go ignores in a walk.
        'd/go.mod': 'module ex/d\n\ngo 1.24\n\nreplace ex/dep => ../_shared\n',
        'd/d.go': 'package d\n',
        '_shared/go.mod': 'module ex/dep\n\ngo 1.24\n',
        // e links back up to itself: no endless walk.
        'e/go.mod': 'module ex/e\n\ngo 1.24\n',
        'e/e.go': 'package e\n',
      });
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, 'node_modules', 'evil', 'x.go'));
      mkdirSync(path.join(root, 'b', 'vendor', 'ex'), { recursive: true });
      symlinkSync(
        path.join(root, 'node_modules', 'evil'),
        path.join(root, 'b', 'vendor', 'ex', 'evil'),
      );
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, 'c', 'inner', 'out.go'));
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, '_shared', 'out.go'));
      symlinkSync(path.join(root, 'e'), path.join(root, 'e', 'self'));
      const plan = planGoModules(root, files, GO);
      expect(plan.modules.map((m) => m.rel)).toEqual(['e']);
      expect(plan.skipped).toEqual([
        {
          rel: 'b',
          reason:
            'b/vendor/ex/evil/x.go is a symbolic link out of the repository, which Go would follow',
        },
        {
          rel: 'c',
          reason: 'c/inner/out.go is a symbolic link out of the repository, which Go would follow',
        },
        {
          rel: 'd',
          reason: '_shared/out.go is a symbolic link out of the repository, which Go would follow',
        },
      ]);
    },
  );

  it.runIf(posix)(
    'does not walk what go never reads or Qualor excludes, but still the module itself and vendor/ (ruling G9-7)',
    () => {
      const root = tmp();
      const outside = tmp();
      writeFileSync(path.join(outside, 'secret.go'), 'package x\n');
      const files = scope(root, {
        'go.mod': 'module ex/m\n\ngo 1.24\n',
        'm.go': 'package m\n',
      });
      // An `npm link`ed package, editor and tool directories, test data: go reads none of them.
      for (const d of ['node_modules/@acme', '.cache', '_build', 'pkg/testdata', 'dist']) {
        mkdirSync(path.join(root, ...d.split('/')), { recursive: true });
      }
      symlinkSync(outside, path.join(root, 'node_modules', '@acme', 'lib'));
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, '.cache', 'x.go'));
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, '_build', 'x.go'));
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, 'pkg', 'testdata', 'x.go'));
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, 'dist', 'x.go'));
      symlinkSync(path.join(outside, 'secret.go'), path.join(root, '_x.go'));
      expect(planGoModules(root, files, GO)).toMatchObject({ modules: [{ rel: '' }], skipped: [] });
      // A link named like an excluded directory is still a link go may follow.
      symlinkSync(outside, path.join(root, 'build'));
      expect(planGoModules(root, files, GO).skipped).toEqual([
        {
          rel: '',
          reason: 'build is a symbolic link out of the repository, which Go would follow',
        },
      ]);
    },
  );
});

describe('goModuleCache and goEnv (config.md §6, plan 9C)', () => {
  it("uses the CI's GOMODCACHE, else GOPATH's, else HOME's, never one inside the repository", () => {
    const root = tmp();
    const work = tmp();
    const own = path.join(work, 'gomodcache');
    const abs = (p: string) => path.resolve(p);
    expect(goModuleCache({ GOMODCACHE: abs('/cache/mod') }, root, work)).toEqual({
      dir: abs('/cache/mod'),
      warning: null,
    });
    expect(
      goModuleCache({ GOPATH: `${abs('/gp')}${path.delimiter}${abs('/other')}` }, root, work),
    ).toEqual({
      dir: path.join(abs('/gp'), 'pkg', 'mod'),
      warning: null,
    });
    expect(goModuleCache({ HOME: abs('/home/ci') }, root, work)).toEqual({
      dir: path.join(abs('/home/ci'), 'go', 'pkg', 'mod'),
      warning: null,
    });
    expect(goModuleCache({ GOMODCACHE: 'relative/mod' }, root, work)).toEqual({
      dir: own,
      warning: null,
    });
    expect(goModuleCache({}, root, work)).toEqual({ dir: own, warning: null });
    const inside = path.join(root, '.go', 'pkg', 'mod');
    expect(goModuleCache({ GOMODCACHE: inside }, root, work)).toEqual({
      dir: own,
      warning: `the Go module cache ${inside} is inside the repository and is not used (config.md §6); keep it outside, for example GOMODCACHE=/tmp/gomodcache`,
    });
  });

  it('locks the go command down and keeps only an allowlist of inherited variables', () => {
    const work = path.resolve('/w');
    const env = goEnv({
      workDir: work,
      go: path.resolve('/opt/qualor/bin/go'),
      moduleCache: path.resolve('/cache'),
      path: path.resolve('/usr/bin'),
    });
    expect(env).toMatchObject({
      PATH: `${path.resolve('/opt/qualor/bin')}${path.delimiter}${path.resolve('/usr/bin')}`,
      HOME: work,
      LC_ALL: 'C.UTF-8',
      GOTOOLCHAIN: 'local',
      GOPROXY: 'off',
      GOFLAGS: '',
      GOWORK: 'off',
      GOENV: 'off',
      GOVCS: '*:off',
      CGO_ENABLED: '0',
      GOPACKAGESDRIVER: 'off',
      GOCACHE: path.join(work, 'gocache'),
      GOPATH: path.join(work, 'gopath'),
      GOMODCACHE: path.resolve('/cache'),
      XDG_CACHE_HOME: path.join(work, 'cache'),
      XDG_CONFIG_HOME: path.join(work, 'config'),
      HTTPS_PROXY: 'http://127.0.0.1:9',
    });
    expect([...GO_KEPT_ENV]).toEqual([
      'PATH',
      'TMPDIR',
      'TEMP',
      'TMP',
      'LANG',
      'LC_ALL',
      'LC_CTYPE',
      'SYSTEMROOT',
      'WINDIR',
    ]);
  });
});

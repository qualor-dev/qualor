import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  checkFixUpload,
  readGoMod,
  readGoSum,
  type FixClaimItem,
  type FixFileChange,
} from '@qualor/shared/fix';
import { afterEach, describe, expect, it } from 'vitest';
import { writeGoProxy, type GoProxyModule } from '../../test/fix/go-proxy';
import { toolInstalled } from '../../test/fix/tools';
import { commitAll, gitSync, GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createGit } from '../git/git';
import { silentLogger, type Logger } from '../log';
import type { FixWorkspace } from './adapter';
import { goAdapter, goGetVersion } from './go';
import { prepareFix, type FixOutcome } from './run';
import { createToolRunner, type ToolResult, type ToolRunner } from './runner';
import { openScratch } from './workspace';

const tmp = useTempDirs();
/** A `go` call's module download and checksum write (Windows runs them slowly). */
const SLOW = 180_000;
const GO = toolInstalled('go');

// ─── Environment ────────────────────────────────────────────────────────────

/** The test process's own Go settings and profile folders, replaced for every `go` call. */
const REPLACED = /^(GO\w*|HOME|USERPROFILE|APPDATA|LOCALAPPDATA|XDG_\w+)$/i;

/** Homes with a module cache, which `go` makes read-only: emptied with `go clean -modcache`. */
const homes: { dir: string; env: Record<string, string> }[] = [];
afterEach(async () => {
  for (const home of homes.splice(0)) {
    const go = createToolRunner({ env: home.env, root: home.dir, log: silentLogger });
    await go('go', ['clean', '-modcache'], { cwd: home.dir, timeoutMs: SLOW }).catch(() => null);
    rmSync(home.dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

/**
 * `go` in a CI job against the offline proxy (R27): `GOPROXY=<file url>`, `GOSUMDB=off`,
 * `GOFLAGS=-mod=mod`, and its own home, `GOPATH`, `GOCACHE` and `GOMODCACHE` in a temporary
 * folder, so nothing of this machine's Go setup or profile plays a part.
 */
function goEnv(proxy: string): Record<string, string> {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-fix-go-home-'));
  const at = (name: string) => path.join(dir, name);
  const inherited = Object.entries(GIT_TEST_ENV).filter(
    (entry): entry is [string, string] => entry[1] !== undefined && !REPLACED.test(entry[0]),
  );
  const env = {
    ...Object.fromEntries(inherited),
    HOME: dir,
    USERPROFILE: dir,
    APPDATA: at('AppData'),
    LOCALAPPDATA: at('LocalAppData'),
    XDG_CONFIG_HOME: at('config'),
    XDG_CACHE_HOME: at('cache'),
    GOENV: 'off',
    GOPATH: at('gopath'),
    GOCACHE: at('gocache'),
    GOMODCACHE: at('gomodcache'),
    GOPROXY: proxy,
    GOSUMDB: 'off',
    GOFLAGS: '-mod=mod',
  };
  homes.push({ dir, env });
  return env;
}

// ─── Modules ────────────────────────────────────────────────────────────────

const QF = 'example.com/qf';

/** `example.com/qf` at `version`, its go.mod asking for `go`. */
const qf = (version: string, go = '1.21'): GoProxyModule => ({
  path: QF,
  version,
  goMod: `module ${QF}\n\ngo ${go}\n`,
  files: {
    'qf.go': 'package qf\n\n// Hello says hello.\nfunc Hello() string { return "hello" }\n',
  },
});

/** A module of the repository: its go.mod (`module`, `go 1.21`, then `blocks`) and a main.go. */
function app(module: string, blocks: string[], imports: string[]): Record<string, string> {
  const goMod = [`module ${module}`, 'go 1.21', ...blocks].join('\n\n');
  const lines = imports.map((p) => `\t"${p}"`).join('\n');
  const calls = imports.map((p) => `${p.slice(p.lastIndexOf('/') + 1)}.Hello()`).join(', ');
  return {
    'go.mod': `${goMod}\n`,
    'main.go': `package main\n\nimport (\n${lines}\n)\n\nfunc main() { println(${calls}) }\n`,
  };
}

/** `files` with every path put under `dir`. */
function under(dir: string, files: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(files).map(([p, text]) => [`${dir}${p}`, text]));
}

/** A repository with `files`, each module in `modules` tidied by `go` itself, committed. */
async function repository(
  files: Record<string, string>,
  modules: readonly string[],
  env: Record<string, string>,
): Promise<string> {
  const dir = tmp('qualor-fix-go-');
  initRepo(dir);
  writeTree(dir, files);
  const go = createToolRunner({ env, root: dir, log: silentLogger });
  for (const module of modules) {
    const r = await go('go', ['mod', 'tidy'], {
      cwd: path.join(dir, ...module.split('/').filter((s) => s !== '')),
      env: { GOTOOLCHAIN: 'local' },
      timeoutMs: SLOW,
    });
    if (r.exitCode !== 0) throw new Error(`go mod tidy failed: ${r.stderr}`);
  }
  commitAll(dir, 'base');
  return dir;
}

/** A repository with `files` as they are, committed, no tool run. */
function committed(files: Record<string, string>): string {
  const dir = tmp('qualor-fix-go-');
  initRepo(dir);
  writeTree(dir, files);
  commitAll(dir, 'base');
  return dir;
}

function claim(installed: string[], fixed: string, packageName = QF): FixClaimItem {
  return {
    id: '0193a4c6-1c2e-7a3b-9f00-000000000002',
    generation: 1,
    leaseToken: 'lease-1',
    family: 'go',
    packageName,
    installedVersions: installed,
    vulnerabilities: [
      {
        id: 'GO-2026-0001',
        severity: 'high',
        title: 'Path traversal',
        url: null,
        installedVersions: installed,
        fixedVersions: fixed.split(',').map((v) => v.trim()),
      },
    ],
    mainBranch: 'main',
    declinedTarget: null,
  };
}

interface Call {
  tool: string;
  args: string[];
  env: Record<string, string>;
  /** The folder it ran in, relative to the scratch copy ('' at its root). */
  cwd: string;
}

interface Fixed {
  outcome: FixOutcome;
  calls: Call[];
  /** The changed files, by path: their text at HEAD and after the fix. */
  files: Map<string, FixFileChange>;
  /** `git diff --cached -U0` of a path in the scratch copy, read before it was removed. */
  diffs: Map<string, string>;
}

/** The `fake` runner's view: the scratch copy's root, to edit files in as a tool would. */
type FakeRunner = (root: string) => ToolRunner;

/** Runs the fix of `item` with the Go adapter in a scratch copy of `dir`, as `qualor fix` does. */
async function fix(
  dir: string,
  env: Record<string, string>,
  item: FixClaimItem,
  o: { fake?: FakeRunner; log?: Logger } = {},
): Promise<Fixed> {
  const git = createGit(dir, GIT_TEST_ENV);
  const scratch = await openScratch(git, tmp('qualor-fix-temp-'));
  const calls: Call[] = [];
  const real = o.fake?.(scratch.root) ?? createToolRunner({ env, root: dir, log: silentLogger });
  const run: ToolRunner = (tool, args, call) => {
    const cwd = path.relative(scratch.root, call.cwd).replaceAll('\\', '/');
    calls.push({ tool, args: [...args], env: { ...call.env }, cwd });
    return real(tool, args, call);
  };
  try {
    const ws: FixWorkspace = {
      root: scratch.root,
      files: gitSync(dir, 'ls-files').split('\n'),
      run,
      deadline: Date.now() + SLOW,
      log: o.log ?? silentLogger,
    };
    const outcome = await prepareFix(item, goAdapter, ws, git);
    const files = new Map<string, FixFileChange>();
    const diffs = new Map<string, string>();
    for (const f of 'files' in outcome ? outcome.files : []) {
      const next = Buffer.from(f.content, 'base64').toString('utf8');
      files.set(f.path, { path: f.path, base: readFileSync(path.join(dir, f.path), 'utf8'), next });
      diffs.set(f.path, gitSync(scratch.root, 'diff', '--cached', '-U0', '--', f.path));
    }
    return { outcome, calls, files, diffs };
  } finally {
    await scratch.close();
  }
}

function uploaded(r: Fixed): Extract<FixOutcome, { files: unknown }> {
  if (!('files' in r.outcome)) throw new Error(`expected files, got ${JSON.stringify(r.outcome)}`);
  return r.outcome;
}

function textOf(r: Fixed, file: string): string {
  const change = r.files.get(file);
  if (change === undefined) throw new Error(`${file} did not change`);
  return change.next;
}

/** The `+` and `-` lines of a diff, without its headers. */
const changedLines = (diff: string | undefined): string[] =>
  (diff ?? '').split('\n').filter((l) => /^[+-](?![+-]{2} )/.test(l));

/** The B1 content check the server runs, over the outcome's own files. */
function contentCheck(r: Fixed, item: FixClaimItem) {
  return checkFixUpload({
    family: 'go',
    packageName: item.packageName,
    targets: uploaded(r).targets,
    files: [...r.files.values()],
  });
}

/** The package's requires in a go.mod text. */
const requiresOf = (text: string, module = QF) =>
  readGoMod(text)
    .requires.filter((r) => r.path === module)
    .map((r) => ({ version: r.version, indirect: r.indirect }));

/** The go.sum lines of a module at a version (zip and `/go.mod`), and whether each has `h1:`. */
const sumLines = (text: string, version: string, module = QF) =>
  readGoSum(text)
    .filter((e) => e.name === module && e.version.replace(/\/go\.mod$/, '') === version)
    .map((e) => [e.version, e.integrity?.startsWith('h1:') ?? false]);

const lockfileLine = (file: string, relation: 'direct' | 'transitive') => ({
  path: file,
  relation,
  mechanism: null,
  dependents: [],
});

// ─── With the real go ───────────────────────────────────────────────────────

describe.runIf(GO)('the Go adapter with go and a file:// GOPROXY', () => {
  it(
    'direct: go get and go mod tidy move the require to the target; go.sum gets its h1: lines',
    async () => {
      const env = goEnv(writeGoProxy(tmp('qualor-fix-goproxy-'), [qf('v1.2.5'), qf('v1.2.6')]));
      const dir = await repository(
        app('example.com/app', [`require ${QF} v1.2.5`], [QF]),
        [''],
        env,
      );
      const item = claim(['v1.2.5'], '1.2.6');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect(up.targets).toEqual([{ installed: 'v1.2.5', target: '1.2.6', lockfile: 'go.mod' }]);
      expect(up).toMatchObject({ targetVersion: '1.2.6', installedVersion: 'v1.2.5' });
      expect(up.lockfiles).toEqual([lockfileLine('go.mod', 'direct')]);
      expect([...r.files.keys()].sort()).toEqual(['go.mod', 'go.sum']);
      expect(changedLines(r.diffs.get('go.mod'))).toEqual([
        `-require ${QF} v1.2.5`,
        `+require ${QF} v1.2.6`,
      ]);
      expect(sumLines(textOf(r, 'go.sum'), 'v1.2.6')).toEqual([
        ['v1.2.6', true],
        ['v1.2.6/go.mod', true],
      ]);
      expect(contentCheck(r, item)).toEqual({ ok: true });
      expect(r.calls.map((c) => c.args)).toEqual([
        ['get', `${QF}@v1.2.6`],
        ['mod', 'tidy'],
      ]);
    },
    SLOW,
  );

  it(
    'indirect: the // indirect require is raised and stays indirect; the relation is transitive',
    async () => {
      const parent: GoProxyModule = {
        path: 'example.com/parent',
        version: 'v1.0.0',
        goMod: `module example.com/parent\n\ngo 1.21\n\nrequire ${QF} v1.2.5\n`,
        files: {
          'parent.go': `package parent\n\nimport "${QF}"\n\n// Hello says hello.\nfunc Hello() string { return qf.Hello() }\n`,
        },
      };
      const env = goEnv(
        writeGoProxy(tmp('qualor-fix-goproxy-'), [qf('v1.2.5'), qf('v1.2.6'), parent]),
      );
      const dir = await repository(
        app(
          'example.com/app',
          ['require example.com/parent v1.0.0', `require ${QF} v1.2.5 // indirect`],
          ['example.com/parent'],
        ),
        [''],
        env,
      );
      expect(requiresOf(readFileSync(path.join(dir, 'go.mod'), 'utf8'))).toEqual([
        { version: 'v1.2.5', indirect: true },
      ]);
      const item = claim(['v1.2.5'], '1.2.6');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect(up.lockfiles).toEqual([lockfileLine('go.mod', 'transitive')]);
      expect(requiresOf(textOf(r, 'go.mod'))).toEqual([{ version: 'v1.2.6', indirect: true }]);
      expect(changedLines(r.diffs.get('go.mod'))).toEqual([
        `-require ${QF} v1.2.5 // indirect`,
        `+require ${QF} v1.2.6 // indirect`,
      ]);
      expect(sumLines(textOf(r, 'go.sum'), 'v1.2.6')).toEqual([
        ['v1.2.6', true],
        ['v1.2.6/go.mod', true],
      ]);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );

  it(
    'two modules (§11.7): svc/a and svc/b both move to the target, each in its own folder',
    async () => {
      const env = goEnv(writeGoProxy(tmp('qualor-fix-goproxy-'), [qf('v1.2.5'), qf('v1.2.6')]));
      const dir = await repository(
        {
          ...under('svc/a/', app('example.com/a', [`require ${QF} v1.2.5`], [QF])),
          ...under('svc/b/', app('example.com/b', [`require ${QF} v1.2.5`], [QF])),
        },
        ['svc/a/', 'svc/b/'],
        env,
      );
      const item = claim(['v1.2.5'], '1.2.6');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect(up.targets).toEqual([
        { installed: 'v1.2.5', target: '1.2.6', lockfile: 'svc/a/go.mod' },
        { installed: 'v1.2.5', target: '1.2.6', lockfile: 'svc/b/go.mod' },
      ]);
      expect(up.lockfiles).toEqual([
        lockfileLine('svc/a/go.mod', 'direct'),
        lockfileLine('svc/b/go.mod', 'direct'),
      ]);
      expect([...r.files.keys()].sort()).toEqual([
        'svc/a/go.mod',
        'svc/a/go.sum',
        'svc/b/go.mod',
        'svc/b/go.sum',
      ]);
      for (const module of ['svc/a/', 'svc/b/']) {
        expect(requiresOf(textOf(r, `${module}go.mod`))).toEqual([
          { version: 'v1.2.6', indirect: false },
        ]);
        expect(sumLines(textOf(r, `${module}go.sum`), 'v1.2.6')).toHaveLength(2);
      }
      expect(r.calls.map((c) => [c.cwd, ...c.args])).toEqual([
        ['svc/a', 'get', `${QF}@v1.2.6`],
        ['svc/a', 'mod', 'tidy'],
        ['svc/b', 'get', `${QF}@v1.2.6`],
        ['svc/b', 'mod', 'tidy'],
      ]);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );

  it(
    'go line: a target that needs a newer go than this one fails package_manager under GOTOOLCHAIN=local, no upload (ruling F21)',
    async () => {
      const env = goEnv(
        writeGoProxy(tmp('qualor-fix-goproxy-'), [qf('v1.2.5'), qf('v1.2.6', '1.99')]),
      );
      const dir = await repository(
        app('example.com/app', [`require ${QF} v1.2.5`], [QF]),
        [''],
        env,
      );

      const r = await fix(dir, env, claim(['v1.2.5'], '1.2.6'));

      expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
      if ('failure' in r.outcome) {
        expect(r.outcome.failure.message).toContain('requires go >= 1.99');
        expect(r.outcome.failure.message).toContain('GOTOOLCHAIN=local');
      }
      expect('files' in r.outcome).toBe(false);
      expect(r.calls.map((c) => c.args)).toEqual([['get', `${QF}@v1.2.6`]]);
    },
    SLOW,
  );

  it(
    'go line: a target whose go line this go can meet raises the module’s go line: unplanned_change go_directive (R24)',
    async () => {
      const env = goEnv(
        writeGoProxy(tmp('qualor-fix-goproxy-'), [qf('v1.2.5'), qf('v1.2.6', '1.22')]),
      );
      const dir = await repository(
        app('example.com/app', [`require ${QF} v1.2.5`], [QF]),
        [''],
        env,
      );

      const r = await fix(dir, env, claim(['v1.2.5'], '1.2.6'));

      expect(r.outcome).toMatchObject({ failure: { code: 'unplanned_change' } });
      if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('go_directive');
    },
    SLOW,
  );

  it(
    'pseudo-version: installed v0.0.0-20191109021931-daa7c04131f5, fixed 0.0.1, becomes v0.0.1',
    async () => {
      const pseudo = 'v0.0.0-20191109021931-daa7c04131f5';
      const env = goEnv(writeGoProxy(tmp('qualor-fix-goproxy-'), [qf(pseudo), qf('v0.0.1')]));
      const dir = await repository(
        app('example.com/app', [`require ${QF} ${pseudo}`], [QF]),
        [''],
        env,
      );
      const item = claim([pseudo], '0.0.1');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect(up.targets).toEqual([{ installed: pseudo, target: '0.0.1', lockfile: 'go.mod' }]);
      expect(requiresOf(textOf(r, 'go.mod'))).toEqual([{ version: 'v0.0.1', indirect: false }]);
      expect(r.calls[0]?.args).toEqual(['get', `${QF}@v0.0.1`]);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );

  it(
    'no version satisfies the target: no fix, unresolvable (ruling F36)',
    async () => {
      const env = goEnv(writeGoProxy(tmp('qualor-fix-goproxy-'), [qf('v1.2.5')]));
      const dir = await repository(
        app('example.com/app', [`require ${QF} v1.2.5`], [QF]),
        [''],
        env,
      );

      const r = await fix(dir, env, claim(['v1.2.5'], '1.2.6'));

      expect(r.outcome).toMatchObject({ noFix: { reason: 'unresolvable' } });
      if ('noFix' in r.outcome) expect(r.outcome.noFix.message).toContain('v1.2.6.info');
    },
    SLOW,
  );

  it(
    '+incompatible: an installed v2.0.0+incompatible with a fixed 3.1.0 is fetched as v3.1.0+incompatible (ruling T1d)',
    async () => {
      const inc = (version: string): GoProxyModule => ({
        path: 'example.com/inc',
        version,
        goMod: 'module example.com/inc\n',
        files: {
          'inc.go': 'package inc\n\n// Hello says hello.\nfunc Hello() string { return "hi" }\n',
        },
      });
      const env = goEnv(
        writeGoProxy(tmp('qualor-fix-goproxy-'), [
          inc('v2.0.0+incompatible'),
          inc('v3.1.0+incompatible'),
        ]),
      );
      const dir = await repository(
        app(
          'example.com/app',
          ['require example.com/inc v2.0.0+incompatible'],
          ['example.com/inc'],
        ),
        [''],
        env,
      );
      const item = claim(['v2.0.0+incompatible'], '3.1.0', 'example.com/inc');

      const r = await fix(dir, env, item);

      expect(r.calls[0]?.args).toEqual(['get', 'example.com/inc@v3.1.0+incompatible']);
      expect(requiresOf(textOf(r, 'go.mod'), 'example.com/inc')).toEqual([
        { version: 'v3.1.0+incompatible', indirect: false },
      ]);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );
});

// ─── With a fake runner (everywhere) ────────────────────────────────────────

/** A go.sum hash of the right shape. */
const H1 = (c: string) => `h1:${c.repeat(43)}=`;
const sumOf = (module: string, version: string, c = 'A') =>
  `${module} ${version} ${H1(c)}\n${module} ${version}/go.mod ${H1(c)}\n`;

const ok = (): ToolResult => ({ exitCode: 0, timedOut: false, stdout: '', stderr: '' });

/** A go.mod text with the version of `module`'s require lines set to `version`. */
function withRequire(text: string, module: string, version: string): string {
  return text
    .split('\n')
    .map((line) => {
      const at = line.indexOf(`${module} v`);
      if (at < 0) return line;
      const start = at + module.length + 1;
      const end = line.indexOf(' ', start);
      return `${line.slice(0, start)}${version}${end < 0 ? '' : line.slice(end)}`;
    })
    .join('\n');
}

/**
 * A fake `go`: `go get <module>@<version>` sets the module's require in the go.mod of its folder to
 * that version and adds its go.sum lines (unless `sum` is false), or answers `get`'s result;
 * `go mod tidy` does nothing.
 */
function fakeGo(o: { sum?: boolean; get?: () => ToolResult } = {}): FakeRunner {
  return () => (_tool, args, call) => {
    if (args[0] !== 'get') return Promise.resolve(ok());
    if (o.get !== undefined) return Promise.resolve(o.get());
    const [module = '', version = ''] = (args[1] ?? '').split('@');
    const goMod = path.join(call.cwd, 'go.mod');
    writeFileSync(goMod, withRequire(readFileSync(goMod, 'utf8'), module, version));
    if (o.sum !== false) {
      const goSum = path.join(call.cwd, 'go.sum');
      writeFileSync(goSum, `${readFileSync(goSum, 'utf8')}${sumOf(module, version, 'B')}`);
    }
    return Promise.resolve(ok());
  };
}

const DOCKER = 'github.com/docker/docker';

describe('the Go adapter with a fake go', () => {
  it('commands: go get <module>@v<target> then go mod tidy, with GOTOOLCHAIN=local and GOFLAGS=-mod=mod, in the module folder (R24, ruling T1d)', async () => {
    const dir = committed({
      'go.mod': `module example.com/app\n\ngo 1.21\n\nrequire ${DOCKER} v20.10.0+incompatible\n`,
      'go.sum': sumOf(DOCKER, 'v20.10.0+incompatible'),
    });
    const item = claim(['v20.10.0+incompatible'], '25.0.6', DOCKER);

    const r = await fix(dir, {}, item, { fake: fakeGo() });

    const env = { GOTOOLCHAIN: 'local', GOFLAGS: '-mod=mod' };
    expect(r.calls).toEqual([
      { tool: 'go', args: ['get', `${DOCKER}@v25.0.6+incompatible`], env, cwd: '' },
      { tool: 'go', args: ['mod', 'tidy'], env, cwd: '' },
    ]);
    const up = uploaded(r);
    expect(up.targets).toEqual([
      { installed: 'v20.10.0+incompatible', target: '25.0.6', lockfile: 'go.mod' },
    ]);
    expect(up.lockfiles).toEqual([lockfileLine('go.mod', 'direct')]);
    expect(requiresOf(textOf(r, 'go.mod'), DOCKER)).toEqual([
      { version: 'v25.0.6+incompatible', indirect: false },
    ]);
    expect(contentCheck(r, item)).toEqual({ ok: true });
  });

  it('vendor: a tracked vendor/modules.txt is manifest_unsupported, before any go runs (R24)', async () => {
    const dir = committed({
      'go.mod': `module example.com/app\n\ngo 1.21\n\nrequire ${QF} v1.2.5\n`,
      'go.sum': sumOf(QF, 'v1.2.5'),
      'vendor/modules.txt': `# ${QF} v1.2.5\n## explicit\n${QF}\n`,
      'vendor/example.com/qf/qf.go': 'package qf\n',
    });

    const r = await fix(dir, {}, claim(['v1.2.5'], '1.2.6'), { fake: fakeGo() });

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('vendor/modules.txt');
    expect(r.calls).toEqual([]);
  });

  it('a replace of the package for every version is manifest_unsupported, before any go runs', async () => {
    const dir = committed({
      'go.mod': `module example.com/app\n\ngo 1.21\n\nrequire ${QF} v1.2.5\n\nreplace ${QF} => ../qf\n`,
      'go.sum': sumOf(QF, 'v1.2.5'),
    });

    const r = await fix(dir, {}, claim(['v1.2.5'], '1.2.6'), { fake: fakeGo() });

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('replace');
    expect(r.calls).toEqual([]);
  });

  const unresolvable = { noFix: { reason: 'unresolvable' } };
  const packageManager = { failure: { code: 'package_manager' } };

  it.each([
    [
      'an HTTP proxy’s 404: unresolvable',
      unresolvable,
      `go: ${QF}@v1.2.6: reading https://proxy.golang.org/${QF}/@v/v1.2.6.info: 404 Not Found\n\tserver response: not found: ${QF}@v1.2.6: invalid version: unknown revision v1.2.6\n`,
    ],
    [
      'a 410 Gone: unresolvable',
      unresolvable,
      `go: ${QF}@v1.2.6: reading https://goproxy.example/${QF}/@v/v1.2.6.info: 410 Gone\n`,
    ],
    [
      'an unknown revision: unresolvable',
      unresolvable,
      `go: ${QF}@v1.2.6: invalid version: unknown revision v1.2.6\n`,
    ],
    [
      'a refused proxy: package_manager',
      packageManager,
      `go: ${QF}@v1.2.6: reading https://goproxy.example/${QF}/@v/v1.2.6.info: 403 Forbidden\n`,
    ],
    [
      'another module’s missing version: package_manager',
      packageManager,
      `go: ${QF}@v1.2.6 requires\n\texample.com/dep@v1.0.0: reading https://goproxy.example/example.com/dep/@v/v1.0.0.info: 404 Not Found\n`,
    ],
  ])('go get failing with %s (ruling F36)', async (_what, expected, stderr) => {
    const dir = committed({
      'go.mod': `module example.com/app\n\ngo 1.21\n\nrequire ${QF} v1.2.5\n`,
      'go.sum': sumOf(QF, 'v1.2.5'),
    });
    const failed = (): ToolResult => ({ exitCode: 1, timedOut: false, stdout: '', stderr });

    const r = await fix(dir, {}, claim(['v1.2.5'], '1.2.6'), { fake: fakeGo({ get: failed }) });

    expect(r.outcome).toMatchObject(expected);
    expect(r.calls.map((c) => c.args)).toEqual([['get', `${QF}@v1.2.6`]]);
  });

  it('verify: a go.sum without the new version’s lines is verify_failed', async () => {
    const dir = committed({
      'go.mod': `module example.com/app\n\ngo 1.21\n\nrequire ${QF} v1.2.5\n`,
      'go.sum': sumOf(QF, 'v1.2.5'),
    });

    const r = await fix(dir, {}, claim(['v1.2.5'], '1.2.6'), { fake: fakeGo({ sum: false }) });

    expect(r.outcome).toMatchObject({ failure: { code: 'verify_failed' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('go.sum');
  });

  it('installed: the require version of every go.mod, none under vendor/, an unreadable one skipped with a warning', async () => {
    const root = tmp('qualor-fix-go-installed-');
    const files = {
      'go.mod': `module example.com/app\n\ngo 1.21\n\nrequire (\n\t${QF} v1.2.5\n\texample.com/other v1.0.0\n)\n`,
      'svc/b/go.mod': `module example.com/b\n\ngo 1.21\n\nrequire ${QF} v1.2.4 // indirect\n`,
      'svc/c/go.mod': 'module example.com/c\n\ngo 1.21\n',
      'svc/d/go.mod': 'module example.com/d\n\nrequire (\n',
      'vendor/example.com/x/go.mod': `module example.com/x\n\nrequire ${QF} v1.0.0\n`,
    };
    writeTree(root, files);
    const warnings: string[] = [];
    const log: Logger = { ...silentLogger, warn: (m: string) => warnings.push(m) };
    const ws: FixWorkspace = {
      root,
      files: Object.keys(files),
      run: () => Promise.reject(new Error('no tool runs')),
      deadline: Date.now() + SLOW,
      log,
    };

    const found = await goAdapter.installed(ws, QF);

    expect(found).toEqual([
      { lockfile: 'go.mod', versions: ['v1.2.5'] },
      { lockfile: 'svc/b/go.mod', versions: ['v1.2.4'] },
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('svc/d/go.mod');
  });
});

describe('goGetVersion', () => {
  it.each([
    [QF, 'v1.2.5', '1.2.6', 'v1.2.6'],
    [QF, 'v1.2.5', 'v1.2.6', 'v1.2.6'],
    [DOCKER, 'v20.10.0+incompatible', '25.0.6', 'v25.0.6+incompatible'],
    [DOCKER, 'v20.10.0+incompatible', 'v25.0.6+incompatible', 'v25.0.6+incompatible'],
    ['example.com/m/v3', 'v3.0.0+incompatible', '3.0.1', 'v3.0.1'],
    [QF, 'v2.0.0', '2.0.1', 'v2.0.1'],
  ])('%s %s with a fixed %s: %s (ruling T1d)', (module, installed, target, expected) => {
    expect(goGetVersion(module, installed, target)).toBe(expected);
  });
});

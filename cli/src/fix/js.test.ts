import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  checkFixUpload,
  readNpmLock,
  readPnpmLock,
  readYarnLock,
  type FixClaimItem,
  type FixFileChange,
  type FixTarget,
  type LockEntry,
} from '@qualor/shared/fix';
import {
  createFakeNpmRegistry,
  type FakeNpmRegistry,
  type FakeNpmVersion,
} from '@qualor/shared/test/npm-registry';
import { afterEach, describe, expect, it } from 'vitest';
import { toolInstalled } from '../../test/fix/tools';
import { commitAll, gitSync, GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createGit } from '../git/git';
import { silentLogger } from '../log';
import type { FixPlan, FixWorkspace } from './adapter';
import { fixToolEnv } from './env';
import { jsAdapter } from './js';
import { prepareFix, type FixOutcome } from './run';
import { createToolRunner, type ToolRunner } from './runner';
import { resolveTool } from './shim';
import { openScratch } from './workspace';

const tmp = useTempDirs();
/** A package manager's resolve, fetch and lockfile write, per call (Windows runs them slowly). */
const SLOW = 180_000;

// ─── Package managers ───────────────────────────────────────────────────────

type Manager = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry';
const MANAGERS: readonly Manager[] = ['npm', 'pnpm', 'yarn-classic', 'yarn-berry'];

/** The major version of the `yarn` the fix job's runner would start here; null without one. */
function yarnMajor(): number | null {
  const found = resolveTool('yarn', { root: process.cwd(), env: fixToolEnv(process.env) });
  if (found === null || 'problem' in found) return null;
  const cwd = mkdtempSync(path.join(os.tmpdir(), 'qualor-yarn-version-'));
  try {
    const out = execFileSync(found.command, [...found.args, '--version'], {
      cwd,
      encoding: 'utf8',
    });
    return Number.parseInt(out.trim(), 10);
  } catch {
    return null;
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

const YARN_MAJOR = yarnMajor();
const AVAILABLE: Readonly<Record<Manager, boolean>> = {
  npm: toolInstalled('npm'),
  pnpm: toolInstalled('pnpm'),
  'yarn-classic': YARN_MAJOR === 1,
  'yarn-berry': YARN_MAJOR !== null && YARN_MAJOR >= 2,
};

const LOCKFILE: Readonly<Record<Manager, string>> = {
  npm: 'package-lock.json',
  pnpm: 'pnpm-lock.yaml',
  'yarn-classic': 'yarn.lock',
  'yarn-berry': 'yarn.lock',
};

/** How a test makes a base lockfile: the adapter's own regeneration (CI defaults off). */
const LOCK_COMMAND: Readonly<Record<Manager, [string, string[], Record<string, string>]>> = {
  npm: [
    'npm',
    ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'],
    {},
  ],
  pnpm: ['pnpm', ['install', '--lockfile-only', '--ignore-scripts', '--no-frozen-lockfile'], {}],
  'yarn-classic': ['yarn', ['install', '--ignore-scripts', '--non-interactive'], {}],
  'yarn-berry': [
    'yarn',
    ['install', '--mode=update-lockfile'],
    { YARN_ENABLE_SCRIPTS: 'false', YARN_ENABLE_IMMUTABLE_INSTALLS: 'false' },
  ],
};

function readLock(lockfile: string, text: string): LockEntry[] {
  if (lockfile.endsWith('package-lock.json')) return readNpmLock(text);
  if (lockfile.endsWith('pnpm-lock.yaml')) return readPnpmLock(text);
  return readYarnLock(text);
}

const versionsIn = (lockfile: string, text: string, name = 'qf-a'): string[] =>
  [
    ...new Set(
      readLock(lockfile, text)
        .filter((e) => e.name === name)
        .map((e) => e.version),
    ),
  ].sort();

// ─── Environment ────────────────────────────────────────────────────────────

/** Variables of the test process that steer a package manager (`pnpm exec` sets `npm_config_*`). */
const MANAGER_VARIABLE = /^(npm_|pnpm_|yarn_|berry_|corepack_)/i;

/** `PATH` under one name, whatever its case in this process (Windows spells it `Path`). */
function withPath(env: Record<string, string>, value: string): Record<string, string> {
  const out = Object.fromEntries(Object.entries(env).filter(([k]) => k.toUpperCase() !== 'PATH'));
  return { ...out, PATH: value };
}

const processPath = (): string =>
  Object.entries(process.env).find(([k]) => k.toUpperCase() === 'PATH')?.[1] ?? '';

/**
 * A package manager's environment in a CI job (`CI=true`) against the fake registry, with its own
 * home, caches and configuration in temporary directories, so nothing of this machine's own
 * `.npmrc`, `.yarnrc.yml` or caches plays a part.
 */
function managerEnv(registry: string, pathValue = processPath()): Record<string, string> {
  const home = tmp('qualor-fix-home-');
  // Berry fetches over http only from hosts it is told to trust.
  writeFileSync(path.join(home, '.yarnrc.yml'), 'unsafeHttpWhitelist:\n  - 127.0.0.1\n');
  const inherited = Object.entries(GIT_TEST_ENV).filter(
    (entry): entry is [string, string] =>
      entry[1] !== undefined && !MANAGER_VARIABLE.test(entry[0]),
  );
  const at = (name: string) => path.join(home, name);
  return withPath(
    {
      ...Object.fromEntries(inherited),
      CI: 'true',
      HOME: home,
      USERPROFILE: home,
      XDG_CONFIG_HOME: at('config'),
      XDG_CACHE_HOME: at('cache'),
      XDG_DATA_HOME: at('data'),
      XDG_STATE_HOME: at('state'),
      npm_config_registry: registry,
      npm_config_userconfig: at('.npmrc'),
      npm_config_cache: at('npm-cache'),
      npm_config_update_notifier: 'false',
      YARN_REGISTRY: registry,
      YARN_CACHE_FOLDER: at('yarn-cache'),
      YARN_NPM_REGISTRY_SERVER: registry,
      YARN_GLOBAL_FOLDER: at('berry'),
      YARN_ENABLE_TELEMETRY: '0',
    },
    pathValue,
  );
}

/** The directories of `PATH` that hold no `yarn`. */
function pathWithoutYarn(): string {
  const names = ['yarn', 'yarn.cmd', 'yarn.exe', 'yarn.js'];
  return processPath()
    .split(path.delimiter)
    .filter((dir) => !names.some((n) => existsSync(path.join(dir, n))))
    .join(path.delimiter);
}

// ─── Repositories ───────────────────────────────────────────────────────────

const registries: FakeNpmRegistry[] = [];
afterEach(async () => {
  for (const r of registries.splice(0)) await r.close();
});

async function registry(packages: Record<string, FakeNpmVersion[]>): Promise<FakeNpmRegistry> {
  const r = await createFakeNpmRegistry(packages);
  registries.push(r);
  return r;
}

/** Makes a base lockfile with the manager itself, against the registry as it is now. */
async function lock(dir: string, env: Record<string, string>, manager: Manager): Promise<void> {
  // Berry takes the nearest yarn.lock's folder as the project; without one, a package.json in a
  // parent folder (the temp folder may hold one) would be taken.
  if (manager === 'yarn-berry' && !existsSync(path.join(dir, 'yarn.lock'))) {
    writeFileSync(path.join(dir, 'yarn.lock'), '');
  }
  const [tool, args, extra] = LOCK_COMMAND[manager];
  const run = createToolRunner({ env, root: dir, log: silentLogger });
  const r = await run(tool, args, { cwd: dir, env: extra, timeoutMs: SLOW });
  if (r.exitCode !== 0) throw new Error(`${tool} failed: ${r.stderr}\n${r.stdout}`);
}

/**
 * A repository with `files`, locked by `managers` in turn, then given `later` (files no manager
 * may see), committed as the main branch's head.
 */
async function repository(
  files: Record<string, string>,
  managers: readonly Manager[],
  env: Record<string, string>,
  later: Record<string, string> = {},
): Promise<string> {
  const dir = tmp('qualor-fix-js-');
  initRepo(dir);
  writeTree(dir, { '.gitignore': 'node_modules/\n.yarn/\n.pnp.*\n', ...files });
  for (const manager of managers) await lock(dir, env, manager);
  writeTree(dir, later);
  commitAll(dir, 'base');
  return dir;
}

function claim(installed: string[], fixed: string, packageName = 'qf-a'): FixClaimItem {
  return {
    id: '0193a4c6-1c2e-7a3b-9f00-000000000001',
    generation: 1,
    leaseToken: 'lease-1',
    family: 'js',
    packageName,
    installedVersions: installed,
    vulnerabilities: [
      {
        id: 'CVE-2026-0001',
        severity: 'high',
        title: 'Prototype pollution',
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
}

interface Fixed {
  outcome: FixOutcome;
  calls: Call[];
  /** The changed files, by path: their text at HEAD and after the fix. */
  files: Map<string, FixFileChange>;
  /** `git diff --cached -U0` of a path in the scratch copy, read before it was removed. */
  diffs: Map<string, string>;
}

/** Runs the fix of `item` with the JS adapter in a scratch copy of `dir`, as `qualor fix` does. */
async function fix(
  dir: string,
  env: Record<string, string>,
  item: FixClaimItem,
  fake?: ToolRunner,
): Promise<Fixed> {
  const git = createGit(dir, GIT_TEST_ENV);
  const scratch = await openScratch(git, tmp('qualor-fix-temp-'));
  const calls: Call[] = [];
  const real = fake ?? createToolRunner({ env, root: dir, log: silentLogger });
  const run: ToolRunner = (tool, args, o) => {
    calls.push({ tool, args: [...args], env: { ...o.env } });
    return real(tool, args, o);
  };
  try {
    const ws: FixWorkspace = {
      root: scratch.root,
      files: gitSync(dir, 'ls-files').split('\n'),
      run,
      deadline: Date.now() + SLOW,
      log: silentLogger,
    };
    const outcome = await prepareFix(item, jsAdapter, ws, git);
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
const changedLines = (diff: string): string[] =>
  diff.split('\n').filter((l) => /^[+-](?![+-]{2} )/.test(l));

/** The B1 content check the server runs, over the outcome's own files. */
function contentCheck(r: Fixed, item: FixClaimItem) {
  return checkFixUpload({
    family: 'js',
    packageName: item.packageName,
    targets: uploaded(r).targets,
    files: [...r.files.values()],
  });
}

const json = (lines: string[]) => `${lines.join('\n')}\n`;

/** A 4-space `package.json` with a final newline (§11.3). */
const APP = json([
  '{',
  '    "name": "app",',
  '    "version": "1.0.0",',
  '    "private": true,',
  '    "dependencies": {',
  '        "qf-a": "^1.2.5",',
  '        "qf-other": "^1.0.0"',
  '    }',
  '}',
]);

const PARENT_APP = json([
  '{',
  '    "name": "app",',
  '    "version": "1.0.0",',
  '    "private": true,',
  '    "dependencies": {',
  '        "qf-parent": "^1.0.0"',
  '    }',
  '}',
]);

const OTHER: FakeNpmVersion[] = [{ version: '1.0.0' }];

// ─── Every manager ──────────────────────────────────────────────────────────

const PIN_PATH: Readonly<Record<Manager, string[]>> = {
  npm: ['overrides'],
  pnpm: ['pnpm', 'overrides'],
  'yarn-classic': ['resolutions'],
  'yarn-berry': ['resolutions'],
};

const MECHANISM: Readonly<Record<Manager, string>> = {
  npm: 'overrides',
  pnpm: 'pnpm.overrides',
  'yarn-classic': 'resolutions',
  'yarn-berry': 'resolutions',
};

const UNRESOLVABLE_TEXT: Readonly<Record<Manager, string>> = {
  npm: 'ETARGET',
  pnpm: 'ERR_PNPM_NO_MATCHING_VERSION',
  'yarn-classic': "Couldn't find any versions",
  'yarn-berry': 'No candidates found',
};

const at = (value: unknown, keys: readonly string[]): unknown =>
  keys.reduce<unknown>((v, k) => (v as Record<string, unknown> | undefined)?.[k], value);

/** `"a": { "b": { "qf-a": "^1.2.6" } }` as the adapter writes it, `indent` being its key's. */
function pinBlock(keys: readonly string[], indent: string): string {
  const [head = '', ...rest] = keys;
  const inner = `${indent}    `;
  const body = rest.length === 0 ? '"qf-a": "^1.2.6"' : pinBlock(rest, inner);
  return `"${head}": {\n${inner}${body}\n${indent}}`;
}

for (const manager of MANAGERS) {
  const lockfile = LOCKFILE[manager];

  describe.runIf(AVAILABLE[manager])(`the JS adapter with ${manager}`, () => {
    it(
      'direct: edits only the range in package.json and regenerates the lockfile (§11.3)',
      async () => {
        const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
        const reg = await registry({ 'qf-a': qfA, 'qf-other': OTHER });
        const env = managerEnv(reg.url);
        const dir = await repository({ 'package.json': APP }, [manager], env);
        qfA.push({ version: '1.2.6' });
        const item = claim(['1.2.5'], '1.2.6');

        const r = await fix(dir, env, item);

        const up = uploaded(r);
        expect(up.targets).toEqual([{ installed: '1.2.5', target: '1.2.6', lockfile }]);
        expect(up).toMatchObject({ targetVersion: '1.2.6', installedVersion: '1.2.5' });
        expect(up.lockfiles).toMatchObject([
          { path: lockfile, relation: 'direct', mechanism: null },
        ]);
        expect([...r.files.keys()].sort()).toEqual([lockfile, 'package.json'].sort());
        expect(changedLines(r.diffs.get('package.json') ?? '')).toEqual([
          '-        "qf-a": "^1.2.5",',
          '+        "qf-a": "^1.2.6",',
        ]);
        expect(textOf(r, 'package.json')).toBe(APP.replace('^1.2.5', '^1.2.6'));
        expect(versionsIn(lockfile, textOf(r, lockfile))).toEqual(['1.2.6']);
        const entry = readLock(lockfile, textOf(r, lockfile)).find((e) => e.name === 'qf-a');
        expect(entry?.integrity ?? '').not.toBe('');
        expect(contentCheck(r, item)).toEqual({ ok: true });
      },
      SLOW,
    );

    it(
      `transitive: pins the package through ${MECHANISM[manager]} in the root package.json`,
      async () => {
        const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
        const reg = await registry({
          'qf-a': qfA,
          'qf-parent': [{ version: '1.0.0', dependencies: { 'qf-a': '^1.2.0' } }],
        });
        const env = managerEnv(reg.url);
        const dir = await repository({ 'package.json': PARENT_APP }, [manager], env);
        qfA.push({ version: '1.2.6' });
        const item = claim(['1.2.5'], '1.2.6');

        const r = await fix(dir, env, item);

        const up = uploaded(r);
        expect(up.lockfiles).toEqual([
          {
            path: lockfile,
            relation: 'transitive',
            mechanism: MECHANISM[manager],
            dependents: ['qf-parent'],
          },
        ]);
        const manifest: unknown = JSON.parse(textOf(r, 'package.json'));
        expect(at(manifest, PIN_PATH[manager])).toEqual({ 'qf-a': '^1.2.6' });
        // Only the pin was added, after the last member, in the file's 4-space indent.
        expect(textOf(r, 'package.json')).toBe(
          PARENT_APP.replace(
            / {4}\}\n\}\n$/,
            `    },\n    ${pinBlock(PIN_PATH[manager], '    ')}\n}\n`,
          ),
        );
        expect(versionsIn(lockfile, textOf(r, lockfile))).toEqual(['1.2.6']);
        expect(contentCheck(r, item)).toEqual({ ok: true });
      },
      SLOW,
    );

    it(
      'no version satisfies the target: no fix, unresolvable (ruling F36)',
      async () => {
        const reg = await registry({ 'qf-a': [{ version: '1.2.5' }], 'qf-other': OTHER });
        const env = managerEnv(reg.url);
        const dir = await repository({ 'package.json': APP }, [manager], env);

        const r = await fix(dir, env, claim(['1.2.5'], '1.2.6'));

        expect(r.outcome).toMatchObject({ noFix: { reason: 'unresolvable' } });
        if ('noFix' in r.outcome)
          expect(r.outcome.noFix.message).toContain(UNRESOLVABLE_TEXT[manager]);
      },
      SLOW,
    );

    it(
      'scripts never run: neither the fixed version’s nor the project’s (ruling F20)',
      async () => {
        const marker = path.join(tmp('qualor-fix-marker-'), 'ran').replaceAll('\\', '/');
        const write = (what: string) =>
          `node -e "require('fs').appendFileSync('${marker}', '${what}\\n')"`;
        const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
        const reg = await registry({ 'qf-a': qfA, 'qf-other': OTHER });
        const env = managerEnv(reg.url);
        const scripted = APP.replace(
          '"private": true,',
          `"private": true,\n    "scripts": ${JSON.stringify({ preinstall: write('pre'), postinstall: write('post') })},`,
        );
        const dir = await repository({ 'package.json': scripted }, [manager], env);
        qfA.push({ version: '1.2.6', scripts: { postinstall: write('dependency') } });

        const r = await fix(dir, env, claim(['1.2.5'], '1.2.6'));

        expect(versionsIn(lockfile, textOf(r, lockfile))).toEqual(['1.2.6']);
        expect(existsSync(marker)).toBe(false);
        const installs = r.calls.filter((c) => c.args[0] === 'install');
        expect(installs).toHaveLength(1);
        if (manager === 'yarn-berry') {
          expect(installs[0]?.args).toContain('--mode=update-lockfile');
          expect(installs[0]?.env['YARN_ENABLE_SCRIPTS']).toBe('false');
        } else {
          expect(installs[0]?.args).toContain('--ignore-scripts');
        }
      },
      SLOW,
    );
  });
}

// ─── npm ────────────────────────────────────────────────────────────────────

describe.runIf(AVAILABLE.npm)('the JS adapter with npm: layouts, workspaces and lines', () => {
  it(
    'keeps CRLF line endings and a byte order mark (Review Focus 1)',
    async () => {
      const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
      const reg = await registry({ 'qf-a': qfA, 'qf-other': OTHER });
      const env = managerEnv(reg.url);
      const windows = `\uFEFF${APP.replaceAll('\n', '\r\n')}`;
      const dir = await repository({ 'package.json': windows }, ['npm'], env);
      qfA.push({ version: '1.2.6' });
      const item = claim(['1.2.5'], '1.2.6');

      const r = await fix(dir, env, item);

      expect(textOf(r, 'package.json')).toBe(windows.replace('^1.2.5', '^1.2.6'));
      expect(versionsIn('package-lock.json', textOf(r, 'package-lock.json'))).toEqual(['1.2.6']);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );

  it(
    'workspaces: edits each workspace that declares the package, one root lockfile (§11.7)',
    async () => {
      const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
      const reg = await registry({ 'qf-a': qfA });
      const env = managerEnv(reg.url);
      const member = (name: string) =>
        json([
          '{',
          `  "name": "${name}",`,
          '  "version": "1.0.0",',
          '  "dependencies": {',
          '    "qf-a": "^1.2.5"',
          '  }',
          '}',
        ]);
      const files = {
        'package.json': json([
          '{',
          '  "name": "root",',
          '  "private": true,',
          '  "workspaces": ["packages/*"]',
          '}',
        ]),
        'packages/a/package.json': member('a'),
        'packages/b/package.json': member('b'),
        // Not a workspace: left alone.
        'tools/fixture/package.json': member('fixture'),
      };
      const dir = await repository(files, ['npm'], env);
      qfA.push({ version: '1.2.6' });
      const item = claim(['1.2.5'], '1.2.6');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect([...r.files.keys()].sort()).toEqual([
        'package-lock.json',
        'packages/a/package.json',
        'packages/b/package.json',
      ]);
      expect(textOf(r, 'packages/a/package.json')).toBe(member('a').replace('^1.2.5', '^1.2.6'));
      expect(textOf(r, 'packages/b/package.json')).toBe(member('b').replace('^1.2.5', '^1.2.6'));
      expect(up.lockfiles).toEqual([
        // npm names a workspace's lockfile entry by its folder.
        {
          path: 'package-lock.json',
          relation: 'direct',
          mechanism: null,
          dependents: ['packages/a', 'packages/b'],
        },
      ]);
      expect(versionsIn('package-lock.json', textOf(r, 'package-lock.json'))).toEqual(['1.2.6']);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );

  it(
    'two lines: one override per line, each line reaches its own target (B3, R23)',
    async () => {
      const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }, { version: '2.0.1' }];
      const reg = await registry({
        'qf-a': qfA,
        p1: [{ version: '1.0.0', dependencies: { 'qf-a': '^1.2.0' } }],
        p2: [{ version: '1.0.0', dependencies: { 'qf-a': '^2.0.0' } }],
      });
      const env = managerEnv(reg.url);
      const app = json([
        '{',
        '  "name": "app",',
        '  "private": true,',
        '  "dependencies": {',
        '    "p1": "^1.0.0",',
        '    "p2": "^1.0.0"',
        '  }',
        '}',
      ]);
      const dir = await repository({ 'package.json': app }, ['npm'], env);
      qfA.push({ version: '1.2.6' }, { version: '2.0.3' });
      const item = claim(['1.2.5', '2.0.1'], '1.2.6, 2.0.3');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect(up.targets).toEqual([
        { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' },
        { installed: '2.0.1', target: '2.0.3', lockfile: 'package-lock.json' },
      ]);
      expect(up).toMatchObject({ targetVersion: '2.0.3', installedVersion: '2.0.1' });
      expect(JSON.parse(textOf(r, 'package.json'))).toMatchObject({
        overrides: { 'qf-a@>=1.0.0 <2.0.0': '^1.2.6', 'qf-a@>=2.0.0 <3.0.0': '^2.0.3' },
      });
      expect(up.lockfiles).toEqual([
        {
          path: 'package-lock.json',
          relation: 'transitive',
          mechanism: 'overrides',
          dependents: ['p1', 'p2'],
        },
      ]);
      expect(versionsIn('package-lock.json', textOf(r, 'package-lock.json'))).toEqual([
        '1.2.6',
        '2.0.3',
      ]);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );

  it(
    'a yarn.lock beside the package.json without yarn on PATH: failure missing_tool naming yarn (B7)',
    async () => {
      const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
      const reg = await registry({ 'qf-a': qfA, 'qf-other': OTHER });
      const env = managerEnv(reg.url, pathWithoutYarn());
      // npm rewrites a yarn.lock it finds, so this one is added after npm made its lockfile.
      const dir = await repository({ 'package.json': APP }, ['npm'], env, {
        'yarn.lock': classicLock([
          ['qf-a@^1.2.5', '1.2.5'],
          ['qf-other@^1.0.0', '1.0.0'],
        ]),
      });
      qfA.push({ version: '1.2.6' });

      const r = await fix(dir, env, claim(['1.2.5'], '1.2.6'));

      expect(r.outcome).toMatchObject({ failure: { code: 'missing_tool' } });
      if ('failure' in r.outcome) expect(r.outcome.failure.message).toMatch(/\byarn\b/);
    },
    SLOW,
  );
});

// ─── npm and Yarn ───────────────────────────────────────────────────────────

describe.runIf(AVAILABLE.npm && YARN_MAJOR !== null)('the JS adapter with npm and Yarn', () => {
  it(
    'two lockfiles beside one package.json: both regenerated, both named (§11.7, B7, T9i)',
    async () => {
      const yarn: Manager = YARN_MAJOR === 1 ? 'yarn-classic' : 'yarn-berry';
      const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
      const reg = await registry({ 'qf-a': qfA, 'qf-other': OTHER });
      const env = managerEnv(reg.url);
      const dir = await repository({ 'package.json': APP }, ['npm', yarn], env);
      qfA.push({ version: '1.2.6' });
      const item = claim(['1.2.5'], '1.2.6');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect([...r.files.keys()].sort()).toEqual([
        'package-lock.json',
        'package.json',
        'yarn.lock',
      ]);
      expect(up.targets).toEqual([
        { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' },
        { installed: '1.2.5', target: '1.2.6', lockfile: 'yarn.lock' },
      ]);
      expect(up.lockfiles.map((l) => [l.path, l.relation])).toEqual([
        ['package-lock.json', 'direct'],
        ['yarn.lock', 'direct'],
      ]);
      expect(versionsIn('package-lock.json', textOf(r, 'package-lock.json'))).toEqual(['1.2.6']);
      expect(versionsIn('yarn.lock', textOf(r, 'yarn.lock'))).toEqual(['1.2.6']);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );
});

// ─── pnpm ───────────────────────────────────────────────────────────────────

describe.runIf(AVAILABLE.pnpm)('the JS adapter with pnpm', () => {
  it(
    'two lines: one pnpm.overrides key per line, each line reaches its own target (B3, R23, Ruling T13e)',
    async () => {
      const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }, { version: '2.0.1' }];
      const reg = await registry({
        'qf-a': qfA,
        p1: [{ version: '1.0.0', dependencies: { 'qf-a': '^1.2.0' } }],
        p2: [{ version: '1.0.0', dependencies: { 'qf-a': '^2.0.0' } }],
      });
      const env = managerEnv(reg.url);
      const app = json([
        '{',
        '  "name": "app",',
        '  "private": true,',
        '  "dependencies": {',
        '    "p1": "^1.0.0",',
        '    "p2": "^1.0.0"',
        '  }',
        '}',
      ]);
      const dir = await repository({ 'package.json': app }, ['pnpm'], env);
      qfA.push({ version: '1.2.6' }, { version: '2.0.3' });
      const item = claim(['1.2.5', '2.0.1'], '1.2.6, 2.0.3');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect(up.targets).toEqual([
        { installed: '1.2.5', target: '1.2.6', lockfile: 'pnpm-lock.yaml' },
        { installed: '2.0.1', target: '2.0.3', lockfile: 'pnpm-lock.yaml' },
      ]);
      expect(JSON.parse(textOf(r, 'package.json'))).toMatchObject({
        pnpm: { overrides: { 'qf-a@>=1.0.0 <2.0.0': '^1.2.6', 'qf-a@>=2.0.0 <3.0.0': '^2.0.3' } },
      });
      expect(up.lockfiles).toMatchObject([
        { path: 'pnpm-lock.yaml', relation: 'transitive', mechanism: 'pnpm.overrides' },
      ]);
      expect(versionsIn('pnpm-lock.yaml', textOf(r, 'pnpm-lock.yaml'))).toEqual(['1.2.6', '2.0.3']);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );

  it(
    'pins through pnpm-workspace.yaml overrides when that file has them (ruling F15)',
    async () => {
      const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
      const reg = await registry({
        'qf-a': qfA,
        'qf-parent': [{ version: '1.0.0', dependencies: { 'qf-a': '^1.2.0' } }],
      });
      const env = managerEnv(reg.url);
      const workspace = 'overrides:\n  qf-unused: 1.0.0\n';
      const dir = await repository(
        { 'package.json': PARENT_APP, 'pnpm-workspace.yaml': workspace },
        ['pnpm'],
        env,
      );
      qfA.push({ version: '1.2.6' });
      const item = claim(['1.2.5'], '1.2.6');

      const r = await fix(dir, env, item);

      const up = uploaded(r);
      expect([...r.files.keys()].sort()).toEqual(['pnpm-lock.yaml', 'pnpm-workspace.yaml']);
      expect(textOf(r, 'pnpm-workspace.yaml')).toBe(`${workspace}  qf-a: ^1.2.6\n`);
      expect(up.lockfiles).toEqual([
        {
          path: 'pnpm-lock.yaml',
          relation: 'transitive',
          mechanism: 'overrides',
          dependents: ['qf-parent'],
        },
      ]);
      expect(versionsIn('pnpm-lock.yaml', textOf(r, 'pnpm-lock.yaml'))).toEqual(['1.2.6']);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );
});

// ─── Yarn ───────────────────────────────────────────────────────────────────

/** A stand-in integrity hash of a package version. */
const fakeHash = (name: string, version: string) =>
  Buffer.from([name, version].join('@')).toString('base64');

/** A Yarn classic lockfile of `[pattern, version]` blocks from the public registry. */
function classicLock(blocks: [string, string, Record<string, string>?][]): string {
  const out = [
    '# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.',
    '# yarn lockfile v1',
    '',
  ];
  for (const [pattern, version, dependencies] of blocks) {
    const name = pattern.slice(0, pattern.indexOf('@', 1));
    out.push(
      '',
      `${pattern}:`,
      `  version "${version}"`,
      `  resolved "https://registry.yarnpkg.com/${name}/-/${name}-${version}.tgz#0123456789abcdef0123456789abcdef01234567"`,
      `  integrity sha512-${fakeHash(name, version)}`,
    );
    if (dependencies !== undefined) {
      out.push('  dependencies:');
      for (const [dep, range] of Object.entries(dependencies)) out.push(`    ${dep} "${range}"`);
    }
  }
  return `${out.join('\n')}\n`;
}

/** An npm v3 lockfile of `node_modules/…` folders from the public registry. */
function npmLock(
  folders: Record<string, { version: string; dependencies?: Record<string, string> }>,
): string {
  const packages: Record<string, unknown> = { '': { name: 'app' } };
  for (const [folder, { version, dependencies }] of Object.entries(folders)) {
    const name = folder.slice(folder.lastIndexOf('node_modules/') + 'node_modules/'.length);
    packages[folder] = {
      version,
      resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
      integrity: `sha512-${fakeHash(name, version)}`,
      ...(dependencies !== undefined && { dependencies }),
    };
  }
  return `${JSON.stringify({ name: 'app', lockfileVersion: 3, requires: true, packages }, null, 2)}\n`;
}

const BERRY_LOCK = `# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    qf-a: "npm:^1.2.5"
  languageName: unknown
  linkType: soft

"qf-a@npm:^1.2.5":
  version: 1.2.5
  resolution: "qf-a@npm:1.2.5"
  checksum: 10c0/0123456789abcdef
  languageName: node
  linkType: hard
`;

/** A committed repository of exactly `files` (no lockfile made by a tool). */
function committed(files: Record<string, string>): string {
  const dir = tmp('qualor-fix-js-');
  initRepo(dir);
  writeTree(dir, files);
  commitAll(dir, 'base');
  return dir;
}

describe('the JS adapter: what it refuses before any package manager runs', () => {
  it('Yarn classic with two lines: no fix, several_lines naming 1.x and 2.x (B3, R23)', async () => {
    const app = json([
      '{',
      '  "name": "app",',
      '  "dependencies": { "p1": "^1.0.0", "p2": "^1.0.0" }',
      '}',
    ]);
    const yarnLock = classicLock([
      ['p1@^1.0.0', '1.0.0', { 'qf-a': '^1.2.0' }],
      ['p2@^1.0.0', '1.0.0', { 'qf-a': '^2.0.0' }],
      ['qf-a@^1.2.0', '1.2.5'],
      ['qf-a@^2.0.0', '2.0.1'],
    ]);
    const dir = committed({ 'package.json': app, 'yarn.lock': yarnLock });
    const env = managerEnv('http://127.0.0.1:9', pathWithoutYarn());

    const r = await fix(dir, env, claim(['1.2.5', '2.0.1'], '1.2.6, 2.0.3'));

    expect(r.outcome).toMatchObject({ noFix: { reason: 'several_lines' } });
    if ('noFix' in r.outcome) expect(r.outcome.noFix.message).toContain('1.x and 2.x');
    expect(r.calls).toEqual([]);
  });

  it('a Yarn zero-install repository (.yarn/cache tracked): failure manifest_unsupported (R22)', async () => {
    const app = json(['{', '  "name": "app",', '  "dependencies": { "qf-a": "^1.2.5" }', '}']);
    const dir = committed({
      'package.json': app,
      'yarn.lock': BERRY_LOCK,
      '.yarn/cache/qf-a-npm-1.2.5-0123456789-10c0.zip': 'PK',
    });
    const env = managerEnv('http://127.0.0.1:9', pathWithoutYarn());

    const r = await fix(dir, env, claim(['1.2.5'], '1.2.6'));

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('.yarn/cache');
    expect(r.calls).toEqual([]);
  });

  it('Yarn Berry with a git dependency in yarn.lock: failure manifest_unsupported naming it (Ruling T13c)', async () => {
    const app = json([
      '{',
      '  "name": "app",',
      '  "dependencies": {',
      '    "gitdep": "https://github.com/acme/gitdep.git",',
      '    "qf-a": "^1.2.5"',
      '  }',
      '}',
    ]);
    const withGit = BERRY_LOCK.replace(
      '    qf-a: "npm:^1.2.5"\n',
      '    gitdep: "https://github.com/acme/gitdep.git"\n    qf-a: "npm:^1.2.5"\n',
    ).concat(`
"gitdep@https://github.com/acme/gitdep.git":
  version: 1.0.0
  resolution: "gitdep@https://github.com/acme/gitdep.git#commit=0123456789abcdef0123456789abcdef01234567"
  checksum: 10c0/fedcba9876543210
  languageName: node
  linkType: hard
`);
    const dir = committed({ 'package.json': app, 'yarn.lock': withGit });
    const env = managerEnv('http://127.0.0.1:9', pathWithoutYarn());

    const r = await fix(dir, env, claim(['1.2.5'], '1.2.6'));

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('gitdep');
    expect(r.calls).toEqual([]);
  });

  /** A Yarn Berry fake: the flavour check answers 4.18.1, the install fails. */
  const fakeBerry: ToolRunner = (_tool, args) =>
    Promise.resolve(
      args[0] === '--version'
        ? { exitCode: 0, timedOut: false, truncated: false, stdout: '4.18.1\n', stderr: '' }
        : {
            exitCode: 1,
            timedOut: false,
            truncated: false,
            stdout: 'install stopped by the test',
            stderr: '',
          },
    );

  /** BERRY_LOCK with one more entry, `extra@<descriptor>` resolving to `resolution`. */
  const berryWith = (descriptor: string, resolution: string) =>
    BERRY_LOCK.concat(`
"extra@${descriptor}":
  version: 1.0.0
  resolution: "${resolution}"
  checksum: 10c0/fedcba9876543210
  languageName: node
  linkType: hard
`);

  it.each([
    ['exec:', 'exec:./gen.js', 'extra@exec:./gen.js::locator=app%40workspace%3A.'],
    [
      'git+ssh:',
      'git+ssh://git@github.com/acme/extra.git',
      'extra@git+ssh://git@github.com/acme/extra.git#commit=0123456789abcdef0123456789abcdef01234567',
    ],
    [
      'ssh:',
      'ssh://git@github.com/acme/extra.git',
      'extra@ssh://git@github.com/acme/extra.git#commit=0123456789abcdef0123456789abcdef01234567',
    ],
    [
      'an https tarball',
      'https://cdn.example/extra-1.0.0.tgz',
      'extra@https://cdn.example/extra-1.0.0.tgz',
    ],
    ['file:', 'file:./extra.tgz', 'extra@file:./extra.tgz::locator=app%40workspace%3A.'],
    ['portal:', 'portal:./extra', 'extra@portal:./extra::locator=app%40workspace%3A.'],
    [
      'a patch of a tarball',
      'patch:extra@https%3A//cdn.example/extra.tgz#./extra.patch',
      'extra@patch:extra@https%3A//cdn.example/extra.tgz#./extra.patch::version=1.0.0&hash=1',
    ],
  ])(
    'Yarn Berry with an entry from %s: failure manifest_unsupported naming it, nothing run (Ruling T13f)',
    async (_what, descriptor, resolution) => {
      const app = json(['{', '  "name": "app",', '  "dependencies": { "qf-a": "^1.2.5" }', '}']);
      const dir = committed({
        'package.json': app,
        'yarn.lock': berryWith(descriptor, resolution),
      });

      const r = await fix(
        dir,
        managerEnv('http://127.0.0.1:9', pathWithoutYarn()),
        claim(['1.2.5'], '1.2.6'),
      );

      expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
      if ('failure' in r.outcome)
        expect(r.outcome.failure.message).toContain(`extra@${descriptor}`);
      expect(r.calls).toEqual([]);
    },
  );

  it('Yarn Berry with npm:, workspace: and patch: entries of those only: not refused by the source gate (Ruling T13f)', async () => {
    const app = json(['{', '  "name": "app",', '  "dependencies": { "qf-a": "^1.2.5" }', '}']);
    const lock = BERRY_LOCK.concat(`
"lib@workspace:packages/lib":
  version: 0.0.0-use.local
  resolution: "lib@workspace:packages/lib"
  languageName: unknown
  linkType: soft

"other@patch:other@npm%3A1.0.0#~/.yarn/patches/other-npm-1.0.0-abc.patch":
  version: 1.0.0
  resolution: "other@patch:other@npm%3A1.0.0#~/.yarn/patches/other-npm-1.0.0-abc.patch::version=1.0.0&hash=abc"
  checksum: 10c0/fedcba9876543210
  languageName: node
  linkType: hard

"fsevents@patch:fsevents@npm%3A2.3.3#optional!builtin<compat/fsevents>":
  version: 2.3.3
  resolution: "fsevents@patch:fsevents@npm%3A2.3.3#optional!builtin<compat/fsevents>::version=2.3.3&hash=df0bf1"
  checksum: 10c0/0123456789abcdef
  languageName: node
  linkType: hard

"lib@patch:lib@workspace%3Apackages/lib#./lib.patch":
  version: 0.0.0-use.local
  resolution: "lib@patch:lib@workspace%3Apackages/lib#./lib.patch::version=0.0.0-use.local&hash=1"
  languageName: unknown
  linkType: soft
`);
    const dir = committed({ 'package.json': app, 'yarn.lock': lock });

    const r = await fix(
      dir,
      managerEnv('http://127.0.0.1:9'),
      claim(['1.2.5'], '1.2.6'),
      fakeBerry,
    );

    // Past the gate: the flavour check and the install ran (the fake install fails).
    expect(r.calls.map((c) => [c.tool, ...c.args])).toEqual([
      ['yarn', '--version'],
      ['yarn', 'install', '--mode=update-lockfile'],
    ]);
    expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
  });

  it('Yarn Berry with an exec: spec in a workspace manifest: failure manifest_unsupported naming it, nothing run (Ruling T13g)', async () => {
    const root = json([
      '{',
      '  "name": "app",',
      '  "private": true,',
      '  "workspaces": ["packages/*"],',
      '  "dependencies": { "qf-a": "^1.2.5" }',
      '}',
    ]);
    const member = json([
      '{',
      '  "name": "gen",',
      '  "dependencies": { "generated": "exec:./gen.js" }',
      '}',
    ]);
    const dir = committed({
      'package.json': root,
      'packages/gen/package.json': member,
      'yarn.lock': BERRY_LOCK,
    });

    const r = await fix(
      dir,
      managerEnv('http://127.0.0.1:9'),
      claim(['1.2.5'], '1.2.6'),
      fakeBerry,
    );

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) {
      expect(r.outcome.failure.message).toContain('packages/gen/package.json');
      expect(r.outcome.failure.message).toContain('exec:./gen.js');
    }
    expect(r.calls).toEqual([]);
  });

  it('Yarn Berry with a github: spec in resolutions: failure manifest_unsupported naming it, nothing run (Ruling T13g)', async () => {
    const app = json([
      '{',
      '  "name": "app",',
      '  "dependencies": { "qf-a": "^1.2.5" },',
      '  "resolutions": { "evil": "github:attacker/evil" }',
      '}',
    ]);
    const dir = committed({ 'package.json': app, 'yarn.lock': BERRY_LOCK });

    const r = await fix(
      dir,
      managerEnv('http://127.0.0.1:9'),
      claim(['1.2.5'], '1.2.6'),
      fakeBerry,
    );

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) {
      expect(r.outcome.failure.message).toContain('resolutions');
      expect(r.outcome.failure.message).toContain('github:attacker/evil');
    }
    expect(r.calls).toEqual([]);
  });

  describe('Yarn Berry nested workspaces (Ruling T13j)', () => {
    const root = json([
      '{',
      '  "name": "app",',
      '  "private": true,',
      '  "workspaces": ["packages/*"],',
      '  "dependencies": { "qf-a": "^1.2.5" }',
      '}',
    ]);
    const member = (extra: string) =>
      json(['{', '  "name": "group",', `  "private": true${extra},`, '  "version": "1.0.0"', '}']);

    it('a workspace with its own workspaces field: failure manifest_unsupported naming it, nothing run', async () => {
      const dir = committed({
        'package.json': root,
        'packages/group/package.json': member(',\n  "workspaces": ["sub/*"]'),
        // Not a workspace of the root: only the nested group would bring it in.
        'packages/group/sub/x/package.json': json([
          '{',
          '  "name": "x",',
          '  "dependencies": { "evil": "exec:./gen.js" }',
          '}',
        ]),
        'yarn.lock': BERRY_LOCK,
      });

      const r = await fix(
        dir,
        managerEnv('http://127.0.0.1:9'),
        claim(['1.2.5'], '1.2.6'),
        fakeBerry,
      );

      expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
      if ('failure' in r.outcome) {
        expect(r.outcome.failure.message).toContain('packages/group/package.json');
        expect(r.outcome.failure.message).toContain('workspaces');
      }
      expect(r.calls).toEqual([]);
    });

    it('a workspace without one: not refused by this check', async () => {
      const dir = committed({
        'package.json': root,
        'packages/group/package.json': member(''),
        'yarn.lock': BERRY_LOCK,
      });

      const r = await fix(
        dir,
        managerEnv('http://127.0.0.1:9'),
        claim(['1.2.5'], '1.2.6'),
        fakeBerry,
      );

      // Past the gates: the flavour check and the install ran (the fake install fails).
      expect(r.calls.map((c) => [c.tool, ...c.args])).toEqual([
        ['yarn', '--version'],
        ['yarn', 'install', '--mode=update-lockfile'],
      ]);
      expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
    });
  });

  it('Yarn Berry with ranges, tags, npm: aliases, workspace:* and a patch: of npm: only: not refused by the spec gate (Ruling T13g)', async () => {
    const app = json([
      '{',
      '  "name": "app",',
      '  "private": true,',
      '  "workspaces": ["packages/*"],',
      '  "dependencies": {',
      '    "qf-a": "^1.2.5",',
      '    "any": "*",',
      '    "tagged": "latest",',
      '    "aliased": "npm:other@^1.0.0",',
      '    "scoped": "npm:@scope/other@1.0.0",',
      '    "lib": "workspace:*",',
      '    "patched": "patch:other@npm%3A1.0.0#~/.yarn/patches/other-npm-1.0.0-abc.patch"',
      '  },',
      '  "devDependencies": { "ranged": ">=1 <3" },',
      '  "peerDependencies": { "peer": "^2 || ^3" },',
      '  "optionalDependencies": { "maybe": "~1.0.0" },',
      '  "resolutions": { "qf-b": "1.0.0", "qf-c": "npm:^2.0.0" }',
      '}',
    ]);
    const lib = json(['{', '  "name": "lib",', '  "dependencies": { "ranged": "^1.0.0" }', '}']);
    const dir = committed({
      'package.json': app,
      'packages/lib/package.json': lib,
      'yarn.lock': BERRY_LOCK,
    });

    const r = await fix(
      dir,
      managerEnv('http://127.0.0.1:9'),
      claim(['1.2.5'], '1.2.6'),
      fakeBerry,
    );

    // Past the gate: the flavour check and the install ran (the fake install fails).
    expect(r.calls.map((c) => [c.tool, ...c.args])).toEqual([
      ['yarn', '--version'],
      ['yarn', 'install', '--mode=update-lockfile'],
    ]);
    expect(r.outcome).toMatchObject({ failure: { code: 'package_manager' } });
  });

  it('a workspace manifest that is not a JSON object: failure manifest_unsupported (Ruling T13e)', async () => {
    const root = json([
      '{',
      '  "name": "root",',
      '  "private": true,',
      '  "workspaces": ["packages/*"],',
      '  "dependencies": { "qf-a": "^1.2.5" }',
      '}',
    ]);
    const dir = committed({
      'package.json': root,
      'packages/b/package.json': '[]\n',
      'package-lock.json': npmLock({ 'node_modules/qf-a': { version: '1.2.5' } }),
    });
    const failing: ToolRunner = () =>
      Promise.resolve({
        exitCode: 1,
        timedOut: false,
        truncated: false,
        stdout: '',
        stderr: 'npm error',
      });

    const r = await fix(dir, managerEnv('http://127.0.0.1:9'), claim(['1.2.5'], '1.2.6'), failing);

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) {
      expect(r.outcome.failure.message).toContain('packages/b/package.json');
    }
    expect(r.calls).toEqual([]);
  });

  it('a range Qualor cannot rewrite: failure manifest_unsupported naming it (R22)', async () => {
    const app = json(['{', '  "name": "app",', '  "dependencies": { "qf-a": "1.x" }', '}']);
    const dir = committed({
      'package.json': app,
      'yarn.lock': classicLock([['qf-a@1.x', '1.2.5']]),
    });
    const env = managerEnv('http://127.0.0.1:9', pathWithoutYarn());

    const r = await fix(dir, env, claim(['1.2.5'], '1.2.6'));

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('1.x');
    expect(r.calls).toEqual([]);
  });

  it('a pin of the package under another key: failure manifest_unsupported, left to a person', async () => {
    const app = json([
      '{',
      '  "name": "app",',
      '  "dependencies": { "qf-parent": "^1.0.0" },',
      '  "overrides": { "qf-a@^1.0.0": "1.2.5" }',
      '}',
    ]);
    const lock = npmLock({
      'node_modules/qf-parent': { version: '1.0.0', dependencies: { 'qf-a': '^1.2.0' } },
      'node_modules/qf-a': { version: '1.2.5' },
    });
    const dir = committed({ 'package.json': app, 'package-lock.json': lock });
    const env = managerEnv('http://127.0.0.1:9');

    const r = await fix(dir, env, claim(['1.2.5'], '1.2.6'));

    expect(r.outcome).toMatchObject({ failure: { code: 'manifest_unsupported' } });
    if ('failure' in r.outcome) expect(r.outcome.failure.message).toContain('"qf-a@^1.0.0"');
    expect(r.calls).toEqual([]);
  });

  it('a yarn of the other flavour: failure missing_tool, before any edit or install', async () => {
    const app = json(['{', '  "name": "app",', '  "dependencies": { "qf-a": "^1.2.5" }', '}']);
    const dir = committed({
      'package.json': app,
      'yarn.lock': classicLock([['qf-a@^1.2.5', '1.2.5']]),
    });
    const berry: ToolRunner = () =>
      Promise.resolve({
        exitCode: 0,
        timedOut: false,
        truncated: false,
        stdout: '4.18.1\n',
        stderr: '',
      });

    const r = await fix(dir, managerEnv('http://127.0.0.1:9'), claim(['1.2.5'], '1.2.6'), berry);

    expect(r.outcome).toMatchObject({ failure: { code: 'missing_tool' } });
    if ('failure' in r.outcome) {
      expect(r.outcome.failure.message).toBe(
        'yarn.lock needs Yarn classic (1.x), but the yarn on PATH is 4.18.1.',
      );
    }
    expect(r.calls.map((c) => [c.tool, ...c.args])).toEqual([['yarn', '--version']]);
  });
});

describe('the JS adapter: reading lockfiles and verifying them (B3)', () => {
  const plan = (targets: FixTarget[]): FixPlan => ({
    targets,
    greatest: '2.0.3',
    installed: '2.0.1',
    unfixable: [],
    majorJump: false,
  });
  const TWO_LINES = [
    { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' },
    { installed: '2.0.1', target: '2.0.3', lockfile: 'package-lock.json' },
  ];

  function workspace(files: Record<string, string>, log = silentLogger): FixWorkspace {
    const root = tmp('qualor-fix-ws-');
    writeTree(root, files);
    const run: ToolRunner = () => Promise.reject(new Error('no tool runs here'));
    return { root, files: Object.keys(files), run, deadline: Date.now() + SLOW, log };
  }

  const lockOf = (qfA: Record<string, string>) =>
    npmLock(
      Object.fromEntries(Object.entries(qfA).map(([folder, version]) => [folder, { version }])),
    );

  it('passes when each line reached its own target', async () => {
    const ws = workspace({
      'package-lock.json': lockOf({
        'node_modules/qf-a': '1.2.6',
        'node_modules/p2/node_modules/qf-a': '2.0.3',
      }),
    });
    await expect(
      jsAdapter.verify?.(ws, claim(['1.2.5', '2.0.1'], '1.2.6, 2.0.3'), plan(TWO_LINES)),
    ).resolves.toBeNull();
  });

  it('is several_lines when an instance was pushed across a major, naming the lines', async () => {
    const ws = workspace({
      'package-lock.json': lockOf({
        'node_modules/qf-a': '2.0.3',
        'node_modules/p2/node_modules/qf-a': '2.0.3',
      }),
    });
    const stop = await jsAdapter.verify?.(
      ws,
      claim(['1.2.5', '2.0.1'], '1.2.6, 2.0.3'),
      plan(TWO_LINES),
    );
    expect(stop).toMatchObject({ kind: 'no_fix', reason: 'several_lines' });
    expect(stop?.message).toContain('1.x and 2.x');
    expect(stop?.message).toContain('no longer resolves 1.x');
  });

  it('is several_lines when an instance is still below its target', async () => {
    const ws = workspace({
      'package-lock.json': lockOf({
        'node_modules/qf-a': '1.2.5',
        'node_modules/p2/node_modules/qf-a': '2.0.3',
      }),
    });
    const stop = await jsAdapter.verify?.(
      ws,
      claim(['1.2.5', '2.0.1'], '1.2.6, 2.0.3'),
      plan(TWO_LINES),
    );
    expect(stop).toMatchObject({ kind: 'no_fix', reason: 'several_lines' });
    expect(stop?.message).toContain('package-lock.json still resolves 1.2.5, below 1.2.6');
  });

  it('reads every JS lockfile, skipping one the readers refuse with a warning', async () => {
    const warnings: string[] = [];
    const log = { ...silentLogger, warn: (m: string) => warnings.push(m) };
    const ws = workspace(
      {
        'package-lock.json': lockOf({ 'node_modules/qf-a': '1.2.5' }),
        'web/yarn.lock': classicLock([
          ['qf-a@^1.2.0', '1.2.4'],
          ['qf-a@^1.2.5', '1.2.5'],
        ]),
        'test/fixtures/broken/package-lock.json': '{ not json',
        'node_modules/x/package-lock.json': lockOf({ 'node_modules/qf-a': '0.0.1' }),
      },
      log,
    );
    await expect(jsAdapter.installed(ws, 'qf-a')).resolves.toEqual([
      { lockfile: 'package-lock.json', versions: ['1.2.5'] },
      { lockfile: 'web/yarn.lock', versions: ['1.2.4', '1.2.5'] },
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('test/fixtures/broken/package-lock.json');
  });
});

interface GitCall {
  args: string[];
  allow: string | null;
  nosystem: string | null;
}

/** The fake git: records its arguments and the two variables that stop a real git, then fails. */
const FAKE_GIT = [
  "const fs = require('node:fs');",
  "const path = require('node:path');",
  'const call = {',
  '  args: process.argv.slice(2),',
  '  allow: process.env.GIT_ALLOW_PROTOCOL ?? null,',
  '  nosystem: process.env.GIT_CONFIG_NOSYSTEM ?? null,',
  '};',
  "fs.appendFileSync(path.join(__dirname, 'calls.jsonl'), JSON.stringify(call) + String.fromCharCode(10));",
  "process.stderr.write('fatal: git is blocked by the test' + String.fromCharCode(10));",
  'process.exit(128);',
  '',
].join('\n');

/**
 * A `git` first on `PATH` (a `.cmd` for Windows, a shell script elsewhere) that records each call
 * and fails (ruling T13g), so no test reaches a real repository host.
 */
function fakeGit(): { dir: string; calls: () => GitCall[] } {
  const dir = tmp('qualor-fix-fake-git-');
  writeTree(dir, {
    'fake-git.cjs': FAKE_GIT,
    'git.cmd': ['@echo off', 'node "%~dp0fake-git.cjs" %*', 'exit /b %errorlevel%', ''].join(
      '\r\n',
    ),
    git: ['#!/bin/sh', 'exec node "$(dirname "$0")/fake-git.cjs" "$@"', ''].join('\n'),
  });
  chmodSync(path.join(dir, 'git'), 0o755);
  const log = path.join(dir, 'calls.jsonl');
  const calls = () =>
    existsSync(log)
      ? readFileSync(log, 'utf8')
          .split('\n')
          .filter((l) => l !== '')
          .map((l) => JSON.parse(l) as GitCall)
      : [];
  return { dir, calls };
}

describe.runIf(AVAILABLE['yarn-berry'])(
  'the JS adapter with Yarn Berry: git during the run',
  () => {
    it(
      'a git dependency the target version brings cannot be cloned: git runs with no protocol allowed (Ruling T13g)',
      async () => {
        const git = fakeGit();
        const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }];
        const reg = await registry({ 'qf-a': qfA, 'qf-other': OTHER });
        const env = managerEnv(reg.url, [git.dir, processPath()].join(path.delimiter));
        // Yarn 4.10+ blocks git repositories outside `approvedGitRepositories` by itself; approve
        // every one, as a project may (and older Yarn has no such list), so the run reaches git.
        const yarnrc = path.join(env['HOME'] ?? '', '.yarnrc.yml');
        writeFileSync(
          yarnrc,
          `${readFileSync(yarnrc, 'utf8')}approvedGitRepositories:\n  - '**'\n`,
        );
        const dir = await repository({ 'package.json': APP }, ['yarn-berry'], env);
        qfA.push({ version: '1.2.6', dependencies: { evil: 'github:attacker/evil' } });

        const r = await fix(dir, env, claim(['1.2.5'], '1.2.6'));

        const install = r.calls.find((c) => c.args[0] === 'install');
        expect(install?.env).toMatchObject({
          GIT_ALLOW_PROTOCOL: 'qualor-none',
          GIT_CONFIG_NOSYSTEM: '1',
        });
        // Berry asked git for the new dependency's refs; each call had no protocol it could use,
        // so a real git could clone nothing.
        const calls = git.calls();
        expect(calls.some((c) => c.args.includes('ls-remote'))).toBe(true);
        for (const call of calls) {
          expect(call).toMatchObject({ allow: 'qualor-none', nosystem: '1' });
        }
        expect(r.outcome).toHaveProperty('failure');
        expect(r.files.size).toBe(0);
      },
      SLOW,
    );
  },
);

describe.runIf(AVAILABLE['yarn-berry'])('the JS adapter with Yarn Berry: two lines', () => {
  it(
    'scopes each resolution to the descriptors of its line, so each line reaches its target (B3)',
    async () => {
      const qfA: FakeNpmVersion[] = [{ version: '1.2.5' }, { version: '2.0.1' }];
      const reg = await registry({
        'qf-a': qfA,
        p1: [{ version: '1.0.0', dependencies: { 'qf-a': '^1.2.0' } }],
        p2: [{ version: '1.0.0', dependencies: { 'qf-a': '^2.0.0' } }],
      });
      const env = managerEnv(reg.url);
      const app = json([
        '{',
        '  "name": "app",',
        '  "private": true,',
        '  "dependencies": {',
        '    "p1": "^1.0.0",',
        '    "p2": "^1.0.0"',
        '  }',
        '}',
      ]);
      const dir = await repository({ 'package.json': app }, ['yarn-berry'], env);
      qfA.push({ version: '1.2.6' }, { version: '2.0.3' });
      const item = claim(['1.2.5', '2.0.1'], '1.2.6, 2.0.3');

      const r = await fix(dir, env, item);

      expect(JSON.parse(textOf(r, 'package.json'))).toMatchObject({
        resolutions: { 'qf-a@npm:^1.2.0': '^1.2.6', 'qf-a@npm:^2.0.0': '^2.0.3' },
      });
      expect(versionsIn('yarn.lock', textOf(r, 'yarn.lock'))).toEqual(['1.2.6', '2.0.3']);
      expect(contentCheck(r, item)).toEqual({ ok: true });
    },
    SLOW,
  );
});

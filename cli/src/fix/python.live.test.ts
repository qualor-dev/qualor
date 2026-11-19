import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  checkFixUpload,
  compareVersions,
  readPoetryLock,
  readUvLock,
  type FixClaimItem,
  type FixFileChange,
} from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { toolInstalled } from '../../test/fix/tools';
import { commitAll, gitSync, GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createGit } from '../git/git';
import { silentLogger } from '../log';
import { pythonAdapter } from './python';
import { prepareFix, type FixOutcome } from './run';
import { createToolRunner } from './runner';
import { openScratch } from './workspace';

/**
 * 0.16 fix MRs (R26, R27): the Python adapter with the real uv and Poetry against pypi.org, run
 * only by `pnpm fix:live` (the unit project excludes `*.live.test.ts`). A project depending on
 * `requests==2.19.1` (CVE-2018-18074, fixed in 2.20.0) is fixed to 2.20.0: the requirement is
 * raised in `pyproject.toml` and the lockfile resolves 2.20.0, with uv and with Poetry.
 */

const tmp = useTempDirs();
const LIVE_MS = 300_000;

/** The tools against the public index, with their own home and caches. */
function liveEnv(): Record<string, string> {
  const home = tmp('qualor-fix-live-home-');
  const inherited = Object.entries(GIT_TEST_ENV).filter(
    (entry): entry is [string, string] =>
      entry[1] !== undefined && !/^(UV|POETRY|PIP)_/i.test(entry[0]),
  );
  return {
    ...Object.fromEntries(inherited),
    CI: 'true',
    HOME: home,
    USERPROFILE: home,
    UV_CACHE_DIR: path.join(home, 'uv-cache'),
    POETRY_CACHE_DIR: path.join(home, 'poetry-cache'),
    POETRY_CONFIG_DIR: path.join(home, 'poetry-config'),
  };
}

const REQUESTS: FixClaimItem = {
  id: '0193a4c6-1c2e-7a3b-9f00-000000000005',
  generation: 1,
  leaseToken: 'lease-1',
  family: 'python',
  packageName: 'requests',
  installedVersions: ['2.19.1'],
  vulnerabilities: [
    {
      id: 'CVE-2018-18074',
      severity: 'high',
      title: 'Requests sends an HTTP Authorization header to an http URI upon redirect',
      url: null,
      installedVersions: ['2.19.1'],
      fixedVersions: ['2.20.0'],
    },
  ],
  mainBranch: 'main',
  declinedTarget: null,
};

const UV_PYPROJECT = [
  '[project]',
  'name = "live"',
  'version = "0.1.0"',
  'requires-python = ">=3.8"',
  'dependencies = [',
  '    "requests==2.19.1",',
  ']',
  '',
].join('\n');

const POETRY_PYPROJECT = [
  '[tool.poetry]',
  'name = "live"',
  'version = "0.1.0"',
  'description = ""',
  'authors = []',
  '',
  '[tool.poetry.dependencies]',
  'python = "^3.8"',
  'requests = "==2.19.1"',
  '',
  '[build-system]',
  'requires = ["poetry-core>=1.0.0"]',
  'build-backend = "poetry.core.masonry.api"',
  '',
].join('\n');

/** Locks the project with the tool, commits it, and fixes `requests` in a scratch copy. */
async function fixed(
  tool: 'uv' | 'poetry',
  lockfile: string,
  pyproject: string,
): Promise<{ outcome: FixOutcome; files: FixFileChange[] }> {
  const env = liveEnv();
  const dir = tmp('qualor-fix-live-');
  initRepo(dir);
  writeTree(dir, { 'pyproject.toml': pyproject });
  const run = createToolRunner({ env, root: dir, log: silentLogger });
  const locked = await run(tool, tool === 'uv' ? ['lock'] : ['lock', '--no-interaction'], {
    cwd: dir,
    timeoutMs: LIVE_MS,
  });
  expect(locked.exitCode, locked.stderr).toBe(0);
  commitAll(dir, 'base');

  const git = createGit(dir, GIT_TEST_ENV);
  const scratch = await openScratch(git, tmp('qualor-fix-live-temp-'));
  try {
    const outcome = await prepareFix(
      REQUESTS,
      pythonAdapter,
      {
        root: scratch.root,
        files: gitSync(dir, 'ls-files').split('\n'),
        env,
        run: createToolRunner({ env, root: dir, log: silentLogger }),
        deadline: Date.now() + LIVE_MS,
        log: silentLogger,
      },
      git,
    );
    if (!('files' in outcome)) throw new Error(JSON.stringify(outcome));
    const files: FixFileChange[] = outcome.files.map((f) => ({
      path: f.path,
      base: readFileSync(path.join(dir, f.path), 'utf8'),
      next: Buffer.from(f.content, 'base64').toString('utf8'),
    }));
    expect(outcome.files.map((f) => f.path)).toEqual(['pyproject.toml', lockfile]);
    return { outcome, files };
  } finally {
    await scratch.close();
  }
}

const requestsVersions = (
  read: (text: string) => { name: string; version: string }[],
  text = '',
) => [
  ...new Set(
    read(text)
      .filter((e) => e.name === 'requests')
      .map((e) => e.version),
  ),
];

describe.runIf(toolInstalled('uv'))('the Python adapter with uv against pypi.org (live)', () => {
  it(
    'fixes requests 2.19.1 to 2.20.0',
    async () => {
      const { outcome, files } = await fixed('uv', 'uv.lock', UV_PYPROJECT);
      const pyproject = files.find((f) => f.path === 'pyproject.toml');
      const lock = files.find((f) => f.path === 'uv.lock');
      expect(pyproject?.next).toBe(UV_PYPROJECT.replace('requests==2.19.1', 'requests==2.20.0'));
      const versions = requestsVersions(readUvLock, lock?.next);
      expect(versions).toHaveLength(1);
      expect(compareVersions('pep440', versions[0] ?? '', '2.20.0')).toBe(0);
      if (!('files' in outcome)) throw new Error('no files');
      expect(outcome.targets).toEqual([
        { installed: '2.19.1', target: '2.20.0', lockfile: 'uv.lock' },
      ]);
      expect(outcome.lockfiles).toEqual([
        { path: 'uv.lock', relation: 'direct', mechanism: null, dependents: ['live'] },
      ]);
      expect(
        checkFixUpload({
          family: 'python',
          packageName: 'requests',
          targets: outcome.targets,
          files,
        }),
      ).toEqual({
        ok: true,
      });
    },
    LIVE_MS,
  );
});

describe.runIf(toolInstalled('poetry'))(
  'the Python adapter with Poetry against pypi.org (live)',
  () => {
    it(
      'fixes requests 2.19.1 to 2.20.0',
      async () => {
        const { outcome, files } = await fixed('poetry', 'poetry.lock', POETRY_PYPROJECT);
        const pyproject = files.find((f) => f.path === 'pyproject.toml');
        const lock = files.find((f) => f.path === 'poetry.lock');
        expect(pyproject?.next).toBe(
          POETRY_PYPROJECT.replace('requests = "==2.19.1"', 'requests = "==2.20.0"'),
        );
        const versions = requestsVersions(readPoetryLock, lock?.next);
        expect(versions).toHaveLength(1);
        expect(compareVersions('pep440', versions[0] ?? '', '2.20.0')).toBe(0);
        if (!('files' in outcome)) throw new Error('no files');
        expect(outcome.targets).toEqual([
          { installed: '2.19.1', target: '2.20.0', lockfile: 'poetry.lock' },
        ]);
        expect(outcome.lockfiles).toEqual([
          { path: 'poetry.lock', relation: 'direct', mechanism: null, dependents: [] },
        ]);
        expect(
          checkFixUpload({
            family: 'python',
            packageName: 'requests',
            targets: outcome.targets,
            files,
          }),
        ).toEqual({ ok: true });
      },
      LIVE_MS,
    );
  },
);

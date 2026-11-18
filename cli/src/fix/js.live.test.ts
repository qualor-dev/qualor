import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  checkFixUpload,
  compareSemver,
  readNpmLock,
  type FixClaimItem,
  type FixFileChange,
} from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { toolInstalled } from '../../test/fix/tools';
import { commitAll, gitSync, GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createGit } from '../git/git';
import { silentLogger } from '../log';
import { jsAdapter } from './js';
import { prepareFix } from './run';
import { createToolRunner } from './runner';
import { openScratch } from './workspace';

/**
 * 0.16 fix MRs (R26, R27): the JS adapter with the real npm against the public registry, run only
 * by `pnpm fix:live` (the unit project excludes `*.live.test.ts`). A repository depending on
 * `minimist ^1.2.5`, locked by npm at 1.2.5, is fixed to 1.2.6 (CVE-2021-44906): the range becomes
 * `^1.2.6` and the lockfile resolves 1.2.6 or a later 1.x from registry.npmjs.org.
 */

const tmp = useTempDirs();
const REGISTRY = 'https://registry.npmjs.org/';

/** npm against the public registry, with its own home, cache and configuration. */
function liveEnv(): Record<string, string> {
  const home = tmp('qualor-fix-live-home-');
  const inherited = Object.entries(GIT_TEST_ENV).filter(
    (entry): entry is [string, string] => entry[1] !== undefined && !/^npm_/i.test(entry[0]),
  );
  return {
    ...Object.fromEntries(inherited),
    CI: 'true',
    HOME: home,
    USERPROFILE: home,
    npm_config_registry: REGISTRY,
    npm_config_userconfig: path.join(home, '.npmrc'),
    npm_config_cache: path.join(home, 'npm-cache'),
    npm_config_update_notifier: 'false',
  };
}

const MINIMIST: FixClaimItem = {
  id: '0193a4c6-1c2e-7a3b-9f00-000000000001',
  generation: 1,
  leaseToken: 'lease-1',
  family: 'js',
  packageName: 'minimist',
  installedVersions: ['1.2.5'],
  vulnerabilities: [
    {
      id: 'CVE-2021-44906',
      severity: 'critical',
      title: 'Prototype Pollution in minimist',
      url: null,
      installedVersions: ['1.2.5'],
      fixedVersions: ['1.2.6', '0.2.4'],
    },
  ],
  mainBranch: 'main',
  declinedTarget: null,
};

describe.runIf(toolInstalled('npm'))('the JS adapter against registry.npmjs.org (live)', () => {
  it('fixes minimist 1.2.5 to 1.2.6 or a later 1.x', async () => {
    const env = liveEnv();
    const dir = tmp('qualor-fix-live-');
    initRepo(dir);
    writeTree(dir, {
      'package.json': '{\n  "name": "live",\n  "version": "1.0.0",\n  "private": true\n}\n',
    });
    // npm saves `^1.2.5` and locks 1.2.5.
    const npm = createToolRunner({ env, root: dir, log: silentLogger });
    const locked = await npm(
      'npm',
      [
        'install',
        '--package-lock-only',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        'minimist@1.2.5',
      ],
      { cwd: dir, timeoutMs: 300_000 },
    );
    expect(locked.exitCode, locked.stderr).toBe(0);
    commitAll(dir, 'base');

    const git = createGit(dir, GIT_TEST_ENV);
    const scratch = await openScratch(git, tmp('qualor-fix-live-temp-'));
    try {
      const outcome = await prepareFix(
        MINIMIST,
        jsAdapter,
        {
          root: scratch.root,
          files: gitSync(dir, 'ls-files').split('\n'),
          run: createToolRunner({ env, root: dir, log: silentLogger }),
          deadline: Date.now() + 300_000,
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
      const manifest = files.find((f) => f.path === 'package.json');
      const lock = files.find((f) => f.path === 'package-lock.json');
      expect(manifest?.next).toBe(manifest?.base.replace('"^1.2.5"', '"^1.2.6"'));
      const versions = readNpmLock(lock?.next ?? '{}')
        .filter((e) => e.name === 'minimist')
        .map((e) => e.version);
      expect(versions).toHaveLength(1);
      expect(compareSemver(versions[0] ?? '0.0.0', '1.2.6')).toBeGreaterThanOrEqual(0);
      expect(versions[0]?.startsWith('1.')).toBe(true);
      expect(outcome.targets).toEqual([
        { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' },
      ]);
      expect(
        checkFixUpload({
          family: 'js',
          packageName: 'minimist',
          targets: outcome.targets,
          files,
        }),
      ).toEqual({ ok: true });
    } finally {
      await scratch.close();
    }
  });
});

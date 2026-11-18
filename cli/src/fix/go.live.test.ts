import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  checkFixUpload,
  readGoMod,
  readGoSum,
  type FixClaimItem,
  type FixFileChange,
} from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { useGoTestEnv } from '../../test/fix/go-env';
import { toolInstalled } from '../../test/fix/tools';
import { commitAll, gitSync, GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createGit } from '../git/git';
import { silentLogger } from '../log';
import { goAdapter } from './go';
import { prepareFix } from './run';
import { createToolRunner } from './runner';
import { openScratch } from './workspace';

/**
 * 0.16 fix MRs (R26, R27): the Go adapter with the real go against proxy.golang.org and
 * sum.golang.org, run only by `pnpm fix:live` (the unit project excludes `*.live.test.ts`). A
 * module requiring `golang.org/x/text v0.3.7` is fixed to 0.3.8 (CVE-2022-32149, GO-2022-1059):
 * go.mod requires v0.3.8, and go.sum holds its `h1:` lines.
 */

const tmp = useTempDirs();
const TEXT = 'golang.org/x/text';
const LIVE_MS = 300_000;

const goTestEnv = useGoTestEnv();

/** go against the public proxy and checksum database, with its own home and caches. */
const liveEnv = () =>
  goTestEnv({
    GOPROXY: 'https://proxy.golang.org',
    GOSUMDB: 'sum.golang.org',
    GOFLAGS: '-mod=mod',
  });

const X_TEXT: FixClaimItem = {
  id: '0193a4c6-1c2e-7a3b-9f00-000000000002',
  generation: 1,
  leaseToken: 'lease-1',
  family: 'go',
  packageName: TEXT,
  installedVersions: ['v0.3.7'],
  vulnerabilities: [
    {
      id: 'CVE-2022-32149',
      severity: 'high',
      title: 'Denial of service via crafted Accept-Language header in golang.org/x/text/language',
      url: null,
      installedVersions: ['v0.3.7'],
      fixedVersions: ['0.3.8'],
    },
  ],
  mainBranch: 'main',
  declinedTarget: null,
};

describe.runIf(toolInstalled('go'))('the Go adapter against proxy.golang.org (live)', () => {
  it('fixes golang.org/x/text v0.3.7 to v0.3.8', async () => {
    const env = liveEnv();
    const dir = tmp('qualor-fix-live-');
    initRepo(dir);
    writeTree(dir, {
      'go.mod': `module example.com/live\n\ngo 1.21\n\nrequire ${TEXT} v0.3.7\n`,
      'main.go': `package main\n\nimport "${TEXT}/language"\n\nfunc main() { println(language.English.String()) }\n`,
    });
    const go = createToolRunner({ env, root: dir, log: silentLogger });
    const tidied = await go('go', ['mod', 'tidy'], {
      cwd: dir,
      env: { GOTOOLCHAIN: 'local' },
      timeoutMs: LIVE_MS,
    });
    expect(tidied.exitCode, tidied.stderr).toBe(0);
    commitAll(dir, 'base');

    const git = createGit(dir, GIT_TEST_ENV);
    const scratch = await openScratch(git, tmp('qualor-fix-live-temp-'));
    try {
      const outcome = await prepareFix(
        X_TEXT,
        goAdapter,
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
      const goMod = files.find((f) => f.path === 'go.mod');
      const goSum = files.find((f) => f.path === 'go.sum');
      const required = readGoMod(goMod?.next ?? '')
        .requires.filter((r) => r.path === TEXT)
        .map((r) => r.version);
      expect(required).toEqual(['v0.3.8']);
      const hashed = readGoSum(goSum?.next ?? '')
        .filter((e) => e.name === TEXT && e.integrity?.startsWith('h1:') === true)
        .map((e) => e.version);
      expect(hashed).toEqual(expect.arrayContaining(['v0.3.8', 'v0.3.8/go.mod']));
      expect(outcome.targets).toEqual([
        { installed: 'v0.3.7', target: '0.3.8', lockfile: 'go.mod' },
      ]);
      expect(outcome.lockfiles).toEqual([
        { path: 'go.mod', relation: 'direct', mechanism: null, dependents: [] },
      ]);
      expect(
        checkFixUpload({ family: 'go', packageName: TEXT, targets: outcome.targets, files }),
      ).toEqual({ ok: true });
    } finally {
      await scratch.close();
    }
  });
});

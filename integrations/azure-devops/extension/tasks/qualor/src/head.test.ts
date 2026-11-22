import { execFile, execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  commitAll,
  fileUrl,
  gitSync,
  GIT_TEST_ENV,
  initRepo,
} from '../../../../../../cli/test/git';
import { headCheckout } from './head';

const execFileAsync = promisify(execFile);
const tmpRoot = mkdtempSync(path.join(os.tmpdir(), 'qualor-azure-head-'));
afterAll(() => rmSync(tmpRoot, { recursive: true, force: true }));

const SHALLOW = {
  problem: 'The pull request head is not in the clone. Set fetchDepth: 0 on the checkout step.',
};

/**
 * A git runner like the task's: resolves with stdout, rejects on a non-zero exit with execFile's
 * error (`code`, `stderr`). Git does not look for a repository above tmpRoot.
 */
function gitIn(dir: string): { git: (args: string[]) => Promise<string>; calls: string[][] } {
  const calls: string[][] = [];
  const env = { ...GIT_TEST_ENV, GIT_CEILING_DIRECTORIES: tmpRoot };
  const git = async (args: string[]): Promise<string> => {
    calls.push(args);
    return (await execFileAsync('git', args, { cwd: dir, env, encoding: 'utf8' })).stdout;
  };
  return { git, calls };
}

const checkedOut = (calls: string[][]): boolean => calls.some((args) => args.includes('checkout'));

/** An error shaped like execFile's for a git that exited with `code`. */
const gitError = (code: number | string, stderr: string, message = 'Command failed: git') =>
  Object.assign(new Error(message), { code, stderr });

interface Repo {
  dir: string;
  /** The pull request head (feature's last commit). */
  head: string;
  /** feature's first commit. */
  older: string;
  /** The merge commit Azure checks out: first parent main, second parent the head. */
  merge: string;
}

let counter = 0;
/** main, a feature branch of two commits, and a `--no-ff` merge of it checked out (as Azure does). */
function mergeRepo(): Repo {
  const dir = path.join(tmpRoot, `repo-${++counter}`);
  mkdirSync(dir);
  initRepo(dir);
  writeFileSync(path.join(dir, 'a.ts'), 'export const a = 1;\n');
  commitAll(dir, 'a');
  gitSync(dir, 'checkout', '-q', '-b', 'feature');
  writeFileSync(path.join(dir, 'b.ts'), 'export const b = 2;\n');
  const older = commitAll(dir, 'b');
  writeFileSync(path.join(dir, 'c.ts'), 'export const c = 3;\n');
  const head = commitAll(dir, 'c');
  gitSync(dir, 'checkout', '-q', 'main');
  gitSync(dir, 'merge', '--no-ff', '-q', '-m', 'Merge pull request 7', 'feature');
  const merge = gitSync(dir, 'rev-parse', 'HEAD');
  gitSync(dir, 'checkout', '-q', '--detach', merge);
  return { dir, head, older, merge };
}

const prBuild = (env: Record<string, string> = {}) => ({ BUILD_REASON: 'PullRequest', ...env });

describe('headCheckout', () => {
  let repo: Repo;
  beforeEach(() => {
    repo = mergeRepo();
  });

  it('checks out the head SYSTEM_PULLREQUEST_SOURCECOMMITID names', async () => {
    const { git } = gitIn(repo.dir);
    const env = prBuild({
      SYSTEM_PULLREQUEST_SOURCECOMMITID: repo.older,
      BUILD_SOURCEVERSION: repo.merge,
    });
    // The variable wins over the merge commit's second parent.
    expect(await headCheckout(git, env)).toEqual({ checkedOut: repo.older });
    expect(gitSync(repo.dir, 'rev-parse', 'HEAD')).toBe(repo.older);
  });

  it('takes the head from HEAD^2 when the variable is missing (Azure DevOps Server 2022)', async () => {
    const { git } = gitIn(repo.dir);
    for (const env of [prBuild(), prBuild({ SYSTEM_PULLREQUEST_SOURCECOMMITID: '' })]) {
      gitSync(repo.dir, 'checkout', '-q', '--detach', repo.merge);
      expect(await headCheckout(git, env)).toEqual({ checkedOut: repo.head });
      expect(gitSync(repo.dir, 'rev-parse', 'HEAD')).toBe(repo.head);
    }
  });

  it('reads the commit ids in any case, as the CLI does', async () => {
    const { git } = gitIn(repo.dir);
    const env = prBuild({
      SYSTEM_PULLREQUEST_SOURCECOMMITID: repo.older.toUpperCase(),
      BUILD_SOURCEVERSION: repo.merge.toUpperCase(),
    });
    expect(await headCheckout(git, env)).toEqual({ checkedOut: repo.older });
    gitSync(repo.dir, 'checkout', '-q', '--detach', repo.merge);
    const fallback = prBuild({ BUILD_SOURCEVERSION: repo.merge.toUpperCase() });
    expect(await headCheckout(git, fallback)).toEqual({ checkedOut: repo.head });
  });

  it('takes the second parent of BUILD_SOURCEVERSION, so a second run stays on the head', async () => {
    const { git } = gitIn(repo.dir);
    const env = prBuild({ BUILD_SOURCEVERSION: repo.merge });
    expect(await headCheckout(git, env)).toEqual({ checkedOut: repo.head });
    expect(await headCheckout(git, env)).toEqual({ checkedOut: null });
    expect(gitSync(repo.dir, 'rev-parse', 'HEAD')).toBe(repo.head);
  });

  it('leaves the clone alone when HEAD already is the head', async () => {
    gitSync(repo.dir, 'checkout', '-q', '--detach', repo.head);
    const { git, calls } = gitIn(repo.dir);
    const env = prBuild({ SYSTEM_PULLREQUEST_SOURCECOMMITID: repo.head });
    expect(await headCheckout(git, env)).toEqual({ checkedOut: null });
    expect(checkedOut(calls)).toBe(false);
  });

  it('refuses a shallow clone, where the head is not in the clone (fetchDepth: 1)', async () => {
    const clone = path.join(tmpRoot, `clone-${++counter}`);
    gitSync(tmpRoot, 'clone', '-q', '--depth', '1', '--branch', 'main', fileUrl(repo.dir), clone);
    expect(gitSync(clone, 'rev-parse', 'HEAD')).toBe(repo.merge);
    const { git, calls } = gitIn(clone);
    for (const env of [
      prBuild({ SYSTEM_PULLREQUEST_SOURCECOMMITID: repo.head, BUILD_SOURCEVERSION: repo.merge }),
      prBuild({ BUILD_SOURCEVERSION: repo.merge }),
      prBuild(),
    ]) {
      expect(await headCheckout(git, env)).toEqual(SHALLOW);
    }
    expect(checkedOut(calls)).toBe(false);
    expect(gitSync(clone, 'rev-parse', 'HEAD')).toBe(repo.merge);
  });

  it('runs git without hooks or an fsmonitor command', async () => {
    const hook = path.join(repo.dir, '.git', 'hooks', 'post-checkout');
    writeFileSync(hook, '#!/bin/sh\necho ran > hook-ran\n');
    chmodSync(hook, 0o755);
    const { git, calls } = gitIn(repo.dir);
    expect(await headCheckout(git, prBuild({ BUILD_SOURCEVERSION: repo.merge }))).toEqual({
      checkedOut: repo.head,
    });
    expect(existsSync(path.join(repo.dir, 'hook-ran'))).toBe(false);
    expect(calls.length).toBeGreaterThan(0);
    for (const args of calls) {
      expect(args.slice(0, 4)).toEqual([
        '-c',
        'core.hooksPath=/dev/null',
        '-c',
        'core.fsmonitor=false',
      ]);
    }
    // The hook itself works: git without those options runs it.
    gitSync(repo.dir, 'checkout', '-q', '--detach', repo.merge);
    expect(existsSync(path.join(repo.dir, 'hook-ran'))).toBe(true);
  });

  it('names the git failure when the clone cannot be read (not exit code 1)', async () => {
    const notRepo = path.join(tmpRoot, `not-a-repo-${++counter}`);
    mkdirSync(notRepo);
    const { git } = gitIn(notRepo);
    const result = await headCheckout(git, prBuild({ BUILD_SOURCEVERSION: repo.merge }));
    expect(result).toEqual({
      problem: expect.stringMatching(
        /^Could not read the pull request head from the clone: fatal: not a git repository[^\n]*$/,
      ),
    });
  });

  it("keeps only the first line of git's standard error, or the error without one", async () => {
    const stderr =
      "fatal: detected dubious ownership in repository at '/src'\n" +
      'To add an exception for this directory, call:\n';
    const dubious = vi.fn(() => Promise.reject(gitError(128, stderr)));
    expect(await headCheckout(dubious, prBuild())).toEqual({
      problem:
        "Could not read the pull request head from the clone: fatal: detected dubious ownership in repository at '/src'",
    });
    const missing = vi.fn(() => Promise.reject(gitError('ENOENT', '', 'spawn git ENOENT')));
    expect(await headCheckout(missing, prBuild())).toEqual({
      problem: 'Could not read the pull request head from the clone: spawn git ENOENT',
    });
    const exitOne = vi.fn(() => Promise.reject(gitError(1, '')));
    expect(await headCheckout(exitOne, prBuild())).toEqual(SHALLOW);
  });

  it('does nothing outside a pull request build, without calling git', async () => {
    const git = vi.fn(() => Promise.reject(new Error('git must not run')));
    for (const env of [
      {},
      { BUILD_REASON: 'IndividualCI', SYSTEM_PULLREQUEST_SOURCECOMMITID: repo.head },
      { BUILD_REASON: 'Manual' },
    ]) {
      expect(await headCheckout(git, env)).toEqual({ checkedOut: null });
    }
    expect(git).not.toHaveBeenCalled();
  });
});

/** Runs bash scripts; false when this machine has no usable bash with git. */
const HAS_BASH = ((): boolean => {
  try {
    execFileSync('bash', ['-c', 'git --version && mktemp -u >/dev/null'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

/**
 * The "Check out the pull request head" step of the docker examples, run with bash against the
 * same merge-commit repositories. Both files carry the same script, and so does the task.
 */
describe.skipIf(!HAS_BASH)('the YAML head checkout step', () => {
  const EXAMPLES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
  const stepScript = (file: string): string => {
    const lines = readFileSync(path.join(EXAMPLES, file), 'utf8').split('\n');
    const name = lines.findIndex(
      (l) => l.trim() === 'displayName: Check out the pull request head',
    );
    let start = name;
    while (start > 0 && lines[start]?.trim() !== '- script: |') start--;
    return lines
      .slice(start + 1, name)
      .map((l) => l.replace(/^ {6}/, ''))
      .join('\n');
  };
  const FILES = ['qualor-docker.yml', 'qualor-dotnet-docker.yml'];

  interface Ran {
    status: number;
    stdout: string;
    stderr: string;
  }
  const run = (script: string, cwd: string, env: Record<string, string | undefined>): Ran => {
    const home = path.join(tmpRoot, `agent-temp-${++counter}`).split(path.sep).join('/');
    mkdirSync(home);
    const text = script.replaceAll('$(Agent.TempDirectory)', home);
    const result = spawnSync('bash', ['-c', text], {
      cwd,
      env: { ...GIT_TEST_ENV, GIT_CEILING_DIRECTORIES: tmpRoot, ...env },
      encoding: 'utf8',
    });
    return { status: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
  };

  describe.each(FILES)('%s', (file) => {
    const script = stepScript(file);
    let repo: Repo;
    beforeEach(() => {
      repo = mergeRepo();
    });
    const head = (dir: string): string => gitSync(dir, 'rev-parse', 'HEAD');

    it('is the script that was extracted', () => {
      expect(script).toMatch(/^set -euo pipefail\n/);
      expect(script).toContain('git checkout --detach "$head"');
    });

    it('checks out the head SYSTEM_PULLREQUEST_SOURCECOMMITID names', () => {
      const out = run(script, repo.dir, {
        BUILD_REASON: 'PullRequest',
        SYSTEM_PULLREQUEST_SOURCECOMMITID: repo.older,
        BUILD_SOURCEVERSION: repo.merge,
      });
      expect(out.status).toBe(0);
      expect(head(repo.dir)).toBe(repo.older);
    });

    it('takes the head from the merge commit second parent without the variable', () => {
      const out = run(script, repo.dir, {
        BUILD_REASON: 'PullRequest',
        BUILD_SOURCEVERSION: repo.merge.toUpperCase(),
      });
      expect(out.status).toBe(0);
      expect(head(repo.dir)).toBe(repo.head);
    });

    it('leaves a clone that already is on the head alone, and prints nothing on success', () => {
      gitSync(repo.dir, 'checkout', '-q', '--detach', repo.head);
      const env = { BUILD_REASON: 'PullRequest', SYSTEM_PULLREQUEST_SOURCECOMMITID: repo.head };
      const out = run(script, repo.dir, env);
      expect(out).toEqual({ status: 0, stdout: '', stderr: '' });
      expect(head(repo.dir)).toBe(repo.head);
    });

    it('fails with the fetchDepth hint when the head is not in a shallow clone', () => {
      const clone = path.join(tmpRoot, `clone-${++counter}`);
      gitSync(tmpRoot, 'clone', '-q', '--depth', '1', '--branch', 'main', fileUrl(repo.dir), clone);
      for (const env of [
        { SYSTEM_PULLREQUEST_SOURCECOMMITID: repo.head, BUILD_SOURCEVERSION: repo.merge },
        { BUILD_SOURCEVERSION: repo.merge },
      ]) {
        const out = run(script, clone, { BUILD_REASON: 'PullRequest', ...env });
        expect(out.status).toBe(1);
        expect(out.stderr).toContain(
          'The pull request head is not in the clone. Set fetchDepth: 0 on the checkout step.',
        );
      }
      expect(head(clone)).toBe(repo.merge);
    });

    it('names a git failure that is not a missing commit', () => {
      const notRepo = path.join(tmpRoot, `not-a-repo-${++counter}`);
      mkdirSync(notRepo);
      const out = run(script, notRepo, {
        BUILD_REASON: 'PullRequest',
        BUILD_SOURCEVERSION: repo.merge,
      });
      expect(out.status).toBe(1);
      expect(out.stderr).toMatch(
        /Could not read the pull request head from the clone: fatal: not a git repository/,
      );
    });

    it('calls no git outside a pull request build', () => {
      // A directory that is no repository: any git call would fail.
      const plain = path.join(tmpRoot, `plain-${++counter}`);
      mkdirSync(plain);
      for (const env of [{}, { BUILD_REASON: 'IndividualCI' }]) {
        expect(run(script, plain, env)).toEqual({ status: 0, stdout: '', stderr: '' });
      }
    });
  });
});

import { execFile } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
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

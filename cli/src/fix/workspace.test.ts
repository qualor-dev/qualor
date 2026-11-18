import { chmodSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { commitAll, gitSync, GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { createGit } from '../git/git';
import { changedPaths, openScratch } from './workspace';

const tmp = useTempDirs();

function repo(): { dir: string; head: string } {
  const dir = tmp('qualor-fix-repo-');
  initRepo(dir);
  writeTree(dir, {
    'package.json': '{ "name": "app" }\n',
    'package-lock.json': '{}\n',
    'apps/web/package.json': '{ "name": "web" }\n',
    'README.md': 'app\n',
  });
  return { dir, head: commitAll(dir, 'base') };
}

/** The paths `git worktree list` names, as git spells them. */
function worktrees(dir: string): string[] {
  return gitSync(dir, 'worktree', 'list', '--porcelain')
    .split('\n')
    .filter((line) => line.startsWith('worktree '))
    .map((line) => line.slice('worktree '.length));
}

describe('openScratch and close', () => {
  it('checks HEAD out in a temporary directory outside the checkout and removes it again', async () => {
    const { dir, head } = repo();
    const temp = tmp('qualor-fix-temp-');
    const git = createGit(dir, GIT_TEST_ENV);
    const scratch = await openScratch(git, temp);
    expect(path.relative(temp, scratch.root).startsWith('..')).toBe(false);
    expect(existsSync(path.join(scratch.root, 'apps', 'web', 'package.json'))).toBe(true);
    expect(gitSync(scratch.root, 'rev-parse', 'HEAD')).toBe(head);
    expect(worktrees(dir)).toHaveLength(2);

    writeFileSync(path.join(scratch.root, 'package.json'), '{ "name": "changed" }\n');
    writeFileSync(path.join(scratch.root, 'new.txt'), 'x\n');
    await scratch.close();

    expect(existsSync(scratch.root)).toBe(false);
    expect(readdirSync(temp)).toEqual([]);
    expect(worktrees(dir)).toHaveLength(1);
    expect(gitSync(dir, 'status', '--porcelain')).toBe('');
    expect(gitSync(dir, 'rev-parse', 'HEAD')).toBe(head);
    // A second close does nothing.
    await scratch.close();
  });

  it('cleans up after a failed step too (an adapter that throws)', async () => {
    const { dir } = repo();
    const temp = tmp('qualor-fix-temp-');
    const git = createGit(dir, GIT_TEST_ENV);
    const scratch = await openScratch(git, temp);
    const failing = async () => {
      try {
        mkdirSync(path.join(scratch.root, 'node_modules', 'x'), { recursive: true });
        writeFileSync(path.join(scratch.root, 'node_modules', 'x', 'index.js'), '');
        throw new Error('adapter failed');
      } finally {
        await scratch.close();
      }
    };
    await expect(failing()).rejects.toThrow('adapter failed');
    expect(existsSync(scratch.root)).toBe(false);
    expect(worktrees(dir)).toHaveLength(1);
    expect(gitSync(dir, 'status', '--porcelain')).toBe('');
  });

  it('runs none of the repository’s hooks (ruling T12d)', async () => {
    const { dir } = repo();
    const marker = path.join(tmp('qualor-fix-marker-'), 'hook-ran');
    const hook = path.join(dir, '.git', 'hooks', 'post-checkout');
    writeFileSync(hook, `#!/bin/sh\necho ran > '${marker.replaceAll('\\', '/')}'\n`);
    chmodSync(hook, 0o755);
    // The hook works: a checkout in the repository itself runs it.
    gitSync(dir, 'checkout', '-q', '-b', 'probe');
    expect(existsSync(marker)).toBe(true);
    rmSync(marker);
    gitSync(dir, 'checkout', '-q', 'main');
    rmSync(marker);

    const git = createGit(dir, GIT_TEST_ENV);
    const scratch = await openScratch(git, tmp('qualor-fix-temp-'));
    try {
      writeTree(scratch.root, { 'package.json': '{ "name": "changed" }\n' });
      expect((await changedPaths(git, scratch)).changed).toEqual(['package.json']);
    } finally {
      await scratch.close();
    }
    expect(existsSync(marker)).toBe(false);
  });

  it('prunes the worktree entry when its directory is already gone', async () => {
    const { dir } = repo();
    const temp = tmp('qualor-fix-temp-');
    const git = createGit(dir, GIT_TEST_ENV);
    const scratch = await openScratch(git, temp);
    rmSync(scratch.root, { recursive: true, force: true });
    await scratch.close();
    expect(worktrees(dir)).toHaveLength(1);
  });

  it('is a usage error outside a git checkout, and leaves nothing behind', async () => {
    const dir = tmp('qualor-fix-norepo-');
    const temp = tmp('qualor-fix-temp-');
    const git = createGit(dir, GIT_TEST_ENV);
    await expect(openScratch(git, temp)).rejects.toMatchObject({ exitCode: 2 });
    expect(readdirSync(temp)).toEqual([]);
  });
});

describe('changedPaths', () => {
  it('lists changed tracked files and added files, nested paths included, never node_modules/ or .yarn/', async () => {
    const { dir } = repo();
    const git = createGit(dir, GIT_TEST_ENV);
    const scratch = await openScratch(git, tmp('qualor-fix-temp-'));
    try {
      expect(await changedPaths(git, scratch)).toEqual({ changed: [], added: [] });
      writeTree(scratch.root, {
        'package-lock.json': '{ "lockfileVersion": 3 }\n',
        'apps/web/package.json': '{ "name": "web", "version": "2" }\n',
        'apps/web/x.txt': 'new\n',
        'odd name ü.txt': 'new\n',
        'node_modules/qf-a/package.json': '{}\n',
        'apps/web/node_modules/qf-a/index.js': '',
        '.yarn/install-state.gz': 'x',
      });
      rmSync(path.join(scratch.root, 'README.md'));
      const paths = await changedPaths(git, scratch);
      expect(paths.changed.toSorted()).toEqual([
        'README.md',
        'apps/web/package.json',
        'package-lock.json',
      ]);
      expect(paths.added.toSorted()).toEqual(['apps/web/x.txt', 'odd name ü.txt']);
    } finally {
      await scratch.close();
    }
  });
});

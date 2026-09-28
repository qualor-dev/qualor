import { chmodSync, existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { GIT_TEST_ENV, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { CliError } from '../errors';
import { createGit, gitText, scrubCredentials } from './git';

const tmp = useTempDirs();

/** `env` with `dir` first on its PATH (whatever the variable's spelling on Windows). */
function withPath(
  env: Readonly<Record<string, string | undefined>>,
  dir: string,
): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  let current = '';
  for (const [k, v] of Object.entries(env)) {
    if (k.toUpperCase() === 'PATH') current = v ?? '';
    else out[k] = v;
  }
  return { ...out, PATH: `${dir}${path.delimiter}${current}` };
}

describe('createGit: timeouts', () => {
  it('kills a hung git command after the configured timeout and reports it as a failed GitResult', async () => {
    const root = tmp();
    initRepo(root);
    const git = createGit(root, GIT_TEST_ENV, { timeoutMs: 200 });
    // `cat-file --batch` reads object names from stdin, which nothing ever closes here, so it
    // hangs until killed.
    const r = await git(['cat-file', '--batch']);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain('timed out after 200ms');
  });

  it('surfaces a git-call timeout through gitText as a clear, non-network-crashing CliError', async () => {
    const root = tmp();
    initRepo(root);
    const git = createGit(root, GIT_TEST_ENV, { timeoutMs: 200 });
    const err: unknown = await gitText(git, ['cat-file', '--batch']).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).message).toContain('timed out after 200ms');
  });

  it('kills the whole git process tree on timeout, so nothing keeps the work tree busy', async () => {
    // Git for Windows' `cmd\git.exe` is a launcher: killing only it leaves the real git running
    // (and holding the directory open), so an immediate removal would fail with EPERM/EBUSY.
    const root = tmp();
    initRepo(root);
    const git = createGit(root, GIT_TEST_ENV, { timeoutMs: 200 });
    const r = await git(['cat-file', '--batch']);
    expect(r.code).toBe(-1);
    expect(() => {
      rmSync(root, { recursive: true, force: true });
    }).not.toThrow();
  });

  it('lets a fetch-tier call override the instance default timeout', async () => {
    const root = tmp();
    initRepo(root);
    const git = createGit(root, GIT_TEST_ENV, { timeoutMs: 60_000 });
    const start = Date.now();
    const r = await git(['cat-file', '--batch'], { timeoutMs: 150 });
    expect(Date.now() - start).toBeLessThan(30_000);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain('timed out after 150ms');
  });
});

describe('createGit: secrets', () => {
  it('scrubs scheme://user:pass@ credentials from git stderr', async () => {
    const root = tmp();
    initRepo(root);
    const git = createGit(root, GIT_TEST_ENV);
    const r = await git([
      '-c',
      'alias.leak=!echo "fatal: unable to access https://ci-user:hunter2secret@git.example.invalid/r.git" >&2; exit 1',
      'leak',
    ]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('https://«redacted»@git.example.invalid/r.git');
    expect(r.stderr).not.toContain('hunter2secret');
    const err: unknown = await gitText(git, [
      '-c',
      'alias.leak=!echo "ssh://git:tok3n@h.invalid/x" >&2; exit 1',
      'leak',
    ]).catch((e: unknown) => e);
    expect((err as CliError).message).not.toContain('tok3n');
  });

  it('never passes QUALOR_TOKEN (or other QUALOR_ secrets) to git and its hooks', async () => {
    const root = tmp();
    initRepo(root);
    const git = createGit(root, { ...GIT_TEST_ENV, QUALOR_TOKEN: 'qlr_leak', SAFE_VAR: 'kept' });
    const r = await git(['-c', 'alias.env=!echo "[$QUALOR_TOKEN][$SAFE_VAR]"', 'env']);
    expect(r.stdout.trim()).toBe('[][kept]');
  });

  it('confines the search paths of git and its hooks like an analyzer environment', async () => {
    const root = tmp();
    initRepo(root);
    const git = createGit(root, { ...GIT_TEST_ENV, PYTHONPATH: 'lib', CLASSPATH: '.' });
    const r = await git(['-c', 'alias.env=!echo "[$PYTHONPATH][$CLASSPATH]"', 'env']);
    expect(r.stdout.trim()).toBe('[][]');
  });

  it('runs the git from PATH outside the repository, never a git inside the checkout', async () => {
    const root = tmp();
    initRepo(root);
    const marker = path.join(tmp(), 'ran');
    // A POSIX script, or on Windows an .exe that is not a program: either way, running it fails.
    writeTree(root, {
      'bin/git': `#!/bin/sh\necho repo > ${JSON.stringify(marker)}\nexit 1\n`,
      'bin/git.exe': 'not a program',
    });
    chmodSync(path.join(root, 'bin', 'git'), 0o755);
    const git = createGit(root, withPath(GIT_TEST_ENV, path.join(root, 'bin')));
    const r = await git(['--version']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('git version');
    expect(existsSync(marker)).toBe(false);
  });

  it('scrubCredentials leaves URLs without credentials alone', () => {
    expect(scrubCredentials('from https://example.invalid/a and git@host:x.git')).toBe(
      'from https://example.invalid/a and git@host:x.git',
    );
    expect(scrubCredentials('https://tok@h/x http://u:p@h2')).toBe(
      'https://«redacted»@h/x http://«redacted»@h2',
    );
  });
});

/** Field 5 of /proc/<pid>/stat (after the parenthesised command name): the process group id. */
function pgidOf(stat: string): string {
  return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[2] ?? '';
}

// Linux only (reads /proc). A Ctrl+C in the terminal reaches the foreground process group; git
// must be in it, so an interrupted scan never leaves a `git fetch` running.
describe.runIf(process.platform === 'linux')('createGit: process group', () => {
  it("runs git (and what it starts) in the CLI's own process group", async () => {
    const root = tmp();
    initRepo(root);
    const git = createGit(root, GIT_TEST_ENV);
    const r = await git(['-c', 'alias.pg=!cat /proc/$$/stat', 'pg']);
    expect(r.code).toBe(0);
    expect(pgidOf(r.stdout)).toBe(pgidOf(readFileSync(`/proc/${process.pid}/stat`, 'utf8')));
  });
});

describe('createGit: spawn failure', () => {
  it('rejects with a usage error when git cannot be started at all', async () => {
    const git = createGit(tmp(), { PATH: '' });
    const err: unknown = await git(['--version']).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).exitCode).toBe(2);
    expect((err as CliError).message).toContain('cannot run git --version');
  });
});

describe('createGit: output size', () => {
  it('reports a distinct message, not a crash, when git output exceeds the configured buffer', async () => {
    const root = tmp();
    initRepo(root);
    const git = createGit(root, GIT_TEST_ENV, { maxBufferBytes: 5 });
    const r = await git(['--version']);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain('produced more than 5 bytes of output');
  });
});

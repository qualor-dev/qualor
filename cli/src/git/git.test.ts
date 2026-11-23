import { chmodSync, existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { GIT_TEST_ENV, gitSync, initRepo } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { CliError } from '../errors';
import { createGit, GIT_OPTIONS, gitText, scrubCredentials } from './git';

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

describe('createGit: repository configuration that runs programs', () => {
  it('turns fsmonitor and hooks off after the other options', () => {
    expect(GIT_OPTIONS.slice(-4)).toEqual([
      '-c',
      'core.fsmonitor=false',
      '-c',
      'core.hooksPath=/dev/null',
    ]);
  });

  it('does not run a core.fsmonitor command planted in the repository', async () => {
    const root = tmp();
    initRepo(root);
    const dir = root.replaceAll('\\', '/');
    writeTree(root, { 'a.txt': 'a\n', 'hook.sh': `#!/bin/sh\necho ran > '${dir}/ran.txt'\n` });
    chmodSync(path.join(root, 'hook.sh'), 0o755);
    gitSync(root, 'config', 'core.fsmonitor', `sh ${dir}/hook.sh`);
    const git = createGit(root, GIT_TEST_ENV);
    const r = await git(['status', '--porcelain']);
    expect(r.code).toBe(0);
    expect(existsSync(path.join(root, 'ran.txt'))).toBe(false);
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

describe('createGit: standard input and streamed output', () => {
  /** A repository holding one blob: `hello\n`, which is `HELLO` (its object id). */
  const HELLO = 'ce013625030ba8dba906f756967f9e9ca394464a';
  function repoWithHello(): string {
    const root = tmp();
    initRepo(root);
    writeTree(root, { 'hello.txt': 'hello\n' });
    gitSync(root, 'add', 'hello.txt');
    return root;
  }

  it('writes `input` to standard input and closes it', async () => {
    const git = createGit(tmp(), GIT_TEST_ENV);
    const r = await git(['hash-object', '--stdin'], { input: 'hello\n' });
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toBe(HELLO);
  });

  it('hands the output to onStdout as it comes, without collecting it or capping it', async () => {
    const root = repoWithHello();
    const git = createGit(root, GIT_TEST_ENV, { maxBufferBytes: 5 });
    const chunks: Buffer[] = [];
    const r = await git(['cat-file', '--batch'], {
      input: `${HELLO}\n`.repeat(3),
      onStdout: (chunk) => {
        chunks.push(chunk);
        return true;
      },
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe('');
    expect(Buffer.concat(chunks).toString('utf8')).toBe(`${HELLO} blob 6\nhello\n\n`.repeat(3));
  });

  it('stops git when onStdout answers false', async () => {
    const root = repoWithHello();
    const git = createGit(root, GIT_TEST_ENV);
    let calls = 0;
    // Without the stop, git would answer 200 000 requests (8 MB).
    const r = await git(['cat-file', '--batch'], {
      input: `${HELLO}\n`.repeat(200_000),
      onStdout: () => {
        calls += 1;
        return false;
      },
    });
    expect(calls).toBe(1);
    expect(r.code).not.toBe(0);
  });

  it('stops git and rejects with the error when onStdout throws', async () => {
    const root = repoWithHello();
    const git = createGit(root, GIT_TEST_ENV);
    const boom = new Error('boom');
    const err: unknown = await git(['cat-file', '--batch'], {
      input: `${HELLO}\n`.repeat(200_000),
      onStdout: () => {
        throw boom;
      },
    }).catch((e: unknown) => e);
    expect(err).toBe(boom);
  });

  it('bounds each wait for streamed output by the timeout, not the whole call', async () => {
    const root = tmp();
    initRepo(root);
    writeTree(root, { 'big.txt': 'x'.repeat(4 * 1024 * 1024) });
    gitSync(root, 'add', 'big.txt');
    const big = gitSync(root, 'rev-parse', ':big.txt');
    const git = createGit(root, GIT_TEST_ENV, { timeoutMs: 400 });
    // The consumer takes 150 ms over each of its first six pieces: the call lasts longer than the
    // timeout, but git never waits that long for it, and the call succeeds.
    let slow = 6;
    let bytes = 0;
    const start = Date.now();
    const r = await git(['cat-file', '--batch'], {
      input: `${big}\n`,
      onStdout: (chunk) => {
        bytes += chunk.length;
        if (slow > 0) {
          slow -= 1;
          const until = Date.now() + 150;
          while (Date.now() < until) {
            // the consumer is busy
          }
        }
        return true;
      },
    });
    expect(r.code).toBe(0);
    expect(bytes).toBeGreaterThan(4 * 1024 * 1024);
    expect(Date.now() - start).toBeGreaterThan(400);
    // Standard input is never closed here, so git waits for it, silent, until the timeout.
    const hung = await git(['cat-file', '--batch'], { onStdout: () => true });
    expect(hung.code).toBe(-1);
    expect(hung.stderr).toContain('timed out after 400ms without output');
  });
});

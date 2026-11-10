import { spawn } from 'node:child_process';
import { REDACTED } from '@qualor/shared';
import { resolveBinary } from '../analyzers/binary';
import { confineAnalyzerEnv, sanitizeAnalyzerEnv } from '../analyzers/env';
import { killTree } from '../analyzers/process';
import { CliError, EXIT } from '../errors';

export interface GitResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface GitCallOptions {
  /** Overrides the `Git` instance's default timeout for this one call. */
  timeoutMs?: number;
  /** Written to git's standard input, which is then closed (`cat-file --batch`). */
  input?: string;
  /**
   * Takes standard output piece by piece as it comes, instead of collecting it: the output cap
   * does not apply and the result's `stdout` is empty. The timeout then bounds each wait for
   * output, not the whole call, so the consumer may take its time over a piece. Answering `false`
   * stops git (its process tree is killed) and the call resolves; a throw stops git too, and the
   * call rejects with it.
   */
  onStdout?: (chunk: Buffer) => boolean;
}

export type Git = (args: readonly string[], options?: GitCallOptions) => Promise<GitResult>;

/**
 * Keeps git's output stable whatever the user's configuration or `.gitattributes` says.
 * `diff.interHunkContext=0` and the per-call `--inter-hunk-context=0 --no-textconv
 * --no-ext-diff` in `scm.ts`'s `-U0` diff are belt and braces for the same problem: a large
 * `interHunkContext` merges nearby hunks (turning unchanged context lines into part of a
 * bigger "changed" range if a caller trusted hunk headers), and a textconv/ext-diff driver can
 * rewrite content so line numbers no longer match the real file. `diff.submodule=short` keeps a
 * runner's `log` or `diff` setting from writing a submodule's commit subjects or file diffs into
 * the diff, without a header of their own, where they would end up in the previous file's patch
 * (the review snapshot's). `gc.auto`/`maintenance.auto` are disabled so a scan never triggers
 * background repository maintenance.
 */
export const GIT_OPTIONS: readonly string[] = [
  '-c',
  'core.quotepath=off',
  '-c',
  'diff.noprefix=false',
  '-c',
  'diff.mnemonicPrefix=false',
  '-c',
  'diff.relative=false',
  '-c',
  'diff.renames=true',
  '-c',
  'diff.interHunkContext=0',
  '-c',
  'diff.submodule=short',
  '-c',
  'color.ui=false',
  '-c',
  'gc.auto=0',
  '-c',
  'maintenance.auto=false',
];

/** Local plumbing/diff commands (report and repository reads). */
export const GIT_LOCAL_TIMEOUT_MS = 60_000;
/** `git fetch`, including `--deepen`/`--unshallow` steps, which can be slow over a real network. */
export const GIT_FETCH_TIMEOUT_MS = 300_000;
const MAX_GIT_OUTPUT_BYTES = 256 * 1024 * 1024;

export interface GitDefaults {
  timeoutMs?: number;
  maxBufferBytes?: number;
}

/** After the process exits, wait this long for its pipes to close before giving up on them. */
const CLOSE_GRACE_MS = 1_000;

/** `scheme://user:pass@` or `scheme://token@` in a URL: the userinfo part. */
const URL_CREDENTIALS = /\b([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi;

/**
 * Replaces the credentials in every `scheme://user:pass@host` URL with «redacted». git echoes
 * remote URLs in its errors, and a CI remote often carries a token (`https://ci-token:…@`), so
 * git's stderr is scrubbed before it can reach a log line or an error message.
 */
export function scrubCredentials(text: string): string {
  return text.replace(URL_CREDENTIALS, `$1${REDACTED}@`);
}

function joinMessage(stderr: string, message: string): string {
  return [stderr.trim(), message].filter((s) => s !== '').join('\n');
}

/**
 * Runs the `git` binary in `cwd` (no shell, no prompts). A non-zero exit, a timeout or an
 * output overflow all resolve as a `GitResult` (never an error) with a clear `stderr`, so every
 * existing caller's non-zero-exit handling covers them too: `gitText` turns the message into a
 * `CliError`, and `baseline.ts`'s `fetch()` helper just treats it as "fetch failed" — matching
 * how a network hiccup during `scm.autoFetch` already degrades to `baseline.status: unavailable`
 * instead of crashing the scan. The promise only rejects when git itself could not be spawned
 * at all (for example, the binary is missing), or with what an `onStdout` consumer threw.
 *
 * A timeout or an overflow kills the process tree (`killTree`): Git for Windows' `cmd\git.exe` is
 * only a launcher, so killing just the direct child would leave the real git running. On POSIX
 * git deliberately stays in the CLI's own process group (not `detached`): a Ctrl+C in the
 * terminal then reaches git and its helpers directly, with no signal handler needed, and a
 * timeout kills git itself. The result is delivered once every stdio pipe has closed; if a
 * helper still holds them after git exits, the pipes are dropped after a short grace period.
 */
export function createGit(
  cwd: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
  defaults: GitDefaults = {},
): Git {
  const defaultTimeoutMs = defaults.timeoutMs ?? GIT_LOCAL_TIMEOUT_MS;
  const maxBuffer = defaults.maxBufferBytes ?? MAX_GIT_OUTPUT_BYTES;
  // Like an analyzer binary (ruling V3): git comes from PATH or the scanner image, never from the
  // checkout, and it runs hooks and credential helpers that may be repo-controlled, so it gets
  // the analyzer environment (secrets stripped, search paths confined to outside the checkout).
  let binary: string | null | undefined;
  const childEnv = confineAnalyzerEnv(sanitizeAnalyzerEnv(env), cwd);
  return (args, options) =>
    new Promise((resolve, reject) => {
      const timeoutMs = options?.timeoutMs ?? defaultTimeoutMs;
      const label = args[0] ?? '';
      binary ??= resolveBinary('git', { root: cwd, env });
      if (binary === null) {
        reject(
          new CliError(
            EXIT.USAGE,
            `cannot run git ${label}: git is not installed (on PATH, outside the repository)`,
          ),
        );
        return;
      }
      const child = spawn(binary, [...GIT_OPTIONS, ...args], {
        cwd,
        env: {
          ...childEnv,
          GIT_TERMINAL_PROMPT: '0',
          GIT_OPTIONAL_LOCKS: '0',
          LC_ALL: 'C',
        },
        shell: false,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const stream = options?.onStdout;
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let size = 0;
      let failure: 'timeout' | 'overflow' | 'stopped' | null = null;
      /** What the onStdout consumer threw, which the call rejects with. */
      let thrown: { error: unknown } | null = null;
      let settled = false;
      const kill = (why: 'timeout' | 'overflow' | 'stopped') => {
        if (failure !== null) return;
        failure = why;
        killTree(child.pid);
      };
      const arm = () => setTimeout(kill, timeoutMs, 'timeout');
      let timer = arm();
      const collect = (into: Buffer[], chunk: Buffer) => {
        if (failure === 'overflow') return;
        size += chunk.length;
        if (size > maxBuffer) {
          kill('overflow');
          return;
        }
        into.push(chunk);
      };
      const take = (consume: (chunk: Buffer) => boolean, chunk: Buffer) => {
        if (failure !== null) return;
        let more: boolean;
        try {
          more = consume(chunk);
        } catch (error) {
          thrown = { error };
          kill('stopped');
          return;
        }
        if (!more) {
          kill('stopped');
          return;
        }
        // A streamed call is bounded per wait for output: the clock starts again after each piece.
        clearTimeout(timer);
        timer = arm();
      };
      child.stdout.on(
        'data',
        stream === undefined
          ? (chunk: Buffer) => collect(stdout, chunk)
          : (chunk: Buffer) => take(stream, chunk),
      );
      child.stderr.on('data', (chunk: Buffer) => collect(stderr, chunk));
      if (options?.input !== undefined) {
        // git may stop reading before the end (a call that was stopped): no error of the call.
        child.stdin.on('error', () => undefined);
        child.stdin.end(options.input);
      }
      const finish = (code: number | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.stdin.destroy();
        if (thrown !== null) {
          reject(thrown.error);
          return;
        }
        const out = Buffer.concat(stdout).toString('utf8');
        const err = scrubCredentials(Buffer.concat(stderr).toString('utf8'));
        if (failure === 'timeout') {
          const wait = stream === undefined ? '' : ' without output';
          resolve({
            code: -1,
            stdout: out,
            stderr: joinMessage(err, `git ${label} timed out after ${timeoutMs}ms${wait}`),
          });
        } else if (failure === 'stopped') {
          resolve({ code: -1, stdout: '', stderr: err });
        } else if (failure === 'overflow') {
          resolve({
            code: -1,
            stdout: out,
            stderr: joinMessage(
              err,
              `git ${label} produced more than ${maxBuffer} bytes of output`,
            ),
          });
        } else {
          resolve({ code: code ?? -1, stdout: out, stderr: err });
        }
      };
      child.on('error', (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        killTree(child.pid);
        reject(new CliError(EXIT.USAGE, `cannot run git ${label}: ${error.message}`));
      });
      const dropPipes = () => {
        if (settled) return;
        child.stdout.destroy();
        child.stderr.destroy();
        finish(child.exitCode);
      };
      child.on('exit', () => {
        // Normally 'close' follows at once. If something git started still holds the pipes, stop
        // waiting for them after a short grace period. No kill here: git has exited, so its pid
        // may already belong to another process.
        setTimeout(dropPipes, CLOSE_GRACE_MS).unref();
      });
      child.on('close', (code) => {
        finish(code);
      });
    });
}

export async function gitText(git: Git, args: readonly string[]): Promise<string> {
  const r = await git(args);
  if (r.code !== 0) {
    const detail = r.stderr.trim() || `exit code ${r.code}`;
    throw new CliError(EXIT.USAGE, scrubCredentials(`git ${args.join(' ')} failed: ${detail}`));
  }
  return r.stdout;
}

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
}

export type Git = (args: readonly string[], options?: GitCallOptions) => Promise<GitResult>;

/**
 * Keeps git's output stable whatever the user's configuration or `.gitattributes` says.
 * `diff.interHunkContext=0` and the per-call `--inter-hunk-context=0 --no-textconv
 * --no-ext-diff` in `scm.ts`'s `-U0` diff are belt and braces for the same problem: a large
 * `interHunkContext` merges nearby hunks (turning unchanged context lines into part of a
 * bigger "changed" range if a caller trusted hunk headers), and a textconv/ext-diff driver can
 * rewrite content so line numbers no longer match the real file. `gc.auto`/`maintenance.auto`
 * are disabled so a scan never triggers background repository maintenance.
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
  'color.ui=false',
  '-c',
  'gc.auto=0',
  '-c',
  'maintenance.auto=false',
];

/** Local plumbing/diff commands (report and repository reads). */
const GIT_LOCAL_TIMEOUT_MS = 60_000;
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
 * at all (for example, the binary is missing).
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
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let size = 0;
      let failure: 'timeout' | 'overflow' | null = null;
      let settled = false;
      const kill = (why: 'timeout' | 'overflow') => {
        if (failure !== null) return;
        failure = why;
        killTree(child.pid);
      };
      const timer = setTimeout(() => {
        kill('timeout');
      }, timeoutMs);
      const collect = (into: Buffer[]) => (chunk: Buffer) => {
        if (failure === 'overflow') return;
        size += chunk.length;
        if (size > maxBuffer) {
          kill('overflow');
          return;
        }
        into.push(chunk);
      };
      child.stdout.on('data', collect(stdout));
      child.stderr.on('data', collect(stderr));
      const finish = (code: number | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.stdin.destroy();
        const out = Buffer.concat(stdout).toString('utf8');
        const err = scrubCredentials(Buffer.concat(stderr).toString('utf8'));
        if (failure === 'timeout') {
          resolve({
            code: -1,
            stdout: out,
            stderr: joinMessage(err, `git ${label} timed out after ${timeoutMs}ms`),
          });
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
      child.on('exit', () => {
        // Normally 'close' follows at once. If something git started still holds the pipes, stop
        // waiting for them after a short grace period. No kill here: git has exited, so its pid
        // may already belong to another process.
        setTimeout(() => {
          if (settled) return;
          child.stdout.destroy();
          child.stderr.destroy();
          finish(child.exitCode);
        }, CLOSE_GRACE_MS).unref();
      });
      child.on('close', (code) => {
        finish(code);
      });
    });
}

export async function gitText(git: Git, args: readonly string[]): Promise<string> {
  const r = await git(args);
  if (r.code !== 0) {
    throw new CliError(
      EXIT.USAGE,
      scrubCredentials(`git ${args.join(' ')} failed: ${r.stderr.trim() || `exit code ${r.code}`}`),
    );
  }
  return r.stdout;
}

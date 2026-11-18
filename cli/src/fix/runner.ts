import { FIX_LIMITS, scrubToolOutput, secretEnvValues } from '@qualor/shared/fix';
import { isInside, resolveBinary } from '../analyzers/binary';
import { runProcess } from '../analyzers/process';
import { silentLogger, type Logger } from '../log';
import { fixToolEnv } from './env';

/** What a package manager did: its exit code (null when it did not exit), and its output. */
export interface ToolResult {
  exitCode: number | null;
  timedOut: boolean;
  /** The last 64 KiB of standard output, as the tool wrote it. */
  stdout: string;
  /** The last 64 KiB of standard error, the job's known secrets replaced by `[redacted]`. */
  stderr: string;
}

/**
 * Runs a package manager (§6.5): `tool` is a program name, looked up on `PATH` (never in the
 * repository or the scratch copy), `args` are passed as they are, never through a shell (B9).
 * `env` adds variables to the tool environment for this call.
 */
export type ToolRunner = (
  tool: string,
  args: readonly string[],
  o: { cwd: string; env?: Readonly<Record<string, string>>; timeoutMs: number },
) => Promise<ToolResult>;

/** B7: the tool is not installed (on `PATH`, outside the repository); the fix fails `missing_tool`. */
export class MissingToolError extends Error {
  override name = 'MissingToolError';
  constructor(readonly tool: string) {
    super(`${tool} is not installed (on PATH, outside the repository)`);
  }
}

const REDACTED = '[redacted]';

/** Each known secret (4 characters or more, R21) replaced, the longest first. */
function withoutSecrets(text: string, secrets: readonly string[]): string {
  return secrets
    .filter((s) => s.length >= 4)
    .toSorted((a, b) => b.length - a.length)
    .reduce((out, secret) => out.split(secret).join(REDACTED), text);
}

/**
 * The job's runner (B9). Every call gets {@link fixToolEnv} of `env` and its own variables, so no
 * call can hand a tool the Qualor or CI job credentials. The tool is resolved like an analyzer
 * (`resolveBinary`: `PATH`, never under `root`) and never from the directory it runs in. A call
 * without time left does not start. The tools' output is never logged; their stderr comes back
 * with the job's known secrets (`secrets`, and the values of the environment's secret-named
 * variables) replaced, so whatever an adapter makes of it holds none of them.
 */
export function createToolRunner(o: {
  env: Record<string, string>;
  root: string;
  log: Logger;
  /** Secrets beyond the environment's own, such as the project token. */
  secrets?: readonly string[];
}): ToolRunner {
  return async (tool, args, call) => {
    if (call.timeoutMs <= 0) return { exitCode: null, timedOut: true, stdout: '', stderr: '' };
    const env = fixToolEnv({ ...o.env, ...call.env });
    const binary = resolveBinary(tool, { root: o.root, env });
    if (binary === null || isInside(call.cwd, binary)) throw new MissingToolError(tool);
    o.log.debug(`running ${tool} ${args.join(' ')}`);
    const r = await runProcess(
      { command: binary, args, cwd: call.cwd, env, timeoutMs: call.timeoutMs },
      silentLogger,
    );
    if (r.spawnErrorCode === 'ENOENT') throw new MissingToolError(tool);
    o.log.debug(
      `${tool} exited ${r.exitCode ?? 'without an exit code'} after ${Math.round(r.durationMs)} ms`,
    );
    const stderr = r.spawnError === undefined ? r.stderr : `${r.stderr}${r.spawnError}`;
    return {
      exitCode: r.exitCode,
      timedOut: r.timedOut,
      stdout: r.stdout,
      stderr: withoutSecrets(stderr, [...(o.secrets ?? []), ...secretEnvValues(env)]),
    };
  };
}

/** The last `maxBytes` bytes of the UTF-8 text, starting at a whole character. */
function utf8Tail(text: string, maxBytes: number): string {
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= maxBytes) return text;
  let start = bytes.length - maxBytes;
  // A continuation byte (10xxxxxx) is the inside of a character.
  while (start < bytes.length && ((bytes[start] ?? 0) & 0xc0) === 0x80) start++;
  return bytes.subarray(start).toString('utf8');
}

/**
 * A package manager's failure as a fix's `failure` (§6.5 step 5, §6.9): `timeout` when it ran out
 * of time, else `package_manager` with "`<tool>` exited with <code>: " and the tail of its stderr,
 * scrubbed (`scrubToolOutput`: `secrets`, the B9 shapes, Qualor's secret redaction). The whole
 * message is at most 2 KiB. The job's runner already replaced the job's known secrets in stderr;
 * `secrets` names any other.
 */
export function toolFailure(
  tool: string,
  r: ToolResult,
  secrets: readonly string[],
): { code: 'package_manager' | 'timeout'; message: string } {
  const code = r.timedOut ? 'timeout' : 'package_manager';
  const head = r.timedOut
    ? `\`${tool}\` did not finish in time`
    : `\`${tool}\` exited with ${r.exitCode ?? 'no exit code'}`;
  const tail = scrubToolOutput(r.stderr, secrets).trim();
  if (tail === '') return { code, message: head };
  const prefix = `${head}: `;
  const room = FIX_LIMITS.messageBytes - Buffer.byteLength(prefix);
  return { code, message: `${prefix}${utf8Tail(tail, room).trimStart()}` };
}

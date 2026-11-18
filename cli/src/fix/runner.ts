import {
  FIX_LIMITS,
  replaceSecrets,
  scrubToolOutput,
  secretEnvValues,
  utf8Tail,
} from '@qualor/shared/fix';
import { isInside } from '../analyzers/binary';
import { runProcess } from '../analyzers/process';
import { silentLogger, type Logger } from '../log';
import { fixToolEnv } from './env';
import { resolveTool } from './shim';

/** What a package manager did: its exit code (null when it did not exit), and its output. */
export interface ToolResult {
  exitCode: number | null;
  timedOut: boolean;
  /**
   * The end of standard output (64 KiB unless the call asks for more), the job's known secrets
   * replaced by `[redacted]` (ruling T13e).
   */
  stdout: string;
  /** The end of standard error, the job's known secrets replaced by `[redacted]`. */
  stderr: string;
}

/**
 * Runs a package manager (§6.5): `tool` is a program name, looked up on `PATH` (never in the
 * repository or the scratch copy), `args` are passed as they are, never through a shell (B9).
 * `env` adds variables to the tool environment for this call; `outputLimitBytes` is how much of the
 * end of each stream comes back (64 KiB by default; ruling T12j, for output an adapter parses).
 */
export type ToolRunner = (
  tool: string,
  args: readonly string[],
  o: {
    cwd: string;
    env?: Readonly<Record<string, string>>;
    timeoutMs: number;
    outputLimitBytes?: number;
  },
) => Promise<ToolResult>;

/**
 * B7: the tool is not installed (on `PATH`, outside the repository), or cannot be started without a
 * shell (ruling T12a, `why`); the fix fails `missing_tool`.
 */
export class MissingToolError extends Error {
  override name = 'MissingToolError';
  constructor(
    readonly tool: string,
    why = `${tool} is not installed (on PATH, outside the repository)`,
  ) {
    super(why);
  }
}

/**
 * The job's runner (B9). Every call gets {@link fixToolEnv} of `env` and its own variables, so no
 * call can hand a tool the Qualor or CI job credentials. The tool is resolved like an analyzer
 * (`resolveBinary`: `PATH`, never under `root`; on Windows an npm node shim as node and its
 * script, ruling T12a, `resolveTool`) and never from the directory it runs in. A call
 * without time left does not start. The tools' output is never logged; their stdout and stderr
 * come back with the job's known secrets (`secrets`, and the values of the environment's
 * secret-named variables) replaced, so whatever an adapter makes of them holds none of them.
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
    const resolved = resolveTool(tool, { root: o.root, env });
    if (resolved === null) throw new MissingToolError(tool);
    if ('problem' in resolved) throw new MissingToolError(tool, resolved.problem);
    const program = [resolved.command, ...resolved.args];
    if (program.some((p) => isInside(call.cwd, p))) throw new MissingToolError(tool);
    o.log.debug(`running ${tool} ${args.join(' ')}`);
    const r = await runProcess(
      {
        command: resolved.command,
        args: [...resolved.args, ...args],
        cwd: call.cwd,
        env,
        timeoutMs: call.timeoutMs,
        ...(call.outputLimitBytes !== undefined && { outputLimitBytes: call.outputLimitBytes }),
      },
      silentLogger,
    );
    if (r.spawnErrorCode === 'ENOENT') throw new MissingToolError(tool);
    o.log.debug(
      `${tool} exited ${r.exitCode ?? 'without an exit code'} after ${Math.round(r.durationMs)} ms`,
    );
    const stderr = r.spawnError === undefined ? r.stderr : `${r.stderr}${r.spawnError}`;
    const known = [...(o.secrets ?? []), ...secretEnvValues(env)];
    return {
      exitCode: r.exitCode,
      timedOut: r.timedOut,
      // Ruling T13e: pnpm and Berry print their errors on stdout, which an adapter may cut.
      stdout: replaceSecrets(r.stdout, known),
      stderr: replaceSecrets(stderr, known),
    };
  };
}

/**
 * A package manager's failure as a fix's `failure` (§6.5 step 5, §6.9): `timeout` when it ran out
 * of time, else `package_manager` with "`<tool>` exited with <code>: " and the tail of its stderr,
 * scrubbed (`scrubToolOutput`: `secrets`, the B9 shapes, Qualor's secret redaction). The whole
 * message is at most 2 KiB. The job's runner already replaced the job's known secrets in both
 * streams; `secrets` names any other.
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

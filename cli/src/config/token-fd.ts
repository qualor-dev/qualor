import { closeSync, readSync } from 'node:fs';
import { CliError, EXIT } from '../errors';

/** The most a token descriptor or token file may hold. */
export const MAX_TOKEN_BYTES = 64 * 1024;

type Env = Readonly<Record<string, string | undefined>>;
interface Outcome {
  raw: string;
  token?: string;
  error?: CliError;
}

/**
 * What each environment object's `QUALOR_TOKEN_FD` yielded. A descriptor is read once: a number
 * is never touched again (it may name a later, unrelated open file by then), so a second ask in
 * the same process, such as `qualor dotnet end` loading its settings several times, gets the same
 * token or the same error.
 */
const outcomes = new WeakMap<object, Outcome>();

function readDescriptor(raw: string): string {
  if (!/^\d+$/.test(raw) || Number(raw) < 3 || !Number.isSafeInteger(Number(raw))) {
    throw new CliError(EXIT.USAGE, 'QUALOR_TOKEN_FD must be a descriptor number of 3 or more');
  }
  const fd = Number(raw);
  const buffer = Buffer.alloc(MAX_TOKEN_BYTES + 1);
  let length = 0;
  try {
    for (;;) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
      if (length > MAX_TOKEN_BYTES) throw new Error('larger than 64 KiB');
    }
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new CliError(EXIT.USAGE, `QUALOR_TOKEN_FD ${fd} could not be read: ${reason}`);
  } finally {
    try {
      closeSync(fd);
    } catch {
      // not open: the read above has already reported it
    }
  }
  const token = buffer.toString('utf8', 0, length).trim();
  if (token === '') throw new CliError(EXIT.USAGE, `QUALOR_TOKEN_FD ${fd} is empty`);
  return token;
}

/**
 * Reads and closes the descriptor once, when the CLI starts and before any command runs, so no
 * child process a command starts (an analyzer, the taint engine) ever inherits it, whatever fails
 * first. The outcome is kept for {@link consumeTokenFd}: the command that reads the token gets it,
 * or the descriptor's error then (a `--token-file` still wins over it), never here.
 */
export function consumeTokenFdAtStartUp(env: Env): void {
  try {
    consumeTokenFd(env);
  } catch (err) {
    if (!(err instanceof CliError)) throw err;
  }
}

/**
 * The token from the descriptor `QUALOR_TOKEN_FD` names (the scanner image's entrypoint opens it
 * on a here-document), trimmed; null when the variable is unset or empty. Reads at most 64 KiB
 * and closes the descriptor, once per environment object, so no analyzer or package manager
 * started later inherits it. The token is never put back into the environment.
 */
export function consumeTokenFd(env: Env): string | null {
  const raw = env['QUALOR_TOKEN_FD'];
  if (raw === undefined || raw.trim() === '') return null;
  const seen = outcomes.get(env);
  if (seen?.raw === raw) {
    if (seen.error !== undefined) throw seen.error;
    return seen.token ?? null;
  }
  try {
    const token = readDescriptor(raw.trim());
    outcomes.set(env, { raw, token });
    return token;
  } catch (err) {
    if (err instanceof CliError) outcomes.set(env, { raw, error: err });
    throw err;
  }
}

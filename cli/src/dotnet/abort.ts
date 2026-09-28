import { EXIT, type ExitCode } from '../errors';
import type { CliIO } from '../io';
import type { Logger } from '../log';
import { releaseCheckout } from './end';
import { removeSession } from './session';

/**
 * `qualor dotnet abort` (config.md §6.1): a failed build's cleanup. `end`'s step 2 (lease, stale
 * leases, hook, re-count), then `.qualor/dotnet/` goes. No configuration, no scan, no upload; a
 * `.qualor` or `.qualor/dotnet` that is a link makes `removeSession` exit 2 without touching it.
 */
export function runDotnetAbort(io: CliIO, log: Logger): ExitCode {
  const root = io.cwd;
  releaseCheckout(root, io, log);
  removeSession(root);
  log.info('qualor dotnet abort: cleaned up, nothing scanned');
  return EXIT.OK;
}

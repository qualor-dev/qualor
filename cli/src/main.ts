import { parseCommandLine, USAGE } from './args';
import { runImportSonarqube } from './commands/import-sonarqube';
import { runValidate } from './commands/validate';
import { runVersion } from './commands/version';
import { runDotnetAbort } from './dotnet/abort';
import { runDotnetBegin } from './dotnet/begin';
import { runDotnetEnd } from './dotnet/end';
import { CliError, EXIT, type ExitCode } from './errors';
import type { CliIO } from './io';
import { createLogger, parseLogLevel, type Logger } from './log';
import { runScan } from './scan/run';

async function dispatch(argv: readonly string[], io: CliIO, log: Logger): Promise<ExitCode> {
  const command = parseCommandLine(argv);
  switch (command.name) {
    case 'help':
      io.stdout(USAGE);
      return EXIT.OK;
    case 'version':
      return await runVersion(io);
    case 'validate':
      return runValidate(command, io, log);
    case 'scan':
      return await runScan(command.flags, io, log);
    case 'import-sonarqube':
      return await runImportSonarqube(command.flags, io, log);
    case 'dotnet-begin':
      return runDotnetBegin(
        command.config === undefined ? {} : { config: command.config },
        io,
        log,
      );
    case 'dotnet-end':
      return await runDotnetEnd(command.flags, io, log);
    case 'dotnet-abort':
      return runDotnetAbort(io, log);
  }
}

/** The whole CLI. No globals: tests call it with a captured `CliIO`. */
export async function main(argv: readonly string[], io: CliIO): Promise<ExitCode> {
  let log = createLogger('info', io.stderr);
  try {
    log = createLogger(parseLogLevel(io.env['QUALOR_LOG_LEVEL']), io.stderr);
    return await dispatch(argv, io, log);
  } catch (err) {
    if (err instanceof CliError) {
      log.error(err.message);
      return err.exitCode;
    }
    // Ruling C14: an unexpected failure exits 4; the stack is only useful with debug logging.
    log.error(`internal error: ${err instanceof Error ? err.message : String(err)}`);
    if (err instanceof Error && err.stack !== undefined) log.debug(err.stack);
    return EXIT.SERVER;
  }
}

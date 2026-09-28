import { renderSettings } from '../config/render';
import { loadSettings } from '../config/settings';
import { EXIT, type ExitCode } from '../errors';
import type { CliIO } from '../io';
import type { Logger } from '../log';

export function runValidate(command: { config?: string }, io: CliIO, log: Logger): ExitCode {
  const settings = loadSettings({
    cwd: io.cwd,
    env: io.env,
    flags: command.config === undefined ? {} : { config: command.config },
    log,
  });
  io.stdout(renderSettings(settings));
  return EXIT.OK;
}

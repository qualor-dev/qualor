import { CliError, EXIT } from './errors';

export const LOG_LEVELS = ['error', 'warn', 'info', 'debug'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export interface Logger {
  readonly level: LogLevel;
  error(message: string): void;
  warn(message: string): void;
  info(message: string): void;
  debug(message: string): void;
}

export function parseLogLevel(value: string | undefined): LogLevel {
  if (value === undefined || value.trim() === '') return 'info';
  const level = LOG_LEVELS.find((l) => l === value.trim().toLowerCase());
  if (level === undefined) {
    throw new CliError(
      EXIT.USAGE,
      `QUALOR_LOG_LEVEL must be one of ${LOG_LEVELS.join(', ')}; got ${JSON.stringify(value)}`,
    );
  }
  return level;
}

/** Log lines go to stderr: stdout is reserved for command output (`validate`, `version`). */
export function createLogger(level: LogLevel, write: (text: string) => void): Logger {
  const rank = LOG_LEVELS.indexOf(level);
  const at = (l: LogLevel) => (message: string) => {
    if (LOG_LEVELS.indexOf(l) <= rank) write(`${l === 'info' ? '' : `${l}: `}${message}\n`);
  };
  return { level, error: at('error'), warn: at('warn'), info: at('info'), debug: at('debug') };
}

export const silentLogger: Logger = createLogger('error', () => undefined);

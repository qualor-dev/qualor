/** config.md §7. */
export const EXIT = {
  OK: 0,
  GATE_FAILED: 1,
  USAGE: 2,
  ANALYZER_FAILED: 3,
  SERVER: 4,
  AUTH: 5,
} as const;
export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

/** A failure the user can act on; `main` prints the message and exits with `exitCode`. */
export class CliError extends Error {
  override name = 'CliError';
  constructor(
    readonly exitCode: ExitCode,
    message: string,
  ) {
    super(message);
  }
}

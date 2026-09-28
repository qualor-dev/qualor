import type { CliIO } from '../src/io';

export interface CapturedIO {
  io: CliIO;
  stdout(): string;
  stderr(): string;
}

export function captureIO(
  options: { cwd?: string; env?: Record<string, string | undefined> } = {},
): CapturedIO {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      cwd: options.cwd ?? process.cwd(),
      env: options.env ?? {},
      stdout: (text) => {
        out.push(text);
      },
      stderr: (text) => {
        err.push(text);
      },
    },
    stdout: () => out.join(''),
    stderr: () => err.join(''),
  };
}

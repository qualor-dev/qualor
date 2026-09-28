import { EXIT, type ExitCode } from '../errors';
import { VERSION } from '../index';
import type { CliIO } from '../io';
import { GRAMMARS, loadParsers } from '../parse/grammars';

export function platformId(): string {
  return `${process.platform}-${process.arch}`;
}

/** Loading the grammars here proves the binary's embedded WASM files work (smoke test). */
export async function runVersion(io: CliIO): Promise<ExitCode> {
  const parsers = await loadParsers();
  try {
    const grammars = GRAMMARS.map((g) => `${g} (ABI ${parsers.abiVersion(g)})`).join(', ');
    io.stdout(`qualor ${VERSION} (${platformId()})\ngrammars: ${grammars}\n`);
  } finally {
    parsers.delete();
  }
  return EXIT.OK;
}

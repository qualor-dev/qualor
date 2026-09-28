import { loadParsers, type Parsers } from '../src/parse/grammars';

let shared: Promise<Parsers> | undefined;

/** One parser set per test file (WASM initialisation costs ≈50 ms). */
export function testParsers(): Promise<Parsers> {
  shared ??= loadParsers();
  return shared;
}

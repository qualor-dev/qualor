import { compare, explain, type Pep440Version } from '@renovatebot/pep440';

/** A PEP 440 version (uv, Poetry); null when it does not parse. */
export function parsePep440(v: string): Pep440Version | null {
  return explain(v);
}

/** PEP 440 order: negative, zero or positive; null when either version does not parse. */
export function comparePep440(a: string, b: string): number | null {
  if (explain(a) === null || explain(b) === null) return null;
  return compare(a, b);
}

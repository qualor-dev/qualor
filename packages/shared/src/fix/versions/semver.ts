import { parse, type SemVer } from 'semver';

/** A SemVer 2.0 version, strictly (not loose); null when it does not parse. */
export function parseSemver(v: string): SemVer | null {
  return parse(v, { loose: false });
}

/**
 * SemVer precedence for npm, pnpm and Yarn (§6.5 step 2): negative, zero or positive; build
 * metadata is ignored. Null when either version does not parse.
 */
export function compareSemver(a: string, b: string): number | null {
  const x = parseSemver(a);
  const y = parseSemver(b);
  return x === null || y === null ? null : x.compare(y);
}

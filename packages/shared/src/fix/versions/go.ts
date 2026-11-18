import type { SemVer } from 'semver';
import { parseSemver } from './semver';

/**
 * A Go module version as SemVer: the leading `v` and a `+incompatible` suffix dropped. A
 * pseudo-version (`v0.0.0-20191109021931-daa7c04131f5`, `v1.2.4-0.2020…-abcdef…`) is a SemVer
 * pre-release, so it orders below the release it precedes. Null when it does not parse.
 */
export function parseGo(v: string): SemVer | null {
  const bare = v.startsWith('v') ? v.slice(1) : v;
  return parseSemver(
    bare.endsWith('+incompatible') ? bare.slice(0, -'+incompatible'.length) : bare,
  );
}

/** SemVer precedence of two Go module versions; null when either does not parse. */
export function compareGo(a: string, b: string): number | null {
  const x = parseGo(a);
  const y = parseGo(b);
  return x === null || y === null ? null : x.compare(y);
}

/**
 * R3: whether two versions belong to the same module path, whose major is in the path from v2 on
 * (`/v2`): equal majors, or both at most 1. False when either does not parse.
 */
export function goSameModuleMajor(a: string, b: string): boolean {
  const x = parseGo(a);
  const y = parseGo(b);
  if (x === null || y === null) return false;
  return x.major === y.major || (x.major <= 1 && y.major <= 1);
}

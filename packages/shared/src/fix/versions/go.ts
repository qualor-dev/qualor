import type { SemVer } from 'semver';
import { parseSemver } from './semver';

const INCOMPATIBLE = '+incompatible';

/**
 * A Go module version as SemVer: the leading `v` and a `+incompatible` suffix dropped. A
 * pseudo-version (`v0.0.0-20191109021931-daa7c04131f5`, `v1.2.4-0.2020…-abcdef…`) is a SemVer
 * pre-release, so it orders below the release it precedes. Null when it does not parse.
 */
export function parseGo(v: string): SemVer | null {
  const bare = v.startsWith('v') ? v.slice(1) : v;
  return parseSemver(bare.endsWith(INCOMPATIBLE) ? bare.slice(0, -INCOMPATIBLE.length) : bare);
}

/** SemVer precedence of two Go module versions; null when either does not parse. */
export function compareGo(a: string, b: string): number | null {
  const x = parseGo(a);
  const y = parseGo(b);
  return x === null || y === null ? null : x.compare(y);
}

/**
 * R3 (Ruling T1b): whether a candidate version lives on the installed version's module path. From
 * v2 on the major is part of the path (`/v2`); every version below v2 and every `+incompatible`
 * version share the path without it. On that path each version from v2 on is `+incompatible`, and
 * fixed versions often drop the suffix (Trivy lists `25.0.6` for `github.com/docker/docker`), so
 * any candidate fits an installed `+incompatible` version. False when either does not parse.
 */
export function goSameModuleMajor(candidate: string, installed: string): boolean {
  const c = parseGo(candidate);
  const i = parseGo(installed);
  if (c === null || i === null) return false;
  if (installed.endsWith(INCOMPATIBLE)) return true;
  if (i.major <= 1) return c.major <= 1 || candidate.endsWith(INCOMPATIBLE);
  return c.major === i.major && !candidate.endsWith(INCOMPATIBLE);
}

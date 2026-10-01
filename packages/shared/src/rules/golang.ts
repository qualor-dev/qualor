/**
 * Go (plan 9C, config.md §6). The versions the qualor/scanner image ships
 * (tools/analyzers/install-go.sh; tools/ci.test.ts checks they agree) and the version policy.
 * Task 7 of plan 9C adds the rule tables and the mapping helpers.
 */
export const GO_VERSION = '1.27.1';
/** The oldest `go` the Go engines run with (staticcheck 2026.2 supports the two newest Go releases). */
export const GO_MIN_VERSION = '1.26';
export const STATICCHECK_VERSION = '2026.2.1';
export const GOSEC_VERSION = '2.29.0';
/** gosec's noisiest rules, left out by default: G104 (unchecked errors) and G115 (integer conversions). */
export const GOSEC_DEFAULT_EXCLUDE: readonly string[] = ['G104', 'G115'];
export const GOSEC_RULE_ID = /^G\d{3}$/;

function majorMinor(version: string): [number, number] | null {
  const m = /^(\d+)\.(\d+)/.exec(version);
  return m === null ? null : [Number(m[1]), Number(m[2])];
}

/** A `go` of GO_MIN_VERSION or newer (`1.26`, `1.27.1`, `1.28rc1`). */
export function goVersionSupported(version: string): boolean {
  const v = majorMinor(version);
  const min = majorMinor(GO_MIN_VERSION) as [number, number];
  return v !== null && (v[0] > min[0] || (v[0] === min[0] && v[1] >= min[1]));
}

function sameMinor(pinned: string, version: string): boolean {
  const a = majorMinor(pinned);
  const b = /^\d+\.\d+\.\d+$/.test(version) ? majorMinor(version) : null;
  return a !== null && b !== null && a[0] === b[0] && a[1] === b[1];
}

/** staticcheck's own scheme is `year.minor.patch` (`2026.2.1`): the pinned year.minor only. */
export function staticcheckVersionSupported(version: string): boolean {
  return sameMinor(STATICCHECK_VERSION, version);
}

export function gosecVersionSupported(version: string): boolean {
  return sameMinor(GOSEC_VERSION, version);
}

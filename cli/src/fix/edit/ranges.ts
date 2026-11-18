import { compareSemver } from '@qualor/shared/fix';

/**
 * R22: the dependency ranges a JS fix rewrites. A spec is a lone `^`, `~`, `>=` or `=` before a
 * full SemVer version, or that version bare; every other shape (`1.x`, `>=1 <2`, `||`, hyphen
 * ranges, dist-tags, URLs, `workspace:`, `catalog:`, `npm:` aliases, white space) is left to a
 * person (`manifest_unsupported`).
 */

const VERSION = String.raw`\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?`;
const SPEC = new RegExp(String.raw`^(\^|~|>=|=)?(${VERSION})$`);
const PLAIN_VERSION = new RegExp(String.raw`^${VERSION}$`);

type Operator = '' | '^' | '~' | '>=' | '=';

function parseSpec(spec: string): { operator: Operator; version: string } | null {
  const m = SPEC.exec(spec);
  if (m?.[2] === undefined) return null;
  return { operator: (m[1] ?? '') as Operator, version: m[2] };
}

/** Whether the spec has a shape {@link rangeWithTarget} rewrites. */
export function isRewritableRange(spec: string): boolean {
  return parseSpec(spec) !== null;
}

/** The spec with its version replaced by `target`, the operator kept; null for any other shape. */
export function rangeWithTarget(spec: string, target: string): string | null {
  const parsed = parseSpec(spec);
  if (parsed === null || !PLAIN_VERSION.test(target)) return null;
  return `${parsed.operator}${target}`;
}

/** Major, minor and patch of a version the spec pattern matched. */
function numbers(version: string): [number, number, number] {
  const core = version.split(/[-+]/, 1)[0] ?? '';
  const [major = 0, minor = 0, patch = 0] = core.split('.').map(Number);
  return [major, minor, patch];
}

/** `^base`: the left-most non-zero number of `base` stays, as npm reads a caret. */
function sameCaretLine(version: string, base: string): boolean {
  const [vMajor, vMinor, vPatch] = numbers(version);
  const [bMajor, bMinor, bPatch] = numbers(base);
  if (bMajor > 0) return vMajor === bMajor;
  if (bMinor > 0) return vMajor === 0 && vMinor === bMinor;
  return vMajor === 0 && vMinor === 0 && vPatch === bPatch;
}

function sameMinorLine(version: string, base: string): boolean {
  const [vMajor, vMinor] = numbers(version);
  const [bMajor, bMinor] = numbers(base);
  return vMajor === bMajor && vMinor === bMinor;
}

/**
 * Whether a spec {@link rangeWithTarget} can rewrite allows `version` (pre-release rules aside):
 * which installed version a manifest's spec resolved to. False for any other shape.
 */
export function rangeAllows(spec: string, version: string): boolean {
  const parsed = parseSpec(spec);
  const c = parsed === null ? null : compareSemver(version, parsed.version);
  if (parsed === null || c === null) return false;
  switch (parsed.operator) {
    case '^':
      return c >= 0 && sameCaretLine(version, parsed.version);
    case '~':
      return c >= 0 && sameMinorLine(version, parsed.version);
    case '>=':
      return c >= 0;
    default:
      return c === 0;
  }
}

/**
 * Version order per family (§6.5 step 2): SemVer for npm, pnpm and Yarn, SemVer with Go's `v`
 * prefix and pseudo-versions for Go, PEP 440 for uv and Poetry, and Maven's order for Maven.
 */
import type { SemVer } from 'semver';
import type { FixFamily } from './families';
import { compareGo, parseGo } from './versions/go';
import { compareMaven, mavenIsPrerelease, mavenMajorMinor } from './versions/maven';
import { comparePep440, parsePep440 } from './versions/pep440';
import { compareSemver, parseSemver } from './versions/semver';

export type VersionScheme = 'semver' | 'go' | 'pep440' | 'maven';

const FAMILY_SCHEME: Readonly<Record<FixFamily, VersionScheme>> = {
  js: 'semver',
  go: 'go',
  maven: 'maven',
  python: 'pep440',
};

/** The version order of a family. */
export function schemeOf(family: FixFamily): VersionScheme {
  return FAMILY_SCHEME[family];
}

/** What target choice needs to know of one version. */
interface VersionFacts {
  readonly prerelease: boolean;
  /** {@link releaseLine}; null when the version has no leading number (Maven only). */
  readonly line: string | null;
}

interface Scheme {
  compare(a: string, b: string): number | null;
  /** Null when the version does not parse. */
  facts(v: string): VersionFacts | null;
}

/** The release line: the major, or `0.<minor>` when the major is 0. */
function lineOf(major: string, minor: string): string {
  return major === '0' ? `0.${minor}` : major;
}

function semverFacts(v: SemVer | null): VersionFacts | null {
  if (v === null) return null;
  return { prerelease: v.prerelease.length > 0, line: lineOf(`${v.major}`, `${v.minor}`) };
}

function pep440Facts(v: string): VersionFacts | null {
  const parsed = parsePep440(v);
  if (parsed === null) return null;
  const line = lineOf(`${parsed.release[0] ?? 0}`, `${parsed.release[1] ?? 0}`);
  return {
    prerelease: parsed.is_prerelease,
    line: parsed.epoch === 0 ? line : `${parsed.epoch}!${line}`,
  };
}

/** A Maven version is any non-empty string without white space. */
function mavenParses(v: string): boolean {
  return v !== '' && !/\s/.test(v);
}

function mavenFacts(v: string): VersionFacts | null {
  if (!mavenParses(v)) return null;
  const mm = mavenMajorMinor(v);
  return {
    prerelease: mavenIsPrerelease(v),
    line: mm === null ? null : lineOf(mm.major, mm.minor),
  };
}

const SCHEMES: Readonly<Record<VersionScheme, Scheme>> = {
  semver: { compare: compareSemver, facts: (v) => semverFacts(parseSemver(v)) },
  go: { compare: compareGo, facts: (v) => semverFacts(parseGo(v)) },
  pep440: { compare: comparePep440, facts: pep440Facts },
  maven: {
    compare: (a, b) => (mavenParses(a) && mavenParses(b) ? compareMaven(a, b) : null),
    facts: mavenFacts,
  },
};

function sign(n: number): number {
  if (n > 0) return 1;
  return n < 0 ? -1 : 0;
}

/** -1, 0 or 1 by the scheme's order; null when either version does not parse. */
export function compareVersions(scheme: VersionScheme, a: string, b: string): number | null {
  const c = SCHEMES[scheme].compare(a, b);
  return c === null ? null : sign(c);
}

/**
 * Ruling T1c: the same version by the scheme's order (`v1.2.3` and `1.2.3` for Go), or the same
 * text when either does not parse. The one copy for the CLI and the server (ruling T11c).
 */
export function sameVersion(scheme: VersionScheme, a: string, b: string): boolean {
  const c = compareVersions(scheme, a, b);
  return c === null ? a === b : c === 0;
}

/** Whether `a` is greater than `b` by the scheme's order; false when either does not parse. */
export function isGreater(scheme: VersionScheme, a: string, b: string): boolean {
  return (compareVersions(scheme, a, b) ?? 0) > 0;
}

/** Whether a version parses by the scheme. */
export function versionParses(scheme: VersionScheme, v: string): boolean {
  return SCHEMES[scheme].facts(v) !== null;
}

/** Whether a version is a pre-release (PEP 440: dev releases too); false when it does not parse. */
export function isPrerelease(scheme: VersionScheme, v: string): boolean {
  return SCHEMES[scheme].facts(v)?.prerelease ?? false;
}

/**
 * The release line of a version: `"<major>"`, or `"0.<minor>"` when the major is 0; PEP 440 puts a
 * non-zero epoch in front (`"1!2"`). Null when the version does not parse.
 */
export function releaseLine(scheme: VersionScheme, v: string): string | null {
  return SCHEMES[scheme].facts(v)?.line ?? null;
}

/** Trivy's fixed versions: a comma list, split and trimmed, empties and duplicates dropped. */
export function parseFixedVersions(raw: string | null): string[] {
  if (raw === null) return [];
  const versions = raw
    .split(',')
    .map((v) => v.trim())
    .filter((v) => v !== '');
  return [...new Set(versions)];
}

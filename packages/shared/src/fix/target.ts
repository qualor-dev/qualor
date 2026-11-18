/**
 * Target choice (§6.5 step 2, B3, R2, R3): for one installed version, the smallest fixed version
 * greater than it on its own release line, else the smallest greater one; over several
 * vulnerabilities, the greatest of those choices.
 */
import { goSameModuleMajor } from './versions/go';
import {
  compareVersions,
  isGreater,
  isPrerelease,
  releaseLine,
  sameVersion,
  versionParses,
} from './versions';
import type { VersionScheme } from './versions';

/** What target choice needs of one vulnerability of the package. */
export interface VulnerabilityFixFacts {
  id: string;
  /** The installed versions it affects. */
  installedVersions: readonly string[];
  /** Its fixed versions (`parseFixedVersions`); empty when there is none. */
  fixedVersions: readonly string[];
}

/** B3: the target of one installed version. */
export interface InstalledTarget {
  installed: string;
  /** Null when none of its vulnerabilities has a fixed version above it. */
  target: string | null;
  /** The target is on another release line. */
  majorJump: boolean;
  /** Ids of its vulnerabilities without a fixed version above it. */
  unfixable: string[];
}

export interface TargetChoice {
  version: string;
  majorJump: boolean;
}

/**
 * A fixed version is a candidate when it parses, is no pre-release unless the installed version is
 * a pre-release on the same line (R2), keeps the Go module path's major (R3), and is greater.
 */
function isCandidate(scheme: VersionScheme, installed: string, fixed: string): boolean {
  if (!versionParses(scheme, fixed)) return false;
  if (isPrerelease(scheme, fixed)) {
    const line = releaseLine(scheme, installed);
    if (!isPrerelease(scheme, installed) || line === null || releaseLine(scheme, fixed) !== line) {
      return false;
    }
  }
  if (scheme === 'go' && !goSameModuleMajor(fixed, installed)) return false;
  return isGreater(scheme, fixed, installed);
}

/**
 * The target for one installed version and one vulnerability's fixed versions; null when the
 * installed version does not parse or no candidate is greater.
 */
export function chooseTarget(
  scheme: VersionScheme,
  installed: string,
  fixed: readonly string[],
): TargetChoice | null {
  if (!versionParses(scheme, installed)) return null;
  const line = releaseLine(scheme, installed);
  const above = fixed
    .filter((v) => isCandidate(scheme, installed, v))
    .toSorted((a, b) => compareVersions(scheme, a, b) ?? 0);
  const pick = above.find((v) => line !== null && releaseLine(scheme, v) === line) ?? above[0];
  if (pick === undefined) return null;
  const pickLine = releaseLine(scheme, pick);
  return { version: pick, majorJump: pickLine === null || pickLine !== line };
}

function targetFor(
  scheme: VersionScheme,
  installed: string,
  vulnerabilities: readonly VulnerabilityFixFacts[],
): InstalledTarget {
  const unfixable: string[] = [];
  let best: TargetChoice | null = null;
  for (const v of vulnerabilities) {
    if (!v.installedVersions.some((x) => sameVersion(scheme, x, installed))) continue;
    const choice = chooseTarget(scheme, installed, v.fixedVersions);
    if (choice === null) unfixable.push(v.id);
    else if (best === null || isGreater(scheme, choice.version, best.version)) best = choice;
  }
  return {
    installed,
    target: best?.version ?? null,
    majorJump: best?.majorJump ?? false,
    unfixable,
  };
}

/**
 * B3: one target per installed version, in input order, over the vulnerabilities that affect it:
 * the greatest of their choices, and the ids of those without one.
 */
export function chooseTargets(
  scheme: VersionScheme,
  installed: readonly string[],
  vulnerabilities: readonly VulnerabilityFixFacts[],
): InstalledTarget[] {
  return installed.map((version) => targetFor(scheme, version, vulnerabilities));
}

/** The greatest of the versions that parse; null when none does. */
export function greatestVersion(scheme: VersionScheme, versions: readonly string[]): string | null {
  let best: string | null = null;
  for (const v of versions) {
    if (versionParses(scheme, v) && (best === null || isGreater(scheme, v, best))) best = v;
  }
  return best;
}

import {
  isModularityLabel,
  isOsPackageType,
  isPackageArch,
  LONE_SURROGATE_SOURCE,
  TRIVY_OS_FAMILIES,
  type OsPackageType,
} from '@qualor/shared';
import { readableEpoch, splitOsVersion } from './sbom';

/**
 * The purl type of each ecosystem a scan or an SBOM stores: a scan's is Trivy's `Result.Type`, an
 * SBOM's (0.16) the purl type itself, so every language type maps to itself too. OS types (deb,
 * rpm, apk) are not here: their key needs the distribution ({@link matchKeyOf}).
 */
const TYPE_OF: Readonly<Record<string, string>> = {
  npm: 'npm',
  yarn: 'npm',
  pnpm: 'npm',
  bun: 'npm',
  'node-pkg': 'npm',
  pypi: 'pypi',
  pip: 'pypi',
  pipenv: 'pypi',
  poetry: 'pypi',
  uv: 'pypi',
  'python-pkg': 'pypi',
  maven: 'maven',
  pom: 'maven',
  gradle: 'maven',
  sbt: 'maven',
  jar: 'maven',
  nuget: 'nuget',
  'dotnet-core': 'nuget',
  'packages-props': 'nuget',
  golang: 'golang',
  gomod: 'golang',
  gobinary: 'golang',
  cargo: 'cargo',
  'rust-binary': 'cargo',
  composer: 'composer',
  'composer-vendor': 'composer',
  gem: 'gem',
  bundler: 'gem',
  gemspec: 'gem',
  pub: 'pub',
  hex: 'hex',
  'mix-lock': 'hex',
  swift: 'swift',
  cocoapods: 'cocoapods',
  conan: 'conan',
};

const LONE_SURROGATES = new RegExp(LONE_SURROGATE_SOURCE, 'g');

/**
 * Encodes one path segment or qualifier value: everything but unreserved characters is
 * percent-encoded. A lone surrogate (which `encodeURIComponent` rejects) becomes U+FFFD.
 */
const segment = (s: string): string =>
  encodeURIComponent(s.replace(LONE_SURROGATES, '�')).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );

/**
 * Package URL of a stored dependency (`branch_dependencies.ecosystem` is Trivy's `Result.Type`),
 * or null when the ecosystem has no purl type (it is counted as "not checked").
 */
export function purlOf(ecosystem: string, name: string, version: string): string | null {
  // Own keys only: `constructor` or `__proto__` is no ecosystem.
  const type = Object.hasOwn(TYPE_OF, ecosystem) ? TYPE_OF[ecosystem] : undefined;
  if (type === undefined || name === '' || version === '') return null;
  let path = name;
  if (type === 'pypi') path = name.toLowerCase().replace(/_/g, '-');
  else if (type === 'maven') path = name.replace(':', '/');
  const encoded = path.split('/').map(segment).join('/');
  return `pkg:${type}/${encoded}@${segment(version)}`;
}

/**
 * The epoch of an rpm version as stored (`[epoch:]version-release`, spec §6.4) and the rest: the
 * text before the first `:`, or none. Linear: one `indexOf`.
 */
function rpmEpoch(version: string): { epoch: string; rest: string } {
  const colon = version.indexOf(':');
  return colon < 0
    ? { epoch: '', rest: version }
    : { epoch: version.slice(0, colon), rest: version.slice(colon + 1) };
}

/**
 * What an rpm's key holds besides the parts of every OS key (Task 9b). An absent or empty value
 * writes no qualifier.
 */
export interface RpmKeyParts {
  arch?: string | null;
  modularityLabel?: string | null;
}

/**
 * The key an OS package is matched and stored under (spec §6.5, Trivy's own purl form). It holds
 * everything the re-check sends Trivy for the package (ruling R15): the distribution, so two
 * distributions or two releases of one never share matches, and the source package, so that one
 * row's claimed source never answers for another row's package (the match cache is shared by
 * every project of the instance).
 * - deb: `pkg:deb/<family>/<name>@<version>?distro=<family>-<osVersion>&upstream=<src>@<srcVersion>`;
 * - rpm: `pkg:rpm/<family>/<name>@<version-release>?arch=<a>&epoch=<e>&distro=<family>-<osVersion>&modularitylabel=<l>&upstream=…`,
 *   the stored `e:` prefix moved to `epoch=`, and no `epoch` without one (ruling R6). The arch
 *   and the modularity label (Task 9b) are Trivy inputs for Red Hat, CentOS, Rocky, Alma and
 *   Oracle advisories: each is written only when the row has one;
 * - apk: `pkg:apk/<family>/<name>@<version>?distro=<osVersion>&upstream=…`.
 * `upstream` is Syft's qualifier, its version in the stored form `[epoch:]version[-release]`.
 * Every part is percent-encoded on its own, so an `@` inside a part is `%40`: the one literal `@`
 * of `upstream` separates the source's name from its version, and no two sources share a key
 * (ruling R18). The OS version stays as given (`12.15`). deb and apk keys never carry the arch:
 * their Trivy detectors do not read it, and one key serves every arch of a fleet.
 */
export function osMatchKey(
  type: OsPackageType,
  family: string,
  osVersion: string,
  name: string,
  version: string,
  source: { name: string; version: string },
  rpm: RpmKeyParts = {},
): string {
  const path = `pkg:${type}/${segment(family)}/${segment(name)}`;
  // R18: each part encoded on its own (`segment` encodes `@`), joined by the one literal `@`.
  const upstream = `upstream=${segment(source.name)}@${segment(source.version)}`;
  if (type === 'apk') {
    return `${path}@${segment(version)}?distro=${segment(osVersion)}&${upstream}`;
  }
  const familyVersion = `${family}-${osVersion}`;
  const distro = `distro=${segment(familyVersion)}`;
  if (type === 'deb') return `${path}@${segment(version)}?${distro}&${upstream}`;
  const { epoch, rest } = rpmEpoch(version);
  const qualifiers = [
    rpm.arch ? `arch=${segment(rpm.arch)}` : '',
    epoch === '' ? '' : `epoch=${segment(epoch)}`,
    distro,
    rpm.modularityLabel ? `modularitylabel=${segment(rpm.modularityLabel)}` : '',
    upstream,
  ];
  return `${path}@${segment(rest)}?${qualifiers.filter((q) => q !== '').join('&')}`;
}

/** What {@link matchKeyOf} reads of an inventory row and its version's distribution. */
export interface MatchKeyInput {
  ecosystem: string;
  name: string;
  version: string;
  /** The distribution of the row's version (SBOM versions only); null on a branch. */
  osFamily: string | null;
  osVersion: string | null;
  /** The source package an SBOM named for an OS package; null otherwise. */
  sourceName: string | null;
  sourceVersion: string | null;
  /**
   * The arch and modularity label an SBOM named for an OS package (Task 9b); null otherwise. Only
   * an rpm's are keyed and sent to Trivy.
   */
  arch: string | null;
  modularityLabel: string | null;
}

/**
 * The source package an OS package is matched by: the one its row names, else the binary itself,
 * as Trivy takes it for an SBOM that names none. The key and the SBOM both use this one.
 */
export function osSourceOf(
  p: Pick<MatchKeyInput, 'name' | 'version' | 'sourceName' | 'sourceVersion'>,
): { name: string; version: string } {
  return {
    name: p.sourceName === null || p.sourceName === '' ? p.name : p.sourceName,
    version: p.sourceVersion === null || p.sourceVersion === '' ? p.version : p.sourceVersion,
  };
}

/** The bounds of a stored package's strings: the report schema's, and migration 0031's. */
const MAX_NAME = 512;
const MAX_VERSION = 256;
const MAX_OS_FIELD = 64;

/**
 * At most `max` characters, none of them a control character (C0, DEL or C1): a stored string
 * Trivy may be given. Empty passes (the key rules decide about absent values). One linear pass.
 */
function plain(text: string, max: number): boolean {
  if (text.length > max) return false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return false;
  }
  return true;
}

/** The epoch of a deb or rpm version is absent or one Trivy reads as an int (1 to 9 digits). */
const readableVersion = (type: OsPackageType, version: string): boolean =>
  type === 'apk' || readableEpoch(splitOsVersion(type, version).epoch);

/**
 * An OS family or version: within its bound, no control characters, and neither blank nor padded
 * with spaces (Trivy 0.74.0 panics on an Amazon Linux version of only spaces).
 */
const osField = (text: string): boolean => plain(text, MAX_OS_FIELD) && text.trim() === text;

/**
 * An rpm's arch and modularity label: absent, or as the SBOM parser keeps them (`isPackageArch`,
 * `isModularityLabel`). A deb's or an apk's are never keyed or sent to Trivy, so they are not
 * checked.
 */
const rpmPartsValid = (p: MatchKeyInput): boolean =>
  p.ecosystem !== 'rpm' ||
  ((p.arch === null || p.arch === '' || isPackageArch(p.arch)) &&
    (p.modularityLabel === null ||
      p.modularityLabel === '' ||
      isModularityLabel(p.modularityLabel)));

/**
 * Whether a stored package's values may be sent to Trivy (ruling R16): every string within its
 * bound and free of control characters, and, for deb and rpm, the binary's and the source's epoch
 * absent or 1 to 9 digits (Trivy fails a whole SBOM on a `SrcEpoch` it cannot read as an int), and
 * an rpm's arch and modularity label absent or well-formed.
 * Values stored by an upload, which any organisation controls, pass here before they reach the
 * SBOM that every project's packages share. A row that fails has no key: it is unchecked.
 */
export function validStoredValues(p: MatchKeyInput): boolean {
  if (!plain(p.name, MAX_NAME) || !plain(p.version, MAX_VERSION)) return false;
  if (!isOsPackageType(p.ecosystem)) return true;
  if (p.osFamily !== null && !osField(p.osFamily)) return false;
  if (p.osVersion !== null && !osField(p.osVersion)) return false;
  if (!rpmPartsValid(p)) return false;
  const source = osSourceOf(p);
  // No `@` in a source name: the parser splits `upstream` at its first `@` (no deb, rpm or apk
  // package name holds one), so a key always reads back to the same source.
  if (!plain(source.name, MAX_NAME) || source.name.includes('@')) return false;
  if (!plain(source.version, MAX_VERSION)) return false;
  return readableVersion(p.ecosystem, p.version) && readableVersion(p.ecosystem, source.version);
}

/**
 * The longest key stored, in UTF-8 bytes. The key is indexed in `matched_packages`,
 * `vulnerability_matches` and `target_vulnerabilities`, and PostgreSQL's B-tree takes at most
 * 2 704 bytes per index row: a longer key would fail the run's write, for every project.
 */
export const MAX_KEY_BYTES = 2_000;

/** The key of a row ({@link matchKeyOf}), and whether its stored values are what keeps it from one. */
function keyCheck(p: MatchKeyInput): { key: string | null; invalid: boolean } {
  if (!validStoredValues(p)) return { key: null, invalid: true };
  let key: string | null;
  if (!isOsPackageType(p.ecosystem)) {
    key = purlOf(p.ecosystem, p.name, p.version);
  } else if (
    p.osFamily === null ||
    p.osVersion === null ||
    p.osVersion === '' ||
    !TRIVY_OS_FAMILIES.has(p.osFamily) ||
    p.name === '' ||
    p.version === ''
  ) {
    key = null;
  } else {
    key = osMatchKey(p.ecosystem, p.osFamily, p.osVersion, p.name, p.version, osSourceOf(p), {
      arch: p.arch,
      modularityLabel: p.modularityLabel,
    });
  }
  if (key !== null && Buffer.byteLength(key, 'utf8') > MAX_KEY_BYTES) {
    return { key: null, invalid: true };
  }
  return { key, invalid: false };
}

/**
 * The key a stored package is matched under: an OS package's {@link osMatchKey} when its version
 * names a distribution Trivy knows, a library's {@link purlOf}. Null, "not checked", for values
 * that fail {@link validStoredValues} or give a key over {@link MAX_KEY_BYTES}, an OS package
 * without a distribution or of an unknown family, and anything without a purl type.
 */
export function matchKeyOf(p: MatchKeyInput): string | null {
  return keyCheck(p).key;
}

/** Whether a row has no key because of its stored values ({@link matchKeyOf}): it is "invalid". */
export function invalidStoredPackage(p: MatchKeyInput): boolean {
  return keyCheck(p).invalid;
}

/**
 * The purl type of a stored ecosystem: an OS package's is its ecosystem (deb, rpm, apk), a
 * library's the one {@link purlOf} writes. Null for an ecosystem with no purl type.
 */
export function purlTypeOf(ecosystem: string): string | null {
  if (isOsPackageType(ecosystem)) return ecosystem;
  return Object.hasOwn(TYPE_OF, ecosystem) ? (TYPE_OF[ecosystem] ?? null) : null;
}

/** The ecosystems stored for a purl type: the type itself and every one that maps to it. */
export function ecosystemsOfType(type: string): string[] {
  const ecosystems = [type];
  for (const [ecosystem, of] of Object.entries(TYPE_OF)) {
    if (of === type && ecosystem !== type) ecosystems.push(ecosystem);
  }
  return ecosystems;
}

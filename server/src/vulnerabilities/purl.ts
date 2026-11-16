import {
  isOsPackageType,
  LONE_SURROGATE_SOURCE,
  TRIVY_OS_FAMILIES,
  type OsPackageType,
} from '@qualor/shared';

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
 * The key an OS package is matched and stored under (spec §6.5, Trivy's own purl form): the
 * distribution is in it, so two distributions, or two releases of one, never share matches.
 * - deb: `pkg:deb/<family>/<name>@<version>?distro=<family>-<osVersion>`;
 * - rpm: `pkg:rpm/<family>/<name>@<version-release>?epoch=<e>&distro=<family>-<osVersion>`, the
 *   stored `e:` prefix moved to `epoch=`, and no `epoch` without one (ruling R6);
 * - apk: `pkg:apk/<family>/<name>@<version>?distro=<osVersion>`.
 * Every part is percent-encoded; the OS version stays as given (`12.15`).
 */
export function osMatchKey(
  type: OsPackageType,
  family: string,
  osVersion: string,
  name: string,
  version: string,
): string {
  const path = `pkg:${type}/${segment(family)}/${segment(name)}`;
  if (type === 'apk') return `${path}@${segment(version)}?distro=${segment(osVersion)}`;
  const distro = `distro=${segment(`${family}-${osVersion}`)}`;
  if (type === 'deb') return `${path}@${segment(version)}?${distro}`;
  const { epoch, rest } = rpmEpoch(version);
  const qualifiers = epoch === '' ? distro : `epoch=${segment(epoch)}&${distro}`;
  return `${path}@${segment(rest)}?${qualifiers}`;
}

/** What {@link matchKeyOf} reads of an inventory row and its version's distribution. */
export interface MatchKeyInput {
  ecosystem: string;
  name: string;
  version: string;
  /** The distribution of the row's version (SBOM versions only); null on a branch. */
  osFamily: string | null;
  osVersion: string | null;
}

/**
 * The key a stored package is matched under: an OS package's {@link osMatchKey} when its version
 * names a distribution Trivy knows, a library's {@link purlOf}. Null, "not checked", for an OS
 * package without a distribution or of an unknown family, and for anything without a purl type.
 */
export function matchKeyOf(p: MatchKeyInput): string | null {
  if (!isOsPackageType(p.ecosystem)) return purlOf(p.ecosystem, p.name, p.version);
  if (p.osFamily === null || p.osVersion === null || p.osVersion === '') return null;
  if (!TRIVY_OS_FAMILIES.has(p.osFamily) || p.name === '' || p.version === '') return null;
  return osMatchKey(p.ecosystem, p.osFamily, p.osVersion, p.name, p.version);
}

/** The ecosystems stored for a purl type: the type itself and every one that maps to it. */
export function ecosystemsOfType(type: string): string[] {
  const ecosystems = [type];
  for (const [ecosystem, of] of Object.entries(TYPE_OF)) {
    if (of === type && ecosystem !== type) ecosystems.push(ecosystem);
  }
  return ecosystems;
}

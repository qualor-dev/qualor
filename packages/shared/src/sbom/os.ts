/**
 * Operating systems of an SBOM, named as Trivy names them.
 * Sources: Trivy v0.74.0 `pkg/fanal/types/const.go` (the `OSType` constants and `OSTypeAliases`,
 * https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/fanal/types/const.go) and the os-release
 * `ID` values Syft reports as the distribution (`syft/linux/identify_release.go` in
 * https://github.com/anchore/syft, which passes `ID` through unchanged).
 */
export const OS_PACKAGE_TYPES = ['deb', 'rpm', 'apk'] as const;
export type OsPackageType = (typeof OS_PACKAGE_TYPES)[number];

export function isOsPackageType(type: string): type is OsPackageType {
  return (OS_PACKAGE_TYPES as readonly string[]).includes(type);
}

/** Every `OSType` of Trivy 0.74.0. */
export const TRIVY_OS_FAMILIES: ReadonlySet<string> = new Set([
  'activestate',
  'alma',
  'alpine',
  'amazon',
  'azurelinux',
  'bottlerocket',
  'cbl-mariner',
  'centos',
  'centos-stream',
  'chainguard',
  'coreos',
  'debian',
  'echo',
  'fedora',
  'minimos',
  'opensuse',
  'opensuse-leap',
  'opensuse-tumbleweed',
  'oracle',
  'photon',
  'redhat',
  'rocky',
  'slem',
  'sles',
  'ubuntu',
  'wolfi',
]);

/** os-release ids, Syft ids and Trivy's own aliases (lowercase) to Trivy's family names. */
export const OS_FAMILY_ALIASES: Readonly<Record<string, string>> = {
  rhel: 'redhat',
  'red hat enterprise linux': 'redhat',
  almalinux: 'alma',
  'almalinux os': 'alma',
  amzn: 'amazon',
  'amazon linux': 'amazon',
  ol: 'oracle',
  oraclelinux: 'oracle',
  'oracle linux': 'oracle',
  mariner: 'cbl-mariner',
  'azure linux': 'azurelinux',
  'debian gnu/linux': 'debian',
  'alpine linux': 'alpine',
  'rocky linux': 'rocky',
  'centos linux': 'centos',
  'centos stream': 'centos-stream',
  'opensuse.leap': 'opensuse-leap',
  'opensuse.tumbleweed': 'opensuse-tumbleweed',
  'suse linux enterprise server': 'sles',
  sles_sap: 'sles',
  'suse linux enterprise micro': 'slem',
  'sle-micro': 'slem',
  sle_micro: 'slem',
  'vmware photon os': 'photon',
  'fedora linux': 'fedora',
};

/** The Trivy family of an os-release id or OS name; an unknown name comes back lowercased with `known: false`. */
export function osFamilyOf(raw: string): { family: string; known: boolean } {
  const lower = raw.trim().toLowerCase();
  const family =
    (Object.hasOwn(OS_FAMILY_ALIASES, lower) ? OS_FAMILY_ALIASES[lower] : undefined) ?? lower;
  return { family, known: TRIVY_OS_FAMILIES.has(family) };
}

/** Equal, or one is the other plus more dot-separated parts (`12` and `12.15`; not `12.1` and `12.15`). */
export function sameOsVersion(a: string, b: string): boolean {
  if (a === b) return true;
  const [short, long] = a.length <= b.length ? [a, b] : [b, a];
  return long.startsWith(`${short}.`);
}

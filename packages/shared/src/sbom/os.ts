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

/** The database's bounds on `version_dependencies.arch` and `modularity_label` (migration 0031). */
export const PACKAGE_ARCH_MAX_CHARS = 64;
export const MODULARITY_LABEL_MAX_CHARS = 256;

/** `[A-Za-z0-9_.+-]`, by character code. */
function isArchChar(c: number): boolean {
  return (
    (c >= 0x30 && c <= 0x39) ||
    (c >= 0x41 && c <= 0x5a) ||
    (c >= 0x61 && c <= 0x7a) ||
    c === 0x5f ||
    c === 0x2e ||
    c === 0x2b ||
    c === 0x2d
  );
}

/**
 * A package arch as stored and sent to Trivy (`x86_64`, `noarch`, `amd64`): 1 to 64 characters of
 * `[A-Za-z0-9_.+-]`. One pass over the characters.
 */
export function isPackageArch(value: string): boolean {
  if (value.length === 0 || value.length > PACKAGE_ARCH_MAX_CHARS) return false;
  for (let i = 0; i < value.length; i++) {
    if (!isArchChar(value.charCodeAt(i))) return false;
  }
  return true;
}

/**
 * An RPM modularity label as stored and sent to Trivy (`nodejs:18:8090020240112121244:a75119d5`):
 * 1 to 256 characters, none a control character (C0, DEL or C1). One pass over the characters.
 */
export function isModularityLabel(value: string): boolean {
  if (value.length === 0 || value.length > MODULARITY_LABEL_MAX_CHARS) return false;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return false;
  }
  return true;
}

/** Equal, or one is the other plus more dot-separated parts (`12` and `12.15`; not `12.1` and `12.15`). */
export function sameOsVersion(a: string, b: string): boolean {
  if (a === b) return true;
  const [short, long] = a.length <= b.length ? [a, b] : [b, a];
  return long.startsWith(`${short}.`);
}

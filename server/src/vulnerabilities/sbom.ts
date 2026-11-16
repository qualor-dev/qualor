import type { OsPackageType } from '@qualor/shared';

export interface SbomPackage {
  /** The match key: the purl of a library, the OS match key of an OS package. */
  purl: string;
  name: string;
  version: string;
  /** An OS package (0.16): its distribution and the source package it was built from. */
  os?: {
    type: OsPackageType;
    family: string;
    osVersion: string;
    sourceName: string;
    sourceVersion: string;
  };
}

/**
 * The SBOM a package goes into: `''` for a library, else one per OS type and distribution. Trivy
 * takes one distribution per SBOM, and OS packages of one purl type ("multiple types of OS
 * packages in SBOM are not supported").
 */
export function sbomGroupKey(p: SbomPackage): string {
  if (p.os === undefined) return '';
  return JSON.stringify([p.os.type, p.os.family, p.os.osVersion]);
}

/**
 * A stored OS version (`[epoch:]version[-release]`, spec §6.4) split as Trivy splits a source
 * version into `SrcEpoch`, `SrcVersion` and `SrcRelease`: deb and rpm take the epoch before the
 * first `:` and the release after the last `-`; apk keeps the version whole. Missing parts are
 * `''`. Linear (`indexOf`, `lastIndexOf`), so a hostile stored string costs nothing.
 */
export function splitOsVersion(
  type: OsPackageType,
  version: string,
): { epoch: string; version: string; release: string } {
  if (type === 'apk') return { epoch: '', version, release: '' };
  const colon = version.indexOf(':');
  const epoch = colon < 0 ? '' : version.slice(0, colon);
  const rest = colon < 0 ? version : version.slice(colon + 1);
  const dash = rest.lastIndexOf('-');
  return dash < 0
    ? { epoch, version: rest, release: '' }
    : { epoch, version: rest.slice(0, dash), release: rest.slice(dash + 1) };
}

/**
 * Whether Trivy can read this split source version. It reads `SrcEpoch` as an int and fails the
 * whole SBOM when it cannot (`invalid src epoch`), so an epoch is 1 to 9 digits or none.
 */
export function readableEpoch(epoch: string): boolean {
  return epoch === '' || /^\d{1,9}$/.test(epoch);
}

/**
 * CycloneDX 1.6 JSON for Trivy. One component per distinct purl (Trivy reports the vulnerabilities
 * of a duplicate on one BOM reference only); `name` is the decoded purl path, `bom-ref` the purl.
 */
export function buildSbom(packages: readonly SbomPackage[]): string {
  const seen = new Set<string>();
  const components: object[] = [];
  for (const p of packages) {
    if (seen.has(p.purl)) continue;
    seen.add(p.purl);
    components.push({
      type: 'library',
      'bom-ref': p.purl,
      name: p.name,
      version: p.version,
      purl: p.purl,
    });
  }
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    components,
  });
}

const TRIVY = 'aquasecurity:trivy:';

/**
 * CycloneDX 1.6 JSON for Trivy of one {@link sbomGroupKey} group of OS packages (spec §6.7): an
 * `operating-system` component names the distribution (Trivy reads the OS from it alone), and each
 * package carries its match key as `purl` and `bom-ref`, and its source package in Trivy's own
 * properties, which Trivy 0.74.0 reads in any SBOM (the real test, server/test/
 * sbom-os-matching.db.test.ts): Debian and Alpine advisories are keyed by the source package.
 * `SrcEpoch` is always written, `0` for none: Trivy reads an empty one as an error. Every stored
 * string goes in through `JSON.stringify`, as data.
 */
export function buildOsSbom(packages: readonly SbomPackage[]): string {
  const os = packages.find((p) => p.os !== undefined)?.os;
  const components: object[] = [];
  if (os !== undefined) {
    components.push({
      type: 'operating-system',
      'bom-ref': 'operating-system',
      name: os.family,
      version: os.osVersion,
    });
  }
  const seen = new Set<string>();
  for (const p of packages) {
    if (p.os === undefined || seen.has(p.purl)) continue;
    seen.add(p.purl);
    const source = splitOsVersion(p.os.type, p.os.sourceVersion);
    components.push({
      type: 'library',
      'bom-ref': p.purl,
      name: p.name,
      version: p.version,
      purl: p.purl,
      properties: [
        { name: `${TRIVY}PkgType`, value: p.os.family },
        { name: `${TRIVY}SrcName`, value: p.os.sourceName },
        { name: `${TRIVY}SrcVersion`, value: source.version },
        { name: `${TRIVY}SrcRelease`, value: source.release },
        { name: `${TRIVY}SrcEpoch`, value: source.epoch === '' ? '0' : source.epoch },
      ],
    });
  }
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    components,
  });
}

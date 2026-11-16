import type { SbomDistribution } from '@qualor/shared';

/** What an export document says about itself and the target it describes. */
export interface ExportDocument {
  project: { key: string; name: string };
  organization: string;
  target: { kind: 'branch' | 'version'; name: string };
  generatedAt: Date;
  /** A uuid, the document's serial number. */
  serial: string;
  toolVersion: string;
  /** The operating system of an SBOM version (0.16); null or absent for a branch and a scan. */
  distribution?: SbomDistribution | null;
}

/** One entry of a target's dependency inventory. */
export interface ExportPackage {
  ecosystem: string;
  name: string;
  version: string;
  purl: string | null;
  licenses: string[];
  /**
   * The source package of an OS package written under its match key (0.16); null for every other
   * package, including an OS package without a key, which is written as a plain component.
   */
  source: { name: string; version: string } | null;
}

/**
 * The CycloneDX SBOM's `version`, which a BOM-Link into it names (`urn:cdx:<serial>/<version>#…`):
 * one constant, so the VEX's links always name the SBOM as it is built.
 */
export const SBOM_BOM_VERSION = 1;

/** The product identity of a target: a generic purl, used by every export format. */
export function productId(project: { key: string }, target: { name: string }): string {
  return `pkg:generic/${encodeURIComponent(project.key)}@${encodeURIComponent(target.name)}`;
}

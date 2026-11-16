/**
 * What an uploaded SBOM reads into (0.16, spec §6.1–6.5). A format reader (`readCycloneDx`, and
 * the SPDX one) turns the parsed JSON into an {@link SbomDocument}; `parseSbom` turns that into the
 * {@link SbomInventory} the server stores.
 */
import type { Purl } from './purl';

/** CycloneDX `components` are read to this depth; the ones below are counted (ruling R3). */
export const SBOM_MAX_DEPTH = 32;
/** A JSON text with more objects and arrays than this is refused before `JSON.parse` (ruling R2). */
export const SBOM_MAX_JSON_CONTAINERS = 2_000_000;

/** The operating system of an image SBOM, its family named as Trivy names it. */
export interface SbomDistribution {
  family: string;
  version: string;
}

/** One stored package. */
export interface SbomEntry {
  /** The purl type (`npm`, `deb`, …). */
  ecosystem: string;
  name: string;
  version: string;
  path: string;
  licenses: string[];
  direct: boolean | null;
  /** The source package; set for OS packages (deb, rpm, apk) only. */
  source: { name: string; version: string } | null;
  /**
   * The purl's `arch` qualifier (`x86_64`, `noarch`, `amd64`), for OS packages only: 1 to 64
   * characters of `[A-Za-z0-9_.+-]`, else null. Trivy matches Red Hat-family advisories by it.
   */
  arch: string | null;
  /**
   * The purl's `modularitylabel` qualifier of a modular RPM
   * (`nodejs:18:8090020240112121244:a75119d5`), for OS packages only: at most 256 characters, none
   * a control character, else null.
   */
  modularityLabel: string | null;
}

export interface SbomSkipped {
  noPurl: number;
  unsupportedType: number;
  duplicate: number;
}

export interface SbomWarning {
  code: string;
  message: string;
}

export interface SbomInventory {
  /** `CycloneDX 1.6`, `SPDX 2.3`, … */
  format: string;
  subject: string | null;
  subjectVersion: string | null;
  distribution: SbomDistribution | null;
  entries: SbomEntry[];
  osPackages: number;
  skipped: SbomSkipped;
  warnings: SbomWarning[];
}

export type SbomRefusalCode =
  | 'SBOM_INVALID'
  | 'SBOM_FORMAT_UNSUPPORTED'
  | 'SBOM_TOO_MANY_PACKAGES'
  | 'SBOM_MULTIPLE_OS'
  | 'SBOM_TOO_LARGE';

export interface SbomRefusal {
  code: SbomRefusalCode;
  message: string;
  /** The JSON path of the field with the wrong shape (`SBOM_INVALID`). */
  path?: string;
}

/** A package as a reader found it: its strings cleaned and bounded, its purl not yet checked. */
export interface SbomComponent {
  purl: Purl;
  path: string;
  /** Normalised, sorted, unique, at most 16. */
  licenses: string[];
  direct: boolean | null;
  /** The source package the SBOM names, if any (Trivy's properties, SPDX `sourceInfo`). */
  source: { name: string; version: string } | null;
}

/** What a reader found in one document. */
export interface SbomDocument {
  format: string;
  subject: { name: string; version: string | null } | null;
  /** The OS components or packages (name as written, version `''` when missing). */
  operatingSystems: { name: string; version: string }[];
  components: SbomComponent[];
  skipped: { noPurl: number; unsupportedType: number };
  /** The first three purls that do not parse (counted in `skipped.noPurl`). */
  invalidPurls: string[];
  /** Components below {@link SBOM_MAX_DEPTH}, not read. */
  tooDeep: number;
}

export function isSbomRefusal(value: SbomDocument | SbomRefusal): value is SbomRefusal {
  return 'code' in value;
}

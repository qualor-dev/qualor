/**
 * `parseSbom`: an uploaded SBOM's text to the inventory the server stores (0.16, spec §6.1–6.5).
 * It detects the format, guards `JSON.parse` (ruling R2), hands the document to its reader, and
 * then works out the distribution, the OS packages' sources, the duplicates, the package cap and
 * the warnings, the same for every format.
 */
import { REPORT_BOUNDS } from '../report/schema';
import { readCycloneDx } from './cyclonedx';
import { cutText, mergeLicenses, SBOM_BOUNDS } from './fields';
import { isOsPackageType, osFamilyOf, sameOsVersion } from './os';
import { inventoryName, inventoryVersion, type Purl } from './purl';
import {
  SBOM_MAX_DEPTH,
  SBOM_MAX_JSON_CONTAINERS,
  type SbomComponent,
  type SbomDistribution,
  type SbomDocument,
  type SbomEntry,
  type SbomInventory,
  type SbomRefusal,
  type SbomWarning,
} from './types';

export interface ParseSbomOptions {
  /** At most this many packages after deduplication; `REPORT_BOUNDS.dependencies` by default. */
  maxPackages?: number;
}

export type ParseSbomResult = { inventory: SbomInventory } | { refusal: SbomRefusal };

/** The report schema's ecosystem pattern; a purl type outside it is an unsupported type (R3). */
const ECOSYSTEM = /^[a-z0-9-]{1,32}$/;
/** How much of the start of a text is looked at to tell XML or tag-value apart. */
const HEAD_CHARS = 4_096;
/** The database's bound on `os_family` and `os_version`. */
const OS_FIELD_CHARS = 64;

const EXPORT_HINT = 'Export the SBOM as CycloneDX JSON or SPDX 2.3 JSON';

function refuse(code: SbomRefusal['code'], message: string): { refusal: SbomRefusal } {
  return { refusal: { code, message } };
}

/**
 * Whether a JSON text holds more than `limit` objects and arrays: one linear scan counting `{` and
 * `[` outside strings (a backslash in a string skips the character after it), stopping at the
 * limit. `JSON.parse` builds every value at once, so a flood of `{}` must be refused before it.
 */
function exceedsContainers(text: string, limit: number): boolean {
  let count = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++;
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) {
      inString = true;
    } else if ((c === 0x7b || c === 0x5b) && ++count > limit) {
      return true;
    }
  }
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A DSSE envelope, an in-toto Statement or a Sigstore bundle. */
function isAttestation(doc: Record<string, unknown>): boolean {
  if (typeof doc.payloadType === 'string' && 'payload' in doc) return true;
  if (typeof doc._type === 'string' && doc._type.startsWith('https://in-toto.io/Statement')) {
    return true;
  }
  return (
    typeof doc.mediaType === 'string' &&
    doc.mediaType.startsWith('application/vnd.dev.sigstore.bundle')
  );
}

function readDocument(doc: Record<string, unknown>): SbomDocument | SbomRefusal {
  if (isAttestation(doc)) {
    return {
      code: 'SBOM_FORMAT_UNSUPPORTED',
      message: `This is an attestation, not an SBOM. Upload the SBOM it carries: ${EXPORT_HINT}.`,
    };
  }
  if ('@context' in doc || '@graph' in doc) {
    return {
      code: 'SBOM_FORMAT_UNSUPPORTED',
      message: `SPDX 3 (JSON-LD) is not read. ${EXPORT_HINT}.`,
    };
  }
  if (doc.bomFormat === 'CycloneDX') return readCycloneDx(doc);
  if ('spdxVersion' in doc) {
    return {
      code: 'SBOM_FORMAT_UNSUPPORTED',
      message: 'SPDX documents are not read yet. Export the SBOM as CycloneDX JSON.',
    };
  }
  return {
    code: 'SBOM_INVALID',
    message:
      'The JSON is neither a CycloneDX document (bomFormat "CycloneDX") nor an SPDX document (spdxVersion).',
  };
}

/** `distro=debian-12` → debian, 12; `rhel-8.10` → rhel, 8.10; apk's bare `3.20.3` → no id. */
function splitDistro(value: string): { id: string | null; version: string } {
  const [, id, version] = /^(.+?)-(\d.*)$/.exec(value) ?? [];
  if (id !== undefined && version !== undefined) return { id, version };
  const dash = value.lastIndexOf('-');
  if (dash > 0 && dash < value.length - 1) {
    return { id: value.slice(0, dash), version: value.slice(dash + 1) };
  }
  return { id: null, version: value };
}

/** A distribution as one source names it; the version may be missing (a purl namespace alone). */
interface Candidate {
  family: string;
  version: string | null;
  fromComponent: boolean;
}

/**
 * The distributions an SBOM names (spec §6.4), merged: the same family with no version on one
 * side, or versions where one only adds parts (`12` and `12.15`), is one distribution. The OS
 * components are added first, and a purl's version never replaces a component's; between two
 * components, or two purls, the longer version wins.
 */
class Distributions {
  readonly found: Candidate[] = [];
  private readonly seen = new Set<string>();

  add(name: string, version: string | null, fromComponent: boolean): void {
    const family = osFamilyOf(name).family;
    const key = `${family}\0${version ?? ''}\0${fromComponent}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const same = this.found.find(
      (c) =>
        c.family === family &&
        (c.version === null || version === null || sameOsVersion(c.version, version)),
    );
    if (same === undefined) {
      this.found.push({ family, version, fromComponent });
    } else if (version === null) {
      // Nothing to add: the family is known already.
    } else if (same.version === null) {
      same.version = version;
      same.fromComponent = fromComponent;
    } else if (fromComponent === same.fromComponent && version.length > same.version.length) {
      same.version = version;
    }
  }

  addPurl(purl: Purl): void {
    const distro = purl.qualifiers.distro;
    if (distro !== undefined) {
      const { id, version } = splitDistro(distro);
      const family = id ?? purl.namespace;
      if (family !== null) this.add(family, version, false);
    } else if (purl.namespace !== null) {
      this.add(purl.namespace, null, false);
    }
  }

  label(c: Candidate): string {
    return c.version === null ? c.family : `${c.family} ${c.version}`;
  }
}

/** The source package a purl's `upstream` qualifier names (spec §6.4), or null. */
function upstreamSource(purl: Purl, version: string): SbomEntry['source'] {
  const upstream = purl.qualifiers.upstream;
  if (upstream === undefined) return null;
  if (purl.type === 'rpm') {
    // <name>-<version>-<release>.src.rpm, with the binary's epoch.
    const [, name, srcVersion, release] = /^(.+)-([^-]+)-([^-]+)\.src\.rpm$/.exec(upstream) ?? [];
    if (name === undefined || srcVersion === undefined || release === undefined) return null;
    const epoch = /^(\d+):/.exec(version)?.[1];
    const prefix = epoch === undefined ? '' : `${epoch}:`;
    return { name, version: `${prefix}${srcVersion}-${release}` };
  }
  if (purl.type === 'deb') {
    const at = upstream.indexOf('@');
    if (at > 0) return { name: upstream.slice(0, at), version: upstream.slice(at + 1) || version };
  }
  return { name: upstream, version };
}

function fits(source: SbomEntry['source']): source is NonNullable<SbomEntry['source']> {
  return (
    source !== null &&
    source.name !== '' &&
    source.version !== '' &&
    source.name.length <= SBOM_BOUNDS.name &&
    source.version.length <= SBOM_BOUNDS.version
  );
}

/** The SBOM's source package, else the `upstream` qualifier's, else the binary itself. */
function sourceOf(c: SbomComponent, name: string, version: string): SbomEntry['source'] {
  if (fits(c.source)) return c.source;
  const upstream = upstreamSource(c.purl, version);
  return fits(upstream) ? upstream : { name, version };
}

function toInventory(doc: SbomDocument, maxPackages: number): ParseSbomResult {
  let noPurl = doc.skipped.noPurl;
  let unsupportedType = doc.skipped.unsupportedType;
  let duplicate = 0;
  const entries = new Map<string, SbomEntry>();
  const osTypes = new Set<string>();
  const distributions = new Distributions();
  for (const os of doc.operatingSystems) distributions.add(os.name, os.version || null, true);

  for (const c of doc.components) {
    const ecosystem = c.purl.type;
    if (!ECOSYSTEM.test(ecosystem)) {
      unsupportedType++;
      continue;
    }
    const name = inventoryName(c.purl);
    const version = inventoryVersion(c.purl);
    if (
      version === null ||
      name.length > SBOM_BOUNDS.name ||
      version.length > SBOM_BOUNDS.version
    ) {
      noPurl++;
      continue;
    }
    const os = isOsPackageType(ecosystem);
    if (os) {
      osTypes.add(ecosystem);
      distributions.addPurl(c.purl);
    }
    const key = `${c.path}\0${ecosystem}\0${name}\0${version}`;
    const seen = entries.get(key);
    if (seen !== undefined) {
      duplicate++;
      seen.licenses = mergeLicenses(seen.licenses, c.licenses);
      if (c.direct === true || (c.direct === false && seen.direct === null)) seen.direct = c.direct;
      continue;
    }
    if (entries.size >= maxPackages) {
      return refuse(
        'SBOM_TOO_MANY_PACKAGES',
        `The SBOM holds more than ${maxPackages} packages after removing duplicates.`,
      );
    }
    entries.set(key, {
      ecosystem,
      name,
      version,
      path: c.path,
      licenses: c.licenses,
      direct: c.direct,
      source: os ? sourceOf(c, name, version) : null,
    });
  }

  const found = distributions.found;
  if (found.length > 1 || osTypes.size > 1) {
    const labels =
      found.length > 1
        ? found.map((c) => distributions.label(c))
        : [...osTypes].map((type) => `${type} packages`);
    return refuse(
      'SBOM_MULTIPLE_OS',
      `The SBOM describes more than one operating system (${labels.join(', ')}). Upload one SBOM per image.`,
    );
  }
  const only = found[0];
  const distribution: SbomDistribution | null =
    only === undefined || only.version === null
      ? null
      : {
          family: cutText(only.family, OS_FIELD_CHARS),
          version: cutText(only.version, OS_FIELD_CHARS),
        };

  const list = [...entries.values()];
  const osPackages = list.filter((e) => isOsPackageType(e.ecosystem)).length;
  const warnings: SbomWarning[] = [];
  if (doc.invalidPurls.length > 0) {
    warnings.push({
      code: 'SBOM_PURL_INVALID',
      message: `Components whose purl does not parse were counted as without purl, for example ${doc.invalidPurls.map((p) => JSON.stringify(p)).join(', ')}.`,
    });
  }
  if (doc.tooDeep > 0) {
    warnings.push({
      code: 'SBOM_NESTING_TOO_DEEP',
      message: `${doc.tooDeep} components nested deeper than ${SBOM_MAX_DEPTH} levels were not read.`,
    });
  }
  if (osPackages > 0 && (distribution === null || !osFamilyOf(distribution.family).known)) {
    const why =
      distribution === null
        ? 'the SBOM names no distribution (no operating-system component and no distro qualifier)'
        : `${distribution.family} is not a distribution the vulnerability database covers`;
    warnings.push({
      code: 'SBOM_OS_PACKAGES_UNCHECKED',
      message: `${osPackages} operating-system packages are stored but not checked for vulnerabilities: ${why}.`,
    });
  }

  const subjectVersion = doc.subject?.version ?? null;
  const subject =
    doc.subject === null
      ? null
      : cutText(
          subjectVersion === null ? doc.subject.name : `${doc.subject.name} ${subjectVersion}`,
          SBOM_BOUNDS.subject,
        );
  return {
    inventory: {
      format: doc.format,
      subject,
      subjectVersion: subjectVersion === null ? null : cutText(subjectVersion, SBOM_BOUNDS.version),
      distribution,
      entries: list,
      osPackages,
      skipped: { noPurl, unsupportedType, duplicate },
      warnings,
    },
  };
}

export function parseSbom(text: string, options: ParseSbomOptions = {}): ParseSbomResult {
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const head = body.slice(0, HEAD_CHARS).trimStart();
  if (head.startsWith('<')) {
    return /<bom[\s>]|cyclonedx\.org\/schema\/bom/.test(head)
      ? refuse('SBOM_FORMAT_UNSUPPORTED', `CycloneDX XML is not read. ${EXPORT_HINT}.`)
      : refuse('SBOM_INVALID', `The SBOM is XML, not JSON. ${EXPORT_HINT}.`);
  }
  if (!head.startsWith('{') && !head.startsWith('[') && /^SPDXVersion:/m.test(head)) {
    return refuse('SBOM_INVALID', `The SBOM is SPDX tag-value, not JSON. ${EXPORT_HINT}.`);
  }
  if (exceedsContainers(body, SBOM_MAX_JSON_CONTAINERS)) {
    return refuse(
      'SBOM_TOO_LARGE',
      `The SBOM holds more than ${SBOM_MAX_JSON_CONTAINERS} JSON objects and arrays.`,
    );
  }
  let doc: unknown;
  try {
    doc = JSON.parse(body);
  } catch {
    return refuse('SBOM_INVALID', `The SBOM is not valid JSON. ${EXPORT_HINT}.`);
  }
  if (!isRecord(doc)) {
    return refuse('SBOM_INVALID', 'The SBOM is not a JSON object.');
  }
  const read = readDocument(doc);
  if ('code' in read) return { refusal: read };
  return toInventory(read, options.maxPackages ?? REPORT_BOUNDS.dependencies);
}

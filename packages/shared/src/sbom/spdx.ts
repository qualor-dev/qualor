/**
 * The SPDX JSON reader (spec §6.3): SPDX 2.2 and 2.3 documents (`SPDXID: SPDXRef-DOCUMENT`),
 * checked with lenient zod schemas that cover only the fields read. The relationships are indexed
 * once, by the element they start at, so every package costs a map lookup (input is up to 64 MiB:
 * nothing here may be quadratic).
 */
import { z } from 'zod';
import { cleanText, cutText, licenseList, SBOM_BOUNDS } from './fields';
import { parsePurl } from './purl';
import type { SbomComponent, SbomDocument, SbomRefusal } from './types';

export const SPDX_VERSIONS: readonly string[] = ['SPDX-2.2', 'SPDX-2.3'];

const DOCUMENT_ID = 'SPDXRef-DOCUMENT';
/** Trivy's OS package ids start with this; the purpose says it for others: SPDX 2.3's `OPERATING_SYSTEM`, and the `OPERATING-SYSTEM` some tools write. */
const OS_PURPOSES: ReadonlySet<string> = new Set(['OPERATING_SYSTEM', 'OPERATING-SYSTEM']);
const OS_ID_PREFIX = 'SPDXRef-OperatingSystem-';
const BUILT_FROM = 'built package from: ';
/** A longer `sourceInfo` is not Trivy's one-line form. */
const SOURCE_INFO_CHARS = 1_024;
/** How many invalid purls the warning names. */
const NAMED_INVALID_PURLS = 3;

const packageSchema = z.object({
  SPDXID: z.string(),
  name: z.string().optional(),
  versionInfo: z.string().optional(),
  licenseConcluded: z.string().optional(),
  licenseDeclared: z.string().optional(),
  sourceInfo: z.string().optional(),
  primaryPackagePurpose: z.string().optional(),
  externalRefs: z
    .array(
      z.object({
        referenceCategory: z.string().optional(),
        referenceType: z.string().optional(),
        referenceLocator: z.string().optional(),
      }),
    )
    .optional(),
});
type Package = z.infer<typeof packageSchema>;

const relationshipSchema = z.object({
  spdxElementId: z.string(),
  relatedSpdxElement: z.string(),
  relationshipType: z.string(),
});

const documentSchema = z.object({
  packages: z.array(z.unknown()).optional(),
  relationships: z.array(z.unknown()).optional(),
  documentDescribes: z.array(z.string()).optional(),
});

function invalid(error: z.ZodError, prefix: readonly (string | number)[]): SbomRefusal {
  const issue = error.issues[0];
  const path = [...prefix, ...(issue?.path ?? [])].map(String).join('.');
  return {
    code: 'SBOM_INVALID',
    message: `The SBOM's ${path === '' ? 'document' : path} has the wrong shape: ${issue?.message ?? 'invalid'}.`,
    path,
  };
}

function isPurlCategory(category: string | undefined): boolean {
  return category === 'PACKAGE-MANAGER' || category === 'PACKAGE_MANAGER';
}

/** The first purl a package's `PACKAGE-MANAGER` references carry, trimmed; `''` when none. */
function purlTextOf(p: Package): string {
  for (const ref of p.externalRefs ?? []) {
    if (isPurlCategory(ref.referenceCategory) && ref.referenceType === 'purl') {
      return ref.referenceLocator?.trim() ?? '';
    }
  }
  return '';
}

/** `licenseConcluded` unless it says nothing (`NOASSERTION`, `NONE`), then `licenseDeclared`. */
function licensesOf(p: Package): string[] {
  const says = (value: string | undefined): value is string => {
    const text = value?.trim();
    return text !== undefined && text !== '' && text !== 'NOASSERTION' && text !== 'NONE';
  };
  if (says(p.licenseConcluded)) return licenseList([p.licenseConcluded]);
  return says(p.licenseDeclared) ? licenseList([p.licenseDeclared]) : [];
}

/** Trivy's `built package from: <name> <version>`; any other `sourceInfo` names no source. */
function sourceOf(p: Package): SbomComponent['source'] {
  const info = p.sourceInfo;
  if (info === undefined || info.length > SOURCE_INFO_CHARS || !info.startsWith(BUILT_FROM)) {
    return null;
  }
  const rest = info.slice(BUILT_FROM.length).trim();
  const space = rest.indexOf(' ');
  if (space < 1) return null;
  const name = cleanText(rest.slice(0, space));
  const version = cleanText(rest.slice(space + 1).trim());
  return name === '' || version === '' ? null : { name, version };
}

/** What the relationships say, indexed once. */
interface Graph {
  /** The elements the document describes, in order. */
  described: string[];
  /** Per element, the elements it `DEPENDS_ON`. */
  dependsOn: Map<string, Set<string>>;
}

function indexRelationships(items: readonly unknown[]): Graph | SbomRefusal {
  const described: string[] = [];
  const dependsOn = new Map<string, Set<string>>();
  for (let i = 0; i < items.length; i++) {
    const parsed = relationshipSchema.safeParse(items[i]);
    if (!parsed.success) return invalid(parsed.error, ['relationships', i]);
    const r = parsed.data;
    if (r.relationshipType === 'DESCRIBES' && r.spdxElementId === DOCUMENT_ID) {
      described.push(r.relatedSpdxElement);
    } else if (r.relationshipType === 'DESCRIBED_BY' && r.relatedSpdxElement === DOCUMENT_ID) {
      described.push(r.spdxElementId);
    } else if (r.relationshipType === 'DEPENDS_ON') {
      let targets = dependsOn.get(r.spdxElementId);
      if (targets === undefined) {
        targets = new Set();
        dependsOn.set(r.spdxElementId, targets);
      }
      targets.add(r.relatedSpdxElement);
    }
  }
  return { described, dependsOn };
}

/** The document's spdxVersion, once its header is one this reader takes; else the refusal. */
function checkedVersion(doc: Record<string, unknown>): string | SbomRefusal {
  const spdxVersion = doc.spdxVersion;
  if (typeof spdxVersion !== 'string') {
    return {
      code: 'SBOM_INVALID',
      message: 'The SPDX document has no spdxVersion.',
      path: 'spdxVersion',
    };
  }
  if (!SPDX_VERSIONS.includes(spdxVersion)) {
    return {
      code: 'SBOM_FORMAT_UNSUPPORTED',
      message: `${cutText(cleanText(spdxVersion), 32)} is not read. Export the SBOM as SPDX 2.3 JSON (or 2.2).`,
    };
  }
  if (doc.SPDXID !== DOCUMENT_ID) {
    return {
      code: 'SBOM_INVALID',
      message: `The SPDX document's SPDXID is not ${DOCUMENT_ID}.`,
      path: 'SPDXID',
    };
  }
  return spdxVersion;
}

/** The packages, each checked when read, so a bad one is named by its index. */
function parsePackages(items: readonly unknown[]): Package[] | SbomRefusal {
  const packages: Package[] = [];
  for (let i = 0; i < items.length; i++) {
    const parsed = packageSchema.safeParse(items[i]);
    if (!parsed.success) return invalid(parsed.error, ['packages', i]);
    packages.push(parsed.data);
  }
  return packages;
}

/** The subject package's name and version, bounded and cleaned; null without a name. */
function subjectOf(p: Package | undefined): SbomDocument['subject'] {
  if (p === undefined) return null;
  const name = cleanText(cutText(p.name ?? '', SBOM_BOUNDS.subject)).trim();
  const version = cleanText(cutText(p.versionInfo ?? '', SBOM_BOUNDS.version)).trim();
  return name === '' ? null : { name, version: version === '' ? null : version };
}

/**
 * Whether a package is one the subject `DEPENDS_ON`; null for every package when there is no
 * subject, or no `DEPENDS_ON` at all.
 */
function directness(subjectId: string | undefined, graph: Graph): (id: string) => boolean | null {
  if (subjectId === undefined || graph.dependsOn.size === 0) return () => null;
  const subjectDepends = graph.dependsOn.get(subjectId);
  return (id) => subjectDepends?.has(id) ?? false;
}

/** Trivy's OS package id, or a purpose that names an operating system. */
function isOperatingSystem(p: Package): boolean {
  return (
    p.SPDXID.startsWith(OS_ID_PREFIX) ||
    (p.primaryPackagePurpose !== undefined && OS_PURPOSES.has(p.primaryPackagePurpose))
  );
}

/** An operating-system package's name and version, bounded and cleaned; null without a name. */
function operatingSystemOf(p: Package): SbomDocument['operatingSystems'][number] | null {
  const name = cleanText(cutText(p.name ?? '', SBOM_BOUNDS.name)).trim();
  if (name === '') return null;
  return { name, version: cleanText(cutText(p.versionInfo ?? '', SBOM_BOUNDS.version)).trim() };
}

/** What the packages other than the subject hold. */
interface Contents {
  components: SbomComponent[];
  operatingSystems: SbomDocument['operatingSystems'];
  invalidPurls: string[];
  noPurl: number;
}

/** Reads a package that is neither the subject nor an operating system into `out`. */
function readPackage(p: Package, direct: (id: string) => boolean | null, out: Contents): void {
  const text = purlTextOf(p);
  if (text === '') {
    out.noPurl++;
    return;
  }
  const purl = parsePurl(text);
  if (purl === null) {
    out.noPurl++;
    if (out.invalidPurls.length < NAMED_INVALID_PURLS) {
      out.invalidPurls.push(cutText(cleanText(text), 200));
    }
    return;
  }
  out.components.push({
    purl,
    path: '',
    licenses: licensesOf(p),
    direct: direct(p.SPDXID),
    source: sourceOf(p),
  });
}

/** Reads every package but the subject, by kind: an operating system, or a package. */
function contentsOf(
  packages: readonly Package[],
  subjectId: string | undefined,
  direct: (id: string) => boolean | null,
): Contents {
  const out: Contents = { components: [], operatingSystems: [], invalidPurls: [], noPurl: 0 };
  for (const p of packages) {
    if (p.SPDXID === subjectId) continue;
    if (isOperatingSystem(p)) {
      const os = operatingSystemOf(p);
      if (os !== null) out.operatingSystems.push(os);
      continue;
    }
    readPackage(p, direct, out);
  }
  return out;
}

export function readSpdx(doc: Record<string, unknown>): SbomDocument | SbomRefusal {
  const spdxVersion = checkedVersion(doc);
  if (typeof spdxVersion !== 'string') return spdxVersion;
  const top = documentSchema.safeParse(doc);
  if (!top.success) return invalid(top.error, []);

  const graph = indexRelationships(top.data.relationships ?? []);
  if ('code' in graph) return graph;
  const describedIds = [...graph.described, ...(top.data.documentDescribes ?? [])];

  const packages = parsePackages(top.data.packages ?? []);
  if (!Array.isArray(packages)) return packages;
  const byId = new Map<string, Package>();
  for (const p of packages) if (!byId.has(p.SPDXID)) byId.set(p.SPDXID, p);

  // The subject: the first described element that is a package.
  const subjectId = describedIds.find((id) => byId.has(id));
  const subject = subjectOf(subjectId === undefined ? undefined : byId.get(subjectId));
  const contents = contentsOf(packages, subjectId, directness(subjectId, graph));

  return {
    format: `SPDX ${spdxVersion.slice('SPDX-'.length)}`,
    subject,
    operatingSystems: contents.operatingSystems,
    components: contents.components,
    skipped: { noPurl: contents.noPurl, unsupportedType: 0 },
    invalidPurls: contents.invalidPurls,
    tooDeep: 0,
  };
}

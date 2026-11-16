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
/** Trivy's OS package ids start with this; the purpose `OPERATING-SYSTEM` says it for others. */
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

export function readSpdx(doc: Record<string, unknown>): SbomDocument | SbomRefusal {
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
  const top = documentSchema.safeParse(doc);
  if (!top.success) return invalid(top.error, []);

  const graph = indexRelationships(top.data.relationships ?? []);
  if ('code' in graph) return graph;
  const describedIds = [...graph.described, ...(top.data.documentDescribes ?? [])];

  // The packages, each checked when read, so a bad one is named by its index.
  const packages: Package[] = [];
  for (let i = 0; i < (top.data.packages?.length ?? 0); i++) {
    const parsed = packageSchema.safeParse(top.data.packages?.[i]);
    if (!parsed.success) return invalid(parsed.error, ['packages', i]);
    packages.push(parsed.data);
  }
  const byId = new Map<string, Package>();
  for (const p of packages) if (!byId.has(p.SPDXID)) byId.set(p.SPDXID, p);

  // The subject: the first described element that is a package.
  const subjectId = describedIds.find((id) => byId.has(id));
  const subjectPackage = subjectId === undefined ? undefined : byId.get(subjectId);
  let subject: SbomDocument['subject'] = null;
  if (subjectPackage !== undefined) {
    const name = cleanText(cutText(subjectPackage.name ?? '', SBOM_BOUNDS.subject)).trim();
    const version = cleanText(
      cutText(subjectPackage.versionInfo ?? '', SBOM_BOUNDS.version),
    ).trim();
    if (name !== '') subject = { name, version: version === '' ? null : version };
  }
  const subjectDepends = subjectId === undefined ? undefined : graph.dependsOn.get(subjectId);

  const components: SbomComponent[] = [];
  const operatingSystems: SbomDocument['operatingSystems'] = [];
  const invalidPurls: string[] = [];
  let noPurl = 0;

  for (const p of packages) {
    if (p.SPDXID === subjectId) continue;
    if (p.SPDXID.startsWith(OS_ID_PREFIX) || p.primaryPackagePurpose === 'OPERATING-SYSTEM') {
      const name = cleanText(cutText(p.name ?? '', SBOM_BOUNDS.name)).trim();
      if (name !== '') {
        operatingSystems.push({
          name,
          version: cleanText(cutText(p.versionInfo ?? '', SBOM_BOUNDS.version)).trim(),
        });
      }
      continue;
    }
    const text = purlTextOf(p);
    if (text === '') {
      noPurl++;
      continue;
    }
    const purl = parsePurl(text);
    if (purl === null) {
      noPurl++;
      if (invalidPurls.length < NAMED_INVALID_PURLS) {
        invalidPurls.push(cutText(cleanText(text), 200));
      }
      continue;
    }
    components.push({
      purl,
      path: '',
      licenses: licensesOf(p),
      direct:
        subjectId === undefined || graph.dependsOn.size === 0
          ? null
          : (subjectDepends?.has(p.SPDXID) ?? false),
      source: sourceOf(p),
    });
  }

  return {
    format: `SPDX ${spdxVersion.slice('SPDX-'.length)}`,
    subject,
    operatingSystems,
    components,
    skipped: { noPurl, unsupportedType: 0 },
    invalidPurls,
    tooDeep: 0,
  };
}

/**
 * The CycloneDX JSON reader (spec §6.2): specVersion 1.2 to 1.7, checked with lenient zod schemas
 * that cover only the fields read. A component's schema is not recursive: the walk reads nested
 * `components` as `unknown[]` and checks each child when it reaches it, so no schema copies the
 * whole document, and the walk keeps at most {@link SBOM_MAX_DEPTH} frames.
 */
import { z } from 'zod';
import { cleanText, cutText, licenseList, SBOM_BOUNDS } from './fields';
import { parsePurl } from './purl';
import { SBOM_MAX_DEPTH, type SbomComponent, type SbomDocument, type SbomRefusal } from './types';

export const CYCLONEDX_SPEC_VERSIONS: readonly string[] = [
  '1.2',
  '1.3',
  '1.4',
  '1.5',
  '1.6',
  '1.7',
];

/** Component types that describe no package: counted as `unsupportedType`. */
const UNSUPPORTED_TYPES: ReadonlySet<string> = new Set([
  'file',
  'data',
  'machine-learning-model',
  'cryptographic-asset',
  'device',
  'firmware',
  'platform',
]);

/** The properties that name a package's path, first match wins. */
const PATH_PROPERTIES = ['aquasecurity:trivy:FilePath', 'syft:location:0:path'];
const TRIVY = 'aquasecurity:trivy:';

/** How many invalid purls the warning names. */
const NAMED_INVALID_PURLS = 3;

const licenseChoice = z.object({
  license: z.object({ id: z.string().optional(), name: z.string().optional() }).optional(),
  expression: z.string().optional(),
});

/** What is read of every component. */
const componentSchema = z.object({
  type: z.string().optional(),
  'bom-ref': z.string().optional(),
  purl: z.string().optional(),
  licenses: z.array(licenseChoice).optional(),
  // CycloneDX 1.2 to 1.4 do not require a property's name; one without is skipped.
  properties: z
    .array(z.object({ name: z.string().optional(), value: z.string().optional() }))
    .optional(),
  evidence: z
    .object({ occurrences: z.array(z.object({ location: z.string() })).optional() })
    .optional(),
  components: z.array(z.unknown()).optional(),
});
type Component = z.infer<typeof componentSchema>;

/** What is read, besides, of the subject and of an operating-system component. */
const namedSchema = z.object({
  group: z.string().optional(),
  name: z.string().optional(),
  version: z.string().optional(),
});

const bomSchema = z.object({
  metadata: z.object({ component: z.unknown().optional() }).optional(),
  components: z.array(z.unknown()).optional(),
  dependencies: z
    .array(z.object({ ref: z.string(), dependsOn: z.array(z.string()).optional() }))
    .optional(),
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

function named(
  value: unknown,
  prefix: readonly (string | number)[],
): z.infer<typeof namedSchema> | SbomRefusal {
  const parsed = namedSchema.safeParse(value);
  return parsed.success ? parsed.data : invalid(parsed.error, prefix);
}

/** The first non-empty value of each property name. */
function propertiesOf(c: Component): Map<string, string> {
  const map = new Map<string, string>();
  for (const p of c.properties ?? []) {
    if (p.name === undefined || p.value === undefined || p.value === '' || map.has(p.name))
      continue;
    map.set(p.name, p.value);
  }
  return map;
}

function pathOf(c: Component, properties: ReadonlyMap<string, string>): string {
  const raw =
    PATH_PROPERTIES.map((name) => properties.get(name)).find((v) => v !== undefined) ??
    c.evidence?.occurrences?.[0]?.location ??
    '';
  return cutText(cleanText(raw), SBOM_BOUNDS.path);
}

function licensesOf(c: Component): string[] {
  const raw: string[] = [];
  for (const choice of c.licenses ?? []) {
    const licence = choice.license?.id ?? choice.license?.name;
    if (licence !== undefined) raw.push(licence);
    if (choice.expression !== undefined) raw.push(choice.expression);
  }
  return licenseList(raw);
}

/** Trivy's source package properties: `[SrcEpoch:]SrcVersion[-SrcRelease]`, the epoch left out when 0. */
function trivySource(properties: ReadonlyMap<string, string>): SbomComponent['source'] {
  const name = properties.get(`${TRIVY}SrcName`);
  const version = properties.get(`${TRIVY}SrcVersion`);
  if (name === undefined || version === undefined) return null;
  const epoch = properties.get(`${TRIVY}SrcEpoch`);
  const release = properties.get(`${TRIVY}SrcRelease`);
  const prefix = epoch === undefined || /^0*$/.test(epoch) ? '' : `${epoch}:`;
  const suffix = release === undefined ? '' : `-${release}`;
  return { name: cleanText(name), version: cleanText(`${prefix}${version}${suffix}`) };
}

/** The nested `components` of a value that is not checked (below the depth limit). */
function nestedOf(value: unknown): readonly unknown[] | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const nested = (value as { components?: unknown }).components;
  return Array.isArray(nested) ? nested : undefined;
}

/** Every component under these, at any depth, counted without being read. */
function countComponents(items: readonly unknown[]): number {
  let count = 0;
  const pending: (readonly unknown[])[] = [items];
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    count += next.length;
    for (const item of next) {
      const nested = nestedOf(item);
      if (nested !== undefined) pending.push(nested);
    }
  }
  return count;
}

interface Frame {
  items: readonly unknown[];
  index: number;
  depth: number;
  path: readonly (string | number)[];
}

/** The document's specVersion when it is one this reader takes; else the refusal. */
function specVersionOf(doc: Record<string, unknown>): string | SbomRefusal {
  const specVersion = doc.specVersion;
  if (typeof specVersion !== 'string') {
    return {
      code: 'SBOM_INVALID',
      message: 'The CycloneDX document has no specVersion.',
      path: 'specVersion',
    };
  }
  if (!CYCLONEDX_SPEC_VERSIONS.includes(specVersion)) {
    return {
      code: 'SBOM_FORMAT_UNSUPPORTED',
      message: `CycloneDX ${cutText(cleanText(specVersion), 32)} is not read. Export the SBOM as CycloneDX JSON 1.2 to 1.7.`,
    };
  }
  return specVersion;
}

/** What `metadata.component` says: the subject, and the bom-ref and purl that name it. */
interface Subject {
  subject: SbomDocument['subject'];
  ref: string | undefined;
  purl: string | undefined;
}

function subjectOf(metadataComponent: unknown): Subject | SbomRefusal {
  if (metadataComponent === undefined) return { subject: null, ref: undefined, purl: undefined };
  const where = ['metadata', 'component'];
  const parsed = componentSchema.safeParse(metadataComponent);
  if (!parsed.success) return invalid(parsed.error, where);
  const names = named(metadataComponent, where);
  if ('code' in names) return names;
  const name = [names.group, names.name]
    .map((part) => cleanText(part ?? '').trim())
    .filter((part) => part !== '')
    .join('/');
  const version = cleanText(names.version ?? '').trim();
  return {
    subject: name === '' ? null : { name, version: version === '' ? null : version },
    ref: parsed.data['bom-ref'],
    purl: parsed.data.purl?.trim(),
  };
}

/** The subject's direct dependencies, when the graph names the subject; else null. */
function directOf(
  dependencies: z.infer<typeof bomSchema>['dependencies'],
  subjectRef: string | undefined,
): Set<string> | null {
  let direct: Set<string> | null = null;
  for (const dependency of dependencies ?? []) {
    if (subjectRef === undefined || dependency.ref !== subjectRef) continue;
    direct ??= new Set();
    for (const ref of dependency.dependsOn ?? []) direct.add(ref);
  }
  return direct;
}

/**
 * The walk over `components`, depth first: each component is checked when it is reached, its
 * children are queued (or counted, at {@link SBOM_MAX_DEPTH}), and it is read by its kind.
 */
class ComponentWalk {
  readonly components: SbomComponent[] = [];
  readonly operatingSystems: SbomDocument['operatingSystems'] = [];
  readonly invalidPurls: string[] = [];
  noPurl = 0;
  unsupportedType = 0;
  tooDeep = 0;
  private readonly stack: Frame[] = [];
  private readonly subject: Subject;
  private readonly direct: Set<string> | null;

  constructor(subject: Subject, direct: Set<string> | null) {
    this.subject = subject;
    this.direct = direct;
  }

  /** Walks the top-level components; the refusal of the first one with the wrong shape. */
  run(items: readonly unknown[] | undefined): SbomRefusal | null {
    if (items !== undefined) this.stack.push({ items, index: 0, depth: 1, path: ['components'] });
    for (let frame = this.stack.at(-1); frame !== undefined; frame = this.stack.at(-1)) {
      if (frame.index >= frame.items.length) {
        this.stack.pop();
        continue;
      }
      const index = frame.index++;
      const item = frame.items[index];
      const parsed = componentSchema.safeParse(item);
      if (!parsed.success) return invalid(parsed.error, [...frame.path, index]);
      this.queueChildren(frame, index, parsed.data);
      const refusal = this.read(item, parsed.data, frame, index);
      if (refusal !== null) return refusal;
    }
    return null;
  }

  /** Queues the children of the component at `index`, or counts them below the depth limit. */
  private queueChildren(frame: Frame, index: number, c: Component): void {
    if (c.components === undefined || c.components.length === 0) return;
    if (frame.depth >= SBOM_MAX_DEPTH) {
      this.tooDeep += countComponents(c.components);
    } else {
      this.stack.push({
        items: c.components,
        index: 0,
        depth: frame.depth + 1,
        path: [...frame.path, index, 'components'],
      });
    }
  }

  /**
   * Reads one component by its kind: the subject is left out, an operating system names the
   * distribution, a type that describes no package is counted, anything else is a package.
   */
  private read(item: unknown, c: Component, frame: Frame, index: number): SbomRefusal | null {
    if (this.subject.ref !== undefined && c['bom-ref'] === this.subject.ref) return null;
    if (c.type === 'operating-system')
      return this.readOperatingSystem(item, [...frame.path, index]);
    if (c.type !== undefined && UNSUPPORTED_TYPES.has(c.type)) {
      this.unsupportedType++;
      return null;
    }
    this.readPackage(c);
    return null;
  }

  /** An operating system, read when it has a name; `where` names its JSON path. */
  private readOperatingSystem(
    item: unknown,
    where: readonly (string | number)[],
  ): SbomRefusal | null {
    const names = named(item, where);
    if ('code' in names) return names;
    const name = cleanText(names.name ?? '').trim();
    if (name !== '') {
      this.operatingSystems.push({ name, version: cleanText(names.version ?? '').trim() });
    }
    return null;
  }

  /** A package: counted without purl when it has none or one that does not parse. */
  private readPackage(c: Component): void {
    const text = c.purl?.trim() ?? '';
    if (text === '') {
      this.noPurl++;
      return;
    }
    const purl = parsePurl(text);
    if (purl === null) {
      this.noPurl++;
      if (this.invalidPurls.length < NAMED_INVALID_PURLS)
        this.invalidPurls.push(cutText(cleanText(text), 200));
      return;
    }
    if (this.subject.purl !== undefined && text === this.subject.purl) return;
    const properties = propertiesOf(c);
    const ref = c['bom-ref'];
    this.components.push({
      purl,
      path: pathOf(c, properties),
      licenses: licensesOf(c),
      direct: this.direct === null ? null : ref !== undefined && this.direct.has(ref),
      source: trivySource(properties),
    });
  }
}

export function readCycloneDx(doc: Record<string, unknown>): SbomDocument | SbomRefusal {
  const specVersion = specVersionOf(doc);
  if (typeof specVersion !== 'string') return specVersion;
  const bom = bomSchema.safeParse(doc);
  if (!bom.success) return invalid(bom.error, []);
  const subject = subjectOf(bom.data.metadata?.component);
  if ('code' in subject) return subject;

  const walk = new ComponentWalk(subject, directOf(bom.data.dependencies, subject.ref));
  const refusal = walk.run(bom.data.components);
  if (refusal !== null) return refusal;
  return {
    format: `CycloneDX ${specVersion}`,
    subject: subject.subject,
    operatingSystems: walk.operatingSystems,
    components: walk.components,
    skipped: { noPurl: walk.noPurl, unsupportedType: walk.unsupportedType },
    invalidPurls: walk.invalidPurls,
    tooDeep: walk.tooDeep,
  };
}

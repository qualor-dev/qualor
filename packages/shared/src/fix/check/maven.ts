/**
 * B1 for Maven (spec §12): a fix may change the `<version>` of the `groupId:artifactId`
 * dependency in the project's `<dependencies>` or `<dependencyManagement><dependencies>`, or the
 * `<properties>` child that version references, or add one managed `<dependency>` with exactly
 * `groupId`, `artifactId`, `version` (and an optional `scope`). Undoing those changes must leave
 * the base pom, element by element; anything else (`<plugins>`, `<repositories>`, `<build>`,
 * `<profiles>`, `<parent>`, …) is `other_change`.
 */
import { SaxesParser } from 'saxes';
import { belowTarget } from './lock-entries';
import {
  FIX_CHECK_OK,
  fixRefused,
  type FixCheckContext,
  type FixCheckResult,
  type FixFileChange,
  type FixRule,
} from './types';
import { stripBom } from './values';

/** One element of a pom: its name, its text (trimmed), its attributes and its child elements. */
export interface PomElement {
  name: string;
  /** The element's own text and CDATA, joined and trimmed; comments dropped. */
  text: string;
  /** Its attributes, as written (compared too: `combine.self` and the like change merging). */
  attributes: Record<string, string>;
  children: PomElement[];
}

function pomElement(name: string, attributes: Record<string, string>): PomElement {
  return {
    name,
    text: '',
    attributes: Object.fromEntries(Object.entries(attributes)),
    children: [],
  };
}

/**
 * A pom read with saxes, which expands no external entity: a DOCTYPE throws, as does an entity
 * other than the predefined ones and character references, or anything that is not well formed.
 * Comments and processing instructions are dropped; each element's text is trimmed.
 */
export function readPom(text: string): PomElement {
  const parser = new SaxesParser({ xmlns: false });
  const stack: PomElement[] = [];
  const texts: string[][] = [];
  let root: PomElement | null = null;
  parser.on('doctype', () => {
    throw new Error('a DOCTYPE in a pom');
  });
  parser.on('opentag', (tag) => {
    const element = pomElement(tag.name, tag.attributes as Record<string, string>);
    const parent = stack.at(-1);
    if (parent === undefined) root = element;
    else parent.children.push(element);
    stack.push(element);
    texts.push([]);
  });
  const addText = (t: string) => texts.at(-1)?.push(t);
  parser.on('text', addText);
  parser.on('cdata', addText);
  parser.on('closetag', () => {
    const element = stack.pop();
    const parts = texts.pop() ?? [];
    if (element !== undefined) element.text = parts.join('').trim();
  });
  parser.write(stripBom(text)).close();
  if (root === null) throw new Error('a pom without a root element');
  return root;
}

function childrenNamed(element: PomElement, name: string): PomElement[] {
  return element.children.filter((child) => child.name === name);
}

function childText(element: PomElement, name: string): string | null {
  return element.children.find((child) => child.name === name)?.text ?? null;
}

interface Coordinates {
  groupId: string;
  artifactId: string;
}

/** `groupId:artifactId`; null without a `:`. */
function coordinates(ga: string): Coordinates | null {
  const colon = ga.indexOf(':');
  if (colon <= 0 || colon === ga.length - 1) return null;
  return { groupId: ga.slice(0, colon), artifactId: ga.slice(colon + 1) };
}

/** Review Focus 3: a dependency is the package by both `groupId` and `artifactId`. */
function isPackage(dependency: PomElement, ga: Coordinates): boolean {
  return (
    dependency.name === 'dependency' &&
    childText(dependency, 'groupId') === ga.groupId &&
    childText(dependency, 'artifactId') === ga.artifactId
  );
}

type PomSection = 'dependencies' | 'dependencyManagement';

/** The `<dependencies>` lists of a section of the project (each one, should there be several). */
function dependencyLists(project: PomElement, section: PomSection): PomElement[] {
  if (section === 'dependencies') return childrenNamed(project, 'dependencies');
  return childrenNamed(project, 'dependencyManagement').flatMap((managed) =>
    childrenNamed(managed, 'dependencies'),
  );
}

function packageDependencies(
  project: PomElement,
  section: PomSection,
  ga: Coordinates,
): PomElement[] {
  return dependencyLists(project, section).flatMap((list) =>
    list.children.filter((dependency) => isPackage(dependency, ga)),
  );
}

/** `${name}` → `name`; null for any other text. */
function propertyReference(version: string): string | null {
  return version.startsWith('${') &&
    version.endsWith('}') &&
    version.indexOf('}') === version.length - 1
    ? version.slice(2, -1)
    : null;
}

/** The project's `<properties>` children named `name`. */
function propertyElements(project: PomElement, name: string): readonly PomElement[] {
  let index = PROPERTY_INDEX.get(project);
  if (index === undefined) {
    index = new Map();
    for (const properties of childrenNamed(project, 'properties')) {
      for (const property of properties.children) {
        const list = index.get(property.name);
        if (list === undefined) index.set(property.name, [property]);
        else list.push(property);
      }
    }
    PROPERTY_INDEX.set(project, index);
  }
  return index.get(name) ?? [];
}

/**
 * The project's `<properties>` children by name, built once per pom, so looking up the property of
 * each of many dependencies stays linear. The checks change texts, never these elements.
 */
const PROPERTY_INDEX = new WeakMap<PomElement, Map<string, PomElement[]>>();

/** A property's value in this pom; null when it is not defined here exactly once. */
function propertyValue(project: PomElement, name: string): string | null {
  const found = propertyElements(project, name);
  return found.length === 1 ? (found[0]?.text ?? null) : null;
}

/** A dependency's version: its text, or the value of the one property it references. */
function resolvedVersion(project: PomElement, dependency: PomElement): string | null {
  const version = childText(dependency, 'version');
  if (version === null) return null;
  const property = propertyReference(version);
  return property === null ? version : propertyValue(project, property);
}

/**
 * Where a pom declares the version of `groupId:artifactId`: the first such dependency with a
 * `<version>` in `<dependencies>`, else in `<dependencyManagement><dependencies>`, else a
 * dependency without a version (managed elsewhere). `property` names a `${property}` reference;
 * `version` is then the property's value in this pom, or null when the pom does not define it
 * (a parent does, Ruling F13). Null when the pom does not name the package.
 */
export function pomDependencyVersion(
  pom: PomElement,
  ga: string,
): { version: string | null; property: string | null; section: PomSection } | null {
  const coords = coordinates(ga);
  if (coords === null) return null;
  let unversioned: PomSection | null = null;
  for (const section of ['dependencies', 'dependencyManagement'] as const) {
    for (const dependency of packageDependencies(pom, section, coords)) {
      const text = childText(dependency, 'version');
      if (text === null) {
        unversioned ??= section;
        continue;
      }
      const property = propertyReference(text);
      return { version: resolvedVersion(pom, dependency), property, section };
    }
  }
  return unversioned === null ? null : { version: null, property: null, section: unversioned };
}

/**
 * A plain version: letters, digits, `.`, `-`, `_` and `+` only (so no range `[`/`(`, no `${…}`,
 * no white space, and no `/` or `:`, which Maven builds repository paths from), and not the
 * meta-versions `LATEST` or `RELEASE`.
 */
const MAVEN_VERSION = /^[\w.+-]+$/;

function isPlainMavenVersion(version: string): boolean {
  const upper = version.toUpperCase();
  return MAVEN_VERSION.test(version) && upper !== 'LATEST' && upper !== 'RELEASE';
}

const MANAGED_SCOPES = new Set(['compile', 'provided', 'runtime', 'test']);
const MANAGED_REQUIRED = ['groupId', 'artifactId', 'version'];

/** An added managed entry holds exactly groupId, artifactId, version and an optional scope. */
function managedEntryRule(entry: PomElement): FixRule | null {
  const names = entry.children.map((child) => child.name);
  const plain = entry.children.every(
    (child) => child.children.length === 0 && Object.keys(child.attributes).length === 0,
  );
  const scope = childText(entry, 'scope');
  const shape =
    plain &&
    Object.keys(entry.attributes).length === 0 &&
    new Set(names).size === names.length &&
    MANAGED_REQUIRED.every((name) => names.includes(name)) &&
    names.length === MANAGED_REQUIRED.length + (scope === null ? 0 : 1) &&
    (scope === null || MANAGED_SCOPES.has(scope));
  if (!shape) return 'other_change';
  return isPlainMavenVersion(childText(entry, 'version') ?? '') ? null : 'bad_spec';
}

function isEmptyElement(element: PomElement): boolean {
  return (
    element.children.length === 0 &&
    element.text === '' &&
    Object.keys(element.attributes).length === 0
  );
}

function removeChild(parent: PomElement, child: PomElement): void {
  parent.children = parent.children.filter((c) => c !== child);
}

/** Drops the `<dependencyManagement>` and `<dependencies>` the change created for the entry. */
function pruneCreatedManagement(base: PomElement, next: PomElement): void {
  const baseManaged = childrenNamed(base, 'dependencyManagement');
  const hadLists = baseManaged.some((m) => childrenNamed(m, 'dependencies').length > 0);
  const emptyNamed = (name: string) => (c: PomElement) => c.name === name && isEmptyElement(c);
  if (!hadLists) {
    for (const managed of childrenNamed(next, 'dependencyManagement')) {
      managed.children = managed.children.filter((c) => !emptyNamed('dependencies')(c));
    }
  }
  if (baseManaged.length === 0) {
    next.children = next.children.filter((c) => !emptyNamed('dependencyManagement')(c));
  }
}

/**
 * The one managed `<dependency>` a fix may add for the package (its shape checked, then taken
 * out with any section created for it), when the base manages the package nowhere. Any other
 * added entry is left for the final comparison.
 */
function takeAddedManaged(base: PomElement, next: PomElement, ga: Coordinates): FixRule | null {
  if (packageDependencies(base, 'dependencyManagement', ga).length > 0) return null;
  const lists = dependencyLists(next, 'dependencyManagement');
  const added = lists.flatMap((list) =>
    list.children.filter((d) => isPackage(d, ga)).map((entry) => ({ list, entry })),
  );
  const [only] = added;
  if (added.length !== 1 || only === undefined) return null;
  const rule = managedEntryRule(only.entry);
  if (rule !== null) return rule;
  removeChild(only.list, only.entry);
  pruneCreatedManagement(base, next);
  return null;
}

/**
 * A changed `<version>` of a package dependency (paired by order in its section) must be plain,
 * and is put back to the base's for the final comparison.
 */
function restoreVersion(base: PomElement, next: PomElement): FixRule | null {
  const before = base.children.find((child) => child.name === 'version');
  const after = next.children.find((child) => child.name === 'version');
  if (before === undefined || after === undefined || before.text === after.text) return null;
  if (!isPlainMavenVersion(after.text)) return 'bad_spec';
  after.text = before.text;
  return null;
}

/** {@link restoreVersion} over the package's dependencies of both sections. */
function restoreVersions(base: PomElement, next: PomElement, ga: Coordinates): FixRule | null {
  for (const section of ['dependencies', 'dependencyManagement'] as const) {
    const before = packageDependencies(base, section, ga);
    const after = packageDependencies(next, section, ga);
    if (before.length !== after.length) continue;
    for (const [i, dependency] of before.entries()) {
      const counterpart = after[i];
      const rule = counterpart === undefined ? null : restoreVersion(dependency, counterpart);
      if (rule !== null) return rule;
    }
  }
  return null;
}

/** The properties the package's dependencies reference (`${name}`) in the base. */
function referencedProperties(base: PomElement, ga: Coordinates): Set<string> {
  const names = new Set<string>();
  for (const section of ['dependencies', 'dependencyManagement'] as const) {
    for (const dependency of packageDependencies(base, section, ga)) {
      const property = propertyReference(childText(dependency, 'version') ?? '');
      if (property !== null) names.add(property);
    }
  }
  return names;
}

/** A changed referenced property, defined once on both sides, must be plain; it is put back. */
function restoreProperties(base: PomElement, next: PomElement, ga: Coordinates): FixRule | null {
  for (const name of referencedProperties(base, ga)) {
    const before = propertyElements(base, name);
    const after = propertyElements(next, name);
    const [b] = before;
    const [a] = after;
    if (before.length !== 1 || after.length !== 1 || b === undefined || a === undefined) continue;
    if (a.text === b.text) continue;
    if (!isPlainMavenVersion(a.text)) return 'bad_spec';
    a.text = b.text;
  }
  return null;
}

function sameAttributes(a: Record<string, string>, b: Record<string, string>): boolean {
  const keys = Object.keys(a);
  return (
    keys.length === Object.keys(b).length &&
    keys.every((key) => Object.hasOwn(b, key) && a[key] === b[key])
  );
}

/** Element-by-element equality (names, text, attributes, children in order), without recursion. */
function samePom(a: PomElement, b: PomElement): boolean {
  const pending: [PomElement, PomElement][] = [[a, b]];
  for (let pair = pending.pop(); pair !== undefined; pair = pending.pop()) {
    const [x, y] = pair;
    if (x.name !== y.name || x.text !== y.text || x.children.length !== y.children.length) {
      return false;
    }
    if (!sameAttributes(x.attributes, y.attributes)) return false;
    x.children.forEach((child, i) => {
      const other = y.children[i];
      if (other !== undefined) pending.push([child, other]);
    });
  }
  return true;
}

/** The package's resolved versions in a pom, both sections. */
function packageVersions(project: PomElement, ga: Coordinates): string[] {
  return (['dependencies', 'dependencyManagement'] as const)
    .flatMap((section) => packageDependencies(project, section, ga))
    .map((dependency) => resolvedVersion(project, dependency))
    .filter((version): version is string => version !== null);
}

/** The package's versions in the uploaded pom against the targets of this pom (Ruling F14). */
function pomBelowTarget(
  base: PomElement,
  uploaded: readonly string[],
  ga: Coordinates,
  ctx: FixCheckContext,
  path: string,
): boolean {
  const targets = ctx.targets.filter((t) => t.lockfile === path);
  if (targets.length === 0) return false;
  return belowTarget(uploaded, targets, 'maven', packageVersions(base, ga));
}

function readBothPoms(change: FixFileChange): [PomElement, PomElement] | null {
  try {
    const base = readPom(change.base);
    const next = readPom(change.next);
    return base.name === 'project' && next.name === 'project' ? [base, next] : null;
  } catch {
    return null;
  }
}

/** The allowed changes undone in `next` (or the first rule they break), then the comparison. */
function pomRule(base: PomElement, next: PomElement, ga: Coordinates): FixRule | null {
  const rule =
    takeAddedManaged(base, next, ga) ??
    restoreVersions(base, next, ga) ??
    restoreProperties(base, next, ga);
  if (rule !== null) return rule;
  return samePom(base, next) ? null : 'other_change';
}

/**
 * B1 for `pom.xml`. Allowed: the package's `<version>` in `<dependencies>` or
 * `<dependencyManagement><dependencies>`, the `<properties>` child it references, and one added
 * managed entry of exactly `groupId`, `artifactId`, `version` (optional `scope`), its sections
 * created when absent. A version with `[`, `(`, `${…}`, `LATEST` or `RELEASE` is `bad_spec`;
 * anything else changed is `other_change`; the package's versions in this pom must reach its
 * targets (`below_target`, Ruling F14).
 */
export function checkPom(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const both = readBothPoms(change);
  if (both === null) return fixRefused('unparsable', change.path);
  const ga = coordinates(ctx.packageName);
  if (ga === null) return fixRefused('other_change', change.path);
  const [base, next] = both;
  // Read before pomRule puts the allowed changes back.
  const uploaded = packageVersions(next, ga);
  const rule = pomRule(base, next, ga);
  if (rule !== null) return fixRefused(rule, change.path);
  if (pomBelowTarget(base, uploaded, ga, ctx, change.path)) {
    return fixRefused('below_target', change.path);
  }
  return FIX_CHECK_OK;
}

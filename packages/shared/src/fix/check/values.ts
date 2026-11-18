/**
 * Reading parsed documents of a fix upload, which come from an untrusted run: own keys only (never
 * a prototype's), plain objects only, and no recursion over the document's depth.
 */
import { isScalar, parseDocument, visit, type YAMLMap } from 'yaml';

export type JsonObject = Record<string, unknown>;

export function stripBom(text: string): string {
  return text.startsWith('\uFEFF') ? text.slice(1) : text;
}

/** A plain object, as `JSON.parse` and `yaml` build them (not an array, buffer or class). */
export function isObject(value: unknown): value is JsonObject {
  if (typeof value !== 'object' || value === null) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** An own property's value; undefined when the object does not have it itself. */
export function own(object: JsonObject, key: string): unknown {
  return Object.hasOwn(object, key) ? object[key] : undefined;
}

/** The value at a path of own properties; undefined when a step is missing or not an object. */
export function at(object: JsonObject, path: readonly string[]): unknown {
  let value: unknown = object;
  for (const key of path) {
    if (!isObject(value)) return undefined;
    value = own(value, key);
  }
  return value;
}

/**
 * A source as the package managers read it: the WHATWG URL parser (`new URL`), which also takes
 * `https:\\host`, `https:/host` and surrounding space; null when it does not parse.
 */
export function parseUrl(source: string): URL | null {
  try {
    return new URL(source.trim());
  } catch {
    return null;
  }
}

export function str(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

/** Sets an own data property, also for a key such as `__proto__`. */
export function setOwn(object: JsonObject, key: string, value: unknown): void {
  Object.defineProperty(object, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

type Pair = [unknown, unknown];

function pushArrays(a: unknown[], b: unknown, pending: Pair[]): boolean {
  if (!Array.isArray(b) || a.length !== b.length) return false;
  a.forEach((item, i) => pending.push([item, b[i]]));
  return true;
}

function pushObjects(a: JsonObject, b: unknown, pending: Pair[]): boolean {
  if (!isObject(b)) return false;
  const keys = Object.keys(a);
  if (keys.length !== Object.keys(b).length) return false;
  for (const key of keys) {
    if (!Object.hasOwn(b, key)) return false;
    pending.push([a[key], b[key]]);
  }
  return true;
}

/**
 * Deep equality of parsed JSON or YAML values, ignoring key order. It keeps its own stack, so a
 * deeply nested document cannot overflow the call stack.
 */
export function sameValue(a: unknown, b: unknown): boolean {
  const pending: Pair[] = [[a, b]];
  for (let pair = pending.pop(); pair !== undefined; pair = pending.pop()) {
    const [x, y] = pair;
    let same: boolean;
    if (Array.isArray(x)) same = pushArrays(x, y, pending);
    else if (isObject(x)) same = pushObjects(x, y, pending);
    else same = x === y;
    if (!same) return false;
  }
  return true;
}

export interface YamlReadOptions {
  /**
   * Applies `<<` merge keys. pnpm reads its files with js-yaml's default schema, which merges, so
   * the check must see the merged mapping pnpm sees.
   */
  merge?: boolean;
  /** `failsafe` reads every scalar as a string, as Yarn Berry reads `yarn.lock`. */
  schema?: 'core' | 'failsafe';
}

/**
 * Refuses a mapping with two equal keys, compared as text (so `1` and `'1'` collide, as they do
 * in the parsed object), with one set per mapping: linear, unlike `yaml`'s own `uniqueKeys` check.
 */
function assertUniqueKeys(map: YAMLMap): void {
  const seen = new Set<string>();
  for (const { key } of map.items) {
    const text = isScalar(key) ? String(key.value) : String(key);
    if (seen.has(text)) throw new Error(`duplicate YAML key ${text.slice(0, 100)}`);
    seen.add(text);
  }
}

/**
 * One YAML document, with the `yaml` package's safe defaults (no custom tags, at most 100 aliases)
 * and unique keys (checked in linear time, fix round 1 I1). Errors throw; warnings are not printed.
 */
export function parseYaml(text: string, options: YamlReadOptions = {}): unknown {
  const doc = parseDocument(stripBom(text), { ...options, uniqueKeys: false });
  const [error] = doc.errors;
  if (error !== undefined) throw error;
  visit(doc, { Map: (_key, map) => assertUniqueKeys(map) });
  return doc.toJS({ maxAliasCount: 100 });
}

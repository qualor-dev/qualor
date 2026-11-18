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

/** A value's number in `ids`, given on first sight. */
export function idOf<T>(ids: Map<T, number>, value: T): number {
  let id = ids.get(value);
  if (id === undefined) {
    id = ids.size;
    ids.set(value, id);
  }
  return id;
}

type Arrays = ReadonlySet<readonly string[]>;

/**
 * One value per distinct set of arrays, by reference, built once (fix round 4, R4-1): entries
 * that share their dependencies arrays share what is built from them, whatever their names.
 */
export function perArraySet<T>(
  build: (arrays: readonly (readonly string[])[]) => T,
): (arrays: Arrays) => T {
  const byArray = new Map<readonly string[], T>();
  const arrayIds = new Map<readonly string[], number>();
  const bySet = new Map<string, T>();
  return (arrays) => {
    const [only] = arrays;
    if (arrays.size === 1 && only !== undefined) {
      const value = byArray.get(only) ?? build([only]);
      byArray.set(only, value);
      return value;
    }
    const ids = [...arrays].map((array) => idOf(arrayIds, array));
    const key = ids.sort((a, b) => a - b).join(',');
    const value = bySet.get(key) ?? build([...arrays]);
    bySet.set(key, value);
    return value;
  };
}

/** A key of a tuple of strings, made by {@link tupleKeys}. */
export type TupleKey = (...parts: (string | null | undefined)[]) => string;

/**
 * Short keys for tuples of strings: each distinct string gets a number, so a key never copies a
 * long string that many entries share (fix round 4, R4-4). Keys of one returned function compare.
 */
export function tupleKeys(): TupleKey {
  const ids = new Map<string | null | undefined, number>();
  return (...parts) => {
    let key = '';
    for (const part of parts) key += `${idOf(ids, part)},`;
    return key;
  };
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

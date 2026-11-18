/**
 * Reading parsed documents of a fix upload, which come from an untrusted run: own keys only (never
 * a prototype's), plain objects only, and no recursion over the document's depth.
 */
import {
  Composer,
  isScalar,
  Lexer,
  parseDocument,
  Parser,
  Schema,
  visit,
  type CST,
  type Document,
  type Scalar,
  type YAMLMap,
} from 'yaml';

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

/** The key of a set of arrays, by reference: their ids, sorted. */
function arraySetKey(arrays: Arrays, ids: Map<readonly string[], number>): string {
  const [only] = arrays;
  if (arrays.size === 1 && only !== undefined) return String(idOf(ids, only));
  const numbers = [...arrays].map((array) => idOf(ids, array));
  return numbers.sort((a, b) => a - b).join(',');
}

/**
 * One value per distinct set of arrays among the groups, built once (fix round 4, R4-1): groups
 * that share their arrays share what is built from them, whatever their names. Fix round 5
 * (R5-1): the distinct sets' total length is summed first, and above `limit` nothing is built
 * and the answer is null.
 */
export function perArraySet<K, T>(
  groups: ReadonlyMap<K, Arrays>,
  limit: number,
  build: (arrays: readonly (readonly string[])[]) => T,
): Map<K, T> | null {
  const ids = new Map<readonly string[], number>();
  const distinct = new Map<string, Arrays>();
  const keys = new Map<K, string>();
  let planned = 0;
  for (const [group, arrays] of groups) {
    const key = arraySetKey(arrays, ids);
    if (!distinct.has(key)) {
      distinct.set(key, arrays);
      for (const array of arrays) planned += array.length;
    }
    keys.set(group, key);
  }
  if (planned > limit) return null;
  const built = new Map<string, T>();
  for (const [key, arrays] of distinct) built.set(key, build([...arrays]));
  const result = new Map<K, T>();
  for (const [group, key] of keys) {
    const value = built.get(key);
    if (value !== undefined) result.set(group, value);
  }
  return result;
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
 * Two dates (TOML dates and times, `smol-toml`'s `TomlDate`) of one class that print the same;
 * two invalid dates are equal.
 */
function sameDate(x: Date, y: unknown): boolean {
  if (!(y instanceof Date) || Object.getPrototypeOf(x) !== Object.getPrototypeOf(y)) return false;
  const invalid = Number.isNaN(x.getTime());
  if (invalid || Number.isNaN(y.getTime())) return invalid && Number.isNaN(y.getTime());
  return x.toISOString() === y.toISOString();
}

/** Equal leaves: `===`, NaN and NaN (TOML `nan`), or {@link sameDate}. */
function sameLeaf(x: unknown, y: unknown): boolean {
  if (x === y || (Number.isNaN(x) && Number.isNaN(y))) return true;
  return x instanceof Date && sameDate(x, y);
}

/**
 * Deep equality of parsed JSON, YAML or TOML values, ignoring key order. It keeps its own stack,
 * so a deeply nested document cannot overflow the call stack.
 */
export function sameValue(a: unknown, b: unknown): boolean {
  const pending: Pair[] = [[a, b]];
  for (let pair = pending.pop(); pair !== undefined; pair = pending.pop()) {
    const [x, y] = pair;
    let same: boolean;
    if (Array.isArray(x)) same = pushArrays(x, y, pending);
    else if (isObject(x)) same = pushObjects(x, y, pending);
    else same = sameLeaf(x, y);
    if (!same) return false;
  }
  return true;
}

/**
 * Drops the containers along `path` (deepest first) that the change created for its own entries
 * alone, so the final comparison does not see them: each one the base lacks and that is empty.
 */
export function pruneCreated(base: JsonObject, next: JsonObject, path: readonly string[]): void {
  for (let depth = path.length; depth > 0; depth--) {
    const prefix = path.slice(0, depth);
    const container = at(next, prefix);
    const created = at(base, prefix) === undefined && isObject(container);
    if (!created || Object.keys(container).length > 0) return;
    const parent = at(next, prefix.slice(0, -1));
    if (isObject(parent)) Reflect.deleteProperty(parent, prefix[depth - 1] ?? '');
  }
}

export interface YamlReadOptions {
  /**
   * Applies `<<` merge keys. pnpm reads `pnpm-workspace.yaml` with js-yaml's default schema,
   * which merges, so the check must see the merged mapping pnpm sees.
   */
  merge?: boolean;
  /** `failsafe` reads every scalar as a string, as Yarn Berry reads `yarn.lock`. */
  schema?: 'core' | 'failsafe';
  /**
   * Rulings T3o and T3p: a lockfile (`pnpm-lock.yaml`, Berry `yarn.lock`) may hold no anchor
   * (`&`), alias (`*`), tag (`!`), directive (`%`), merge key (`<<`) or key that is not a string;
   * pnpm and Yarn never write them. The first anchor, alias, tag or directive stops the read as
   * soon as it is lexed, before the document is built. Ruling T3q: nor a plain scalar that YAML
   * readers may resolve differently ({@link AMBIGUOUS_PLAIN}).
   */
  lockfile?: boolean;
}

/**
 * A key's text. Ruling T3p: in a lockfile only a string key has one; any other key (a tagged
 * `!!merge`, a `<<` that a `%YAML 1.1` directive makes a merge, `null`, a number, a collection)
 * throws, because the package manager may read it differently.
 */
function keyText(key: unknown, lockfile: boolean): string {
  if (isScalar(key) && typeof key.value === 'string') return key.value;
  if (lockfile) throw new Error('a YAML key that is not a string in a lockfile');
  return isScalar(key) ? String(key.value) : String(key);
}

/**
 * Refuses a mapping with two equal keys, compared as text (so `1` and `'1'` collide, as they do
 * in the parsed object), with one set per mapping: linear, unlike `yaml`'s own `uniqueKeys` check.
 * In a lockfile it also refuses a merge key (Ruling T3o), quoted or not, and any key that is not
 * a string (Ruling T3p).
 */
function assertKeys(map: YAMLMap, lockfile: boolean): void {
  const seen = new Set<string>();
  for (const { key } of map.items) {
    const text = keyText(key, lockfile);
    if (lockfile && text === '<<') throw new Error('a YAML merge key in a lockfile');
    if (seen.has(text)) throw new Error(`duplicate YAML key ${text.slice(0, 100)}`);
    seen.add(text);
  }
}

/**
 * Ruling T3q: plain scalars that pnpm's js-yaml (YAML 1.1 habits) and `yaml` (YAML 1.2 core) may
 * resolve to different values, as keys or values. Each pattern is anchored and has no nested
 * quantifier. pnpm and Berry quote such strings, so a lockfile holding one plain is refused.
 * Ruling T4c: `y`, `n`, `yes`, `no`, `on` and `off` are not among them; js-yaml 4 and the core
 * schema both read them as strings (packages such as `n` are written plain), and Berry reads every
 * scalar as a string.
 */
const AMBIGUOUS_PLAIN: readonly RegExp[] = [
  // 0b, 0o and 0x numbers, each with its own digits only: a hex checksum that starts with `0b`
  // (Berry writes them plain) is no binary number.
  /^[-+]?0b[01_]+$/i,
  /^[-+]?0o[0-7_]+$/i,
  /^[-+]?0x[\da-f_]+$/i,
  // A leading-zero octal such as 0755.
  /^[-+]?0[0-9_]+$/,
  /^[-+]?\.(?:inf|nan)$/i,
  // A timestamp, or anything that starts like one.
  /^\d{4}-\d\d?-\d\d?/,
  // Sexagesimal numbers such as 1:20 or 190:20:30.15.
  /^[-+]?\d+(?::[0-5]?\d)+(?:\.\d*)?$/,
];

/** A number with an `_` (`1_000`, `.5_0`), which YAML 1.1 readers read as a number. */
const UNDERSCORE_NUMBER = /^[-+]?[\d_.]+(?:e[-+]?\d+)?$/i;

function isAmbiguousPlain(text: string): boolean {
  if (text.includes('_') && /\d/.test(text) && UNDERSCORE_NUMBER.test(text)) return true;
  return AMBIGUOUS_PLAIN.some((pattern) => pattern.test(text));
}

/**
 * Ruling T3r: the tests by which the YAML 1.2 core schema resolves a plain scalar to a null,
 * boolean or number (`yaml`'s own core tags), also for Berry's lockfile, read as failsafe.
 */
const CORE_NON_STRING: readonly RegExp[] = new Schema({ schema: 'core' }).tags.flatMap((tag) =>
  'test' in tag && tag.test instanceof RegExp && tag.default === true ? [tag.test] : [],
);

/** Ruling T3r: the only plain scalars a lockfile may hold that the core schema reads as no string. */
const PLAIN_NUMBER = /^-?\d+(?:\.\d+)?$/;
const PLAIN_WORDS: ReadonlySet<string> = new Set(['true', 'false', 'null', '']);

function isAllowedNonString(text: string): boolean {
  return PLAIN_WORDS.has(text) || PLAIN_NUMBER.test(text);
}

/**
 * Rulings T3q and T3r: refuses a plain scalar of a lockfile, key or value, that YAML readers may
 * resolve differently. One the core schema reads as no string must be `-?digits(.digits)`, `true`,
 * `false`, `null` or empty (an allowlist); and none may match {@link AMBIGUOUS_PLAIN} or be a
 * number with an `_` (a denylist of what js-yaml reads as no string).
 */
function assertPlainScalar(scalar: Scalar): void {
  if (scalar.type !== 'PLAIN' || typeof scalar.source !== 'string') return;
  const text = scalar.source;
  const nonString =
    typeof scalar.value !== 'string' || CORE_NON_STRING.some((test) => test.test(text));
  if ((nonString && !isAllowedNonString(text)) || isAmbiguousPlain(text)) {
    throw new Error(`an ambiguous plain YAML scalar in a lockfile: ${text.slice(0, 100)}`);
  }
}

/**
 * What a lockfile's lexeme may not start with (Rulings T3o and T3p). pnpm's js-yaml dump and
 * Berry's syml stringifier quote every plain string that starts with one of these, so only an
 * anchor, an alias, a tag (`!!merge`, `!<tag:yaml.org,2002:merge>`, `!!str`) or a directive
 * (`%YAML 1.1`, which turns a plain `<<` into a merge) starts so.
 */
const REFUSED_LEXEMES: ReadonlyMap<string, string> = new Map([
  ['&', 'an anchor'],
  ['*', 'an alias'],
  ['!', 'a tag'],
  ['%', 'a directive'],
]);

/**
 * Rulings T3o and T3p: a lockfile's tokens, refusing an anchor, an alias, a tag or a directive as
 * soon as it is lexed.
 */
function* lockfileTokens(text: string): Generator<CST.Token> {
  const parser = new Parser();
  for (const lexeme of new Lexer().lex(text)) {
    const refused = REFUSED_LEXEMES.get(lexeme.charAt(0));
    if (refused !== undefined) throw new Error(`${refused} in a YAML lockfile`);
    yield* parser.next(lexeme);
  }
  yield* parser.end();
}

/**
 * The lockfile's documents from its tokens, as `parseDocument` composes each; at least one and at
 * most `max`, else it throws. The token rules hold for every document.
 */
function lockfileDocuments(text: string, options: YamlReadOptions, max: number): Document.Parsed[] {
  const composer = new Composer({ ...options, uniqueKeys: false });
  const docs: Document.Parsed[] = [];
  for (const next of composer.compose(lockfileTokens(text), true, text.length)) {
    if (docs.length === max) throw new Error(`more than ${max} YAML documents in a lockfile`);
    docs.push(next);
  }
  if (docs.length === 0) throw new Error('no YAML document');
  return docs;
}

/** A composed document's value, after its errors and the key and scalar rules. */
function documentValue(doc: Document.Parsed, lockfile: boolean): unknown {
  const [error] = doc.errors;
  if (error !== undefined) throw error;
  visit(doc, {
    Map: (_key, map) => assertKeys(map, lockfile),
    Scalar: (_key, scalar) => (lockfile ? assertPlainScalar(scalar) : undefined),
  });
  return doc.toJS({ maxAliasCount: lockfile ? 0 : 100 });
}

/**
 * One YAML document, with the `yaml` package's safe defaults (no custom tags, at most 100 aliases)
 * and unique keys (checked in linear time, fix round 1 I1); a lockfile with no anchors, aliases
 * or merge keys at all (Ruling T3o), no tags, directives or keys that are not strings (Ruling
 * T3p), no plain scalars that readers may resolve differently (Rulings T3q, T3r and T4c), and
 * one document only. Errors throw; warnings are not printed.
 */
export function parseYaml(text: string, options: YamlReadOptions = {}): unknown {
  const source = stripBom(text);
  const lockfile = options.lockfile === true;
  const doc = lockfile
    ? lockfileDocuments(source, options, 1)[0]
    : parseDocument(source, { ...options, uniqueKeys: false });
  if (doc === undefined) throw new Error('no YAML document');
  return documentValue(doc, lockfile);
}

/**
 * Ruling T4b: the documents of a lockfile (pnpm 11 writes a boot document before the lockfile),
 * one to `max`, each read as {@link parseYaml} reads a lockfile. Errors throw.
 */
export function parseYamlDocuments(
  text: string,
  options: Omit<YamlReadOptions, 'lockfile'>,
  max: number,
): unknown[] {
  const lockfile = { ...options, lockfile: true };
  return lockfileDocuments(stripBom(text), lockfile, max).map((doc) => documentValue(doc, true));
}

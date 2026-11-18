/**
 * Formatting-keeping edits of JSON text (spec §6.5 step 4, §11.3, R22): a value is replaced in its
 * own span, and a new property is written after the last one of its object in that object's
 * indentation, so the rest of the file stays byte for byte: indentation, line endings, a byte
 * order mark, key order and the final newline.
 */

export interface JsonLayout {
  indent: string;
  newline: '\n' | '\r\n';
  bom: boolean;
  finalNewline: boolean;
}

const BOM = '\uFEFF';

/** The leading white space of the first indented line that is not blank. */
function firstIndent(text: string): string | null {
  for (const line of text.split('\n').slice(1)) {
    const indent = /^[ \t]*/.exec(line)?.[0] ?? '';
    if (indent !== '' && line.trim() !== '') return indent;
  }
  return null;
}

/** The file's indent unit (two spaces when nothing is indented), line ending, BOM and final newline. */
export function jsonLayout(text: string): JsonLayout {
  return {
    indent: firstIndent(text) ?? '  ',
    newline: text.includes('\r\n') ? '\r\n' : '\n',
    bom: text.startsWith(BOM),
    finalNewline: text.endsWith('\n'),
  };
}

// ─── A JSON reader that keeps where each value is ──────────────────────────

/** A value's span `[start, end)`; an object also has its members, in text order. */
interface JsonNode {
  start: number;
  end: number;
  members?: JsonMember[];
}

interface JsonMember {
  key: string;
  /** Where the key's opening quote is. */
  keyStart: number;
  value: JsonNode;
}

interface Cursor {
  text: string;
  pos: number;
}

function fail(c: Cursor): never {
  throw new SyntaxError(`not JSON at offset ${c.pos}`);
}

const SPACE = ' \t\n\r';
const DELIMITER = ',:{}[]"';

function skipSpace(c: Cursor): void {
  while (c.pos < c.text.length && SPACE.includes(c.text.charAt(c.pos))) c.pos += 1;
}

function expectChar(c: Cursor, ch: string): void {
  skipSpace(c);
  if (c.text.charAt(c.pos) !== ch) fail(c);
  c.pos += 1;
}

/** A string at the cursor (its opening quote), unescaped as `JSON.parse` reads it. */
function readString(c: Cursor): string {
  const start = c.pos;
  c.pos += 1;
  while (c.pos < c.text.length) {
    const ch = c.text.charAt(c.pos);
    if (ch === '"') {
      c.pos += 1;
      return JSON.parse(c.text.slice(start, c.pos)) as string;
    }
    c.pos += ch === '\\' ? 2 : 1;
  }
  return fail(c);
}

/** A number, `true`, `false` or `null`. */
function readScalar(c: Cursor): void {
  const start = c.pos;
  while (c.pos < c.text.length && !`${SPACE}${DELIMITER}`.includes(c.text.charAt(c.pos))) {
    c.pos += 1;
  }
  if (c.pos === start) fail(c);
  JSON.parse(c.text.slice(start, c.pos));
}

function readObject(c: Cursor): JsonMember[] {
  const members: JsonMember[] = [];
  c.pos += 1;
  skipSpace(c);
  if (c.text.charAt(c.pos) === '}') {
    c.pos += 1;
    return members;
  }
  for (;;) {
    skipSpace(c);
    if (c.text.charAt(c.pos) !== '"') fail(c);
    const keyStart = c.pos;
    const key = readString(c);
    expectChar(c, ':');
    members.push({ key, keyStart, value: readValue(c) });
    skipSpace(c);
    if (c.text.charAt(c.pos) === '}') {
      c.pos += 1;
      return members;
    }
    expectChar(c, ',');
  }
}

function readArray(c: Cursor): void {
  c.pos += 1;
  skipSpace(c);
  if (c.text.charAt(c.pos) === ']') {
    c.pos += 1;
    return;
  }
  for (;;) {
    readValue(c);
    skipSpace(c);
    if (c.text.charAt(c.pos) === ']') {
      c.pos += 1;
      return;
    }
    expectChar(c, ',');
  }
}

function readValue(c: Cursor): JsonNode {
  skipSpace(c);
  const start = c.pos;
  const ch = c.text.charAt(c.pos);
  if (ch === '{') {
    const members = readObject(c);
    return { start, end: c.pos, members };
  }
  if (ch === '[') readArray(c);
  else if (ch === '"') readString(c);
  else readScalar(c);
  return { start, end: c.pos };
}

/** The document's root value, a byte order mark skipped; throws on anything but one JSON value. */
function parseJson(text: string): JsonNode {
  const c: Cursor = { text, pos: text.startsWith(BOM) ? 1 : 0 };
  const root = readValue(c);
  skipSpace(c);
  if (c.pos !== text.length) fail(c);
  return root;
}

/** The value at `path`: the last member of each name, as `JSON.parse` keeps it. */
function nodeAt(root: JsonNode, path: readonly string[]): JsonNode | null {
  let node: JsonNode | undefined = root;
  for (const key of path) {
    node = node.members?.findLast((m) => m.key === key)?.value;
    if (node === undefined) return null;
  }
  return node;
}

function splice(text: string, start: number, end: number, insert: string): string {
  return `${text.slice(0, start)}${insert}${text.slice(end)}`;
}

/**
 * `text` with the value at `path` replaced by the JSON string `value`, only that value's span
 * changed; null when the text is not JSON or the path is missing.
 */
export function setJsonString(text: string, path: readonly string[], value: string): string | null {
  let node: JsonNode | null;
  try {
    node = nodeAt(parseJson(text), path);
  } catch {
    return null;
  }
  return node === null ? null : splice(text, node.start, node.end, JSON.stringify(value));
}

// ─── Adding a property ─────────────────────────────────────────────────────

/** The white space a line starts with, for the line holding `pos`. */
function indentAt(text: string, pos: number): string {
  const start = text.lastIndexOf('\n', pos - 1) + 1;
  let end = start;
  while (end < pos && (text.charAt(end) === ' ' || text.charAt(end) === '\t')) end += 1;
  return text.slice(start, end);
}

const quote = (s: string) => JSON.stringify(s);

/** `"a": { "b": "value" }` over several lines: `indent` is the first key's, each level one unit more. */
function block(
  chain: readonly string[],
  value: string,
  indent: string,
  layout: JsonLayout,
): string {
  const [head = '', ...rest] = chain;
  if (rest.length === 0) return `${quote(head)}: ${quote(value)}`;
  const inner = `${indent}${layout.indent}`;
  const nl = layout.newline;
  return `${quote(head)}: {${nl}${inner}${block(rest, value, inner, layout)}${nl}${indent}}`;
}

/** `"a": { "b": "value" }` on one line. */
function inline(chain: readonly string[], value: string): string {
  const [head = '', ...rest] = chain;
  return rest.length === 0
    ? `${quote(head)}: ${quote(value)}`
    : `${quote(head)}: { ${inline(rest, value)} }`;
}

/** Writes `chain` (the objects to create, then the key) into `object`. */
function insertInto(
  text: string,
  object: JsonNode,
  chain: readonly string[],
  value: string,
): string {
  const layout = jsonLayout(text);
  const last = object.members?.at(-1);
  if (last === undefined) {
    const outer = indentAt(text, object.start);
    const inner = `${outer}${layout.indent}`;
    const body = `{${layout.newline}${inner}${block(chain, value, inner, layout)}${layout.newline}${outer}}`;
    return splice(text, object.start, object.end, body);
  }
  if (!text.slice(object.start, last.keyStart).includes('\n')) {
    return splice(text, last.value.end, last.value.end, `, ${inline(chain, value)}`);
  }
  const indent = indentAt(text, last.keyStart);
  const member = `,${layout.newline}${indent}${block(chain, value, indent, layout)}`;
  return splice(text, last.value.end, last.value.end, member);
}

/**
 * `text` with the string property `key: value` added to the object at `path`; the objects of
 * `path` that are missing are created. The new member follows the last one of its object, in its
 * indentation and the file's line ending (an empty object gets the file's indent unit, an object
 * written on one line stays on one line). Throws when the text is not JSON, a step of `path` is
 * not an object, or the key is already there.
 */
export function addJsonProperty(
  text: string,
  path: readonly string[],
  key: string,
  value: string,
): string {
  let object = parseJson(text);
  let depth = 0;
  for (const step of path) {
    const next = object.members?.findLast((m) => m.key === step)?.value;
    if (next === undefined) break;
    object = next;
    depth += 1;
  }
  if (object.members === undefined) {
    const where = depth === 0 ? 'the document' : path.slice(0, depth).join('.');
    throw new Error(`${where} is not an object`);
  }
  if (depth === path.length && object.members.some((m) => m.key === key)) {
    throw new Error(`${[...path, key].join('.')} is already set`);
  }
  return insertInto(text, object, [...path.slice(depth), key], value);
}

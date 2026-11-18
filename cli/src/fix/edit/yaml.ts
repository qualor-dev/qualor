import { isMap, isScalar, parse, parseDocument } from 'yaml';

/**
 * Ruling F15: the `overrides` pin of a `pnpm-workspace.yaml`, edited as text so every other byte
 * stays. Only a top-level block mapping (`overrides:` alone on its line) whose entries are one-line
 * `key: value` pairs of plain or quoted scalars, at one indent, is edited; flow style, anchors,
 * aliases, tags, nested values and comments inside the map are left to a person (null, which the
 * adapter reports as `manifest_unsupported`). The edited text is read back as YAML: it must equal
 * the original but for the one pin.
 */

interface Line {
  /** The line without its `\r`. */
  text: string;
  crlf: boolean;
}

/** One `key: value` entry of the map. */
interface Entry {
  index: number;
  indent: string;
  key: string;
  /** The value's span in the line. */
  valueStart: number;
  valueEnd: number;
}

const HEADER = /^overrides:[ \t]*$/;

function linesOf(text: string): Line[] {
  return text.split('\n').map((raw) => {
    const crlf = raw.endsWith('\r');
    return { text: crlf ? raw.slice(0, -1) : raw, crlf };
  });
}

const isBlank = (line: Line) => line.text.trim() === '';
/** A line at column 0 that is not blank and not a comment: the map ends before it. */
const isTopLevel = (line: Line) => !isBlank(line) && !/^[ \t#]/.test(line.text);
/** A blank line or a comment at column 0 after the map: it belongs to what follows. */
const isTrailing = (line: Line) => isBlank(line) || line.text.startsWith('#');

/** The lines after the header that belong to the map: up to the next top-level line, trailers off. */
function blockEnd(lines: readonly Line[], header: number): number {
  let end = header + 1;
  while (end < lines.length && !isTopLevel(lines[end] as Line)) end += 1;
  while (end > header + 1 && isTrailing(lines[end - 1] as Line)) end -= 1;
  return end;
}

/** One line as a `key: value` pair of scalars, read by the YAML parser; null for anything else. */
function readEntry(line: Line, index: number): Entry | null {
  const indent = /^ */.exec(line.text)?.[0] ?? '';
  const body = line.text.slice(indent.length);
  if (indent === '' || body.startsWith('\t')) return null;
  const doc = parseDocument(body);
  const map = doc.contents;
  if (doc.errors.length > 0 || doc.warnings.length > 0 || !isMap(map) || map.flow) return null;
  const pair = map.items.length === 1 ? map.items[0] : undefined;
  const { key, value } = pair ?? {};
  if (!isScalar(key) || !isScalar(value) || value.value === null) return null;
  const decorated = [key.anchor, key.tag, value.anchor, value.tag].some((d) => d !== undefined);
  if (decorated) return null;
  const [start, end] = value.range ?? [0, 0];
  // Nothing may follow the value: a comment there is a comment inside the map.
  if (body.slice(end).trim() !== '') return null;
  return {
    index,
    indent,
    key: String(key.value),
    valueStart: indent.length + start,
    valueEnd: indent.length + end,
  };
}

/** The map's entries, all at one indent; null when a line is a comment or not a simple entry. */
function readEntries(lines: readonly Line[], from: number, to: number): Entry[] | null {
  const entries: Entry[] = [];
  for (let i = from; i < to; i += 1) {
    const line = lines[i] as Line;
    if (isBlank(line)) continue;
    const entry = readEntry(line, i);
    if (entry === null || (entries.length > 0 && entry.indent !== entries[0]?.indent)) return null;
    entries.push(entry);
  }
  return entries;
}

const PLAIN_KEY = /^[A-Za-z_][\w./-]*$/;
const RESERVED = /^(?:true|false|null|yes|no|on|off|y|n)$/i;
const PLAIN_VALUE = /^[\^~]?\d+\.\d+\.\d+(?:[-+][\w.+-]*)?$/;

const singleQuoted = (s: string) => `'${s.replaceAll("'", "''")}'`;

function renderKey(key: string): string {
  return PLAIN_KEY.test(key) && !RESERVED.test(key) ? key : singleQuoted(key);
}

/** The value in the quoting of the one it replaces (`"`, `'`, or plain when that reads back). */
function renderValue(value: string, style: string): string {
  if (style === '"') return JSON.stringify(value);
  if (style === "'" || !PLAIN_VALUE.test(value)) return singleQuoted(value);
  return value;
}

/** The first indent the file uses (two spaces when none). */
function fileIndent(lines: readonly Line[]): string {
  const indented = lines.find((l) => /^ +\S/.test(l.text));
  const indent = /^ */.exec(indented?.text ?? '')?.[0] ?? '';
  return indent === '' ? '  ' : indent;
}

function joinLines(lines: readonly Line[]): string {
  return lines.map((l) => (l.crlf ? `${l.text}\r` : l.text)).join('\n');
}

/** Inserts `text` as a line after line `after`, in the file's line ending. */
function insertLine(lines: Line[], after: number, text: string, crlf: boolean): void {
  const previous = lines[after] as Line;
  if (after === lines.length - 1) {
    // The file ends without a newline: the previous line gets one, the new line has none.
    lines[after] = { text: previous.text, crlf };
    lines.push({ text, crlf: false });
    return;
  }
  lines.splice(after + 1, 0, { text, crlf });
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** The document with `key` taken out of `overrides` (an empty `overrides` reads as `{}`). */
function withoutPin(doc: Record<string, unknown>, key: string): Record<string, unknown> {
  const pins = isRecord(doc['overrides']) ? { ...doc['overrides'] } : {};
  Reflect.deleteProperty(pins, key);
  return { ...doc, overrides: pins };
}

/** Whether `after` reads as `before` with `overrides[key]` set to `value`, and nothing else. */
function onlyThePin(before: string, after: string, key: string, value: string): boolean {
  try {
    const a: unknown = parse(before);
    const b: unknown = parse(after);
    if (!isRecord(a) || !isRecord(b) || !isRecord(b['overrides'])) return false;
    if (b['overrides'][key] !== value) return false;
    return JSON.stringify(withoutPin(a, key)) === JSON.stringify(withoutPin(b, key));
  } catch {
    return false;
  }
}

/**
 * `text` with `overrides[key]` set to `value`: an existing entry's value is replaced in its own
 * quoting, a new entry goes after the last one at the map's indent (an empty `overrides:` gets the
 * file's first indent). Null when the file has no block-style `overrides:` this can edit.
 */
export function setYamlOverride(text: string, key: string, value: string): string | null {
  const lines = linesOf(text);
  const header = lines.findIndex((l) => HEADER.test(l.text));
  if (header < 0) return null;
  const entries = readEntries(lines, header + 1, blockEnd(lines, header));
  if (entries === null) return null;
  const found = entries.find((e) => e.key === key);
  if (found === undefined) {
    const indent = entries[0]?.indent ?? fileIndent(lines);
    const after = entries.at(-1)?.index ?? header;
    const crlf = (lines[header] as Line).crlf;
    insertLine(lines, after, `${indent}${renderKey(key)}: ${renderValue(value, '')}`, crlf);
  } else {
    const line = lines[found.index] as Line;
    const style = line.text.charAt(found.valueStart);
    const next = `${line.text.slice(0, found.valueStart)}${renderValue(value, style)}${line.text.slice(found.valueEnd)}`;
    lines[found.index] = { text: next, crlf: line.crlf };
  }
  const edited = joinLines(lines);
  return onlyThePin(text, edited, key, value) ? edited : null;
}

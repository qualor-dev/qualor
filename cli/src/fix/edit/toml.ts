/**
 * Formatting-keeping edits of a `pyproject.toml` (spec §6.5, §11.3): a value, an array entry or a
 * key is changed or added as text where it stands, at the file's line ending, so every other byte
 * stays (comments, blank lines, key order, CRLF, a byte order mark).
 *
 * The text is read by a small scanner of TOML's lines: table headers (`[x]`, `[[x]]`), key/value
 * pairs and comments. Strings, multi-line strings, arrays and inline tables are read whole, so a `[`
 * inside a value is never taken for a header and a `#` inside a string is no comment. It reads only
 * what the edits need and throws on a text it cannot read; the Python adapter reads every result
 * back with the full parser (`readPyproject`) and compares it with the planned change.
 */

/** A span of the text: `start` inclusive, `end` exclusive (JavaScript string indexes). */
export interface TomlSpan {
  start: number;
  end: number;
}

/** One `[x]` or `[[x]]` header and the lines it governs. */
export interface TomlSection {
  /** The header's key ({@link tomlSectionName}): `tool.uv`, `tool."my.tool"`. */
  name: string;
  /** Where the header's line starts. */
  start: number;
  /** Where the next header's line starts, or the end of the text. */
  end: number;
}

const BOM = '\uFEFF';
const BARE_KEY = /^[A-Za-z0-9_-]+$/;
const BARE_KEY_CHAR = /[A-Za-z0-9_-]/;
/** Four spaces: the indentation of an entry added to an empty multi-line array (uv's own). */
const INDENT = '    ';

interface Header {
  name: string;
  start: number;
  /** After the header's line break. */
  bodyStart: number;
}

/** A key/value pair at the top level of a table. */
interface Pair {
  /** The index of its header; -1 before the first one. */
  section: number;
  /** The key's parts, unquoted. */
  key: string[];
  value: TomlSpan;
  /** After the line break of the line the value ends on. */
  lineEnd: number;
}

interface Scanned {
  headers: Header[];
  pairs: Pair[];
  comments: TomlSpan[];
}

/** An array value: where its brackets are, its items, and the comma after its last item. */
interface ArrayItems {
  open: number;
  close: number;
  items: TomlSpan[];
  /** The comma after the last item; null when there is none. */
  comma: number | null;
}

/** A quoted key's text: a basic string's escapes decoded where JSON reads them alike. */
function unquote(raw: string): string {
  if (raw.startsWith("'")) return raw.slice(1, -1);
  try {
    return JSON.parse(raw) as string;
  } catch {
    return raw.slice(1, -1);
  }
}

class Scanner {
  pos = 0;
  readonly comments: TomlSpan[] = [];
  private readonly text: string;

  constructor(text: string, pos = 0) {
    this.text = text;
    this.pos = pos;
  }

  fail(what: string): never {
    const line = this.text.slice(0, this.pos).split('\n').length;
    throw new Error(`not TOML this edit can read: ${what} on line ${line}`);
  }

  peek(): string {
    return this.text.charAt(this.pos);
  }

  private startsWith(s: string): boolean {
    return this.text.startsWith(s, this.pos);
  }

  skipSpaces(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.pos++;
  }

  atLineBreak(): boolean {
    return this.peek() === '\n' || this.startsWith('\r\n');
  }

  atLineEnd(): boolean {
    return this.pos >= this.text.length || this.atLineBreak();
  }

  private lineBreak(): void {
    this.pos += this.startsWith('\r\n') ? 2 : 1;
  }

  private comment(): void {
    if (this.peek() !== '#') return;
    const start = this.pos;
    while (!this.atLineEnd()) this.pos++;
    this.comments.push({ start, end: this.pos });
  }

  /** Spaces, comments and line breaks between the items of an array or inline table. */
  private skipBlank(): void {
    for (;;) {
      this.skipSpaces();
      this.comment();
      if (!this.atLineBreak()) return;
      this.lineBreak();
    }
  }

  /** The rest of a line: spaces, a comment, the line break (none at the end of the text). */
  endLine(): void {
    this.skipSpaces();
    this.comment();
    if (!this.atLineEnd()) this.fail('text after a value');
    if (this.pos < this.text.length) this.lineBreak();
  }

  private basicString(): void {
    this.pos++;
    for (;;) {
      const c = this.peek();
      if (c === '' || c === '\n' || c === '\r') this.fail('an unterminated string');
      this.pos += c === '\\' ? 2 : 1;
      if (c === '"') return;
    }
  }

  private literalString(): void {
    const close = this.text.indexOf("'", this.pos + 1);
    const lineBreak = this.text.indexOf('\n', this.pos);
    if (close < 0 || (lineBreak >= 0 && lineBreak < close)) this.fail('an unterminated string');
    this.pos = close + 1;
  }

  /** `"""…"""` or `'''…'''`; up to two more quotes after the closing three are content. */
  private multiLineString(quote: string): void {
    const delimiter = quote.repeat(3);
    this.pos += 3;
    for (;;) {
      if (this.pos >= this.text.length) this.fail('an unterminated multi-line string');
      if (this.startsWith(delimiter)) {
        this.pos += 3;
        for (let extra = 0; extra < 2 && this.peek() === quote; extra++) this.pos++;
        return;
      }
      this.pos += quote === '"' && this.peek() === '\\' ? 2 : 1;
    }
  }

  /** A number, boolean or date: up to `,`, `]`, `}`, a comment or the line end, spaces trimmed. */
  private bareValue(): void {
    const start = this.pos;
    while (!this.atLineEnd() && !',]}#'.includes(this.peek())) this.pos++;
    while (this.pos > start && ' \t'.includes(this.text.charAt(this.pos - 1))) this.pos--;
    if (this.pos === start) this.fail('a value');
  }

  value(): TomlSpan {
    const start = this.pos;
    const c = this.peek();
    if (this.startsWith('"""') || this.startsWith("'''")) this.multiLineString(c);
    else if (c === '"') this.basicString();
    else if (c === "'") this.literalString();
    else if (c === '[') this.arrayItems();
    else if (c === '{') this.inlineTable();
    else this.bareValue();
    return { start, end: this.pos };
  }

  arrayItems(): ArrayItems {
    const open = this.pos;
    this.pos++;
    const items: TomlSpan[] = [];
    let comma: number | null = null;
    for (;;) {
      this.skipBlank();
      if (this.peek() === ']') {
        this.pos++;
        return { open, close: this.pos - 1, items, comma };
      }
      items.push(this.value());
      comma = null;
      this.skipBlank();
      if (this.peek() === ',') {
        comma = this.pos;
        this.pos++;
      } else if (this.peek() !== ']') {
        this.fail('an array');
      }
    }
  }

  private inlineTable(): void {
    this.pos++;
    for (;;) {
      this.skipBlank();
      if (this.peek() === '}') {
        this.pos++;
        return;
      }
      this.keyValue();
      this.skipBlank();
      if (this.peek() === ',') this.pos++;
      else if (this.peek() !== '}') this.fail('an inline table');
    }
  }

  private keyPart(): string {
    const start = this.pos;
    const c = this.peek();
    if (c === '"') this.basicString();
    else if (c === "'") this.literalString();
    else while (BARE_KEY_CHAR.test(this.peek())) this.pos++;
    if (this.pos === start) this.fail('a key');
    const raw = this.text.slice(start, this.pos);
    return c === '"' || c === "'" ? unquote(raw) : raw;
  }

  /** A dotted key: its parts, unquoted. */
  key(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.skipSpaces();
      parts.push(this.keyPart());
      this.skipSpaces();
      if (this.peek() !== '.') return parts;
      this.pos++;
    }
  }

  keyValue(): { key: string[]; value: TomlSpan } {
    const key = this.key();
    if (this.peek() !== '=') this.fail('a key without "="');
    this.pos++;
    this.skipSpaces();
    return { key, value: this.value() };
  }

  /** `[x]` or `[[x]]`: its name. */
  headerName(): string {
    const array = this.text.charAt(this.pos + 1) === '[';
    this.pos += array ? 2 : 1;
    const parts = this.key();
    const close = array ? ']]' : ']';
    if (!this.startsWith(close)) this.fail('a table header');
    this.pos += close.length;
    return tomlSectionName(parts);
  }
}

/** The headers, top-level pairs and comments of a text; throws on a text it cannot read. */
function scan(text: string): Scanned {
  const s = new Scanner(text, text.startsWith(BOM) ? 1 : 0);
  const headers: Header[] = [];
  const pairs: Pair[] = [];
  while (s.pos < text.length) {
    const lineStart = s.pos;
    s.skipSpaces();
    const c = s.peek();
    if (c === '[') {
      const name = s.headerName();
      s.endLine();
      headers.push({ name, start: lineStart, bodyStart: s.pos });
    } else if (c === '#' || s.atLineEnd()) {
      s.endLine();
    } else {
      const { key, value } = s.keyValue();
      s.endLine();
      pairs.push({ section: headers.length - 1, key, value, lineEnd: s.pos });
    }
  }
  return { headers, pairs, comments: s.comments };
}

/** A section name from key parts: bare parts as they are, any other as a basic string. */
export function tomlSectionName(parts: readonly string[]): string {
  return parts.map(tomlKey).join('.');
}

/** A TOML basic string: `"` and `\` escaped, control characters as `\uXXXX`. */
export function tomlString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === '"' || ch === '\\') out += `\\${ch}`;
    else if (code < 0x20 || code === 0x7f) out += `\\u${code.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return `${out}"`;
}

/** A key: bare when TOML allows, else a basic string. */
function tomlKey(key: string): string {
  return BARE_KEY.test(key) ? key : tomlString(key);
}

/** The text without line breaks or other control characters (and U+2028, U+2029). */
export function oneLine(text: string): string {
  return text.replaceAll(/[\p{Cc}\u2028\u2029]/gu, '');
}

/** The line ending of the text's first line (LF when it has none). */
function lineEnding(text: string): string {
  const lf = text.indexOf('\n');
  return lf > 0 && text.charAt(lf - 1) === '\r' ? '\r\n' : '\n';
}

function splice(text: string, span: TomlSpan, value: string): string {
  return `${text.slice(0, span.start)}${value}${text.slice(span.end)}`;
}

/** After the line break of the line `pos` is on (the end of the text on the last line). */
function lineEndAfter(text: string, pos: number): number {
  const lf = text.indexOf('\n', pos);
  return lf < 0 ? text.length : lf + 1;
}

function lineStartOf(text: string, pos: number): number {
  return text.lastIndexOf('\n', pos - 1) + 1;
}

/** The spaces before `pos` on its line, when only spaces come before it; else null. */
function indentBefore(text: string, pos: number): string | null {
  const before = text.slice(lineStartOf(text, pos), pos);
  return /^[ \t]*$/.test(before) ? before : null;
}

function sectionIndex(scanned: Scanned, section: string): number {
  return scanned.headers.findIndex((h) => h.name === section);
}

function pairOf(scanned: Scanned, section: number, key: string): Pair | undefined {
  return scanned.pairs.find((p) => p.section === section && p.key.length === 1 && p.key[0] === key);
}

/** The pair `key` of the section `section`, if both exist. */
function findPair(scanned: Scanned, section: string, key: string): Pair | undefined {
  const i = sectionIndex(scanned, section);
  return i < 0 ? undefined : pairOf(scanned, i, key);
}

/** Lines (each ending in `eol`) at `at`; at the end of a text without a final line break, one first. */
function insertLines(text: string, at: number, lines: string, eol: string): string {
  const needsBreak = at === text.length && text.length > 0 && !text.endsWith('\n');
  return `${text.slice(0, at)}${needsBreak ? eol : ''}${lines}${text.slice(at)}`;
}

/** A new section at the end of the text, after one blank line. */
function appendSection(text: string, section: string, lines: string, eol: string): string {
  let gap = eol;
  if (text === '' || text === BOM) gap = '';
  else if (!text.endsWith('\n')) gap = eol + eol;
  else if (text.endsWith('\n\n') || text.endsWith('\n\r\n')) gap = '';
  return `${text}${gap}[${section}]${eol}${lines}`;
}

/** Lines after the last pair of a section (or its header), or in a new section at the end. */
function addToSection(
  text: string,
  scanned: Scanned,
  section: string,
  lines: string,
  eol: string,
): string {
  const i = sectionIndex(scanned, section);
  const header = scanned.headers[i];
  if (header === undefined) return appendSection(text, section, lines, eol);
  const last = scanned.pairs.filter((p) => p.section === i).at(-1);
  return insertLines(text, last?.lineEnd ?? header.bodyStart, lines, eol);
}

/**
 * Every `[x]` and `[[x]]` header of the text, in order, with the lines up to the next header. Names
 * are {@link tomlSectionName}s, so `[ tool . "uv" ]` is `tool.uv`. A `[` inside a value (a
 * multi-line string or array) is no header. Throws on a text it cannot read.
 */
export function tomlSections(text: string): TomlSection[] {
  const { headers } = scan(text);
  return headers.map((h, i) => ({
    name: h.name,
    start: h.start,
    end: headers[i + 1]?.start ?? text.length,
  }));
}

/**
 * The text with the first exact occurrence of `find` after the header of the first section named
 * `section` (and before the next header) replaced by `replace`; an occurrence that touches a
 * comment is skipped. Null when the section or such an occurrence is missing.
 */
export function replaceInSection(
  text: string,
  section: string,
  find: string,
  replace: string,
): string | null {
  const scanned = scan(text);
  const i = sectionIndex(scanned, section);
  const header = scanned.headers[i];
  if (header === undefined || find === '') return null;
  const end = scanned.headers[i + 1]?.start ?? text.length;
  const inComment = (at: number) =>
    scanned.comments.some((c) => at < c.end && at + find.length > c.start);
  for (let at = text.indexOf(find, header.bodyStart); at >= 0; at = text.indexOf(find, at + 1)) {
    if (at + find.length > end) return null;
    if (!inComment(at)) return splice(text, { start: at, end: at + find.length }, replace);
  }
  return null;
}

/** The span of the value of `key` (one part, unquoted) in the section `section`; null when missing. */
export function tomlValue(text: string, section: string, key: string): TomlSpan | null {
  return findPair(scan(text), section, key)?.value ?? null;
}

/**
 * `key = value` in the section `section`: an existing key's value is replaced where it stands
 * (its comment kept, `comment` unused); a new key goes after the section's last pair, with
 * `comment` (one line, a `#` added when missing) on the line above; a missing section is added at
 * the end of the text. `value` is TOML text (a quoted string, a number, …).
 */
export function setTomlKey(
  text: string,
  section: string,
  key: string,
  value: string,
  comment?: string,
): string {
  const scanned = scan(text);
  const pair = findPair(scanned, section, key);
  if (pair !== undefined) return splice(text, pair.value, value);
  const eol = lineEnding(text);
  const note = comment === undefined ? '' : oneLine(comment);
  const marker = note.startsWith('#') ? '' : '# ';
  const above = note === '' ? '' : `${marker}${note}${eol}`;
  return addToSection(text, scanned, section, `${above}${tomlKey(key)} = ${value}${eol}`, eol);
}

/** The first item of an empty array: between its brackets, or on a line of its own. */
function addFirstItem(text: string, array: ArrayItems, literal: string, eol: string): string {
  if (!text.slice(array.open, array.close).includes('\n')) {
    return splice(text, { start: array.open + 1, end: array.close }, literal);
  }
  const indent = `${indentBefore(text, array.close) ?? ''}${INDENT}`;
  return insertLines(text, lineEndAfter(text, array.open), `${indent}${literal},${eol}`, eol);
}

/** An item after the last of a multi-line array, on its own line at the last item's indentation. */
function addItemLine(
  text: string,
  array: ArrayItems,
  last: TomlSpan,
  literal: string,
  eol: string,
): string {
  const indent =
    indentBefore(text, last.start) ?? `${indentBefore(text, array.close) ?? ''}${INDENT}`;
  if (array.comma !== null) {
    const at = lineEndAfter(text, array.comma);
    return insertLines(text, at, `${indent}${literal},${eol}`, eol);
  }
  const at = lineEndAfter(text, last.end);
  return `${text.slice(0, last.end)},${text.slice(last.end, at)}${indent}${literal}${eol}${text.slice(at)}`;
}

function addArrayItem(text: string, array: ArrayItems, literal: string, eol: string): string {
  const last = array.items.at(-1);
  if (last === undefined) return addFirstItem(text, array, literal, eol);
  // `]` on the line of the last item (and its comma): the new item goes inline after it.
  if (!text.slice(last.end, array.close).includes('\n')) {
    return splice(text, { start: last.end, end: last.end }, `, ${literal}`);
  }
  return addItemLine(text, array, last, literal, eol);
}

/**
 * `entry` (a string) added to the array `key` of the section `section`: a one-line array gets it
 * after its last item, a multi-line array on a new line at its items' indentation (a comma added
 * after the last item when it has none; the new item has a trailing comma when the last one had);
 * a missing key becomes `key = ["entry"]` after the section's last pair, a missing section is added
 * at the end of the text. Throws when the key holds no array, or on a text it cannot read.
 */
export function setTomlArrayEntry(
  text: string,
  section: string,
  key: string,
  entry: string,
): string {
  const scanned = scan(text);
  const eol = lineEnding(text);
  const literal = tomlString(entry);
  const pair = findPair(scanned, section, key);
  if (pair === undefined) {
    return addToSection(text, scanned, section, `${tomlKey(key)} = [${literal}]${eol}`, eol);
  }
  if (text.charAt(pair.value.start) !== '[') {
    throw new Error(`${key} in [${section}] is not an array`);
  }
  const array = new Scanner(text, pair.value.start).arrayItems();
  return addArrayItem(text, array, literal, eol);
}

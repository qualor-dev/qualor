/**
 * Just enough TOML (1.0) to find the `[extend]` keys of a Gitleaks config with certainty: tables,
 * array tables, dotted, quoted and escaped keys, all four string forms, arrays and inline tables.
 * Anything this reader does not understand is an error, never a pass (the same rule as the PMD
 * ruleset reader of ruling V4).
 */

/** A Gitleaks config larger than this is not read (the built-in one is about 100 KiB). */
export const MAX_GITLEAKS_CONFIG_BYTES = 4 * 1024 * 1024;

type Value =
  | { kind: 'string'; value: string }
  | { kind: 'array'; items: Value[] }
  | { kind: 'table'; entries: Entry[] }
  | { kind: 'other' };

interface Entry {
  key: string[];
  value: Value;
}

class TomlError extends Error {}

const BARE_KEY = /[A-Za-z0-9_-]+/y;
/** Numbers, booleans, dates and times (a space may separate a date from its time). */
const SCALAR = /[A-Za-z0-9_:+.-]+(?: [0-9][0-9:.+Z-]*)?/y;
const ESCAPES: Readonly<Record<string, string>> = {
  b: '\b',
  t: '\t',
  n: '\n',
  f: '\f',
  r: '\r',
  e: '\u001b',
  '"': '"',
  '\\': '\\',
};

class Reader {
  private pos = 0;
  constructor(private readonly text: string) {}

  private peek(s: string): boolean {
    return this.text.startsWith(s, this.pos);
  }

  private fail(): never {
    throw new TomlError();
  }

  private eof(): boolean {
    return this.pos >= this.text.length;
  }

  private spaces(): void {
    while (this.peek(' ') || this.peek('\t')) this.pos += 1;
  }

  /** Whitespace, line breaks and comments (between array items, lines and statements). */
  private blank(): void {
    for (;;) {
      this.spaces();
      if (this.peek('#')) {
        while (!this.eof() && !this.peek('\n')) this.pos += 1;
      } else if (this.peek('\n') || this.peek('\r\n')) {
        this.pos += this.peek('\n') ? 1 : 2;
      } else {
        return;
      }
    }
  }

  /** The end of a statement: optional comment, then a line break or the end of the text. */
  private endOfLine(): void {
    this.spaces();
    if (this.peek('#')) while (!this.eof() && !this.peek('\n')) this.pos += 1;
    if (this.eof()) return;
    if (this.peek('\n')) this.pos += 1;
    else if (this.peek('\r\n')) this.pos += 2;
    else this.fail();
  }

  private escape(): string {
    this.pos += 1;
    const c = this.text[this.pos];
    if (c === undefined) this.fail();
    const simple = ESCAPES[c];
    if (simple !== undefined) {
      this.pos += 1;
      return simple;
    }
    const digits = c === 'u' ? 4 : c === 'U' ? 8 : c === 'x' ? 2 : 0;
    if (digits === 0) this.fail();
    const hex = this.text.slice(this.pos + 1, this.pos + 1 + digits);
    if (!new RegExp(`^[0-9A-Fa-f]{${digits}}$`).test(hex)) this.fail();
    const cp = Number.parseInt(hex, 16);
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) this.fail();
    this.pos += 1 + digits;
    return String.fromCodePoint(cp);
  }

  private basicString(): string {
    this.pos += 1;
    let out = '';
    for (;;) {
      const c = this.text[this.pos];
      if (c === undefined || c === '\n' || c === '\r') this.fail();
      if (c === '"') {
        this.pos += 1;
        return out;
      }
      if (c === '\\') out += this.escape();
      else {
        out += c;
        this.pos += 1;
      }
    }
  }

  private literalString(): string {
    const end = this.text.indexOf("'", this.pos + 1);
    const value = end < 0 ? '' : this.text.slice(this.pos + 1, end);
    if (end < 0 || /[\r\n]/.test(value)) this.fail();
    this.pos = end + 1;
    return value;
  }

  /** `"""…"""` or `'''…'''`: up to two quotes may directly precede the closing delimiter. */
  private multiLine(quote: '"' | "'"): string {
    const delim = quote.repeat(3);
    this.pos += 3;
    if (this.peek('\n')) this.pos += 1;
    else if (this.peek('\r\n')) this.pos += 2;
    let out = '';
    for (;;) {
      if (this.eof()) this.fail();
      if (this.peek(delim)) {
        let extra = 0;
        while (extra < 2 && this.text[this.pos + 3 + extra] === quote) extra += 1;
        out += quote.repeat(extra);
        this.pos += 3 + extra;
        return out;
      }
      const c = this.text[this.pos] as string;
      if (quote === '"' && c === '\\') {
        // A backslash at the end of a line trims the line break and the whitespace after it.
        const rest = /\\[ \t]*\r?\n[\s]*/y;
        rest.lastIndex = this.pos;
        if (rest.test(this.text)) this.pos = rest.lastIndex;
        else out += this.escape();
      } else {
        out += c;
        this.pos += 1;
      }
    }
  }

  private keySegment(): string {
    if (this.peek('"')) return this.basicString();
    if (this.peek("'")) return this.literalString();
    BARE_KEY.lastIndex = this.pos;
    const m = BARE_KEY.exec(this.text);
    if (m === null) this.fail();
    this.pos = BARE_KEY.lastIndex;
    return m[0];
  }

  private key(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.spaces();
      parts.push(this.keySegment());
      this.spaces();
      if (!this.peek('.')) return parts;
      this.pos += 1;
    }
  }

  private value(): Value {
    if (this.peek('"""')) return { kind: 'string', value: this.multiLine('"') };
    if (this.peek("'''")) return { kind: 'string', value: this.multiLine("'") };
    if (this.peek('"')) return { kind: 'string', value: this.basicString() };
    if (this.peek("'")) return { kind: 'string', value: this.literalString() };
    if (this.peek('[')) {
      this.pos += 1;
      const items: Value[] = [];
      for (;;) {
        this.blank();
        if (this.peek(']')) break;
        items.push(this.value());
        this.blank();
        if (this.peek(',')) this.pos += 1;
        else if (!this.peek(']')) this.fail();
      }
      this.pos += 1;
      return { kind: 'array', items };
    }
    if (this.peek('{')) {
      this.pos += 1;
      const entries: Entry[] = [];
      this.blank();
      if (this.peek('}')) {
        this.pos += 1;
        return { kind: 'table', entries };
      }
      for (;;) {
        this.blank();
        entries.push(this.keyValue());
        this.blank();
        if (this.peek('}')) break;
        if (!this.peek(',')) this.fail();
        this.pos += 1;
      }
      this.pos += 1;
      return { kind: 'table', entries };
    }
    SCALAR.lastIndex = this.pos;
    if (SCALAR.exec(this.text) === null) this.fail();
    this.pos = SCALAR.lastIndex;
    return { kind: 'other' };
  }

  private keyValue(): Entry {
    const key = this.key();
    if (!this.peek('=')) this.fail();
    this.pos += 1;
    this.spaces();
    return { key, value: this.value() };
  }

  /** Every key/value pair with its full key (table path included), and every array table. */
  document(): { entries: Entry[]; arrayTables: string[][] } {
    const entries: Entry[] = [];
    const arrayTables: string[][] = [];
    let table: string[] = [];
    for (;;) {
      this.blank();
      if (this.eof()) return { entries, arrayTables };
      if (this.peek('[')) {
        const array = this.peek('[[');
        this.pos += array ? 2 : 1;
        table = this.key();
        if (!this.peek(array ? ']]' : ']')) this.fail();
        this.pos += array ? 2 : 1;
        if (array) arrayTables.push(table);
      } else {
        const kv = this.keyValue();
        entries.push({ key: [...table, ...kv.key], value: kv.value });
      }
      this.endOfLine();
    }
  }
}

/** Viper reads keys case-insensitively and splits them on dots, quoted or not. */
function normalise(key: readonly string[]): string[] {
  return key.flatMap((k) => k.split('.')).map((k) => k.toLowerCase());
}

/** Inline tables become one entry per leaf, with the full key. */
function flatten(entries: readonly Entry[], prefix: readonly string[] = []): Entry[] {
  return entries.flatMap((e) => {
    const key = [...prefix, ...e.key];
    return e.value.kind === 'table' ? flatten(e.value.entries, key) : [{ key, value: e.value }];
  });
}

const EXTEND_KEYS = new Set(['path', 'usedefault', 'disabledrules']);

/**
 * The `extend.path` values of a Gitleaks config (Gitleaks 8 reads `path`, `useDefault` and
 * `disabledRules` under `[extend]`). Another key under `extend` (for example `url`, declared but
 * unused by Gitleaks 8.30), an `[[extend]]` array or an `extend` that is not a table is an error,
 * so a later Gitleaks cannot start honouring something this check never looked at.
 */
export function gitleaksExtends(bytes: Buffer): { paths: string[] } | { error: string } {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { error: 'is not UTF-8' };
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  // TOML allows no control character but tab and line breaks, and no CR outside CRLF (Gitleaks
  // rejects them too); a reader that took `# c\r[extend]` for one comment would miss the table.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]|\r(?!\n)/.test(text)) {
    return { error: 'cannot be parsed as TOML' };
  }
  let doc: ReturnType<Reader['document']>;
  try {
    doc = new Reader(text).document();
  } catch (err) {
    if (err instanceof TomlError || err instanceof RangeError) {
      return { error: 'cannot be parsed as TOML' };
    }
    throw err;
  }
  if (doc.arrayTables.some((t) => normalise(t)[0] === 'extend')) {
    return { error: 'has an [[extend]] array, which Qualor does not check' };
  }
  const paths: string[] = [];
  for (const entry of flatten(doc.entries)) {
    const key = normalise(entry.key);
    if (key[0] !== 'extend') continue;
    if (key.length === 1) return { error: 'has an extend that is not a table' };
    const name = key.slice(1).join('.');
    if (key.length > 2 || !EXTEND_KEYS.has(name)) {
      return { error: `has extend.${name}, which Qualor does not check` };
    }
    if (name !== 'path') continue;
    if (entry.value.kind !== 'string') return { error: 'has an extend.path that is not a string' };
    paths.push(entry.value.value);
  }
  return { paths };
}

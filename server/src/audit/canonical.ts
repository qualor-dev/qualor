export type AuditJson =
  string | number | boolean | null | AuditJson[] | { [key: string]: AuditJson };

const isHigh = (code: number): boolean => code >= 0xd800 && code <= 0xdbff;
const isLow = (code: number): boolean => code >= 0xdc00 && code <= 0xdfff;

/**
 * Whether PostgreSQL can store `text` exactly: no U+0000 (text and jsonb refuse it) and no lone
 * surrogate (jsonb refuses its escape, and a text column would store U+FFFD, so the stored record
 * would no longer hash to the stored hash).
 */
export function isStorableText(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 0) return false;
    if (isHigh(code)) {
      if (!isLow(text.charCodeAt(i + 1))) return false;
      i += 1;
    } else if (isLow(code)) {
      return false;
    }
  }
  return true;
}

/** `text` with U+0000 and every lone surrogate replaced by U+FFFD. */
export function toStorableText(text: string): string {
  if (isStorableText(text)) return text;
  let out = '';
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (isHigh(code) && isLow(text.charCodeAt(i + 1))) {
      out += text.slice(i, i + 2);
      i += 1;
    } else {
      out +=
        code === 0 || isHigh(code) || isLow(code) ? String.fromCharCode(0xfffd) : text.charAt(i);
    }
  }
  return out;
}

function checkString(text: string): string {
  if (!isStorableText(text)) {
    throw new TypeError('audit strings may not hold U+0000 or a lone surrogate');
  }
  return JSON.stringify(text);
}

/**
 * rbac-audit.md §10.1: keys sorted by UTF-16 code units at every level, no whitespace, strings
 * (and keys) as JSON.stringify escapes them (`"`, `\`, `\b \t \n \f \r`, other control characters
 * as lowercase `\u00xx`, everything else as the character itself), integers only (a float would not
 * round-trip through jsonb). A key whose value is `undefined` is left out, as JSON.stringify does;
 * anything else that is not JSON (undefined elsewhere, a bigint, a function, a class instance such
 * as a Date) is refused, so two writers can never disagree on the text. No Unicode normalisation
 * is applied: a string is hashed as the exact code units it holds (NFC and NFD forms of the same
 * text hash differently), and jsonb stores and returns those code units unchanged.
 */
export function canonicalJson(value: AuditJson): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return checkString(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value))
      throw new TypeError('audit values may hold safe integers only');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  if (typeof value !== 'object') throw new TypeError(`audit values may not hold a ${typeof value}`);
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError('audit values may hold plain objects only');
  }
  // Array.prototype.sort without a comparator compares UTF-16 code units.
  const keys = Object.keys(value).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const item = value[key];
    if (item === undefined) continue;
    parts.push(`${checkString(key)}:${canonicalJson(item)}`);
  }
  return `{${parts.join(',')}}`;
}

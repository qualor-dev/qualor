/**
 * §6.9, B9: package-manager output is scrubbed before it becomes a fix's `failure.message`, by the
 * CLI and again by the server: known secret values, the B9 shapes, Qualor's general secret
 * redaction, then the last {@link FIX_LIMITS} `messageBytes` bytes.
 */
import { redactText } from '../llm/redact';
import { FIX_LIMITS } from './families';

/** B9: an environment variable whose name says it holds a secret. */
export const FIX_SECRET_NAME = /TOKEN|PASSWORD|PASS|PWD|SECRET|AUTH|KEY|CREDENTIAL/i;

/** R21: these exact names hold directories, not secrets. */
const NOT_SECRET_NAMES: ReadonlySet<string> = new Set(['PWD', 'OLDPWD']);
/** R21: a shorter value is not scrubbed (it would hit ordinary text). */
const MIN_SECRET_CHARS = 4;

/** What a scrubbed secret becomes. */
export const FIX_REDACTED = '[redacted]';
const REDACTED = FIX_REDACTED;

/**
 * B9, R21: the values of the secret-named variables of an environment, at least 4 characters each,
 * without duplicates, longest first (so a value that holds another is replaced whole).
 */
export function secretEnvValues(env: Readonly<Record<string, string | undefined>>): string[] {
  const values = new Set<string>();
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined || value.length < MIN_SECRET_CHARS) continue;
    if (FIX_SECRET_NAME.test(name) && !NOT_SECRET_NAMES.has(name)) values.add(value);
  }
  return [...values].toSorted((a, b) => b.length - a.length);
}

/** Each known secret of 4 characters or more (R21) replaced by `[redacted]`, the longest first. */
export function replaceSecrets(text: string, secrets: readonly string[]): string {
  return secrets
    .filter((s) => s.length >= MIN_SECRET_CHARS)
    .toSorted((a, b) => b.length - a.length)
    .reduce((out, secret) => out.split(secret).join(REDACTED), text);
}

/** `.npmrc` `_auth=`, `_password=` and `//host/:_authToken=` lines: the value to the line end. */
const NPMRC_AUTH = /(_auth(?:Token)?|_password)([ \t]{0,32}=[ \t]{0,32})\S[^\r\n]*/gi;
/** An `Authorization:` header (`Proxy-Authorization:` too): the value to the line end. */
const AUTHORIZATION = /(authorization["']?[ \t]{0,32}:[ \t]{0,32})\S[^\r\n]*/gi;
/** A Maven `settings.xml` `<password>` start tag, attributes allowed; not `<password/>`. */
const PASSWORD_OPEN = /<password(?:\s[^<>]{0,1024})?(?<!\/)>/gi;
const PASSWORD_CLOSE = /^<\/password\s{0,32}>/i;
const CDATA_OPEN = '<![CDATA[';
const CDATA_CLOSE = ']]>';
/** A CDATA section that does not end within this many characters counts as unclosed. */
const CDATA_MAX_CHARS = 65_536;

function lineEnd(text: string, from: number): number {
  const newline = text.indexOf('\n', from);
  return newline === -1 ? text.length : newline;
}

/**
 * Where the value of a `<password>` element that starts at `start` ends: before its end tag; for an
 * element left open (output cut short), at the end of the value's line, so it is redacted anyway.
 * A CDATA section is part of the value, whatever it holds.
 */
function passwordValueEnd(text: string, start: number): number {
  const at = start + (/^\s{0,64}/.exec(text.slice(start, start + 64))?.[0].length ?? 0);
  let from = at;
  if (text.startsWith(CDATA_OPEN, at)) {
    const close = text.slice(at, at + CDATA_MAX_CHARS).indexOf(CDATA_CLOSE);
    if (close === -1) return lineEnd(text, at);
    from = at + close + CDATA_CLOSE.length;
  }
  const next = text.indexOf('<', from);
  const end = next === -1 ? text.length : next;
  if (PASSWORD_CLOSE.test(text.slice(end, end + 64))) return end;
  return Math.min(end, lineEnd(text, from));
}

/** The value of each `<password>` element: CDATA, attributes, any case, over lines, or unclosed. */
function scrubPasswordElements(text: string): string {
  let out = '';
  let done = 0;
  for (const open of text.matchAll(PASSWORD_OPEN)) {
    const start = open.index + open[0].length;
    const end = start < done ? start : passwordValueEnd(text, start);
    if (end > start) {
      out += text.slice(done, start) + REDACTED;
      done = end;
    }
  }
  return out + text.slice(done);
}

/**
 * A URL's scheme (also JSON-escaped, `https:\/\/`) and authority. The authority ends where the
 * WHATWG URL parser ends it, at `/`, `\`, `?` or `#`, and at white space, a quote or `<>`.
 */
const URL_AUTHORITY = /([a-z][a-z0-9+.-]{0,30}:(?:\/\/|\\\/\\\/))([^\s/\\?#"'`<>]+)/gi;

/**
 * Any userinfo of a URL: everything up to the authority's last `@` (as the WHATWG URL parser reads
 * it), whatever it looks like: a numeric password, a token alone, any length. `host:4873/@scope`
 * has no `@` in its authority, so it stays.
 */
function urlUserinfo(match: string, scheme: string, authority: string): string {
  const at = authority.lastIndexOf('@');
  return at === -1 ? match : `${scheme}${REDACTED}${authority.slice(at)}`;
}

/** B9: the userinfo of every URL in the text replaced by `[redacted]` (`https://[redacted]@host`). */
export function scrubUrlUserinfo(text: string): string {
  return text.replace(URL_AUTHORITY, urlUserinfo);
}

/**
 * How many URLs of the text carry a password: a userinfo (up to the authority's last `@`) with a
 * `:`. A user name alone (`git+ssh://git@github.com/…`) is no credential (Task 12 fix round 1, I1).
 */
export function urlPasswordCount(text: string): number {
  let n = 0;
  for (const m of text.matchAll(URL_AUTHORITY)) {
    const authority = m[2] ?? '';
    const at = authority.lastIndexOf('@');
    if (at !== -1 && authority.slice(0, at).includes(':')) n += 1;
  }
  return n;
}

/** The B9 shapes, in order. */
const B9_SCRUBS: readonly ((text: string) => string)[] = [
  (t) => t.replace(NPMRC_AUTH, `$1$2${REDACTED}`),
  (t) => t.replace(AUTHORIZATION, `$1${REDACTED}`),
  scrubPasswordElements,
  scrubUrlUserinfo,
];

/**
 * `redactText` replaces a text over its limit as a whole, and only the tail is kept: it gets the
 * last whole lines up to this many characters. Starting at a line keeps a secret from being cut in
 * half where no pattern would recognise it.
 */
const REDACT_WINDOW_CHARS = 32_768;

function lastLines(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  const start = text.length - maxChars;
  const newline = text.indexOf('\n', start);
  if (newline !== -1 && newline < text.length - 1) return text.slice(newline + 1);
  // The last line alone is longer: all of it (redactText replaces it whole if it is too long).
  return text.slice(text.lastIndexOf('\n', start) + 1);
}

/** The first `maxBytes` bytes of the UTF-8 text, ending at a whole character. */
export function utf8Head(text: string, maxBytes: number): string {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length <= maxBytes) return text;
  let end = maxBytes;
  // A continuation byte (10xxxxxx) at the cut means the character before it is cut in two.
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) end--;
  return new TextDecoder().decode(bytes.subarray(0, end));
}

/** The last `maxBytes` bytes of the UTF-8 text, starting at a whole character. */
export function utf8Tail(text: string, maxBytes: number): string {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length <= maxBytes) return text;
  let start = bytes.length - maxBytes;
  // A continuation byte (10xxxxxx) is the inside of a character.
  while (start < bytes.length && ((bytes[start] ?? 0) & 0xc0) === 0x80) start++;
  return new TextDecoder().decode(bytes.subarray(start));
}

/**
 * §6.9, B9: tool output fit for `failure.message`. In order: each secret value (the project token,
 * {@link secretEnvValues}) becomes `[redacted]`; the B9 shapes (`.npmrc` auth lines,
 * `Authorization:` values, `<password>` elements, URL credentials) too; Qualor's general secret
 * redaction runs; then only the last 2 KiB stay, cut at a character boundary. Everything is
 * scrubbed before the cut, so no half secret survives it.
 */
export function scrubToolOutput(text: string, secrets: readonly string[]): string {
  const known = replaceSecrets(text, secrets);
  const shaped = B9_SCRUBS.reduce((out, scrub) => scrub(out), known);
  const redacted = redactText(lastLines(shaped, REDACT_WINDOW_CHARS)).text;
  return utf8Tail(redacted, FIX_LIMITS.messageBytes);
}

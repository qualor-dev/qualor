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

const REDACTED = '[redacted]';

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

function replaceSecrets(text: string, secrets: readonly string[]): string {
  return secrets
    .filter((s) => s.length >= MIN_SECRET_CHARS)
    .toSorted((a, b) => b.length - a.length)
    .reduce((out, secret) => out.split(secret).join(REDACTED), text);
}

/** `.npmrc` `_auth=`, `_password=` and `//host/:_authToken=` lines: the value to the line end. */
const NPMRC_AUTH = /(_auth(?:Token)?|_password)([ \t]{0,32}=[ \t]{0,32})\S[^\r\n]*/gi;
/** An `Authorization:` header (`Proxy-Authorization:` too): the value to the line end. */
const AUTHORIZATION = /(authorization["']?[ \t]{0,32}:[ \t]{0,32})\S[^\r\n]*/gi;
/** A Maven `settings.xml` `<password>` element. */
const PASSWORD_ELEMENT = /(<password>)[^<]+(<\/password>)/gi;
/** `scheme://user:password@`; the password may hold `/` or `@`, so it runs to the last `@`. */
const URL_PASSWORD = /([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s:/@"'`]{0,256}:([^\s"'`]{1,1024})@/gi;
/** `scheme://token@`: a user name alone may be a token. */
const URL_USER = /([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s:/@"'`]{1,256}@/gi;
/** `host:8080/…@`: a port and a path, not a password. */
const PORT = /^\d{1,5}(?:\/|$)/;

function urlPassword(match: string, scheme: string, password: string): string {
  return PORT.test(password) ? match : `${scheme}${REDACTED}@`;
}

/** The B9 shapes, in order. */
const B9_SCRUBS: readonly ((text: string) => string)[] = [
  (t) => t.replace(NPMRC_AUTH, `$1$2${REDACTED}`),
  (t) => t.replace(AUTHORIZATION, `$1${REDACTED}`),
  (t) => t.replace(PASSWORD_ELEMENT, `$1${REDACTED}$2`),
  (t) => t.replace(URL_PASSWORD, urlPassword),
  (t) => t.replace(URL_USER, `$1${REDACTED}@`),
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

/** The last `maxBytes` bytes of the UTF-8 text, starting at a whole character. */
function utf8Tail(text: string, maxBytes: number): string {
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

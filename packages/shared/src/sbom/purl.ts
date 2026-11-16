/**
 * Package URL parser, written in-house to purl-spec v1.1.1
 * (https://github.com/package-url/purl-spec/blob/v1.1.1/PURL-SPECIFICATION.rst).
 * No dependencies. Components come back percent-decoded; the type and the qualifier keys are
 * lowercased. A purl is refused (null) when it is malformed, has a bad `%` escape, or decodes to a
 * NUL or a lone surrogate (neither can be stored in PostgreSQL's text or jsonb).
 */
export interface Purl {
  type: string;
  namespace: string | null;
  name: string;
  version: string | null;
  qualifiers: Readonly<Record<string, string>>;
  subpath: string | null;
}

const TYPE = /^[a-zA-Z][a-zA-Z0-9.+-]*$/;
const QUALIFIER_KEY = /^[a-zA-Z][a-zA-Z0-9._-]*$/;
const BAD_UTF16 = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]|\0/;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const ENCODER = new TextEncoder();

/** Percent-decodes one component (`+` stays a plus); null for a bad escape, invalid UTF-8, NUL or lone surrogate. */
function decode(text: string): string | null {
  if (BAD_UTF16.test(text)) return null;
  if (!text.includes('%')) return text;
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x25) {
      const hex = text.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) return null;
      bytes.push(Number.parseInt(hex, 16));
      i += 2;
    } else if (c < 0x80) {
      bytes.push(c);
    } else {
      // A non-ASCII character that is not escaped: keep its UTF-8 bytes.
      const cp = text.codePointAt(i) as number;
      bytes.push(...ENCODER.encode(String.fromCodePoint(cp)));
      if (cp > 0xffff) i++;
    }
  }
  let out: string;
  try {
    out = UTF8.decode(Uint8Array.from(bytes));
  } catch {
    return null;
  }
  return BAD_UTF16.test(out) ? null : out;
}

function parseSubpath(text: string): string | null | undefined {
  const segments: string[] = [];
  for (const raw of text.split('/')) {
    if (raw === '') continue;
    const d = decode(raw);
    if (d === null || d.includes('/') || d === '.' || d === '..') return undefined;
    segments.push(d);
  }
  return segments.length > 0 ? segments.join('/') : null;
}

/** Parses a purl; null for anything that is not one. */
export function parsePurl(text: string): Purl | null {
  if (typeof text !== 'string' || !/^pkg:/i.test(text)) return null;
  let rest = text.slice(4);

  let subpath: string | null = null;
  const hash = rest.lastIndexOf('#');
  if (hash >= 0) {
    const parsed = parseSubpath(rest.slice(hash + 1));
    if (parsed === undefined) return null;
    subpath = parsed;
    rest = rest.slice(0, hash);
  }

  const entries: [string, string][] = [];
  const question = rest.lastIndexOf('?');
  if (question >= 0) {
    const seen = new Set<string>();
    for (const pair of rest.slice(question + 1).split('&')) {
      if (pair === '') continue;
      const eq = pair.indexOf('=');
      if (eq < 0) return null;
      const key = pair.slice(0, eq).toLowerCase();
      if (!QUALIFIER_KEY.test(key) || seen.has(key)) return null;
      seen.add(key);
      const value = decode(pair.slice(eq + 1));
      if (value === null) return null;
      if (value !== '') entries.push([key, value]);
    }
    rest = rest.slice(0, question);
  }

  let version: string | null = null;
  // Only the last segment carries a version: an unencoded `@scope` of npm is no separator.
  const at = rest.lastIndexOf('@');
  if (at > rest.lastIndexOf('/')) {
    version = decode(rest.slice(at + 1));
    if (version === null) return null;
    if (version === '') version = null;
    rest = rest.slice(0, at);
  }

  rest = rest.replace(/^\/+/, '');
  const slash = rest.indexOf('/');
  if (slash < 0) return null;
  const type = rest.slice(0, slash);
  if (!TYPE.test(type)) return null;

  const parts: string[] = [];
  for (const raw of rest.slice(slash + 1).split('/')) {
    if (raw === '') continue;
    const d = decode(raw);
    if (d === null) return null;
    parts.push(d);
  }
  const name = parts.pop();
  if (name === undefined) return null;
  return {
    type: type.toLowerCase(),
    namespace: parts.length > 0 ? parts.join('/') : null,
    name,
    version,
    qualifiers: Object.fromEntries(entries),
    subpath,
  };
}

/** The name an inventory row carries; for pypi the same form as `purlOf` (server) builds a purl from. */
export function inventoryName(purl: Purl): string {
  if (purl.type === 'deb' || purl.type === 'rpm' || purl.type === 'apk') return purl.name;
  if (purl.type === 'maven') {
    return purl.namespace === null ? purl.name : `${purl.namespace}:${purl.name}`;
  }
  const full = purl.namespace === null ? purl.name : `${purl.namespace}/${purl.name}`;
  return purl.type === 'pypi' ? full.toLowerCase().replace(/_/g, '-') : full;
}

/**
 * The version an inventory row carries: rpm and deb fold the `epoch` qualifier in (`1:` prefix,
 * none for 0), unless the version already starts with one. Syft writes a Debian epoch in the
 * version (`login@1%3A4.13…`); Trivy 0.74.0 writes it as `epoch=1`, as for rpm.
 */
export function inventoryVersion(purl: Purl): string | null {
  if ((purl.type !== 'rpm' && purl.type !== 'deb') || purl.version === null) return purl.version;
  const epoch = purl.qualifiers.epoch;
  if (epoch === undefined || /^0*$/.test(epoch) || /^\d+:/.test(purl.version)) return purl.version;
  return `${epoch}:${purl.version}`;
}

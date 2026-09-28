import { lstatSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { isUrl } from '@qualor/shared';
import { real, staysInside, within } from './binary';
import { shown } from './reason';

/** A ruleset PMD resolves from its own classpath (`category/java/…`, `rulesets/java/…`). */
const CLASSPATH_RULESET = /^(category|rulesets)\/[A-Za-z0-9_./-]+\.xml$/;

/** A ruleset file larger than this is not read (PMD rulesets are a few KiB). */
export const MAX_RULESET_BYTES = 4 * 1024 * 1024;
/** At most this many repository rulesets are followed through `ref`s. */
const MAX_RULESETS = 256;

/** A plain PMD built-in ruleset name: no `..` segment can make it reach a file. */
export function isClasspathRuleset(name: string): boolean {
  return CLASSPATH_RULESET.test(name) && !name.split('/').includes('..');
}

const ENCODINGS = /^(utf-?8|us-ascii|ascii|iso-8859-1|latin1)$/i;

/** Comments, CDATA sections and processing instructions: nothing in them is an element. */
const NON_MARKUP = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<\?[\s\S]*?\?>/g;
/** The start of a `rule` element, with or without a namespace prefix. */
const RULE_START = /<(?:[A-Za-z_][\w.-]*:)?rule(?=[\s/>])/g;
/** A complete, well-formed start tag (attribute values may contain `>`). */
const START_TAG =
  /<(?:[A-Za-z_][\w.-]*:)?rule((?:\s+[^\s=/>]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*\/?>/y;
const ATTRIBUTE = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

/** XML attribute-value decoding without a DTD: the five predefined entities and char refs. */
function decodeAttribute(raw: string): string | null {
  let bad = false;
  const decoded = raw.replace(/&([^;&\s]*);|&/g, (m, name: string | undefined) => {
    if (name === undefined) {
      bad = true;
      return m;
    }
    const named: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
    const value = named[name];
    if (value !== undefined) return value;
    const code = /^#x([0-9A-Fa-f]{1,6})$/.exec(name)?.[1] ?? /^#(\d{1,7})$/.exec(name)?.[1];
    const cp = code === undefined ? NaN : Number.parseInt(code, name.startsWith('#x') ? 16 : 10);
    if (!Number.isInteger(cp) || cp > 0x10ffff) {
      bad = true;
      return m;
    }
    return String.fromCodePoint(cp);
  });
  // Attribute-value normalisation turns tab and line breaks into spaces.
  return bad ? null : decoded.replace(/[\t\r\n]/g, ' ');
}

/**
 * The `ref` attributes of every `rule` element of a PMD ruleset, read without any DTD support
 * (PMD's own parser refuses a DOCTYPE too). Anything this reader cannot check with certainty
 * (another encoding, a DOCTYPE, a `rule` tag it cannot parse, an unknown entity) is an error,
 * never a pass.
 */
export function rulesetRefs(bytes: Buffer): { refs: string[] } | { error: string } {
  if (
    bytes.length >= 2 &&
    ((bytes[0] === 0xfe && bytes[1] === 0xff) || (bytes[0] === 0xff && bytes[1] === 0xfe))
  ) {
    return { error: 'is not UTF-8 (only UTF-8 rulesets are checked)' };
  }
  if (bytes.includes(0)) return { error: 'is not UTF-8 (only UTF-8 rulesets are checked)' };
  let text = bytes.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  // An XML parser detects EBCDIC (and other encodings without zero bytes) from the first bytes
  // (`<?xml` is 4C 6F A7 94 in EBCDIC), which UTF-8 decoding here would misread. A ruleset must
  // therefore start with `<` or ASCII whitespace, after an optional byte order mark.
  if (!/^[<\t\n\r ]/.test(text)) {
    return { error: 'does not start with < (only UTF-8 rulesets are checked)' };
  }
  const declared = /^\s*<\?xml\s[^>]*?encoding\s*=\s*["']([^"']*)["']/.exec(text)?.[1];
  if (declared !== undefined && !ENCODINGS.test(declared)) {
    return { error: `declares the encoding ${shown(declared)} (only UTF-8 rulesets are checked)` };
  }
  const markup = text.replace(NON_MARKUP, (m) => ' '.repeat(m.length));
  if (/<!DOCTYPE|<!ENTITY/i.test(markup)) return { error: 'declares a DOCTYPE' };
  const refs: string[] = [];
  for (const m of markup.matchAll(RULE_START)) {
    START_TAG.lastIndex = m.index;
    const tag = START_TAG.exec(markup);
    if (tag === null) return { error: 'has a rule element that cannot be checked' };
    const seen = new Set<string>();
    for (const a of (tag[1] ?? '').matchAll(ATTRIBUTE)) {
      const name = a[1] ?? '';
      if (seen.has(name)) return { error: 'has a rule element with a duplicate attribute' };
      seen.add(name);
      if (name !== 'ref') continue;
      const value = decodeAttribute(a[2] ?? a[3] ?? '');
      if (value === null) return { error: 'has a rule ref with an entity that cannot be checked' };
      refs.push(value);
    }
  }
  return { refs };
}

/** `ref="…"`: the ruleset part of a reference, or null for a rule of the same ruleset. */
function rulesetPart(ref: string): string | null | { error: string } {
  if (ref.endsWith('.xml')) return ref;
  const slash = ref.lastIndexOf('/');
  if (slash > 0 && ref.slice(0, slash).endsWith('.xml')) return ref.slice(0, slash);
  if (/^[A-Za-z0-9_$.-]+$/.test(ref)) return null;
  return { error: 'is neither a ruleset nor a rule name' };
}

function exists(file: string): boolean {
  try {
    lstatSync(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * Ruling V4: a repository's PMD ruleset may reference only other repository rulesets (followed
 * recursively) and PMD's built-in `category/…` and `rulesets/…` rulesets. A reference with a URL
 * scheme (PMD would download it), an absolute path, a backslash, or a path outside the
 * repository is a configuration error. PMD resolves a relative reference both against the
 * working directory (the repository root) and against the referencing ruleset's directory, so
 * every existing candidate is checked; a candidate outside the repository is an error when it
 * exists, or when no candidate exists at all. Returns the error message, or null.
 */
export function checkRulesetTree(root: string, top: string): string | null {
  const queue = [top];
  const visited = new Set<string>();
  const rel = (file: string) => path.relative(root, file).split(path.sep).join('/');
  while (queue.length > 0) {
    const file = queue.shift() as string;
    const key = real(file);
    if (visited.has(key)) continue;
    visited.add(key);
    if (visited.size > MAX_RULESETS) {
      return `ruleset ${shown(rel(top))} references more than ${MAX_RULESETS} rulesets`;
    }
    const name = `ruleset ${shown(rel(file))}`;
    let bytes: Buffer;
    try {
      if (statSync(file).size > MAX_RULESET_BYTES) {
        return `${name} is larger than ${MAX_RULESET_BYTES / 1024 / 1024} MiB`;
      }
      bytes = readFileSync(file);
    } catch {
      return `${name} cannot be read`;
    }
    const parsed = rulesetRefs(bytes);
    if ('error' in parsed) return `${name} ${parsed.error}`;
    for (const ref of parsed.refs) {
      const bad = (why: string) => `${name}: rule ref "${shown(ref)}" ${why}`;
      const v = ref.trim();
      if (v === '') return bad('is empty');
      if (isUrl(v)) return bad('is a URL (PMD would download it)');
      if (path.isAbsolute(v) || path.posix.isAbsolute(v) || path.win32.isAbsolute(v)) {
        return bad('is an absolute path (only repository and PMD built-in rulesets)');
      }
      if (v.includes('\\')) return bad('has a backslash (use / in rule references)');
      const part = rulesetPart(v);
      if (part === null) continue;
      if (typeof part !== 'string') return bad(part.error);
      const candidates = [path.resolve(root, part), path.resolve(path.dirname(file), part)];
      let found = false;
      let outside = false;
      for (const candidate of candidates) {
        if (!within(path.resolve(root), candidate)) {
          // `../x.xml` from a subdirectory is outside only against the root: a candidate
          // outside the repository is an error when PMD could actually read it.
          if (exists(candidate)) return bad('is outside the repository');
          outside = true;
          continue;
        }
        if (!exists(candidate)) continue;
        if (!staysInside(root, candidate)) return bad('is outside the repository');
        found = true;
        queue.push(candidate);
      }
      if (!found && outside) return bad('is outside the repository');
      if (!found && !isClasspathRuleset(part)) {
        return bad('is neither a repository file nor a PMD built-in ruleset');
      }
    }
  }
  return null;
}

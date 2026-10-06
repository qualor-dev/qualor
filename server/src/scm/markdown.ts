/**
 * Safe GitLab Markdown for comments (scm.md §6). Every value that did not come from Qualor's own
 * code goes through {@link codeSpan}: inside a code span GitLab renders no Markdown, HTML, image,
 * link, autolink, emoji, reference (`#1`, `!2`) or mention (`@all`), and a value that can never
 * contain a line break never starts a line, where GitLab would run a quick action (`/merge`).
 *
 * The guarantee, tested by the adversarial corpus of `render.test.ts`:
 * - a value is one line: every C0/C1 control (LF, CR, NEL, VT, FF, NUL...), U+2028/U+2029 and
 *   every bidirectional control becomes a space, so it can neither start a line nor reorder
 *   what a reviewer reads;
 * - invisible format characters (zero-width space, word joiner, BOM, soft hyphen, tag
 *   characters...) and blank-looking fillers (Hangul fillers, the braille blank) are removed and
 *   lone surrogates become U+FFFD; ZWJ, ZWNJ and variation selectors stay, so emoji sequences and
 *   scripts that need them render whole;
 * - it is cut to its bound in code points (never inside a grapheme when a whole one fits)
 *   before the fence is chosen, so the fence is at most bound + 1 backticks;
 * - the fence is one backtick longer than the longest run inside and padded with a space, so
 *   the value cannot close the span;
 * - bodies are shortened only at whole lines ({@link linesWithinBytes}), so no span is cut open;
 * - links are Qualor's own http(s) URLs and rules' https documentation links only
 *   ({@link qualorLink}, {@link ruleKeyMarkdown}), with the characters that could end or break a
 *   link destination percent-encoded.
 */
import { safeCodeSpan, safePlainValue } from '@qualor/shared';

/** Bounds of scm.md §6, in characters (code points). */
export const MAX_MESSAGE_CHARS = 300;
export const MAX_PATH_CHARS = 200;
export const MAX_VALUE_CHARS = 100;

/**
 * Unsafe characters replaced by a space, invisible ones removed, then cut to `max` code points:
 * {@link safePlainValue} of packages/shared, the one implementation the CLI uses too.
 */
export function plainValue(value: string, max: number): string {
  return safePlainValue(value, max);
}

/**
 * `value` as a CommonMark code span ({@link safeCodeSpan} of packages/shared): {@link plainValue},
 * then a backtick fence one longer than the longest backtick run inside, padded with one space on
 * each side (CommonMark strips exactly that padding, so the value shows as it is, even when it
 * starts or ends with a backtick).
 */
export function codeSpan(value: string, max: number = MAX_VALUE_CHARS): string {
  return safeCodeSpan(value, max);
}

/**
 * The longest run of whole lines, from the first, that fits in `maxBytes` of UTF-8 when joined
 * with `\n`. A line is never cut, so a code span is never left open.
 */
export function linesWithinBytes(lines: readonly string[], maxBytes: number): string {
  const kept: string[] = [];
  let bytes = 0;
  for (const line of lines) {
    const size = Buffer.byteLength(line, 'utf8') + (kept.length > 0 ? 1 : 0);
    if (bytes + size > maxBytes) break;
    kept.push(line);
    bytes += size;
  }
  return kept.join('\n');
}

/** Characters that could end or break a Markdown link destination, or start a code span. */
const LINK_UNSAFE = /[()[\]<>`\\ "']/g;

/**
 * `[label](url)` for one of Qualor's own links (`QUALOR_PUBLIC_URL` with ids it generated) or a
 * rule's documentation link ({@link ruleKeyMarkdown}), or null when `url` is null or not a plain
 * http(s) URL. `label` is fixed text or a {@link codeSpan} (never a raw value).
 */
export function qualorLink(label: string, url: string | null): string | null {
  if (url === null || !URL.canParse(url)) return null;
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  if (parsed.username !== '' || parsed.password !== '') return null;
  // Only what follows the origin is encoded: an IPv6 host keeps its brackets
  // (`http://[::1]:8080`), which WHATWG requires. An http(s) URL without credentials is its origin
  // followed by the rest. A host name WHATWG lets through with a character that could end the
  // destination (`a(b).com`) is refused rather than encoded.
  if (!parsed.href.startsWith(parsed.origin)) return null;
  const host = parsed.origin.replace(/^https?:\/\/\[[0-9a-f:.]+\]/, '');
  if (new RegExp(LINK_UNSAFE.source).test(host)) return null;
  const rest = parsed.href
    .slice(parsed.origin.length)
    .replace(LINK_UNSAFE, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`);
  return `[${label}](${parsed.origin}${rest})`;
}

/** A rule documentation link longer than this (once encoded) is left out: bodies have byte bounds. */
export const MAX_RULE_LINK_CHARS = 512;
/** A key that holds none of these is safe as link text in its code span (no bracket to balance). */
const LINK_TEXT_UNSAFE = /[[\]`\\]/;

/**
 * A rule's documentation link when it is safe to show (the server-side twin of the UI's
 * `safeHelpUri`, https only): an https URL without credentials, at most
 * {@link MAX_RULE_LINK_CHARS}, with no space, control or invisible character; else null.
 */
export function ruleDocUrl(helpUri: string | null | undefined): string | null {
  if (helpUri === null || helpUri === undefined || helpUri.length > MAX_RULE_LINK_CHARS)
    return null;
  if (/\s/.test(helpUri) || plainValue(helpUri, MAX_RULE_LINK_CHARS) !== helpUri) return null;
  if (!URL.canParse(helpUri)) return null;
  const parsed = new URL(helpUri);
  if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '') return null;
  return helpUri;
}

/**
 * A rule's key as a {@link codeSpan}, made a link to the rule's documentation when
 * {@link ruleDocUrl} accepts `helpUri`, it stays within {@link MAX_RULE_LINK_CHARS} once encoded
 * by {@link qualorLink}, and the key holds no bracket, backtick or backslash; else the plain code
 * span. The same inputs always give the same text, so a body compared with the one posted before
 * does not change needlessly.
 */
export function ruleKeyMarkdown(ruleKey: string, helpUri: string | null | undefined): string {
  const label = codeSpan(ruleKey);
  const url = ruleDocUrl(helpUri);
  if (url === null || LINK_TEXT_UNSAFE.test(ruleKey)) return label;
  const link = qualorLink(label, url);
  // `[label](destination)`: the destination is what is left after the label and four brackets.
  return link !== null && link.length - label.length - 4 <= MAX_RULE_LINK_CHARS ? link : label;
}

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const IS_UUID = new RegExp(`^${UUID}$`);
const SUMMARY_MARKER = new RegExp(`^<!-- qualor:summary (${UUID}) -->$`);
const ISSUE_MARKER = new RegExp(`^<!-- qualor:issue (${UUID}) -->$`);

function uuid(id: string): string {
  if (!IS_UUID.test(id)) throw new Error('a Qualor marker holds a UUID only');
  return id;
}

/** scm.md §5.3: the first line of a summary note. */
export function summaryMarker(projectId: string): string {
  return `<!-- qualor:summary ${uuid(projectId)} -->`;
}

/** scm.md §5.3: the first line of an inline discussion's first note. */
export function issueMarker(issueId: string): string {
  return `<!-- qualor:issue ${uuid(issueId)} -->`;
}

/**
 * What a note body's first line marks, or null. Only the first line counts: a marker quoted in a
 * reply or inside a value (always on a later line) is ignored. The caller also checks the author.
 */
export function markerOf(
  body: string,
): { kind: 'summary'; projectId: string } | { kind: 'issue'; issueId: string } | null {
  const firstLine = (body.split('\n', 1)[0] ?? '').replace(/\r$/, '');
  const summary = SUMMARY_MARKER.exec(firstLine);
  if (summary?.[1]) return { kind: 'summary', projectId: summary[1] };
  const issue = ISSUE_MARKER.exec(firstLine);
  if (issue?.[1]) return { kind: 'issue', issueId: issue[1] };
  return null;
}

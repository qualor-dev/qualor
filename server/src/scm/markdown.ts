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
 *
 * The AI review's words are the exception that reads as prose, not as a value in a code span: a
 * model's sentences are posted as text through {@link safeProse}, which keeps ordinary words plain
 * and puts every other word in a code span, so nothing it writes is more than a word to GitLab and
 * GitHub either. In a fenced block, which renders none of it, they are cleaned the same way and
 * written as they are ({@link plainProse}).
 */
import {
  CONTROL_CHARS,
  cutAtGrapheme,
  INVISIBLE_CHARS,
  JOINER_CHARS,
  LONE_SURROGATE_SOURCE,
  safeCodeSpan,
  safePlainValue,
} from '@qualor/shared';

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
 * What prose turns into a space: the control and bidirectional characters, the invisible ones and
 * the joiners (packages/shared's lists, imported). A line break is split off before.
 */
const PROSE_UNSAFE = new RegExp(`[${CONTROL_CHARS}${INVISIBLE_CHARS}${JOINER_CHARS}]`, 'gu');
const LONE_SURROGATES = new RegExp(LONE_SURROGATE_SOURCE, 'g');
/**
 * A word of ordinary prose: a core of letters, each with the combining marks that follow it, and
 * decimal digits, with apostrophes and hyphens between its parts, one opening bracket or quote
 * before it and closing marks after it. The other kinds of number (①, ², ½, Ⅷ) are no digits to a
 * provider, and a commit hash beside one is still a hash it links: they are no plain core.
 */
const PROSE_WORD =
  /^[("“‘]?((?:\p{L}\p{M}*|\p{Nd})+(?:['’-](?:\p{L}\p{M}*|\p{Nd})+)*)([.,;:!?)"”’…。।]*)$/u;
/** The mark a plain word may open with, and the ones it may end in. */
const PROSE_OPENERS = '("“‘';
/** ... with the full stops of CJK (。) and of Devanagari (।), which close a sentence as `.` does. */
const PROSE_CLOSERS = '.,;:!?)"”’…。।';
/**
 * A range of numbers, `2–3`: two digit runs and an en dash, with the marks a word may open with
 * and end in. A part that is as long as a commit hash is no number (it is linked, see COMMIT_LIKE).
 */
const PROSE_RANGE = /^[("“‘]?(\p{Nd}+)–(\p{Nd}+)[.,;:!?)"”’…。।]*$/u;
/**
 * The marks that join two code spans of one word and stay plain between them, one at a time:
 * `try`/`catch`, (`a`,`b`). None of them can begin a link, a reference or a quick action there: a
 * code span stands on each side, and the line starts before the first span.
 */
const PROSE_JOINS = '/,-+.:';
/** The dashes of running text: plain by themselves. */
const PROSE_DASHES: ReadonlySet<string> = new Set(['—', '–']);
/** Where a word is cut at a run of dashes that joins two pieces: the run's end is the second piece's start. */
function dashJoinEnd(word: string, from: number): number {
  let end = from;
  while (end < word.length && PROSE_DASHES.has(word.charAt(end))) end += 1;
  return end;
}
/** A list marker at the start of a line: `- `, `* ` or a number (at most the nine CommonMark reads) and a dot. */
const PROSE_LIST_MARKER = /^(?:[-*]|(\d{1,9})\.) +(?=\S)/;
/** Hexadecimal of a commit's size: GitLab and GitHub link it to the commit. */
const COMMIT_LIKE = /^[0-9a-f]{7,64}$/i;
/**
 * A part of a word that holds a letter and is followed by a hyphen and a digit: `GH-26` links to an
 * issue on GitHub, and `JIRA-123`, `AB1-123` and `X9-1` to the tracker a GitLab project has set up.
 * What comes before the letter in its part is no matter: GitHub links `GH-1` wherever the character
 * before the G is no ASCII letter or digit (after an Arabic-Indic digit, an accented letter or a Han
 * character), and GitLab's Jira pattern ends a key at the same characters. So `9GH-1`, which no
 * provider links, is in a code span too.
 * Left plain, being words: GitLab's EWM integration matches `bug 12` and `task 3`, ClickUp's matches
 * `CU-abc`, the autolinks a GitHub repository sets up can match an alphanumeric id (`TICKET-abc`),
 * and a GitLab Jira integration can be given a `jira_issue_regex` of its own. All of them link only
 * to what the project or the repository has configured.
 * Written so that a long word is read in linear time on every engine: a match starts only where a
 * part starts (the word's start, or just after a hyphen or an apostrophe), so each part is read
 * once. A lookbehind (`(?<=\p{L}[^-'’]*)-\p{Nd}`) is linear on Node 24 but not on Node 22, which
 * the images run: 80 ms for a 20 000-character word.
 */
export const TRACKER_LIKE = /(?:^|[-'’])[^-'’\p{L}]*\p{L}[^-'’]*-\p{Nd}/u;
/** A combining mark, which changes nothing of a word a provider reads for a link or a reference. */
const COMBINING_MARKS = /\p{M}/gu;
/** Where a hash may begin or end inside a plain core: at a hyphen, an apostrophe or a combining mark. */
const HASH_EDGES = /['’-]|\p{M}+/u;
/** A word or a model's span is cut to this many characters. */
const PROSE_SPAN_CHARS = MAX_PATH_CHARS;
/**
 * The ending of a word that may follow the model's spans in it and stay plain, before the closing
 * marks: letters with their combining marks, an apostrophe before them or between them allowed, as
 * the `s` of `` `CheckoutError`s ``, the `'s` of `` `codes`'s `` or the `ing` of `` `fetch`ing ``.
 */
const SPAN_ENDING = /^['’]?((?:\p{L}\p{M}*)+(?:['’](?:\p{L}\p{M}*)+)*)$/u;
/** The closing marks that close a bracket or a quote, each with the mark it closes ... */
const OPENING_OF: Readonly<Record<string, string>> = { ')': '(', '"': '"', '”': '“', '’': '‘' };
/** ... and each opening mark with the one that closes it. */
const CLOSING_OF: Readonly<Record<string, string>> = { '(': ')', '"': '"', '“': '”', '‘': '’' };

/**
 * Whether `word` is plain: ordinary letters and digits that no provider turns into a link or a
 * reference. A word that is `www` and a full stop (`www. x`, `(www.) x`, `www.… x`) is not: GitHub
 * links it to `http://www` wherever a space or a bracket comes before it and whatever comes after
 * it. Only lower case links there; any case is refused.
 */
function isPlainProse(word: string): boolean {
  if (PROSE_DASHES.has(word)) return true;
  const range = PROSE_RANGE.exec(word);
  if (range !== null) return !COMMIT_LIKE.test(range[1] ?? '') && !COMMIT_LIKE.test(range[2] ?? '');
  const match = PROSE_WORD.exec(word);
  if (match === null) return false;
  const marked = match[1] ?? '';
  const core = marked.replace(COMBINING_MARKS, '');
  if (core.toLowerCase() === 'www' && (match[2] ?? '').startsWith('.')) return false;
  // A hash is read both with the marks taken out of the word and as the pieces the marks split it
  // into: GitHub reads a hash beside a mark as part of a word, GitLab may not.
  const parts = [...core.split(/['’-]/), ...marked.split(HASH_EDGES)];
  return !TRACKER_LIKE.test(core) && !parts.some((part) => COMMIT_LIKE.test(part));
}

/**
 * Whether what is glued after the model's spans in a word stays plain beside them: closing marks
 * alone, or a word's ending ({@link SPAN_ENDING}) and then closing marks, which the plain-word test
 * would let through alone, so that nothing a provider links or references can hide in it.
 */
function plainAfterSpans(glued: string): boolean {
  let end = glued.length;
  while (end > 0 && PROSE_CLOSERS.includes(glued.charAt(end - 1))) end -= 1;
  if (end === 0) return true;
  const ending = SPAN_ENDING.exec(glued.slice(0, end));
  return ending !== null && isPlainProse(`${ending[1] ?? ''}${glued.slice(end)}`);
}

/**
 * Whether `text` holds `mark` without its `partner`: more of it than of the partner, or, for a quote
 * that is its own partner, an odd number of it.
 */
function unpaired(text: string, mark: string, partner: string): boolean {
  const count = (c: string): number => text.split(c).length - 1;
  return mark === partner ? count(mark) % 2 === 1 : count(mark) > count(partner);
}

/**
 * A word that is not plain, in a code span, with the mark it opens with and the marks it ends in
 * outside the span, as they are around the model's own spans: `src/a.ts.` is `` `src/a.ts`. `` and
 * `(x.y)` is `` (`x.y`) ``. A bracket or a quote among them that pairs with one inside the word is
 * the code's and stays in the span (`foo()`, `x="a"`). A word that is only marks, or that is plain
 * once they are off (`www.`, which GitHub links), is one span, whole.
 */
function wordSpan(word: string): string {
  let start = PROSE_OPENERS.includes(word.charAt(0)) ? 1 : 0;
  let end = word.length;
  while (end > start && PROSE_CLOSERS.includes(word.charAt(end - 1))) {
    const closing = word.charAt(end - 1);
    const opening = OPENING_OF[closing];
    if (opening !== undefined && unpaired(word.slice(start, end - 1), opening, closing)) break;
    end -= 1;
  }
  const opener = word.charAt(0);
  if (start === 1 && unpaired(word.slice(1, end), CLOSING_OF[opener] ?? opener, opener)) start = 0;
  const core = word.slice(start, end);
  if (core === '' || isPlainProse(core)) return codeSpan(word, PROSE_SPAN_CHARS);
  return `${word.slice(0, start)}${codeSpan(core, PROSE_SPAN_CHARS)}${word.slice(end)}`;
}

/**
 * The code span the model wrote that begins at `start` (a backtick): its content, as CommonMark
 * reads it (one space off each side when both have one and the content is not only spaces), and
 * where the span ends. A run of backticks is closed by the next run of the same length; one that
 * is never closed is no span. Null for no span.
 */
function modelSpanAt(text: string, start: number): { content: string; end: number } | null {
  let run = 0;
  while (text[start + run] === '`') run += 1;
  let from = start + run;
  for (;;) {
    const found = text.indexOf('`', from);
    if (found < 0) return null;
    let length = 0;
    while (text[found + length] === '`') length += 1;
    if (length === run) {
      const content = text.slice(start + run, found);
      const padded = content.length >= 2 && content.startsWith(' ') && content.endsWith(' ');
      return {
        content: padded && content.trim() !== '' ? content.slice(1, -1) : content,
        end: found + length,
      };
    }
    from = found + length;
  }
}

/**
 * The code span the model wrote at `start` (a backtick) and the spans joined to it by one of
 * {@link PROSE_JOINS} (`try`/`catch`): each through {@link codeSpan}, the joins plain between them,
 * and where the last one ends. Null when there is no span at `start`.
 */
function spansJoinedAt(text: string, start: number): { out: string; end: number } | null {
  const first = modelSpanAt(text, start);
  if (first === null) return null;
  let out = codeSpan(first.content, PROSE_SPAN_CHARS);
  let end = first.end;
  for (;;) {
    const join = text.charAt(end);
    const span =
      PROSE_JOINS.includes(join) && text[end + 1] === '`' ? modelSpanAt(text, end + 1) : null;
    if (span === null) return { out, end };
    out += `${join}${codeSpan(span.content, PROSE_SPAN_CHARS)}`;
    end = span.end;
  }
}

/**
 * The model's own span or spans at `at`, with the mark that opens before them and what is glued
 * after, as one word; null when there are none, or when something else is glued to them (then the
 * whole of it is one ordinary word).
 */
function spansWordAt(text: string, at: number): { out: string; next: number } | null {
  const opener =
    PROSE_OPENERS.includes(text.charAt(at)) && text[at + 1] === '`' ? text.charAt(at) : '';
  const start = at + opener.length;
  const spans = text[start] === '`' ? spansJoinedAt(text, start) : null;
  if (spans === null) return null;
  const space = text.indexOf(' ', spans.end);
  const end = space < 0 ? text.length : space;
  const glued = text.slice(spans.end, end);
  if (plainAfterSpans(glued)) return { out: `${opener}${spans.out}${glued}`, next: end };
  // A dash after them (and the plain ending or closing marks that come first) joins them to the
  // next piece, which is read on its own, from its start.
  const dash = glued.search(/[—–]/);
  if (dash < 0 || !plainAfterSpans(glued.slice(0, dash))) return null;
  const join = dashJoinEnd(glued, dash);
  const head = `${opener}${spans.out}${glued.slice(0, join)}`;
  if (join >= glued.length) return { out: head, next: end };
  const rest = proseWordAt(text, spans.end + join);
  return { out: `${head}${rest.out}`, next: rest.next };
}

/**
 * An ordinary word with an em or en dash between two pieces: each piece is read on its own (the
 * second from its start, so that a span of the model's after the dash stays one), and the dash
 * stays plain. Null when there is no such dash. A range of hashes is no join: it stays one span.
 */
function dashSplitWordAt(
  text: string,
  at: number,
  word: string,
): { out: string; next: number } | null {
  if (PROSE_RANGE.test(word)) return null;
  for (let i = 0; i < word.length; i += 1) {
    if (word.charAt(i) === '`') break;
    if (i === 0) continue;
    if (!PROSE_DASHES.has(word.charAt(i))) continue;
    const join = dashJoinEnd(word, i);
    if (join >= word.length) break;
    const head = word.slice(0, i);
    const rest = proseWordAt(text, at + join);
    return {
      out: `${isPlainProse(head) ? head : wordSpan(head)}${word.slice(i, join)}${rest.out}`,
      next: rest.next,
    };
  }
  return null;
}

/** The word of a line that begins at `at`, as prose writes it, and where the next one may begin. */
function proseWordAt(text: string, at: number): { out: string; next: number } {
  const spans = spansWordAt(text, at);
  if (spans !== null) return spans;
  const space = text.indexOf(' ', at);
  const end = space < 0 ? text.length : space;
  const word = text.slice(at, end);
  if (isPlainProse(word)) return { out: word, next: end };
  return dashSplitWordAt(text, at, word) ?? { out: wordSpan(word), next: end };
}

/** One line of prose, without its list marker: plain words as they are, anything else in a code span. */
function proseWords(text: string): string {
  const words: string[] = [];
  let at = 0;
  while (at < text.length) {
    if (text[at] === ' ') {
      at += 1;
      continue;
    }
    const word = proseWordAt(text, at);
    words.push(word.out);
    at = word.next;
  }
  return words.join(' ');
}

/** A cleaned line as prose: its list marker normalised, its words plain or in code spans. */
function proseLine(line: string): string {
  const marker = PROSE_LIST_MARKER.exec(line);
  if (marker === null) return proseWords(line);
  const prefix = marker[1] === undefined ? '- ' : `${marker[1]}. `;
  return `${prefix}${proseWords(line.slice(marker[0].length))}`;
}

/** The bounds of a model's text: in characters (code points), and in lines. */
export interface ProseBounds {
  maxChars: number;
  maxLines: number;
}

/**
 * A model's text cleaned and cut, as lines without their line breaks:
 * - a line break is LF, CRLF or CR; every other control, bidirectional, invisible or joiner
 *   character, and every white space but a space, becomes a space, and a lone surrogate U+FFFD;
 * - each line loses the spaces at its ends, and repeated blank lines become one;
 * - the text is cut to `maxChars` characters (at a grapheme boundary, with `…`) and to `maxLines`
 *   lines, with no blank line last.
 * Nothing it takes out is deleted: a character it removes leaves a space (see {@link safeProse}).
 */
function proseLines(text: string, { maxChars, maxLines }: ProseBounds): string[] {
  if (maxChars < 1 || maxLines < 1) return [];
  const lines: string[] = [];
  for (const raw of text.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw
      .replace(LONE_SURROGATES, '\ufffd')
      .replace(PROSE_UNSAFE, ' ')
      .replace(/[^\S ]/gu, ' ')
      .trim();
    if (line === '' && (lines.length === 0 || lines[lines.length - 1] === '')) continue;
    lines.push(line);
  }
  const cut = cutAtGrapheme(lines.join('\n').trimEnd(), maxChars).split('\n').slice(0, maxLines);
  while (cut.length > 0 && cut[cut.length - 1] === '') cut.pop();
  return cut;
}

/**
 * A model's sentences as text for people that GitLab and GitHub cannot read as anything but words.
 * The text is cleaned and cut ({@link proseLines}), then every line is written word by word:
 * - a line that starts with `- `, `* ` or a number and a dot becomes `- ` or `<n>. ` and keeps its
 *   rest;
 * - the backtick spans the model wrote are written again through {@link codeSpan}, with the mark
 *   that opens before them, the one mark that joins two of them (`/`, `,`, `-`, `+`, `.` or `:`)
 *   plain between them, and what is glued after them plain when it is closing marks, or a word's
 *   ending of letters (an apostrophe before or between them) that the plain-word test lets through
 *   alone, then closing marks: `` `try`/`catch` `` is two code spans and a slash, and
 *   `` `CheckoutError`s. `` a code span and `s.`. Anything else glued to a span (`.com`, `/x`,
 *   `@x`, `#1`, a digit) makes the whole word one code span;
 * - every other word, as white space separates them, stays plain only when it is letters and
 *   decimal digits (apostrophes and hyphens inside, combining marks on the letters, a bracket or
 *   quote before, closing marks after) that no provider turns into a commit link, a tracker
 *   reference or a `www.` link; a dash by itself is plain too. Anything else goes in a code span,
 *   with the mark it opens with and the marks it ends in outside the span, but a bracket or quote
 *   that pairs with one inside it (`foo()`), so `@x`, `#1`, `!1`, `~x`, `%x`, `&x`, `$x`, `/x`,
 *   `<x>`, `[x](y)`, `*`, `|`, `=`, `www.x`, `x.y`, `a:b`, `①` and the like are never active.
 * A line therefore starts with a letter, a digit, a backtick, an opening mark, a dash or a list
 * marker.
 *
 * Nothing it takes out is deleted: a character it removes leaves a space, so that a provider's key
 * a model split with hidden characters cannot be joined again here (the shared `codeSpan` and
 * `safePlainValue` delete the invisible ones, but they only ever see words from which this has
 * taken them already). The key itself is scrubbed when the answer is parsed (review/key-scrub.ts).
 */
export function safeProse(text: string, bounds: ProseBounds): string {
  return proseLines(text, bounds).map(proseLine).join('\n');
}

/**
 * A model's text cleaned and cut as {@link safeProse} cleans and cuts it ({@link proseLines}), each
 * line then written as it is, with no code span and no list marker made over: for a block that
 * renders none of it, the fenced block of the summary's prompt for an agent, which its fence (longer
 * than any run of backticks inside it) keeps inert. Anywhere Markdown renders, the model's words go
 * through `safeProse`.
 */
export function plainProse(text: string, bounds: ProseBounds): string {
  return proseLines(text, bounds).join('\n');
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
/** A full commit SHA, SHA-1 or SHA-256, in lower case. */
const FULL_SHA = '[0-9a-f]{40}(?:[0-9a-f]{24})?';
const IS_FULL_SHA = new RegExp(`^${FULL_SHA}$`);
const SUMMARY_MARKER = new RegExp(`^<!-- qualor:summary (${UUID}) -->$`);
const ISSUE_MARKER = new RegExp(`^<!-- qualor:issue (${UUID}) -->$`);
const FIXED_MARKER = new RegExp(`^<!-- qualor:fixed (${UUID}) (${FULL_SHA}) -->$`);

function uuid(id: string): string {
  if (!IS_UUID.test(id)) throw new Error('a Qualor marker holds a UUID only');
  return id;
}

/** Whether `sha` is a full commit SHA in lower case, as a marker holds it. */
export const isFullSha = (sha: string): boolean => IS_FULL_SHA.test(sha);

/** scm.md §5.3: the first line of a summary note. */
export function summaryMarker(projectId: string): string {
  return `<!-- qualor:summary ${uuid(projectId)} -->`;
}

/** scm.md §5.3: the first line of an inline discussion's first note. */
export function issueMarker(issueId: string): string {
  return `<!-- qualor:issue ${uuid(issueId)} -->`;
}

/**
 * github.md §6.4: the first line of the pull request review that carries a decoration's new
 * threads. Nothing reads it back: a review's body is no review comment, so it is never taken for
 * a thread ({@link markerOf} does not know it).
 */
export function reviewMarker(projectId: string): string {
  return `<!-- qualor:review ${uuid(projectId)} -->`;
}

/**
 * The first line of Qualor's answer to a reply in one of its threads (6I-4): the id of the row of
 * the replies ledger it answers, which the answer job looks for before it posts, so that an answer
 * whose post timed out after the provider stored it is never posted twice. A thread is known by its
 * first note only, which this never is: {@link markerOf} does not know it.
 */
export function replyMarker(replyId: string): string {
  return `<!-- qualor:reply ${uuid(replyId)} -->`;
}

/**
 * The first line of Qualor's note in the open thread of a fixed issue that a person replied in
 * (6I-4): the issue, and the full revision it was found fixed at. A decoration looks for it before
 * it writes one, so the thread holds one note each time its issue is fixed. It is no thread's first
 * note, no summary and no answer to a reply: {@link markerOf} tells it apart as `fixed`.
 */
export function fixedMarker(issueId: string, sha: string): string {
  if (!isFullSha(sha)) throw new Error('a Qualor marker holds a full commit SHA only');
  return `<!-- qualor:fixed ${uuid(issueId)} ${sha} -->`;
}

/**
 * Azure DevOps only: the first line of Qualor's comment in a thread it reopened because its issue
 * came back. Thread properties cannot be changed there, so the comment is how a reopening is
 * recorded; {@link markerOf} does not know it.
 */
export function reopenedMarker(issueId: string): string {
  return `<!-- qualor:reopened ${uuid(issueId)} -->`;
}

/** A note body's first line, without the carriage return of a CRLF end: where a marker is. */
export function firstLineOf(body: string): string {
  return (body.split('\n', 1)[0] ?? '').replace(/\r$/, '');
}

/** What a note's first line marks ({@link markerOf}). */
export type Marker =
  | { kind: 'summary'; projectId: string }
  | { kind: 'issue'; issueId: string }
  | { kind: 'fixed'; issueId: string; sha: string };

/**
 * What a note body's first line marks, or null. Only the first line counts: a marker quoted in a
 * reply or inside a value (always on a later line) is ignored. The caller also checks the author.
 */
export function markerOf(body: string): Marker | null {
  const firstLine = firstLineOf(body);
  const summary = SUMMARY_MARKER.exec(firstLine);
  if (summary?.[1]) return { kind: 'summary', projectId: summary[1] };
  const issue = ISSUE_MARKER.exec(firstLine);
  if (issue?.[1]) return { kind: 'issue', issueId: issue[1] };
  const fixed = FIXED_MARKER.exec(firstLine);
  if (fixed?.[1] && fixed[2]) return { kind: 'fixed', issueId: fixed[1], sha: fixed[2] };
  return null;
}

/**
 * The revisions that Qualor's notes among `bodies` say `issueId` was fixed at ({@link fixedMarker}):
 * the notes of a thread, which the caller has kept to Qualor's own.
 */
export function notedFixes(bodies: Iterable<string>, issueId: string): Set<string> {
  const fixes = new Set<string>();
  for (const body of bodies) {
    const marker = markerOf(body);
    if (marker?.kind === 'fixed' && marker.issueId === issueId) fixes.add(marker.sha);
  }
  return fixes;
}

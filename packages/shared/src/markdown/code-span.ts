/**
 * scm.md §6 comment safety, shared so the CLI can apply it to what it writes for GitLab (the SAST
 * report's `description`, scm.md §9) without importing the server. The same rules as the
 * server's `server/src/scm/markdown.ts`, which uses these functions (one implementation):
 * - a value is one line: every C0/C1 control, U+2028/U+2029 and every bidirectional control
 *   becomes a space, so it can neither start a line (a quick action) nor reorder the text;
 * - invisible format characters are removed and lone surrogates become U+FFFD; ZWJ, ZWNJ and
 *   variation selectors stay;
 * - it is cut to its bound in code points (at a grapheme boundary when a whole one fits);
 * - a code span's fence is one backtick longer than the longest run inside, padded with a space,
 *   so the value cannot close the span; inside it GitLab renders no Markdown, HTML, link,
 *   mention or reference.
 */

/*
 * The character lists below are the contents of a `[…]` class of a `u` regular expression, shared
 * with the suggestion check of llm.md §9.5 (`packages/shared/src/llm/fix.ts`), which refuses them all.
 */

/** Replaced by a space: C0 and C1 controls (tab too), line and paragraph separators, bidi controls. */
export const CONTROL_CHARS = String.raw`\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069`;

/**
 * Removed: invisible format characters that could hide or smuggle text, and the blank-looking
 * fillers that are not whitespace (Hangul fillers U+115F, U+1160, U+3164, U+FFA0; the braille
 * blank U+2800), which would show a value as empty or spaced where it is not.
 */
export const INVISIBLE_CHARS = String.raw`\u00ad\u115f\u1160\u180e\u200b\u2060-\u2065\u206a-\u206f\ufeff\ufff9-\ufffb\u2800\u3164\uffa0\u{e0000}-\u{e007f}`;

/**
 * Kept in text for people (they shape emoji and scripts), refused in a suggestion, where they could
 * make two different lines of code look the same: ZWNJ, ZWJ, the combining grapheme joiner U+034F,
 * the Khmer inherent vowels U+17B4 and U+17B5, the Mongolian free variation selectors and the
 * variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF).
 */
export const JOINER_CHARS = String.raw`\u034f\u17b4\u17b5\u180b-\u180d\u180f\u200c\u200d\ufe00-\ufe0f\u{e0100}-\u{e01ef}`;

/** A UTF-16 surrogate without its pair (a regular expression source). */
export const LONE_SURROGATE_SOURCE = String.raw`[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]`;

const UNSAFE = new RegExp(`[${CONTROL_CHARS}]`, 'gu');
const INVISIBLE = new RegExp(`[${INVISIBLE_CHARS}]`, 'gu');
const LONE_SURROGATE = new RegExp(LONE_SURROGATE_SOURCE, 'g');

const graphemes = new Intl.Segmenter(undefined, { granularity: 'grapheme' });

/** `text` cut to `max` code points with `…`, at a grapheme boundary when a whole one fits. */
export function cutAtGrapheme(text: string, max: number): string {
  const chars = [...text];
  if (chars.length <= max) return text;
  const prefix = chars.slice(0, Math.max(0, max - 1)).join('');
  let end = 0;
  for (const { index, segment } of graphemes.segment(text)) {
    const next = index + segment.length;
    if (next > prefix.length) break;
    end = next;
  }
  return `${end === 0 ? prefix : text.slice(0, end)}…`;
}

/** Unsafe characters replaced by a space, invisible ones removed, then cut to `max` code points. */
export function safePlainValue(value: string, max: number): string {
  const text = value.replace(LONE_SURROGATE, '�').replace(INVISIBLE, '').replace(UNSAFE, ' ');
  return cutAtGrapheme(text, max);
}

/** `value` as a CommonMark code span: {@link safePlainValue}, then a fence it cannot close. */
export function safeCodeSpan(value: string, max: number): string {
  const text = safePlainValue(value, max);
  if (text.trim() === '') return '` `';
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = '`'.repeat(longest + 1);
  return `${fence} ${text} ${fence}`;
}

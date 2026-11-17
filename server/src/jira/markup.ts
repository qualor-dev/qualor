/**
 * Wiki markup escaping for the Jira issue content (spec §6.4, §11.1). Nothing from a report, a
 * rule, an advisory or a user may render as a link, an image, a macro or formatting: free text goes
 * into `{noformat}` blocks, short identifiers are backslash-escaped, URLs are built or encoded here.
 */

const ZWSP = '\u200B';
const MARKUP = /[\\*_?\-+^~{}[\]|!#()]/g;
const LINE_BREAKS = /\r\n|[\n\r\v\f\u0085\u2028\u2029]/g;

/** At most `max` UTF-16 units including the `…`; never splits a surrogate pair. */
export function cutText(text: string, max: number): string {
  if (text.length <= max) return text;
  let end = Math.max(0, max - 1);
  const last = text.charCodeAt(end - 1);
  if (end > 0 && last >= 0xd800 && last <= 0xdbff) end -= 1;
  return `${text.slice(0, end)}…`;
}

/** A short identifier made inert: no markup character, no line break, no `://` that could link. */
export function escapeIdentifier(text: string, max = 255): string {
  const escaped = text
    .replace(LINE_BREAKS, ' ')
    .replace(MARKUP, '\\$&')
    .replaceAll('://', `:/${ZWSP}/`)
    .replace(/\b(mailto|file|news):/gi, `$1:${ZWSP}`)
    .replace(/([:;])(?=[DP])/g, `$1${ZWSP}`);
  const cut = cutText(escaped, max);
  if (cut === escaped) return cut;
  // A cut inside an escape pair must not leave a backslash that would escape the `…`.
  const body = cut.slice(0, -1);
  const slashes = body.length - body.replace(/\\+$/, '').length;
  return slashes % 2 === 1 ? `${body.slice(0, -1)}…` : cut;
}

/** Free text in a `{noformat}` block; a `{noformat}` inside it (any case) cannot close the block. */
export function noformat(text: string): string {
  return `{noformat}\n${text.replace(/\{(?=noformat)/gi, `{${ZWSP}`)}\n{noformat}`;
}

/** An advisory's `http(s)` URL with the characters of the link syntax encoded, else null. */
export function advisoryUrl(raw: string | null): string | null {
  if (raw === null) return null;
  const trimmed = raw.trim();
  if (!/^https?:\/\//i.test(trimmed)) return null;
  const encoder = new TextEncoder();
  // Everything outside the allowlist is percent-encoded (UTF-8): no markup character survives.
  return trimmed.replace(/[^A-Za-z0-9\-._~:/?#&=%+,;@]/gu, (c) =>
    Array.from(encoder.encode(c), (b) => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join(
      '',
    ),
  );
}

/** `[<escaped text>|<url>]`; the URL is built or encoded by the caller. */
export function wikiLink(text: string, url: string): string {
  return `[${escapeIdentifier(text)}|${url}]`;
}

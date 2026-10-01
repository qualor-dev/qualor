/**
 * The checks of scm.md §6 on a comment body GitLab or GitHub renders as Markdown, shared by the
 * rendering tests (server/src/scm/render.test.ts) and the AI assistant's end-to-end test.
 */

/**
 * CommonMark code spans of one line, removed: a backtick run opens a span that the next run of
 * the same length closes; an unmatched run is literal text. What is left is what GitLab renders
 * as Markdown.
 */
export function outsideCodeSpans(line: string): string {
  let out = '';
  let i = 0;
  while (i < line.length) {
    if (line[i] !== '`') {
      out += line[i];
      i++;
      continue;
    }
    let n = 0;
    while (line[i + n] === '`') n++;
    const fence = '`'.repeat(n);
    let j = i + n;
    let close = -1;
    while (j < line.length) {
      const at = line.indexOf(fence, j);
      if (at < 0) break;
      let m = 0;
      while (line[at + m] === '`') m++;
      if (m === n) {
        close = at;
        break;
      }
      j = at + m;
    }
    if (close < 0) {
      out += fence;
      i += n;
    } else {
      out += ' ';
      i = close + n;
    }
  }
  return out;
}

/** Characters Qualor's own fixed text may use outside code spans. */
export const FIXED_TEXT = /^[A-Za-z0-9 .,;:()’…*|\-<>·]*$/;
/**
 * {@link FIXED_TEXT} plus the fixed symbols of the summary comment: the status and severity
 * markers, the comparison signs of the Required column, the dash of a skipped row, the arrow of
 * its link and the percent sign of a value.
 */
export const SUMMARY_FIXED_TEXT = /^(?:[A-Za-z0-9 .,;:()’…*|\-<>·✅❌➖⛔🔴🟠🟡🔵≤≥—→%]|⚠️)*$/u;
export const FORBIDDEN_ANYWHERE =
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b\u200e\u200f\u2028-\u202e\u2060-\u206f\u115f\u1160\u2800\u3164\uffa0\ufeff\ud800-\udfff]|[\u{e0000}-\u{e007f}]/u;

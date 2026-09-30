/**
 * A user-supplied name as it appears in a skip reason: bounded, so the reason stays short, and
 * with control characters replaced, so a crafted name cannot forge log lines or report text.
 */
export function shown(name: string): string {
  // eslint-disable-next-line no-control-regex
  const clean = name.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
  return clean.length <= 200 ? clean : `${clean.slice(0, 199)}…`;
}

const MAX_DETAIL_CHARS = 300;

/**
 * One line of a tool's stderr as a `failureDetail` (logged at warn, never a report `reason`):
 * control characters become spaces, and it is trimmed and cut at 300 characters.
 */
export function detailLine(line: string): string {
  const printable = [...line]
    .map((c) => (c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f ? ' ' : c))
    .join('');
  return printable.trim().slice(0, MAX_DETAIL_CHARS);
}

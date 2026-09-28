/**
 * A user-supplied name as it appears in a skip reason: bounded, so the reason stays short, and
 * with control characters replaced, so a crafted name cannot forge log lines or report text.
 */
export function shown(name: string): string {
  // eslint-disable-next-line no-control-regex
  const clean = name.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
  return clean.length <= 200 ? clean : `${clean.slice(0, 199)}…`;
}

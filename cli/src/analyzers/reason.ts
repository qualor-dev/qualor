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

/**
 * The JVM's echo of its option variables, which it prints first on stderr: their values come from
 * the CI configuration and may hold secrets (`-Dhttp.proxyPassword=…`), so no detail ever shows it.
 */
const JVM_OPTIONS_ECHO = /^(NOTE: )?Picked up (JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS):/;

/**
 * A tool's stderr as the lines a `failureDetail` may choose from: non-blank, and without the
 * JVM's echo of `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` or `JDK_JAVA_OPTIONS` (fix round 2 of the
 * Phase 8E final review).
 */
export function stderrLines(stderr: string): string[] {
  return stderr.split(/\r?\n/).filter((l) => l.trim() !== '' && !JVM_OPTIONS_ECHO.test(l));
}

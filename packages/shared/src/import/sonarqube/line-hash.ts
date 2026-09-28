import { createHash } from 'node:crypto';

/**
 * The characters SonarQube's source-line hashing is believed to remove: the space and the tab
 * only (import-sonarqube.md §10.4, ruling S1; not verified against a live SonarQube, §17).
 */
const SPACE_OR_TAB = /[ \t]/g;

/** A SonarQube issue's `hash`: 32 lowercase hex characters. */
export const SONAR_LINE_HASH = /^[0-9a-f]{32}$/;

/**
 * SonarQube's line hash: the lowercase hex MD5 of the line's UTF-8 bytes without spaces and tabs;
 * `""` for a line that is blank after that, which counts as unknown and never matches.
 */
export function sonarLineHash(line: string): string {
  const stripped = line.replace(SPACE_OR_TAB, '');
  if (stripped === '') return '';
  return createHash('md5').update(stripped, 'utf8').digest('hex');
}

/** report-format.md §4 (the secret redaction marker in snippets). */
const REDACTED = '«redacted»';

/**
 * Spec §10.4: SonarQube's line hash of line `line` of a stored snippet (`{ startLine, lines }`,
 * report-format.md §4); null when the line is absent, was cut at 400 characters (it ends in `…`),
 * holds a redacted secret or is blank, since its hash would then say nothing.
 */
export function snippetLineHash(snippet: unknown, line: number | null): string | null {
  if (line === null || typeof snippet !== 'object' || snippet === null) return null;
  const { startLine, lines } = snippet as { startLine?: unknown; lines?: unknown };
  if (typeof startLine !== 'number' || !Array.isArray(lines)) return null;
  const text: unknown = lines[line - startLine];
  if (typeof text !== 'string' || text.endsWith('…') || text.includes(REDACTED)) return null;
  const hash = sonarLineHash(text);
  return hash === '' ? null : hash;
}

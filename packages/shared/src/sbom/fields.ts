/**
 * String bounds and cleaning shared by the SBOM readers (ruling R3): PostgreSQL's text and jsonb
 * refuse U+0000 and lone surrogates, so every kept string loses the first and has the second
 * replaced by U+FFFD; a cut never splits a surrogate pair.
 */
import { normalizeLicense } from '../licenses/normalize';

/** The report schema's bounds of a dependency entry (`dependencyEntrySchema`). */
export const SBOM_BOUNDS = {
  name: 512,
  version: 256,
  path: 1_024,
  licence: 256,
  licences: 16,
  subject: 512,
} as const;

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

/** Without U+0000, lone surrogates replaced by U+FFFD. */
export function cleanText(text: string): string {
  return text.replace(/\0/g, '').replace(LONE_SURROGATE, '\ufffd');
}

/** At most `max` UTF-16 units of clean text, never ending in half a surrogate pair. */
export function cutText(text: string, max: number): string {
  if (text.length <= max) return text;
  const last = text.charCodeAt(max - 1);
  return text.slice(0, last >= 0xd800 && last <= 0xdbff ? max - 1 : max);
}

/**
 * Licence strings as an entry keeps them: cleaned, normalised, unique and sorted, at most 16. A
 * string over 256 characters is dropped, never cut (a shortened expression could change its
 * meaning), as the CLI's licence pass does. It is dropped before normalising too, so no hostile
 * expression reaches the parser.
 */
export function licenseList(raw: Iterable<string>): string[] {
  const kept = new Set<string>();
  for (const text of raw) {
    const cleaned = cleanText(text).trim();
    if (cleaned === '' || cleaned.length > SBOM_BOUNDS.licence) continue;
    const licence = normalizeLicense(cleaned);
    if (licence !== '' && licence.length <= SBOM_BOUNDS.licence) kept.add(licence);
  }
  return [...kept].sort().slice(0, SBOM_BOUNDS.licences);
}

/** The union of two entries' licences, as {@link licenseList} keeps them. */
export function mergeLicenses(a: readonly string[], b: readonly string[]): string[] {
  return [...new Set([...a, ...b])].sort().slice(0, SBOM_BOUNDS.licences);
}

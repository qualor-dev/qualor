/**
 * Maven version order (§6.5 step 2): Qualor's own code, written clean room from the "Version Order
 * Specification" of the Maven POM reference (https://maven.apache.org/pom.html) only.
 *
 * A version is split into tokens at `.`, `-`, `_` and every transition between ASCII digits and
 * other characters (`_` and a transition count as `-`); an empty token is `0`. Each `-` token
 * starts a sub-list,
 * and each sub-list loses its trailing null values (`0`, `""`, `final`, `ga`, `release`). Two
 * versions compare token by token, the shorter one padded with null values.
 */

export type MavenPrefix = '.' | '-';

export interface MavenItem {
  /** The separator before the token; the first token has `.`. */
  readonly prefix: MavenPrefix;
  readonly kind: 'number' | 'qualifier';
  /** A number's digits without leading zeros (`0` for zero), or a qualifier in lower case. */
  readonly value: string;
}

/** The known qualifiers in order; `""`, `final`, `ga` and `release` are the release itself. */
const QUALIFIER_RANK: ReadonlyMap<string, number> = new Map([
  ['alpha', 0],
  ['beta', 1],
  ['milestone', 2],
  ['rc', 3],
  ['cr', 3],
  ['snapshot', 4],
  ['', 5],
  ['final', 5],
  ['ga', 5],
  ['release', 5],
  ['sp', 6],
]);
const RELEASE_RANK = 5;
/** Unknown qualifiers come after all known ones, in lexical order among themselves. */
const UNKNOWN_RANK = 7;

/** `a1`, `b1`, `m1`: the short forms when a number follows directly. */
const SHORT_QUALIFIER: ReadonlyMap<string, string> = new Map([
  ['a', 'alpha'],
  ['b', 'beta'],
  ['m', 'milestone'],
]);

const NULL_QUALIFIERS: ReadonlySet<string> = new Set(['', 'final', 'ga', 'release']);

function isDigit(ch: string): boolean {
  return ch >= '0' && ch <= '9';
}

function withoutLeadingZeros(digits: string): string {
  let i = 0;
  while (i < digits.length - 1 && digits[i] === '0') i++;
  return digits.slice(i);
}

/** One token; `beforeNumber` when a number follows without a separator (`a1`). */
function token(prefix: MavenPrefix, text: string, beforeNumber: boolean): MavenItem {
  if (text === '') return { prefix, kind: 'number', value: '0' };
  if (isDigit(text.charAt(0))) return { prefix, kind: 'number', value: withoutLeadingZeros(text) };
  const value = beforeNumber ? (SHORT_QUALIFIER.get(text) ?? text) : text;
  return { prefix, kind: 'qualifier', value };
}

/** The tokens of a version, before null values are removed. */
function mavenTokens(version: string): MavenItem[] {
  const s = version.toLowerCase();
  const tokens: MavenItem[] = [];
  let prefix: MavenPrefix = '.';
  let start = 0;
  for (let i = 0; i <= s.length; i++) {
    const ch = s.charAt(i);
    if (i === s.length || ch === '.' || ch === '-' || ch === '_') {
      tokens.push(token(prefix, s.slice(start, i), false));
      prefix = ch === '.' ? '.' : '-';
      start = i + 1;
    } else if (i > start && isDigit(ch) !== isDigit(s.charAt(i - 1))) {
      tokens.push(token(prefix, s.slice(start, i), isDigit(ch)));
      prefix = '-';
      start = i;
    }
  }
  return tokens;
}

function isNull(item: MavenItem): boolean {
  return item.kind === 'number' ? item.value === '0' : NULL_QUALIFIERS.has(item.value);
}

/** Each `-` token starts a sub-list. */
function subLists(tokens: readonly MavenItem[]): MavenItem[][] {
  const lists: MavenItem[][] = [];
  for (const t of tokens) {
    const last = lists.at(-1);
    if (last === undefined || t.prefix === '-') lists.push([t]);
    else last.push(t);
  }
  return lists;
}

function withoutTrailingNulls(list: readonly MavenItem[]): MavenItem[] {
  let end = list.length;
  while (end > 0 && isNull(list[end - 1] as MavenItem)) end--;
  return list.slice(0, end);
}

/** The items a version compares by: its tokens, each sub-list without trailing null values. */
export function mavenItems(version: string): MavenItem[] {
  return subLists(mavenTokens(version)).flatMap(withoutTrailingNulls);
}

function rank(qualifier: string): number {
  return QUALIFIER_RANK.get(qualifier) ?? UNKNOWN_RANK;
}

function compareText(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function compareQualifiers(a: string, b: string): number {
  const ra = rank(a);
  const rb = rank(b);
  if (ra !== rb) return ra < rb ? -1 : 1;
  return ra === UNKNOWN_RANK ? compareText(a, b) : 0;
}

function compareNumbers(a: string, b: string): number {
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  return compareText(a, b);
}

/** Qualifiers (either prefix alike) < `-` numbers < `.` numbers. */
function compareItems(a: MavenItem, b: MavenItem): number {
  if (a.kind === 'qualifier' && b.kind === 'qualifier') return compareQualifiers(a.value, b.value);
  if (a.kind !== b.kind) return a.kind === 'qualifier' ? -1 : 1;
  if (a.prefix !== b.prefix) return a.prefix === '-' ? -1 : 1;
  return compareNumbers(a.value, b.value);
}

/**
 * An item against the padding of a shorter version: a null value of the item's own kind, `0` for a
 * number and `""` for a qualifier, which the reference's `1.foo` = `1-foo` needs.
 */
function compareToPadding(item: MavenItem): number {
  if (item.kind === 'qualifier') return compareQualifiers(item.value, '');
  return item.value === '0' ? 0 : 1;
}

function compareAt(a: MavenItem | undefined, b: MavenItem | undefined): number {
  if (a === undefined) return b === undefined ? 0 : 0 - compareToPadding(b);
  return b === undefined ? compareToPadding(a) : compareItems(a, b);
}

/** Maven order: -1, 0 or 1. Every string is a Maven version, so there is no failure. */
export function compareMaven(a: string, b: string): number {
  const x = mavenItems(a);
  const y = mavenItems(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const c = compareAt(x[i], y[i]);
    if (c !== 0) return c;
  }
  return 0;
}

/** Whether a version holds a qualifier that orders before the release (alpha … snapshot). */
export function mavenIsPrerelease(version: string): boolean {
  return mavenItems(version).some((i) => i.kind === 'qualifier' && rank(i.value) < RELEASE_RANK);
}

/**
 * The major and minor of a version, from its leading tokens before null values are removed (so
 * `0-rc1` keeps its major `0`); null when it does not start with a number.
 */
export function mavenMajorMinor(version: string): { major: string; minor: string } | null {
  const [first, second] = mavenTokens(version);
  if (first?.kind !== 'number') return null;
  const minor = second?.kind === 'number' && second.prefix === '.' ? second.value : '0';
  return { major: first.value, minor };
}

/**
 * The order of fixed versions (B2-k, B2-q). Advisories give a fixed version as free text in any
 * ecosystem's scheme, so no scheme's rules apply; one natural order covers them all:
 *
 * - A leading `<digits>:` or `<digits>!` is an epoch, compared first (no epoch is epoch 0).
 * - The rest is split into digit runs and letter runs; anything else separates them.
 * - Two digit runs compare as numbers (of any length), two letter runs ignoring case. A letter
 *   run sorts before a digit run and before the end (`1.0rc1` < `1.0`); the end sorts before a
 *   digit run (`1.0` < `1.0.1`).
 * - A list such as `2.17.1, 2.12.4` compares by its tokens in order, so its first version leads.
 * - A tie in this order falls back to the code units of the strings: the order is total and
 *   answers 0 only for equal strings.
 *
 * Two limits are accepted, since they would need the ecosystem: a post-release spelled as a
 * letter run (`2.0.post1`, `5.2.20.RELEASE`) sorts below the bare version.
 */

const EPOCH = /^(\d+)[:!]/;
const TOKEN = /[0-9]+|[A-Za-z]+/g;

/** Digit strings as numbers of any length: no leading zeros, then the length, then the digits. */
function compareDigits(a: string, b: string): number {
  const x = a.replace(/^0+/, '');
  const y = b.replace(/^0+/, '');
  if (x.length !== y.length) return x.length < y.length ? -1 : 1;
  return x === y ? 0 : x < y ? -1 : 1;
}

const isNumber = (token: string): boolean => token.charCodeAt(0) <= 57;

function compareTokens(a: string | undefined, b: string | undefined): number {
  if (a === undefined) return b === undefined ? 0 : isNumber(b) ? -1 : 1;
  if (b === undefined) return isNumber(a) ? 1 : -1;
  const aNumber = isNumber(a);
  if (aNumber !== isNumber(b)) return aNumber ? 1 : -1;
  if (aNumber) return compareDigits(a, b);
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  return x === y ? 0 : x < y ? -1 : 1;
}

function split(version: string): { epoch: string; tokens: string[] } {
  const epoch = EPOCH.exec(version);
  const rest = epoch === null ? version : version.slice(epoch[0].length);
  return { epoch: epoch?.[1] ?? '0', tokens: rest.match(TOKEN) ?? [] };
}

/** Negative when `a` is the lower fixed version, positive when the higher, 0 only if equal. */
export function compareFixedVersions(a: string, b: string): number {
  if (a === b) return 0;
  const x = split(a);
  const y = split(b);
  const epoch = compareDigits(x.epoch, y.epoch);
  if (epoch !== 0) return epoch;
  const length = Math.max(x.tokens.length, y.tokens.length);
  for (let i = 0; i < length; i += 1) {
    const order = compareTokens(x.tokens[i], y.tokens[i]);
    if (order !== 0) return order;
  }
  return a < b ? -1 : 1;
}

/** The greatest version of the list; null when it holds none. */
export function highestFixedVersion(list: readonly (string | null)[]): string | null {
  let highest: string | null = null;
  for (const version of list) {
    if (version !== null && (highest === null || compareFixedVersions(highest, version) < 0)) {
      highest = version;
    }
  }
  return highest;
}

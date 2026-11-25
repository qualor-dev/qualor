import picomatch from 'picomatch';

/** Pattern lists whose matchers {@link branchMatches} keeps; the cache is cleared when full. */
const CACHED_PATTERN_LISTS = 1_000;
const matchers = new Map<string, (name: string) => boolean>();

const matchesNothing = (): boolean => false;

/**
 * The glob patterns compiled once: true when a branch name matches any of them. No patterns:
 * never matches. For a loop over many branches with one pattern list.
 */
export function branchMatcher(patterns: readonly string[]): (name: string) => boolean {
  if (patterns.length === 0) return matchesNothing;
  const match = picomatch([...patterns], { dot: true });
  return (name) => match(name);
}

/**
 * True when the branch name matches any glob pattern. The matcher of each pattern list is
 * compiled once and cached (at most {@link CACHED_PATTERN_LISTS} lists).
 */
export function branchMatches(name: string, patterns: readonly string[]): boolean {
  if (patterns.length === 0) return false;
  const key = JSON.stringify(patterns);
  let match = matchers.get(key);
  if (match === undefined) {
    if (matchers.size >= CACHED_PATTERN_LISTS) matchers.clear();
    match = branchMatcher(patterns);
    matchers.set(key, match);
  }
  return match(name);
}

/**
 * Whether picomatch can compile the glob and it holds no control character: the check of every
 * stored branch pattern (the monitoring patterns, the cleanup keep patterns).
 */
export function validGlob(pattern: string): boolean {
  for (let i = 0; i < pattern.length; i++) {
    const code = pattern.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  try {
    // Without debug, picomatch swallows the RegExp error and returns a match-nothing regex.
    picomatch.makeRe(pattern, { dot: true, debug: true });
    return true;
  } catch {
    return false;
  }
}

/** Trims, drops empty entries and removes duplicates, keeping order. */
export function normalizePatterns(input: readonly string[]): string[] {
  const seen = new Set<string>();
  for (const raw of input) {
    const pattern = raw.trim();
    if (pattern !== '') seen.add(pattern);
  }
  return [...seen];
}

import picomatch from 'picomatch';

/** True when the branch name matches any glob pattern. */
export function branchMatches(name: string, patterns: readonly string[]): boolean {
  return patterns.length > 0 && picomatch.isMatch(name, [...patterns], { dot: true });
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

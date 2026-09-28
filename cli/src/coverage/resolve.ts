import path from 'node:path';
import { normalizeRepoPath } from '@qualor/shared';

export type Resolution = { path: string } | { unresolved: 'not-found' | 'ambiguous' };

const NOT_FOUND: Resolution = { unresolved: 'not-found' };
const AMBIGUOUS: Resolution = { unresolved: 'ambiguous' };
const DRIVE = /^[A-Za-z]:\//;

function segmentsOf(p: string): string[] {
  return p
    .replace(DRIVE, '')
    .split('/')
    .filter((s) => s !== '' && s !== '.' && s !== '..');
}

function tidy(p: string): string {
  return p.trim().replaceAll('\\', '/').normalize('NFC');
}

/** The report's directory relative to the root ('' for the root), or null outside it. */
export function repoRelativeDir(root: string, absFile: string): string | null {
  const rel = path.relative(root, path.dirname(absFile)).replaceAll('\\', '/');
  if (rel === '') return '';
  if (rel.startsWith('../') || rel === '..' || path.isAbsolute(rel)) return null;
  return rel;
}

/** `a/b/c` → [`a/b/c`, `a/b`, `a`, ``]; nearest first. */
export function ancestorDirs(repoDir: string | null): string[] {
  if (repoDir === null || repoDir === '') return [''];
  const parts = repoDir.split('/');
  return [...parts.map((_, i) => parts.slice(0, parts.length - i).join('/')), ''];
}

/** Maps paths written in coverage reports to analysed repo paths (plan Task 7, Review Focus 2). */
export class PathResolver {
  private readonly known: ReadonlySet<string>;
  private readonly byBasename = new Map<string, string[]>();
  private readonly prefixes: string[];
  private readonly cache = new Map<string, Resolution>();

  constructor(
    private readonly root: string,
    knownPaths: Iterable<string>,
    pathPrefixes: readonly string[],
  ) {
    this.known = new Set(knownPaths);
    for (const p of this.known) {
      const base = p.slice(p.lastIndexOf('/') + 1);
      const list = this.byBasename.get(base);
      if (list === undefined) this.byBasename.set(base, [p]);
      else list.push(p);
    }
    this.prefixes = pathPrefixes.map((p) => tidy(p).replace(/\/+$/, '')).filter((p) => p !== '');
  }

  resolve(reportPath: string, baseDirs: readonly string[]): Resolution {
    const key = `${baseDirs.join('\u0000')}\u0001${reportPath}`;
    let result = this.cache.get(key);
    if (result === undefined) {
      result = this.compute(reportPath, baseDirs);
      this.cache.set(key, result);
    }
    return result;
  }

  private lookup(candidate: string, absolute: boolean): string | null {
    try {
      const p = normalizeRepoPath(candidate, absolute ? this.root : undefined);
      return this.known.has(p) ? p : null;
    } catch {
      return null;
    }
  }

  private compute(reportPath: string, baseDirs: readonly string[]): Resolution {
    let p = tidy(reportPath);
    if (p.startsWith('file://')) p = p.slice('file://'.length).replace(/^\/([A-Za-z]:\/)/, '$1');
    if (p === '') return NOT_FOUND;
    const absolute = p.startsWith('/') || DRIVE.test(p);
    if (absolute) {
      const inside = this.lookup(p, true);
      if (inside !== null) return { path: inside };
    } else {
      // Nearest base first; the root ('') is always tried, last.
      const bases = baseDirs.includes('') ? baseDirs : [...baseDirs, ''];
      for (const base of bases) {
        const found = this.lookup(base === '' ? p : `${base}/${p}`, false);
        if (found !== null) return { path: found };
      }
    }
    for (const prefix of this.prefixes) {
      if (p.startsWith(`${prefix}/`)) {
        const found = this.lookup(p.slice(prefix.length + 1), false);
        if (found !== null) return { path: found };
      }
      if (!absolute) {
        const found = this.lookup(`${prefix}/${p}`, false);
        if (found !== null) return { path: found };
      }
    }
    return this.bySuffix(segmentsOf(p));
  }

  private bySuffix(segments: readonly string[]): Resolution {
    const base = segments.at(-1);
    if (base === undefined) return NOT_FOUND;
    let best: string[] = [];
    let bestLength = 0;
    for (const candidate of this.byBasename.get(base) ?? []) {
      const parts = candidate.split('/');
      const limit = Math.min(parts.length, segments.length);
      let k = 0;
      while (k < limit && parts[parts.length - 1 - k] === segments[segments.length - 1 - k]) k++;
      if (k < limit) continue; // a directory in between differs
      if (k > bestLength) {
        best = [candidate];
        bestLength = k;
      } else if (k === bestLength) best.push(candidate);
    }
    const [only] = best;
    if (best.length === 1 && only !== undefined) return { path: only };
    return best.length > 1 ? AMBIGUOUS : NOT_FOUND;
  }
}

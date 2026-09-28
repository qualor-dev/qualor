export const MAX_PATH_BYTES = 1024;

export type PathProblem =
  | 'empty'
  | 'nul'
  | 'absolute'
  | 'backslash'
  | 'dot-slash'
  | 'dot-segment'
  | 'double-slash'
  | 'too-long'
  | 'not-nfc';

export class PathError extends Error {
  constructor(
    readonly problem: PathProblem | 'outside-root',
    readonly path: string,
  ) {
    super(`invalid repo path (${problem}): ${JSON.stringify(path)}`);
    this.name = 'PathError';
  }
}

const WINDOWS_ABSOLUTE = /^[A-Za-z]:[\\/]/;

function isAbsolute(p: string): boolean {
  return p.startsWith('/') || WINDOWS_ABSOLUTE.test(p);
}

/** Checks the report-format §2 path rules. Returns null when the path is valid. */
export function validateRepoPath(p: string): PathProblem | null {
  if (p.length === 0) return 'empty';
  if (p.includes('\u0000')) return 'nul';
  if (isAbsolute(p)) return 'absolute';
  if (p.includes('\\')) return 'backslash';
  if (p.startsWith('./')) return 'dot-slash';
  const segments = p.split('/');
  if (segments.some((s) => s === '.' || s === '..')) return 'dot-segment';
  if (segments.some((s) => s === '')) return 'double-slash';
  if (Buffer.byteLength(p, 'utf8') > MAX_PATH_BYTES) return 'too-long';
  if (p.normalize('NFC') !== p) return 'not-nfc';
  return null;
}

function toSlashes(p: string): string {
  return p.replaceAll('\\', '/');
}

/**
 * Turns a path produced by a tool (absolute, Windows-style, "./"-prefixed, ...) into a
 * canonical repo-relative path. Throws PathError when that is impossible.
 */
export function normalizeRepoPath(input: string, repoRoot?: string): string {
  let p = toSlashes(input).normalize('NFC');
  if (isAbsolute(p)) {
    if (repoRoot === undefined) throw new PathError('absolute', input);
    const root = toSlashes(repoRoot).normalize('NFC').replace(/\/+$/, '');
    const windows = WINDOWS_ABSOLUTE.test(p);
    const matches = windows
      ? p.toLowerCase().startsWith(`${root.toLowerCase()}/`)
      : p.startsWith(`${root}/`);
    if (!matches) throw new PathError('outside-root', input);
    p = p.slice(root.length + 1);
  }
  const out: string[] = [];
  for (const segment of p.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      if (out.length === 0) throw new PathError('outside-root', input);
      out.pop();
      continue;
    }
    out.push(segment);
  }
  const result = out.join('/');
  const problem = validateRepoPath(result);
  if (problem !== null) throw new PathError(problem, input);
  return result;
}

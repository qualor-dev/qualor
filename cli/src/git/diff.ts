import type { LineRange } from '@qualor/shared';

export interface NameStatus {
  /** First letter of git's status: A, C, D, M, R, T, U, X. */
  status: string;
  path: string;
  from?: string;
}

/** `git diff --name-status -z`: `S\0path\0` or, for renames and copies, `R067\0from\0to\0`. */
export function parseNameStatusZ(output: string): NameStatus[] {
  const parts = output.split('\u0000');
  const out: NameStatus[] = [];
  let i = 0;
  while (i < parts.length) {
    const status = parts[i] ?? '';
    if (status === '') {
      i++;
      continue;
    }
    const letter = status.slice(0, 1);
    if (letter === 'R' || letter === 'C') {
      const from = parts[i + 1];
      const to = parts[i + 2];
      if (from !== undefined && to !== undefined) out.push({ status: letter, from, path: to });
      i += 3;
    } else {
      const p = parts[i + 1];
      if (p !== undefined) out.push({ status: letter, path: p });
      i += 2;
    }
  }
  return out;
}

const ESCAPES = new Map<string, number>([
  ['a', 7],
  ['b', 8],
  ['t', 9],
  ['n', 10],
  ['v', 11],
  ['f', 12],
  ['r', 13],
  ['"', 34],
  ['\\', 92],
]);

/** Decodes git's C-style quoting (`"b/\303\274.ts"`); unquoted input is returned as is. */
export function unquoteGitPath(quoted: string): string {
  if (quoted.length < 2 || !quoted.startsWith('"') || !quoted.endsWith('"')) return quoted;
  const body = quoted.slice(1, -1);
  const bytes: number[] = [];
  let i = 0;
  while (i < body.length) {
    const cp = body.codePointAt(i) ?? 0;
    if (cp !== 0x5c) {
      const ch = String.fromCodePoint(cp);
      bytes.push(...Buffer.from(ch, 'utf8'));
      i += ch.length;
      continue;
    }
    const next = body[i + 1] ?? '';
    if (/^[0-7]$/.test(next)) {
      bytes.push(parseInt(body.slice(i + 1, i + 4), 8));
      i += 4;
    } else {
      bytes.push(ESCAPES.get(next) ?? next.charCodeAt(0));
      i += 2;
    }
  }
  return Buffer.from(bytes).toString('utf8');
}

function newSidePath(rest: string): string | null {
  if (rest === '/dev/null') return null;
  // git appends a TAB after paths containing spaces; quoted paths hold special characters.
  const p = rest.startsWith('"') ? unquoteGitPath(rest) : rest.replace(/\t$/, '');
  return p.startsWith('b/') ? p.slice(2) : p;
}

export function mergeRanges(ranges: readonly LineRange[]): LineRange[] {
  const sorted = [...ranges].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out: LineRange[] = [];
  for (const [start, end] of sorted) {
    const last = out.at(-1);
    if (last !== undefined && start <= last[1] + 1) last[1] = Math.max(last[1], end);
    else out.push([start, end]);
  }
  return out;
}

const HUNK = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/**
 * New-side line ranges added or modified per file, from `git diff -U0` output (report-format
 * §6 `newLines`). Hunk bodies are skipped by count, so content lines that look like headers
 * (`+++ …`) are never misread.
 *
 * Ranges come from walking every `+` line actually present in the hunk body and recording its
 * new-side line number, never from the hunk header's line count alone: with `-U0` a hunk
 * normally holds no context lines, but a user's `diff.interHunkContext` setting (or an
 * equivalent `-U`) can still merge two nearby hunks into one whose body interleaves unchanged
 * `' '` context lines with the real changes (e.g. `@@ -2,3 +2,3 @@` covering an unchanged line
 * 3 between changed lines 2 and 4). Trusting the header would then misreport line 3 as new.
 */
export function parseUnifiedDiff(output: string): Map<string, LineRange[]> {
  const result = new Map<string, LineRange[]>();
  let current: string | null = null;
  let oldLeft = 0;
  let newLeft = 0;
  let newLine = 0;
  let runStart: number | null = null;
  let runEnd = 0;

  const flushRun = () => {
    if (runStart === null) return;
    if (current !== null) {
      const list = result.get(current) ?? [];
      list.push([runStart, runEnd]);
      result.set(current, list);
    }
    runStart = null;
  };

  for (const line of output.split('\n')) {
    if (oldLeft > 0 || newLeft > 0) {
      if (line.startsWith('\\')) {
        // "\ No newline at end of file": metadata about the previous line, consumes neither
        // counter and is not itself a line, so it must not close or extend a run.
        continue;
      }
      if (line.startsWith('-')) {
        oldLeft--;
        flushRun();
      } else if (line.startsWith('+')) {
        newLeft--;
        if (runStart === null) runStart = newLine;
        runEnd = newLine;
        newLine++;
      } else if (line.startsWith(' ')) {
        oldLeft--;
        newLeft--;
        newLine++;
        flushRun(); // an unchanged context line breaks contiguity; it is never "new"
      } else {
        flushRun();
      }
      continue;
    }
    flushRun(); // the previous hunk's body (if any) has ended
    if (line.startsWith('diff --git ')) {
      current = null;
    } else if (line.startsWith('+++ ')) {
      current = newSidePath(line.slice(4));
    } else {
      const m = HUNK.exec(line);
      if (m === null) continue;
      oldLeft = m[1] === undefined ? 1 : Number(m[1]);
      newLeft = m[3] === undefined ? 1 : Number(m[3]);
      newLine = Number(m[2]);
    }
  }
  flushRun();
  for (const [p, ranges] of result) result.set(p, mergeRanges(ranges));
  return result;
}

const BINARY_DIFFER = /^Binary files (?:.+) and (.+) differ$/;

/**
 * New-side paths of files git reports as binary changes (`Binary files a/x and b/x differ`).
 * A binary diff carries no line numbers, so callers must not read `newLines` for these paths
 * out of `parseUnifiedDiff`'s (necessarily empty) result — see `diffAgainst` in `scm.ts`.
 */
export function parseBinaryPaths(output: string): Set<string> {
  const out = new Set<string>();
  for (const line of output.split('\n')) {
    const m = BINARY_DIFFER.exec(line);
    if (m === null) continue;
    const p = newSidePath(m[1] ?? '');
    if (p !== null) out.add(p);
  }
  return out;
}

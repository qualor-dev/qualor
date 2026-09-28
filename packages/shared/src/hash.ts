import { createHash } from 'node:crypto';

export const MAX_HASHED_LINES = 5;
export const CONTEXT_LINES = 2;
const SEP = '\u001f';

export function hex32(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, 32);
}

/** report-format §7.3: removes every Unicode `White_Space` code point. */
export function normalizeLine(line: string): string {
  return line.replace(/\p{White_Space}/gu, '');
}

/**
 * report-format §7.3: the one way source text becomes lines for hashing and snippets. Strips a
 * leading UTF-8 BOM, splits on `\r?\n`, and drops the single empty string after a final newline.
 */
export function splitSourceLines(text: string): string[] {
  const body = text.startsWith('﻿') ? text.slice(1) : text;
  if (body === '') return [];
  const lines = body.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  return lines;
}

function checkRange(lines: readonly string[], startLine: number, endLine: number): void {
  if (!Number.isInteger(startLine) || !Number.isInteger(endLine)) {
    throw new RangeError(`non-integer line range ${startLine}-${endLine}`);
  }
  if (startLine < 1 || endLine < startLine || endLine > lines.length) {
    throw new RangeError(
      `line range ${startLine}-${endLine} outside file of ${lines.length} lines`,
    );
  }
}

/** 1-based inclusive range, clamped to the file. */
function hashLines(lines: readonly string[], from: number, to: number): string {
  const lo = Math.max(1, from);
  const hi = Math.min(lines.length, to);
  return hex32(
    lines
      .slice(lo - 1, hi)
      .map(normalizeLine)
      .join('\n'),
  );
}

function flaggedEnd(startLine: number, endLine: number): number {
  return Math.min(endLine, startLine + MAX_HASHED_LINES - 1);
}

/** report-format §7.3: hash of the flagged lines (at most 5), whitespace removed. */
export function lineHash(lines: readonly string[], startLine: number, endLine: number): string {
  checkRange(lines, startLine, endLine);
  return hashLines(lines, startLine, flaggedEnd(startLine, endLine));
}

/** report-format §7.3: the flagged lines (at most 5) plus 2 lines either side, clamped. */
export function contextHash(lines: readonly string[], startLine: number, endLine: number): string {
  checkRange(lines, startLine, endLine);
  return hashLines(
    lines,
    startLine - CONTEXT_LINES,
    flaggedEnd(startLine, endLine) + CONTEXT_LINES,
  );
}

/**
 * report-format §7.3: a file-less finding hashes `ruleKey + message`. A finding that has a
 * location but whose source is unavailable (unreadable file, region past its end) also hashes
 * its path, NUL-separated, so the same message in two files never collapses into one identity.
 */
export function filelessHash(ruleKey: string, message: string, path?: string): string {
  return path === undefined
    ? hex32(ruleKey + message)
    : hex32(`${ruleKey}\u0000${path}\u0000${message}`);
}

export interface FingerprintInput {
  ruleKey: string;
  path: string | null;
  lineHash: string;
  contextHash: string;
  startLine: number;
  startColumn: number;
}

/** data-model §5.1. Returns fingerprints in the same order as the input. */
export function computeFingerprints(findings: readonly FingerprintInput[]): string[] {
  const groups = new Map<string, number[]>();
  findings.forEach((f, i) => {
    const key = [f.ruleKey, f.path ?? '', f.lineHash, f.contextHash].join(SEP);
    const group = groups.get(key);
    if (group) group.push(i);
    else groups.set(key, [i]);
  });
  const out = new Array<string>(findings.length);
  for (const [key, indexes] of groups) {
    indexes.sort((a, b) => {
      const fa = findings[a];
      const fb = findings[b];
      if (!fa || !fb) return 0;
      return fa.startLine - fb.startLine || fa.startColumn - fb.startColumn || a - b;
    });
    indexes.forEach((index, occurrence) => {
      out[index] = hex32(`${key}${SEP}${occurrence}`);
    });
  }
  return out;
}

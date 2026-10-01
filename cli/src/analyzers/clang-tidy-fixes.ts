import path from 'node:path';
import type { SarifLog, SarifResult, SarifRule } from '@qualor/shared';
import { parseAllDocuments } from 'yaml';
import { within } from './binary';
import { realRootOf, redactForeignPaths } from './cfamily-common';
import { readPlainFile } from './checked-copy';

interface Place {
  FilePath?: unknown;
  FileOffset?: unknown;
  Message?: unknown;
}
interface Diagnostic {
  DiagnosticName?: unknown;
  DiagnosticMessage?: Place;
  Notes?: unknown;
  Level?: unknown;
  BuildDirectory?: unknown;
}

type SarifLocation = NonNullable<SarifResult['locations']>[number];

const CHECK_NAME = /^[A-Za-z0-9._-]+$/;

/** A repository file's bytes and the byte offset of each of its lines. */
interface Source {
  bytes: Buffer;
  lineStarts: number[];
}

function lineStartsOf(bytes: Buffer): number[] {
  const starts = [0];
  for (let i = bytes.indexOf(0x0a); i !== -1; i = bytes.indexOf(0x0a, i + 1)) starts.push(i + 1);
  return starts;
}

/** The index of the last line start at or before `offset` (binary search). */
function lineIndex(starts: readonly number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] ?? 0) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

export interface ClangTidyConversion {
  log: SarifLog;
  /** Diagnostics of `Level: Error`: a translation unit clang could not compile (decision 6). */
  compileErrors: number;
  /**
   * Ruling D9-9: diagnostics and notes that cannot be placed on a file of the scan (outside the
   * repository, a host or system header, a file left out of the scan, past its end). Dropped
   * without a trace of their path; counted for one log line.
   */
  unplaced: number;
}

/** The Diagnostics of every YAML document of clang-tidy's export. */
function parseDiagnostics(text: string): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  if (text.trim() === '') return diagnostics;
  for (const d of parseAllDocuments(text, { prettyErrors: false })) {
    if (d.errors.length > 0) throw new Error('clang-tidy export is not YAML');
    const value = d.toJS({ maxAliasCount: 100 }) as { Diagnostics?: unknown } | null;
    if (value === null || value === undefined) continue;
    if (typeof value !== 'object') throw new Error('clang-tidy export is not a YAML mapping');
    const list = value.Diagnostics ?? [];
    if (!Array.isArray(list)) throw new Error('clang-tidy export has no Diagnostics list');
    diagnostics.push(...(list as Diagnostic[]));
  }
  return diagnostics;
}

/** What placing a location needs: both spellings of the root, the scope, the files read so far. */
interface Placing {
  root: string;
  realRoot: string;
  scope: ReadonlySet<string> | undefined;
  files: Map<string, Source | null>;
}

/** A repository file's bytes and line starts, read once (null: not a plain file of the root). */
function sourceOf(pl: Placing, base: string, abs: string): Source | null {
  let source = pl.files.get(abs);
  if (source === undefined) {
    // readPlainFile checks that `abs` resolves to `realRoot` + its path relative to `base`.
    const bytes = readPlainFile(base, pl.realRoot, abs);
    source = bytes === null ? null : { bytes, lineStarts: lineStartsOf(bytes) };
    pl.files.set(abs, source);
  }
  return source;
}

/** A clang-tidy place (path and byte offset) as a SARIF location on a file of the scan, or null. */
function place(pl: Placing, p: Place | undefined, build: string): SarifLocation | null {
  if (typeof p?.FilePath !== 'string' || typeof p.FileOffset !== 'number') return null;
  const abs = path.resolve(build, p.FilePath);
  const base = [pl.root, pl.realRoot].find((b) => within(b, abs) && abs !== b);
  if (base === undefined) return null;
  const segments = path.relative(base, abs).split(path.sep);
  if (pl.scope !== undefined && !pl.scope.has(segments.join('/'))) return null;
  const source = sourceOf(pl, base, abs);
  const offset = p.FileOffset;
  if (source === null || !Number.isInteger(offset) || offset < 0 || offset > source.bytes.length) {
    return null;
  }
  const line = lineIndex(source.lineStarts, offset);
  const lineStart = source.lineStarts[line] ?? 0;
  // A column in UTF-16 code units, as SARIF counts them by default.
  const column = source.bytes.subarray(lineStart, offset).toString('utf8').length + 1;
  return {
    physicalLocation: {
      artifactLocation: { uri: segments.map(encodeURIComponent).join('/') },
      region: { startLine: line + 1, startColumn: column },
    },
  };
}

/** A diagnostic's notes that can be placed, and how many cannot (ruling D9-9). */
function placedNotes(
  pl: Placing,
  d: Diagnostic,
  build: string,
): { notes: SarifLocation[]; unplaced: number } {
  const notes: SarifLocation[] = [];
  let unplaced = 0;
  for (const n of Array.isArray(d.Notes) ? (d.Notes as (Place | null)[]) : []) {
    const loc = n === null || typeof n !== 'object' ? null : place(pl, n, build);
    if (loc === null) {
      // Ruling D9-9: a note in a host header (an analyzer path through a function there, an
      // "included from" chain) never reaches the report, its message included.
      unplaced++;
      continue;
    }
    notes.push({
      ...loc,
      ...(typeof n?.Message === 'string' && { message: { text: redactRoots(pl, n.Message) } }),
    });
  }
  return { notes, unplaced };
}

/** Ruling D9-11: no host path in a kept message or note text. */
function redactRoots(pl: Placing, text: string): string {
  return redactForeignPaths(text, [pl.root, pl.realRoot]);
}

/** One diagnostic as a result, or what it counts as when it is none. */
function convertDiagnostic(
  pl: Placing,
  d: Diagnostic | null,
): { result: SarifResult; unplaced: number } | 'compile-error' | 'unplaced' {
  if (d === null || typeof d !== 'object') return 'unplaced';
  if (d.Level === 'Error') return 'compile-error';
  const name = d.DiagnosticName;
  const build = typeof d.BuildDirectory === 'string' ? d.BuildDirectory : pl.root;
  const primary = place(pl, d.DiagnosticMessage, build);
  if (typeof name !== 'string' || !CHECK_NAME.test(name) || primary === null) return 'unplaced';
  const { notes, unplaced } = placedNotes(pl, d, build);
  const message = d.DiagnosticMessage?.Message;
  return {
    result: {
      ruleId: name,
      level: 'warning',
      message: { text: typeof message === 'string' ? redactRoots(pl, message) : name },
      locations: [primary],
      ...(notes.length > 0 && { relatedLocations: notes }),
    },
    unplaced,
  };
}

/**
 * config.md §6.2: clang-tidy's `--export-fixes` YAML as SARIF 2.1.0. Paths resolve against each
 * diagnostic's BuildDirectory; byte offsets become lines and columns from the repository file
 * (`readPlainFile`: a regular file inside the root, at most 1 MiB). Compile errors (`Level: Error`)
 * and diagnostics or notes that cannot be placed in the repository (or, with `scope`, on a file
 * of the scan) are counted, not reported.
 */
export function clangTidyFixesToSarif(
  text: string,
  o: { root: string; version: string; scope?: ReadonlySet<string> },
): ClangTidyConversion {
  const diagnostics = parseDiagnostics(text);
  const root = path.resolve(o.root);
  const pl: Placing = { root, realRoot: realRootOf(root), scope: o.scope, files: new Map() };
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];
  let compileErrors = 0;
  let unplaced = 0;
  for (const d of diagnostics) {
    const converted = convertDiagnostic(pl, d);
    if (converted === 'compile-error') compileErrors++;
    else if (converted === 'unplaced') unplaced++;
    else {
      unplaced += converted.unplaced;
      const name = converted.result.ruleId as string;
      if (!rules.has(name)) rules.set(name, { id: name });
      results.push(converted.result);
    }
  }
  return {
    log: {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'clang-tidy', version: o.version, rules: [...rules.values()] } },
          results,
        },
      ],
    },
    compileErrors,
    unplaced,
  };
}

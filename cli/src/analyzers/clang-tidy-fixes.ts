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
  const diagnostics: Diagnostic[] = [];
  if (text.trim() !== '') {
    for (const d of parseAllDocuments(text, { prettyErrors: false })) {
      if (d.errors.length > 0) throw new Error('clang-tidy export is not YAML');
      const value = d.toJS({ maxAliasCount: 100 }) as { Diagnostics?: unknown } | null;
      if (value === null || value === undefined) continue;
      if (typeof value !== 'object') throw new Error('clang-tidy export is not a YAML mapping');
      const list = value.Diagnostics ?? [];
      if (!Array.isArray(list)) throw new Error('clang-tidy export has no Diagnostics list');
      diagnostics.push(...(list as Diagnostic[]));
    }
  }
  const root = path.resolve(o.root);
  const realRoot = realRootOf(root);
  // Ruling D9-11: no host path in a kept message or note text.
  const redact = (t: string) => redactForeignPaths(t, [root, realRoot]);
  const files = new Map<string, Source | null>();
  const place = (p: Place | undefined, build: string): SarifLocation | null => {
    if (typeof p?.FilePath !== 'string' || typeof p.FileOffset !== 'number') return null;
    const abs = path.resolve(build, p.FilePath);
    const base = [root, realRoot].find((b) => within(b, abs) && abs !== b);
    if (base === undefined) return null;
    const segments = path.relative(base, abs).split(path.sep);
    if (o.scope !== undefined && !o.scope.has(segments.join('/'))) return null;
    let source = files.get(abs);
    if (source === undefined) {
      // readPlainFile checks that `abs` resolves to `realRoot` + its path relative to `base`.
      const bytes = readPlainFile(base, realRoot, abs);
      source = bytes === null ? null : { bytes, lineStarts: lineStartsOf(bytes) };
      files.set(abs, source);
    }
    const offset = p.FileOffset;
    if (
      source === null ||
      !Number.isInteger(offset) ||
      offset < 0 ||
      offset > source.bytes.length
    ) {
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
  };
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];
  let compileErrors = 0;
  let unplaced = 0;
  for (const d of diagnostics) {
    if (d === null || typeof d !== 'object') {
      unplaced++;
      continue;
    }
    if (d.Level === 'Error') {
      compileErrors++;
      continue;
    }
    const name = d.DiagnosticName;
    const build = typeof d.BuildDirectory === 'string' ? d.BuildDirectory : root;
    const primary = place(d.DiagnosticMessage, build);
    if (typeof name !== 'string' || !CHECK_NAME.test(name) || primary === null) {
      unplaced++;
      continue;
    }
    const notes: SarifLocation[] = [];
    for (const n of Array.isArray(d.Notes) ? (d.Notes as (Place | null)[]) : []) {
      const loc = n === null || typeof n !== 'object' ? null : place(n, build);
      if (loc === null) {
        // Ruling D9-9: a note in a host header (an analyzer path through a function there, an
        // "included from" chain) never reaches the report, its message included.
        unplaced++;
        continue;
      }
      notes.push({
        ...loc,
        ...(typeof n?.Message === 'string' && { message: { text: redact(n.Message) } }),
      });
    }
    if (!rules.has(name)) rules.set(name, { id: name });
    results.push({
      ruleId: name,
      level: 'warning',
      message: {
        text:
          typeof d.DiagnosticMessage?.Message === 'string'
            ? redact(d.DiagnosticMessage.Message)
            : name,
      },
      locations: [primary],
      ...(notes.length > 0 && { relatedLocations: notes }),
    });
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

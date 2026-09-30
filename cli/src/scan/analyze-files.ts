import type { QualorConfig } from '@qualor/shared';
import { globMatcher, MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { readSource, type SourceText } from '../discovery/source';
import type { DuplicationInput } from '../duplication/detect';
import { lineUnits, type LineUnit } from '../duplication/tokens';
import type { Logger } from '../log';
import { computeMetrics, type FileMetrics } from '../metrics/metrics';
import { hasRealParseErrors } from '../metrics/errors';
import { FAMILY_RULES, familyOf } from '../metrics/rules';
import { DEFAULT_PARSE_TIMEOUT_MS, type Parsers } from '../parse/grammars';
import type { Warnings } from '../warnings';

export interface AnalyzedFile {
  file: ScopeFile;
  sha256: string;
  lines: number;
  metrics?: FileMetrics;
  /** Duplication units; present only for files that `collectUnits` selected. */
  units?: LineUnit[];
}

export interface AnalyzeOptions {
  parsers: Parsers;
  warnings: Warnings;
  log: Logger;
  parseTimeoutMs?: number;
  collectUnits?: (file: ScopeFile) => boolean;
}

/** report-format §8: main files only, minus `duplication.exclude`; nothing when disabled. */
export function duplicationFilter(config: QualorConfig): (file: ScopeFile) => boolean {
  if (!config.duplication.enabled) return () => false;
  const excluded = globMatcher(config.duplication.exclude, true);
  return (f) => f.kind === 'main' && f.grammar !== null && !excluded(f.path);
}

export function duplicationInputs(analyzed: readonly AnalyzedFile[]): DuplicationInput[] {
  return analyzed.flatMap((a) =>
    a.units === undefined ? [] : [{ path: a.file.path, units: a.units }],
  );
}

/** Reads, hashes and (for TS/JS/Java up to 1 MiB) parses each file exactly once. */
export function analyzeFiles(files: readonly ScopeFile[], o: AnalyzeOptions): AnalyzedFile[] {
  const out: AnalyzedFile[] = [];
  for (const file of files) {
    let source: SourceText;
    try {
      source = readSource(file.absPath);
    } catch (err) {
      o.warnings.add('FILE_UNREADABLE', 'a file could not be read and was left out of the report');
      o.log.debug(`cannot read ${file.absPath}: ${String(err)}`);
      continue;
    }
    if (source.encoding !== 'utf-8') {
      o.warnings.add('FILE_NOT_UTF8', 'files that are not valid UTF-8 were read as Latin-1');
    }
    const analyzed: AnalyzedFile = { file, sha256: source.sha256, lines: source.lines };
    out.push(analyzed);
    if (file.grammar === null) continue;
    // `text` is null when readSource streamed the file because it is over 1 MiB on disk now.
    if (file.size > MAX_ANALYZED_BYTES || source.text === null) {
      o.warnings.add(
        'FILE_TOO_LARGE',
        'files larger than 1 MiB were skipped for metrics and duplication',
      );
      continue;
    }
    const tree = o.parsers.parse(
      file.grammar,
      source.text,
      o.parseTimeoutMs ?? DEFAULT_PARSE_TIMEOUT_MS,
    );
    if (tree === null) {
      o.warnings.add(
        'PARSE_TIMEOUT',
        'parsing took too long; metrics and duplication were skipped',
      );
      continue;
    }
    try {
      const family = familyOf(file.grammar);
      if (hasRealParseErrors(tree.rootNode, FAMILY_RULES[family].benignMissing)) {
        o.warnings.add(
          'PARSE_ERRORS',
          'files with syntax errors were measured on a best-effort basis',
        );
      }
      analyzed.metrics = computeMetrics(tree.rootNode, family);
      if (o.collectUnits?.(file) === true) analyzed.units = lineUnits(tree.rootNode, family);
    } finally {
      tree.delete();
    }
  }
  return out;
}

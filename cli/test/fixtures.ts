import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  coverageMeasures,
  expectedSchema,
  parseConfig,
  type Expected,
  type QualorConfig,
} from '@qualor/shared';
import { parse } from 'yaml';
import type { FileCoverage } from '../src/coverage/model';

export const FIXTURES_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../fixtures',
);
export const FIXTURE_NAMES = [
  'ts-basic',
  'java-basic',
  'mixed-secrets',
  'python-basic',
  'html-basic',
  'css-basic',
] as const;
export const METRIC_FIELDS = [
  'ncloc',
  'commentLines',
  'functions',
  'classes',
  'statements',
  'complexity',
  'cognitiveComplexity',
] as const;

export function loadFixture(name: string): {
  dir: string;
  config: QualorConfig;
  expected: Expected;
} {
  const dir = path.join(FIXTURES_DIR, name);
  return {
    dir,
    config: parseConfig(parse(readFileSync(path.join(dir, 'qualor.yml'), 'utf8'))),
    expected: expectedSchema.parse(
      JSON.parse(readFileSync(path.join(dir, 'expected.json'), 'utf8')),
    ),
  };
}

const span = (ranges: readonly (readonly [number, number])[]) =>
  ranges.reduce((n, [a, b]) => n + (b - a + 1), 0);

/** The `expected.json` coverage fields, computed like `compareFixture` does. */
export function coverageSummary(map: ReadonlyMap<string, FileCoverage>) {
  let linesToCover = 0;
  let uncoveredLines = 0;
  let conditionsToCover = 0;
  let uncoveredConditions = 0;
  for (const c of map.values()) {
    uncoveredLines += span(c.uncovered);
    linesToCover += span(c.covered) + span(c.uncovered);
    for (const [, total, covered] of c.branches) {
      conditionsToCover += total;
      uncoveredConditions += total - covered;
    }
  }
  const m = coverageMeasures({
    linesToCover,
    uncoveredLines,
    conditionsToCover,
    uncoveredConditions,
  });
  return {
    lines_to_cover: m.lines_to_cover,
    uncovered_lines: m.uncovered_lines,
    conditions_to_cover: m.conditions_to_cover,
    uncovered_conditions: m.uncovered_conditions,
    coverage: m.coverage,
  };
}

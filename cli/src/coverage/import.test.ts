import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { coverageSummary, loadFixture } from '../../test/fixtures';
import { useTempDirs, writeTree } from '../../test/tmp';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { detectFormat, expandReportPaths, importCoverage, type CoverageTarget } from './import';

const tmp = useTempDirs();
const main = (p: string, lines = 30): CoverageTarget => ({ path: p, kind: 'main', lines });

describe('importCoverage', () => {
  it('reproduces the ts-basic coverage numbers', async () => {
    const { dir, config, expected } = loadFixture('ts-basic');
    const warnings = new Warnings();
    const map = await importCoverage({
      root: dir,
      reports: config.coverage.reports,
      files: [main('src/math.ts', 25), { path: 'src/math.test.ts', kind: 'test', lines: 3 }],
      pathPrefixes: config.coverage.pathPrefixes,
      warnings,
      log: silentLogger,
    });
    const summary = coverageSummary(map);
    expect(summary).toMatchObject({
      lines_to_cover: expected.coverage?.lines_to_cover,
      uncovered_lines: expected.coverage?.uncovered_lines,
      conditions_to_cover: expected.coverage?.conditions_to_cover,
      uncovered_conditions: expected.coverage?.uncovered_conditions,
    });
    expect(Math.abs((summary.coverage ?? 0) - (expected.coverage?.coverage ?? 0))).toBeLessThanOrEqual(0.1);
    expect(warnings.list()).toEqual([]);
  });

  it('sums two reports, ignores test files and warns about unresolved and stale entries', async () => {
    const root = tmp();
    writeTree(root, {
      'a/lcov.info': 'SF:src/x.ts\nDA:1,0\nDA:2,1\nDA:99,1\nend_of_record\nSF:gone.ts\nDA:1,1\nend_of_record\n',
      'b/lcov.info': 'SF:src/x.ts\nDA:1,4\nend_of_record\nSF:src/x.test.ts\nDA:1,1\nend_of_record\n',
    });
    const warnings = new Warnings();
    const map = await importCoverage({
      root,
      reports: [{ path: '**/lcov.info', format: 'auto' }],
      files: [main('src/x.ts', 10), { path: 'src/x.test.ts', kind: 'test', lines: 5 }],
      pathPrefixes: [],
      warnings,
      log: silentLogger,
    });
    expect([...map]).toEqual([['src/x.ts', { covered: [[1, 2]], uncovered: [], branches: [] }]]);
    expect(warnings.list()).toEqual([
      expect.objectContaining({ code: 'COVERAGE_PATH_UNRESOLVED', count: 1 }),
      expect.objectContaining({ code: 'COVERAGE_LINE_OUT_OF_RANGE', count: 1 }),
    ]);
  });

  it('warns about missing, unknown and unparseable reports without failing', async () => {
    const root = tmp();
    writeTree(root, { 'notes.txt': 'hello\n', 'bad.xml': '<coverage><unclosed>' });
    const warnings = new Warnings();
    const map = await importCoverage({
      root,
      reports: [
        { path: 'missing/lcov.info', format: 'auto' },
        { path: 'notes.txt', format: 'auto' },
        { path: 'bad.xml', format: 'cobertura' },
      ],
      files: [main('src/x.ts')],
      pathPrefixes: [],
      warnings,
      log: silentLogger,
    });
    expect(map.size).toBe(0);
    expect(warnings.list().map((w) => w.code)).toEqual([
      'COVERAGE_REPORT_NOT_FOUND',
      'COVERAGE_FORMAT_UNKNOWN',
      'COVERAGE_REPORT_INVALID',
    ]);
  });
});

describe('detectFormat / expandReportPaths', () => {
  it('sniffs the format from the content', () => {
    const root = tmp();
    writeTree(root, {
      'l.info': 'TN:\nSF:a.ts\n',
      'c.xml': '<?xml version="1.0"?>\n<!DOCTYPE coverage SYSTEM "x.dtd">\n<coverage line-rate="1">',
      'j.xml': '<?xml version="1.0"?><!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd"><report name="x">',
      'o.txt': 'nothing',
    });
    expect(detectFormat(path.join(root, 'l.info'))).toBe('lcov');
    expect(detectFormat(path.join(root, 'c.xml'))).toBe('cobertura');
    expect(detectFormat(path.join(root, 'j.xml'))).toBe('jacoco');
    expect(detectFormat(path.join(root, 'o.txt'))).toBeNull();
  });

  it('expands globs inside excluded directories but skips .git and node_modules', () => {
    const root = tmp();
    writeTree(root, {
      'target/site/jacoco/jacoco.xml': 'x',
      'mod/target/site/jacoco/jacoco.xml': 'x',
      'node_modules/p/target/jacoco.xml': 'x',
      '.git/jacoco.xml': 'x',
    });
    expect(expandReportPaths(root, '**/jacoco.xml').map((p) => path.relative(root, p).replaceAll('\\', '/'))).toEqual([
      'mod/target/site/jacoco/jacoco.xml',
      'target/site/jacoco/jacoco.xml',
    ]);
    expect(expandReportPaths(root, 'target/site/jacoco/jacoco.xml')).toHaveLength(1);
    expect(expandReportPaths(root, 'nope.xml')).toEqual([]);
  });
});

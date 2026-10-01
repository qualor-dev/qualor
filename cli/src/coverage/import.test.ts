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

  it('reproduces the go-basic coverage numbers from its Go profile (plan 9C)', async () => {
    const { dir, config, expected } = loadFixture('go-basic');
    const warnings = new Warnings();
    const map = await importCoverage({
      root: dir,
      reports: config.coverage.reports,
      files: [main('store/store.go', 61), main('cmd/gobasic/main.go', 14), main('tools/next.go', 9)],
      pathPrefixes: config.coverage.pathPrefixes,
      warnings,
      log: silentLogger,
    });
    expect(coverageSummary(map)).toMatchObject({
      lines_to_cover: expected.coverage?.lines_to_cover,
      uncovered_lines: expected.coverage?.uncovered_lines,
      conditions_to_cover: 0,
      uncovered_conditions: 0,
    });
    expect(map.get('store/store.go')).toEqual({
      covered: [[17, 17], [22, 24], [29, 32], [35, 35]],
      uncovered: [[40, 40], [45, 45], [50, 53], [55, 55], [60, 60]],
      branches: [],
    });
    expect(warnings.list()).toEqual([]);
  });

  it('resolves the import paths of a module in a subdirectory to its files (plan 9C)', async () => {
    const root = tmp();
    writeTree(root, {
      'svc/coverage.out':
        'mode: set\ngithub.com/acme/repo/svc/store/store.go:3.2,4.1 1 1\ngithub.com/acme/repo/svc/store/store.go:5.2,6.1 1 0\n',
      'svc/store/store.go': 'package store\n',
      'other/store/store.go': 'package store\n',
    });
    const warnings = new Warnings();
    const map = await importCoverage({
      root,
      reports: [{ path: 'svc/coverage.out', format: 'auto' }],
      files: [main('svc/store/store.go', 10), main('other/store/store.go', 10)],
      pathPrefixes: [],
      warnings,
      log: silentLogger,
    });
    expect(map.get('svc/store/store.go')).toEqual({ covered: [[3, 3]], uncovered: [[5, 5]], branches: [] });
    expect(map.has('other/store/store.go')).toBe(false);
    expect(warnings.list()).toEqual([]);
  });

  it('never maps a profile path that climbs out of the repository onto a file (untrusted profile)', async () => {
    const root = tmp();
    writeTree(root, {
      'coverage.out': 'mode: set\n../../etc/store.go:1.1,2.1 1 1\nexample.com/m/../../store.go:1.1,2.1 1 1\n',
      'store.go': 'package store\n',
    });
    const warnings = new Warnings();
    const map = await importCoverage({
      root,
      reports: [{ path: 'coverage.out', format: 'auto' }],
      files: [main('store.go', 10)],
      pathPrefixes: [],
      warnings,
      log: silentLogger,
    });
    expect(map.size).toBe(0);
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

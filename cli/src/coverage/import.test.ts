import { readFileSync } from 'node:fs';
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

// Tool versions that produced cli/test/coverage/{gcovr.xml,gcovr.info,llvm-cov.info}
// (node:22.23.3-bookworm@sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7;
// libclang-rt-14-dev is needed for clang's -fprofile-instr-generate runtime):
// gcc (Debian 12.2.0-14+deb12u1) 12.2.0
// clang 1:14.0-55.7~deb12u1
// libclang-rt-14-dev 1:14.0.6-12
// llvm 1:14.0-55.7~deb12u1
// python3-venv 3.11.2-1+b1
// colorlog==6.12.0
// gcovr==8.6
// Jinja2==3.1.6
// lxml==6.1.3
// MarkupSafe==3.0.3
// pip==23.0.1
// Pygments==2.21.0
// setuptools==66.1.1
describe('C and C++ coverage reports (plan 9D, fact F10)', () => {
  const LIB =
    'int clamp(int v, int lo, int hi) {\n    if (v < lo) return lo;\n    if (v > hi) return hi;\n    return v;\n}\n';
  const MAIN =
    'int clamp(int v, int lo, int hi);\nint main(void) { return clamp(5, 0, 3) == 3 ? 0 : 1; }\n';
  const recorded = (name: string) => readFileSync(path.resolve('cli/test/coverage', name), 'utf8');

  /** The recorded report of another machine (/w/src, /b), imported into a repository with src/. */
  async function importRecorded(file: string, format: 'lcov' | 'cobertura') {
    const root = tmp();
    writeTree(root, {
      'src/lib.c': LIB,
      'src/main.c': MAIN,
      [`reports/${file}`]: recorded(file),
    });
    const warnings = new Warnings();
    const map = await importCoverage({
      root,
      reports: [{ path: `reports/${file}`, format }],
      files: [main('src/lib.c', 5), main('src/main.c', 2)],
      pathPrefixes: [],
      warnings,
      log: silentLogger,
    });
    return { map, warnings: warnings.list() };
  }

  it("maps gcovr's Cobertura (src/lib.c under <source>/w</source>) onto src/ by suffix", async () => {
    const { map, warnings } = await importRecorded('gcovr.xml', 'cobertura');
    expect(warnings).toEqual([]);
    expect(Object.fromEntries(map)).toEqual({
      'src/lib.c': {
        covered: [[1, 3]],
        uncovered: [[4, 4]],
        branches: [
          [2, 2, 1],
          [3, 2, 1],
        ],
      },
      'src/main.c': { covered: [[2, 2]], uncovered: [], branches: [] },
    });
  });

  // gcovr.info (a VER: line per file, ignored):
  //   lib.c:  DA:1,1 DA:2,1 DA:3,1 DA:4,0 -> covered 1-3, uncovered 4
  //           BRDA:2,0,0,- BRDA:2,0,1,1 -> [2,2,1] ('-' is not covered)
  //           BRDA:3,0,0,1 BRDA:3,0,1,- -> [3,2,1]
  //   main.c: DA:2,1 -> covered 2; no BRDA
  it("maps gcovr's LCOV (absolute SF:/w/src/…, a VER: line) onto src/ by suffix", async () => {
    const { map, warnings } = await importRecorded('gcovr.info', 'lcov');
    expect(warnings).toEqual([]);
    expect(Object.fromEntries(map)).toEqual({
      'src/lib.c': {
        covered: [[1, 3]],
        uncovered: [[4, 4]],
        branches: [
          [2, 2, 1],
          [3, 2, 1],
        ],
      },
      'src/main.c': { covered: [[2, 2]], uncovered: [], branches: [] },
    });
  });

  // llvm-cov.info (FN/FNDA lines, ignored):
  //   lib.c:  DA:1,1 DA:2,1 DA:3,1 DA:4,0 DA:5,1 -> covered 1-3 and 5, uncovered 4
  //           BRDA:2,0,0,0 BRDA:2,0,1,1 -> [2,2,1]
  //           BRDA:3,0,0,1 BRDA:3,0,1,0 -> [3,2,1]
  //   main.c: DA:2,1 -> covered 2
  //           BRDA:2,0,0,1 BRDA:2,0,1,0 -> [2,2,1]
  it("maps llvm-cov's LCOV (absolute SF:/w/src/…, FN/FNDA lines) onto src/ by suffix", async () => {
    const { map, warnings } = await importRecorded('llvm-cov.info', 'lcov');
    expect(warnings).toEqual([]);
    expect(Object.fromEntries(map)).toEqual({
      'src/lib.c': {
        covered: [
          [1, 3],
          [5, 5],
        ],
        uncovered: [[4, 4]],
        branches: [
          [2, 2, 1],
          [3, 2, 1],
        ],
      },
      'src/main.c': { covered: [[2, 2]], uncovered: [], branches: [[2, 2, 1]] },
    });
  });
});

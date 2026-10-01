import { describe, expect, it } from 'vitest';
import {
  CLANG_TIDY_DEFAULT_CHECKS,
  CLANG_TIDY_MIN_MAJOR,
  clangTidyMeta,
  clangTidyVersionSupported,
  CPPCHECK_ANALYSIS_IDS,
  CPPCHECK_VERSION,
  cppcheckIsFinding,
  cppcheckQuality,
  cppcheckSeverity,
  cppcheckVersionSupported,
  DEFAULT_CPPCHECK_ENABLE,
} from './cfamily';

describe('cppcheck rules (plan 9D, report-format.md §7.1)', () => {
  it('runs every patch of the pinned minor and nothing else', () => {
    const [major, minor] = CPPCHECK_VERSION.split('.').map(Number) as [number, number];
    expect(cppcheckVersionSupported(CPPCHECK_VERSION)).toBe(true);
    expect(cppcheckVersionSupported(`${major}.${minor}.9`)).toBe(true);
    expect(cppcheckVersionSupported(`${major}.${minor}`)).toBe(true); // cppcheck prints "2.18" for .0 releases before 2.20
    expect(cppcheckVersionSupported(`${major}.${minor + 1}.0`)).toBe(false);
    expect(cppcheckVersionSupported(`${major}.${minor - 4}`)).toBe(false);
    expect(cppcheckVersionSupported('')).toBe(false);
  });

  it('grades by cppcheck severity: error high, warning medium, the rest low', () => {
    expect(cppcheckSeverity('error')).toBe('high');
    expect(cppcheckSeverity('warning')).toBe('medium');
    for (const s of ['style', 'performance', 'portability'])
      expect(cppcheckSeverity(s)).toBe('low');
    expect(cppcheckSeverity('surprise')).toBe('medium');
    expect(cppcheckQuality('error')).toBe('reliability');
    expect(cppcheckQuality('warning')).toBe('reliability');
    expect(cppcheckQuality('style')).toBe('maintainability');
    expect(cppcheckQuality('performance')).toBe('maintainability');
  });

  it('never makes a finding of an analysis error or an information message (decision 6)', () => {
    for (const id of [
      'syntaxError',
      'unknownMacro',
      'internalAstError',
      'preprocessorErrorDirective',
      'missingInclude',
      'checkersReport',
    ]) {
      expect(CPPCHECK_ANALYSIS_IDS.has(id), id).toBe(true);
      expect(cppcheckIsFinding(id, 'error'), id).toBe(false);
    }
    expect(cppcheckIsFinding('nullPointer', 'error')).toBe(true);
    expect(cppcheckIsFinding('constVariable', 'style')).toBe(true);
    for (const s of ['information', 'debug', 'internal', 'none'])
      expect(cppcheckIsFinding('x', s)).toBe(false);
  });

  it('enables warning, performance and portability by default, not style (decision 4)', () => {
    expect([...DEFAULT_CPPCHECK_ENABLE]).toEqual(['warning', 'performance', 'portability']);
  });
});

describe('clang-tidy rules (plan 9D)', () => {
  it('accepts LLVM 14 and newer', () => {
    expect(clangTidyVersionSupported(`${CLANG_TIDY_MIN_MAJOR}.0.6`)).toBe(true);
    expect(clangTidyVersionSupported('22.1.8')).toBe(true);
    expect(clangTidyVersionSupported(`${CLANG_TIDY_MIN_MAJOR - 1}.0.1`)).toBe(false);
    expect(clangTidyVersionSupported('x')).toBe(false);
  });

  it('maps checks by their group', () => {
    expect(clangTidyMeta('clang-analyzer-security.ArrayBound')).toEqual({
      quality: 'security',
      severity: 'high',
    });
    expect(clangTidyMeta('clang-analyzer-optin.taint.GenericTaint')).toEqual({
      quality: 'security',
      severity: 'high',
    });
    expect(clangTidyMeta('clang-analyzer-core.DivideZero')).toEqual({
      quality: 'reliability',
      severity: 'high',
    });
    expect(clangTidyMeta('clang-diagnostic-format')).toEqual({
      quality: 'reliability',
      severity: 'medium',
    });
    for (const c of ['bugprone-use-after-move', 'cert-err33-c', 'concurrency-mt-unsafe']) {
      expect(clangTidyMeta(c), c).toEqual({ quality: 'reliability', severity: 'medium' });
    }
    for (const c of [
      'performance-unnecessary-copy-initialization',
      'readability-identifier-length',
      'misc-const-correctness',
      'my-plugin-check',
    ]) {
      expect(clangTidyMeta(c), c).toEqual({ quality: 'maintainability', severity: 'low' });
    }
  });

  it('starts from nothing and leaves out the noisy checks measured on fmt (F8)', () => {
    const globs = CLANG_TIDY_DEFAULT_CHECKS.split(',');
    expect(globs[0]).toBe('-*');
    for (const g of [
      'bugprone-*',
      'clang-analyzer-*',
      'performance-*',
      'portability-*',
      'concurrency-*',
    ])
      expect(globs).toContain(g);
    for (const g of [
      '-bugprone-easily-swappable-parameters',
      '-bugprone-narrowing-conversions',
      '-performance-enum-size',
      '-concurrency-mt-unsafe',
      '-clang-analyzer-optin.*',
    ])
      expect(globs).toContain(g);
    expect(globs.some((g) => g.startsWith('misc-') || g.startsWith('cert-'))).toBe(false);
  });
});

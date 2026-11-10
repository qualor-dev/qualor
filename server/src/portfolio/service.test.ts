import { describe, expect, it } from 'vitest';
import { ProblemError } from '../http/problem';
import { aggregate, ratingOf, translateTimeout, type ProjectState } from './service';

let n = 0;
function state(over: Partial<ProjectState> = {}): ProjectState {
  n += 1;
  return {
    organizationId: 'org',
    severities: { blocker: 1, high: 0, medium: 0, low: 0, info: 0 },
    organization: { key: 'org', name: 'Org' },
    project: { id: `p${n}`, key: `p${n}`, name: `p${n}` },
    lastAnalysisAt: '2026-10-01T00:00:00.000Z',
    abandoned: false,
    gate: 'passed',
    securityRating: 'A',
    reliabilityRating: 'A',
    ncloc: 100,
    coverage: 50,
    duplication: 10,
    issues: 1,
    bySeverity: { blocker: 1, high: 0, medium: 0, low: 0, info: 0 },
    newIssues: 1,
    secrets: 0,
    vulnerableDependencies: 0,
    vulnerableReleases: null,
    exploited: null,
    securityIssues: 1,
    reliabilityIssues: 0,
    maintainabilityIssues: 0,
    ...over,
  };
}

const NEVER: Partial<ProjectState> = {
  lastAnalysisAt: null,
  abandoned: true,
  gate: null,
  securityRating: null,
  reliabilityRating: null,
  ncloc: null,
  coverage: null,
  duplication: null,
  issues: null,
  bySeverity: null,
  severities: { blocker: null, high: null, medium: null, low: null, info: null },
  newIssues: null,
  securityIssues: null,
  reliabilityIssues: null,
  maintainabilityIssues: null,
};

describe('portfolio aggregate (4E-2 §1)', () => {
  it('weights coverage and duplication by ncloc over the projects that have both', () => {
    const a = aggregate([
      state({ ncloc: 1000, coverage: 90, duplication: 2 }),
      state({ ncloc: 3000, coverage: 50, duplication: null }),
      state({ ncloc: null, coverage: 10, duplication: 40 }),
    ]);
    expect(a.ncloc).toBe(4000);
    expect(a.coverage).toBeCloseTo((90 * 1000 + 50 * 3000) / 4000, 10);
    expect(a.duplication).toBe(2);
  });

  it('leaves nulls out of every aggregate and divides by nothing', () => {
    const a = aggregate([
      state(NEVER),
      state({ ...NEVER, lastAnalysisAt: '2026-10-01T00:00:00Z', gate: 'none' }),
    ]);
    expect(a).toEqual({
      projects: 2,
      analysed: 1,
      abandoned: 2,
      gate: { passed: 0, failed: 0, error: 0, none: 1 },
      passedShare: 0,
      securityRating: { A: 0, B: 0, C: 0, D: 0, E: 0 },
      reliabilityRating: { A: 0, B: 0, C: 0, D: 0, E: 0 },
      ncloc: 0,
      coverage: null,
      duplication: null,
      issues: 0,
      bySeverity: { blocker: 0, high: 0, medium: 0, low: 0, info: 0 },
      securityIssues: 0,
      reliabilityIssues: 0,
      maintainabilityIssues: 0,
      newIssues: 0,
    });
    expect(aggregate([]).passedShare).toBeNull();
    // Zero lines of code: no weight, so no share rather than NaN.
    expect(aggregate([state({ ncloc: 0, coverage: 80 })]).coverage).toBeNull();
  });

  it('sums each severity on its own, leaving out only the missing ones', () => {
    const a = aggregate([
      state({
        bySeverity: null,
        severities: { blocker: 2, high: null, medium: 3, low: null, info: null },
      }),
      state({ severities: { blocker: 1, high: 4, medium: 0, low: 1, info: 5 } }),
    ]);
    expect(a.bySeverity).toEqual({ blocker: 3, high: 4, medium: 3, low: 1, info: 5 });
  });

  it('counts gates, ratings and sums', () => {
    const a = aggregate([
      state({ gate: 'passed', securityRating: 'A', reliabilityRating: 'C', issues: 4 }),
      state({ gate: 'failed', securityRating: 'E', reliabilityRating: null, issues: 6 }),
      state({ gate: 'error', securityRating: 'E', reliabilityRating: 'C', newIssues: null }),
    ]);
    expect(a.gate).toEqual({ passed: 1, failed: 1, error: 1, none: 0 });
    expect(a.passedShare).toBeCloseTo(1 / 3, 10);
    expect(a.securityRating).toEqual({ A: 1, B: 0, C: 0, D: 0, E: 2 });
    expect(a.reliabilityRating).toEqual({ A: 0, B: 0, C: 2, D: 0, E: 0 });
    expect(a.issues).toBe(11);
    expect(a.bySeverity.blocker).toBe(3);
    expect(a.newIssues).toBe(2);
    expect(a.securityIssues).toBe(3);
  });

  it('maps ratings 1–5 to A–E and anything else to null', () => {
    expect([1, 2, 3, 4, 5].map(ratingOf)).toEqual(['A', 'B', 'C', 'D', 'E']);
    expect([null, 0, 6, 2.5, Number.NaN].map(ratingOf)).toEqual([null, null, null, null, null]);
  });

  it('turns a cancelled statement (57014) into 503 PORTFOLIO_TIMEOUT, and nothing else', () => {
    const cancelled = Object.assign(new Error('canceling statement due to statement timeout'), {
      code: '57014',
    });
    const wrapped = Object.assign(new Error('Failed query'), { cause: cancelled });
    for (const err of [cancelled, wrapped]) {
      const out = translateTimeout(err);
      expect(out).toBeInstanceOf(ProblemError);
      expect(out).toMatchObject({
        status: 503,
        code: 'PORTFOLIO_TIMEOUT',
        message: 'The portfolio took too long to compute',
      });
    }
    const other = Object.assign(new Error('unique'), { code: '23505' });
    expect(translateTimeout(other)).toBe(other);
  });
});

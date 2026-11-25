import { describe, expect, it } from 'vitest';
import { effectiveCleanup, type CleanupDefaults } from './settings';

const project = (branches: number | null, mergeRequests: number | null) => ({
  cleanupBranchesDays: branches,
  cleanupMergeRequestsDays: mergeRequests,
});
const OFF: CleanupDefaults = { branchesDays: null, mergeRequestsDays: null };
const DEFAULTS: CleanupDefaults = { branchesDays: 30, mergeRequestsDays: 60 };

describe('effectiveCleanup (issue #38)', () => {
  it('inherits the server default where the project has no value (NULL)', () => {
    expect(effectiveCleanup(project(null, null), DEFAULTS)).toEqual({
      branchesDays: 30,
      mergeRequestsDays: 60,
    });
  });

  it('is off where the project says 0, whatever the server default', () => {
    expect(effectiveCleanup(project(0, 0), DEFAULTS)).toEqual(OFF);
    expect(effectiveCleanup(project(0, 0), OFF)).toEqual(OFF);
  });

  it("takes the project's days over the server default, and without one", () => {
    expect(effectiveCleanup(project(90, 365), DEFAULTS)).toEqual({
      branchesDays: 90,
      mergeRequestsDays: 365,
    });
    expect(effectiveCleanup(project(1, 3650), OFF)).toEqual({
      branchesDays: 1,
      mergeRequestsDays: 3650,
    });
  });

  it('is off when neither the project nor the server sets a rule', () => {
    expect(effectiveCleanup(project(null, null), OFF)).toEqual(OFF);
  });

  it('decides each rule on its own', () => {
    expect(effectiveCleanup(project(0, null), DEFAULTS)).toEqual({
      branchesDays: null,
      mergeRequestsDays: 60,
    });
    expect(effectiveCleanup(project(null, 0), DEFAULTS)).toEqual({
      branchesDays: 30,
      mergeRequestsDays: null,
    });
    expect(effectiveCleanup(project(7, null), OFF)).toEqual({
      branchesDays: 7,
      mergeRequestsDays: null,
    });
  });
});

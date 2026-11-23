import { describe, expect, it } from 'vitest';
import { MAX_AI_THREADS, MAX_FIXED_NOTES, MAX_INLINE_THREADS } from '../inline';
import { MAX_AZURE_REQUESTS } from './client';
import {
  AZURE_REQUESTS_OUTSIDE_THREADS,
  MAX_AZURE_CHANGE_PAGES,
  MAX_AZURE_DIFF_FILES,
  MAX_AZURE_THREAD_UPDATES,
} from './threads';

describe('the request budget (Azure DevOps design §7.4)', () => {
  it('is 400 requests a job', () => {
    expect(MAX_AZURE_REQUESTS).toBe(400);
  });

  it('the Azure request bounds sum to 389', () => {
    // Identity, pull request, iterations, the pages of changes, the thread listing, the status's
    // read and write, the summary's listing and write, and the commit status of a branch.
    expect(AZURE_REQUESTS_OUTSIDE_THREADS).toBe(1 + 1 + 1 + MAX_AZURE_CHANGE_PAGES + 1 + 2 + 2 + 1);
    // Pinned apart from the constants, so a bound raised on its own fails here.
    expect([
      MAX_AZURE_CHANGE_PAGES,
      MAX_AZURE_DIFF_FILES,
      MAX_INLINE_THREADS,
      MAX_AI_THREADS,
      MAX_AZURE_THREAD_UPDATES,
      MAX_FIXED_NOTES,
    ]).toEqual([10, 40, 50, 20, 100, 20]);
    const sum =
      AZURE_REQUESTS_OUTSIDE_THREADS +
      2 * MAX_AZURE_DIFF_FILES + // a file at the head and at the base
      (MAX_INLINE_THREADS + MAX_AI_THREADS) + // the creations
      2 * MAX_AZURE_THREAD_UPDATES + // a status and a comment each
      MAX_FIXED_NOTES;
    expect([AZURE_REQUESTS_OUTSIDE_THREADS, 80, 70, 200, 20]).toEqual([19, 80, 70, 200, 20]);
    expect(sum).toBe(389);
    expect(sum).toBeLessThanOrEqual(MAX_AZURE_REQUESTS);
  });
});

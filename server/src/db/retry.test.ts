import { describe, expect, it } from 'vitest';
import { withConflictRetry } from './retry';

/** A `fn` that fails with each of `errors` in turn, then answers its attempt number. */
function failing(...errors: unknown[]): { fn: () => Promise<number>; calls: () => number } {
  let calls = 0;
  return {
    fn: async () => {
      calls += 1;
      const error = errors[calls - 1];
      if (error !== undefined) throw error;
      return calls;
    },
    calls: () => calls,
  };
}

describe('withConflictRetry', () => {
  it.each([
    ['a serialisation failure', { code: '40001' }],
    ['a deadlock', { code: '40P01' }],
    [
      'a serialisation failure wrapped in cause',
      new Error('query failed', { cause: { code: '40001' } }),
    ],
    ['a deadlock wrapped in cause', new Error('query failed', { cause: { code: '40P01' } })],
  ])('runs again after %s and answers the second attempt', async (_, error) => {
    const attempt = failing(error);
    await expect(withConflictRetry(attempt.fn)).resolves.toBe(2);
    expect(attempt.calls()).toBe(2);
  });

  it('stops after 3 attempts and throws the last error', async () => {
    const last = { code: '40P01', n: 3 };
    const attempt = failing({ code: '40001', n: 1 }, { code: '40P01', n: 2 }, last);
    await expect(withConflictRetry(attempt.fn)).rejects.toBe(last);
    expect(attempt.calls()).toBe(3);
  });

  it('takes another number of attempts', async () => {
    const attempt = failing({ code: '40001' }, { code: '40001' }, { code: '40001' });
    await expect(withConflictRetry(attempt.fn, 4)).resolves.toBe(4);
  });

  it.each([
    ['a unique violation', { code: '23505' }],
    ['a lock timeout', { code: '55P03' }],
    ['an error without a code', new Error('boom')],
  ])('never runs again after %s', async (_, error) => {
    const attempt = failing(error);
    await expect(withConflictRetry(attempt.fn)).rejects.toBe(error);
    expect(attempt.calls()).toBe(1);
  });
});

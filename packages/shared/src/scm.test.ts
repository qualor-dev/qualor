import { describe, expect, it } from 'vitest';
import { assertNever } from './scm';

describe('assertNever', () => {
  it('throws with the value named', () => {
    expect(() => assertNever('x' as never, 'provider')).toThrow('unexpected provider: x');
  });
});

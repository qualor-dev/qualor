import { describe, expect, it } from 'vitest';
import { assertNever } from './scm';

describe('assertNever', () => {
  it('throws with the value named', () => {
    expect(() => assertNever('x' as never, 'provider')).toThrow('unexpected provider: x');
  });

  it('prints the provider of an object, not [object Object]', () => {
    expect(() => assertNever({ provider: 'bitbucket', id: 1 } as never, 'provider')).toThrow(
      'unexpected provider: bitbucket',
    );
  });
});

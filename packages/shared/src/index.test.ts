import { describe, expect, it } from 'vitest';
import { VERSION } from './index';

describe('shared', () => {
  it('exports a semver version', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

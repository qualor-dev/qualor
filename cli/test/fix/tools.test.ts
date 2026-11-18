import { describe, expect, it } from 'vitest';
import { toolInstalled } from './tools';

describe('toolInstalled for the fix adapters (ruling T12a)', () => {
  it('finds what the runner starts, and nothing else', () => {
    expect(toolInstalled('node')).toBe(true);
    expect(toolInstalled('qualor-no-such-tool')).toBe(false);
  });

  it.runIf(process.platform === 'win32')('finds npm through its Windows shim', () => {
    expect(toolInstalled('npm')).toBe(true);
  });
});

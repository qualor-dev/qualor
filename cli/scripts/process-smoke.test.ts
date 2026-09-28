import { describe, expect, it } from 'vitest';
import { checkProcessGroupKill } from './process-smoke-check';

// Linux only (it reads /proc); Windows tree kill is covered by src/analyzers/process.test.ts.
describe.runIf(process.platform === 'linux')('checkProcessGroupKill', () => {
  it('kills a hung fake analyzer and its grandchild on timeout', { timeout: 20_000 }, async () => {
    expect(await checkProcessGroupKill()).toBeNull();
  });
});

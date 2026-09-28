import { describe, expect, it } from 'vitest';
import { checkUploadPath } from './upload-smoke-check';

// The same checks run under Bun (the shipped binary's runtime) with `smoke:upload`, which also
// checks that the process exits promptly after a JSON exchange (`--linger-probe`).
describe('checkUploadPath under Node', () => {
  it(
    'passes every upload and JSON transport check against real local servers',
    { timeout: 60_000 },
    async () => {
      const { passed, failed } = await checkUploadPath();
      expect(failed).toEqual([]);
      expect(passed.length).toBeGreaterThanOrEqual(14);
    },
  );
});

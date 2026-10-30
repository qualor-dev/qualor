import { describe, expect, it } from 'vitest';
import { serverRecordsVersions } from './version';

describe('serverRecordsVersions', () => {
  it.each([
    ['0.14.2', false],
    ['0.9.0', false],
    ['0.14.0-rc.1', false],
    ['0.15.0', true],
    ['0.15.0-rc.1', true],
    ['0.16.3', true],
    ['1.0.0', true],
    // Not a version number, or not said: the upload decides, as before.
    ['dev', true],
    [null, true],
  ] as const)('a server of %s: %s', (version, records) => {
    expect(serverRecordsVersions(version)).toBe(records);
  });
});

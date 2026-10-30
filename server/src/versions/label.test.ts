import { describe, expect, it } from 'vitest';
import { parseVersionLabel } from './label';

describe('parseVersionLabel', () => {
  it.each([
    ['v2.3.4', [2, 3, 4, 0], '2.3', false],
    ['V2.3.4', [2, 3, 4, 0], '2.3', false],
    ['2.3', [2, 3, 0, 0], '2.3', false],
    ['1.2.3.4', [1, 2, 3, 4], '1.2', false],
    ['2.3.4+build.5', [2, 3, 4, 0], '2.3', false],
    ['2.4.0-rc.1', [2, 4, 0, 0], '2.4', true],
    ['2.4.0-SNAPSHOT', [2, 4, 0, 0], '2.4', true],
  ])('parses %s', (label, numbers, line, prerelease) => {
    expect(parseVersionLabel(label)).toEqual({ numbers, line, prerelease });
  });

  it.each(['release-2024-10', 'latest', '2', '', '1.2.3.4.5', '1234567890.1'])(
    'rejects %s',
    (label) => {
      expect(parseVersionLabel(label)).toBeNull();
    },
  );
});

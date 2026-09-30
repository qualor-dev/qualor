import { describe, expect, it } from 'vitest';
import {
  RUFF_DEFAULT_IGNORE,
  RUFF_DEFAULT_SELECT,
  RUFF_SELECTOR,
  RUFF_VERSION,
  ruffSelection,
  ruffVersionSupported,
} from './ruff';

describe('ruffSelection (config.md §6)', () => {
  it('expands qualor-default into its selectors and its ignores', () => {
    expect(ruffSelection(['qualor-default'], [])).toEqual({
      select: [...RUFF_DEFAULT_SELECT],
      ignore: [...RUFF_DEFAULT_IGNORE],
    });
  });

  it('adds explicit selectors, and never ignores a code the project selects itself', () => {
    const { select, ignore } = ruffSelection(['qualor-default', 'UP', 'S311'], ['E731']);
    expect(select).toEqual([...RUFF_DEFAULT_SELECT, 'UP', 'S311']);
    expect(ignore).not.toContain('S311');
    expect(ignore).toContain('S101');
    expect(ignore.at(-1)).toBe('E731');
  });

  it('adds no default ignores without qualor-default, and removes duplicates', () => {
    expect(ruffSelection(['F', 'F', 'B'], ['B008', 'B008'])).toEqual({
      select: ['F', 'B'],
      ignore: ['B008'],
    });
  });

  it('accepts Ruff selectors and refuses anything else', () => {
    for (const s of ['F', 'E4', 'PLE', 'S608', 'ASYNC100', 'FURB105', 'ALL']) {
      expect(RUFF_SELECTOR.test(s), s).toBe(true);
    }
    for (const s of ['f', 'S-608', 'E4,E7', 'TOOLONG1', 'S12345', '', 'qualor-default']) {
      expect(RUFF_SELECTOR.test(s), s).toBe(false);
    }
  });
});

describe('ruffVersionSupported', () => {
  const [major, minor] = RUFF_VERSION.split('.').map(Number) as [number, number];
  it('accepts every patch of the pinned minor and nothing else', () => {
    expect(ruffVersionSupported(RUFF_VERSION)).toBe(true);
    expect(ruffVersionSupported(`${major}.${minor}.0`)).toBe(true);
    expect(ruffVersionSupported(`${major}.${minor}.99`)).toBe(true);
    expect(ruffVersionSupported(`${major}.${minor + 1}.0`)).toBe(false);
    expect(ruffVersionSupported(`${major}.${minor - 1}.9`)).toBe(false);
    expect(ruffVersionSupported(`${major + 1}.${minor}.0`)).toBe(false);
    expect(ruffVersionSupported('garbage')).toBe(false);
  });
});

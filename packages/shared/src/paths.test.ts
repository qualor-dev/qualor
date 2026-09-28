import { describe, expect, it } from 'vitest';
import { normalizeRepoPath, PathError, validateRepoPath } from './paths';

describe('validateRepoPath', () => {
  it.each([
    ['src/a.ts', null],
    ['a', null],
    ['dir.with.dots/.hidden/file', null],
    ['', 'empty'],
    ['a\u0000b', 'nul'],
    ['/etc/passwd', 'absolute'],
    ['C:/x/y.ts', 'absolute'],
    ['src\\a.ts', 'backslash'],
    ['./src/a.ts', 'dot-slash'],
    ['src/../a.ts', 'dot-segment'],
    ['..', 'dot-segment'],
    ['src/./a.ts', 'dot-segment'],
    ['src//a.ts', 'double-slash'],
    ['src/a.ts/', 'double-slash'],
    ['x'.repeat(1025), 'too-long'],
    ['cafe\u0301.ts', 'not-nfc'],
  ])('%j → %s', (input, expected) => {
    expect(validateRepoPath(input)).toBe(expected);
  });

  it('counts UTF-8 bytes, not characters, for the length limit', () => {
    expect(validateRepoPath('é'.repeat(512))).toBe(null);
    expect(validateRepoPath('é'.repeat(513))).toBe('too-long');
  });
});

describe('normalizeRepoPath', () => {
  it.each([
    ['src\\a.ts', 'src/a.ts'],
    ['./src/a.ts', 'src/a.ts'],
    ['././src//b/./c.ts', 'src/b/c.ts'],
    ['src/x/../a.ts', 'src/a.ts'],
    ['cafe\u0301.ts', 'caf\u00e9.ts'],
  ])('%j → %j', (input, expected) => {
    expect(normalizeRepoPath(input)).toBe(expected);
  });

  it('relativises absolute paths under the repo root (POSIX and Windows)', () => {
    expect(normalizeRepoPath('/work/repo/src/a.ts', '/work/repo')).toBe('src/a.ts');
    expect(normalizeRepoPath('C:\\work\\repo\\src\\a.ts', 'c:\\work\\repo\\')).toBe('src/a.ts');
  });

  it('rejects paths escaping the root', () => {
    expect(() => normalizeRepoPath('../secret')).toThrow(PathError);
    expect(() => normalizeRepoPath('/other/a.ts', '/work/repo')).toThrow(/outside-root/);
    expect(() => normalizeRepoPath('/work/repo2/a.ts', '/work/repo')).toThrow(PathError);
  });

  it('rejects absolute paths when no root is given', () => {
    expect(() => normalizeRepoPath('/work/repo/a.ts')).toThrow(PathError);
  });
});

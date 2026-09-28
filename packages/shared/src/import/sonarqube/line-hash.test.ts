import { describe, expect, it } from 'vitest';
import { SONAR_LINE_HASH, snippetLineHash, sonarLineHash } from './line-hash';

const HELLO = '5d41402abc4b2a76b9719d911017c592'; // MD5("hello"), the classic test vector

describe('sonarLineHash (import-sonarqube.md §10.4, ruling S1)', () => {
  it('is the MD5 of the line without spaces and tabs', () => {
    expect(sonarLineHash('  hel lo\t')).toBe(HELLO);
    expect(sonarLineHash('\the\t\tl l o ')).toBe(HELLO);
  });

  it('keeps every other character, form feeds, other controls and Unicode spaces included', () => {
    for (const kept of ['\f', '\u000b', '\r', '\u001c', ' ', ' ', '　']) {
      expect(sonarLineHash(`he${kept}llo`)).not.toBe(HELLO);
    }
    expect(sonarLineHash('he\fllo')).toBe(sonarLineHash('he \f llo'));
  });

  it('hashes the UTF-8 bytes', () => {
    // MD5 of c3 a9 (UTF-8 "é"), not of e9 (Latin-1).
    expect(sonarLineHash(' é\t')).toBe('66ddcd97cfdeabb2f6fb8a999b4bc76f');
  });

  it('is "" (unknown) for a line that is blank after stripping', () => {
    expect(sonarLineHash(' \t ')).toBe('');
    expect(sonarLineHash('')).toBe('');
  });

  it('matches the documented hash format', () => {
    expect(SONAR_LINE_HASH.test(sonarLineHash('x'))).toBe(true);
    expect(SONAR_LINE_HASH.test('ABC')).toBe(false);
    expect(SONAR_LINE_HASH.test('')).toBe(false);
  });

  it('hashes a stored snippet line, and refuses cut, redacted, blank or absent ones', () => {
    const snippet = { startLine: 10, lines: ['a b', 'x…', 'k = «redacted»', ' \t'] };
    expect(snippetLineHash(snippet, 10)).toBe(sonarLineHash('ab'));
    expect(snippetLineHash(snippet, 11)).toBeNull();
    expect(snippetLineHash(snippet, 12)).toBeNull();
    expect(snippetLineHash(snippet, 13)).toBeNull();
    expect(snippetLineHash(snippet, 14)).toBeNull();
    expect(snippetLineHash(snippet, null)).toBeNull();
    expect(snippetLineHash(null, 10)).toBeNull();
    expect(snippetLineHash({ startLine: '1', lines: [] }, 1)).toBeNull();
  });
});

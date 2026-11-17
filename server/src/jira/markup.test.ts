import { describe, expect, it } from 'vitest';
import { advisoryUrl, cutText, escapeIdentifier, noformat, wikiLink } from './markup';

describe('identifiers', () => {
  it('backslash-escapes markup characters', () => {
    expect(escapeIdentifier('feat/x-1 (a)*_')).toBe('feat/x\\-1 \\(a\\)\\*\\_');
    for (const c of '\\*_?-+^~{}[]|!#()') expect(escapeIdentifier(c)).toBe(`\\${c}`);
  });
  it('breaks :// and line breaks', () => {
    expect(escapeIdentifier('see http://x')).toBe('see http:/​/x');
    expect(escapeIdentifier('a\nb\r\nc')).toBe('a b c');
  });
  it('never ends in a dangling escape after a cut', () => {
    const out = escapeIdentifier('ab*cd', 4);
    expect(out.length).toBeLessThanOrEqual(4);
    expect(out).toBe('ab…');
  });
  it('noformat breaks an inner noformat, any case', () => {
    expect(noformat('{NOFORMAT}')).toContain('{​NOFORMAT}');
    expect(noformat('x {noformat} y').match(/\{noformat\}/g)).toHaveLength(2);
  });
});

describe('cuts', () => {
  it('keeps within max and splits no surrogate pair', () => {
    const out = cutText(`${'a'.repeat(253)}😀😀`, 255);
    expect(out.length).toBeLessThanOrEqual(255);
    expect(out.endsWith('…')).toBe(true);
    expect(out).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/);
    expect(cutText('short', 10)).toBe('short');
  });
});

describe('advisory urls', () => {
  it('accepts http(s) only and encodes link syntax', () => {
    expect(advisoryUrl('javascript:alert(1)')).toBeNull();
    expect(advisoryUrl(null)).toBeNull();
    expect(advisoryUrl('https://x.example/a|b]c d')).toBe('https://x.example/a%7Cb%5Dc%20d');
  });
  it('wikiLink escapes the text', () => {
    expect(wikiLink('a|b]', 'https://x.example')).toBe('[a\\|b\\]|https://x.example]');
  });
});

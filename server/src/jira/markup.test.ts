import { describe, expect, it } from 'vitest';
import { advisoryUrl, cutText, escapeIdentifier, noformat, wikiLink } from './markup';

describe('identifiers', () => {
  it('backslash-escapes markup characters', () => {
    expect(escapeIdentifier('feat/x-1 (a)*_')).toBe('feat/x\\-1 \\(a\\)\\*\\_');
    for (const c of '\\*_?-+^~{}[]|!#()') expect(escapeIdentifier(c)).toBe(`\\${c}`);
  });
  it('breaks :// and line breaks', () => {
    expect(escapeIdentifier('see http://x')).toBe('see http:/\u200B/x');
    expect(escapeIdentifier('a\nb\r\nc')).toBe('a b c');
  });
  it('never ends in a dangling escape after a cut', () => {
    const out = escapeIdentifier('ab*cd', 4);
    expect(out.length).toBeLessThanOrEqual(4);
    expect(out).toBe('ab…');
  });
  it('noformat breaks an inner noformat, any case', () => {
    expect(noformat('{NOFORMAT}')).toContain('{\u200BNOFORMAT}');
    expect(noformat('x {noformat} y').match(/\{noformat\}/g)).toHaveLength(2);
  });
});

describe('hardening', () => {
  it('breaks mailto:, file: and news: and emoticons', () => {
    expect(escapeIdentifier('mailto:a@evil.example')).toBe('mailto:\u200Ba@evil.example');
    expect(escapeIdentifier('FILE:///etc/passwd')).toBe('FILE:\u200B/\u200B//etc/passwd');
    expect(escapeIdentifier('news:x')).toBe('news:\u200Bx');
    expect(escapeIdentifier('a :D :P ;P')).toBe('a :\u200BD :\u200BP ;\u200BP');
  });
  it('treats \\v, \\f and U+0085 as line breaks', () => {
    expect(escapeIdentifier('a\u0085h1. x\v* y\fz')).toBe('a h1. x \\* y z');
  });
  it('breaks every noformat opening in free text', () => {
    const out = noformat('{noformat:x} {NoFormat} {noformat}');
    expect(out.match(/\{noformat/gi)).toHaveLength(2);
    expect(out).toContain('{\u200Bnoformat:x}');
    expect(out).toContain('{\u200BNoFormat}');
  });
  it('percent-encodes everything outside the allowlist in advisory urls', () => {
    expect(advisoryUrl('https://x.example/{color:red}x{color}')).toBe(
      'https://x.example/%7Bcolor:red%7Dx%7Bcolor%7D',
    );
    expect(advisoryUrl('https://x.example/{noformat}')).toBe('https://x.example/%7Bnoformat%7D');
    expect(advisoryUrl('https://x.example/{html}<img/src=x/onerror=alert(1)>{html}')).toBe(
      'https://x.example/%7Bhtml%7D%3Cimg/src=x/onerror=alert%281%29%3E%7Bhtml%7D',
    );
    expect(advisoryUrl('https://x.example/!a.png!')).toBe('https://x.example/%21a.png%21');
    expect(advisoryUrl('https://x.example/a\\')).toBe('https://x.example/a%5C');
    expect(advisoryUrl('https://x.example/é\n')).toBe('https://x.example/%C3%A9');
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

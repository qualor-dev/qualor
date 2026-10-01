import { describe, expect, it } from 'vitest';
import { compareGoVersions, goModTokens, parseGoMod } from './go-mod';

describe('parseGoMod (config.md §6, plan 9C)', () => {
  it('reads the module, go, toolchain and every replace, in line and block form', () => {
    expect(
      parseGoMod(
        [
          '// A comment',
          'module example.com/m // trailing',
          '',
          'go 1.24',
          'toolchain go1.25.1',
          'require (',
          '\tgithub.com/pkg/errors v0.9.1',
          ')',
          'replace example.com/x => ../x',
          'replace (',
          '\texample.com/y v1.0.0 => example.com/z v1.2.0',
          '\t"example.com/q" => "./local dir"',
          '\texample.com/r => `/abs/r`',
          ')',
          'godebug default=go1.21',
          'tool example.com/t',
          '',
        ].join('\n'),
      ),
    ).toEqual({
      module: 'example.com/m',
      go: '1.24',
      toolchain: 'go1.25.1',
      replaces: [
        { old: 'example.com/x', oldVersion: null, target: '../x', targetVersion: null },
        {
          old: 'example.com/y',
          oldVersion: 'v1.0.0',
          target: 'example.com/z',
          targetVersion: 'v1.2.0',
        },
        { old: 'example.com/q', oldVersion: null, target: './local dir', targetVersion: null },
        { old: 'example.com/r', oldVersion: null, target: '/abs/r', targetVersion: null },
      ],
    });
  });

  it('refuses what go itself would refuse', () => {
    expect(parseGoMod('module a b\n')).toEqual({ error: 'line 1: module needs one path' });
    expect(parseGoMod('go one\n')).toEqual({ error: 'line 1: go needs a version such as 1.24' });
    expect(parseGoMod('replace a\n')).toEqual({
      error: 'line 1: replace needs old [version] => new [version]',
    });
    expect(parseGoMod('replace (\n\ta => b\n')).toEqual({ error: 'a ( block is not closed' });
    expect(parseGoMod('module "unterminated\n')).toEqual({ error: 'line 1 cannot be read' });
    expect(parseGoMod('')).toEqual({ module: null, go: null, toolchain: null, replaces: [] });
  });

  it('tokenises quoted and raw strings and stops at //', () => {
    expect(goModTokens('replace "a b" => `c d` // x')).toEqual(['replace', 'a b', '=>', 'c d']);
    expect(goModTokens('module "a\\"b"')).toEqual(['module', 'a"b']);
    expect(goModTokens('replace `open')).toBeNull();
  });

  // Go's go.mod lexer skips only space, tab and CR between tokens and refuses any other blank
  // ("unexpected input character"); a line with one cannot be read, and the reader never loops.
  it.each([
    ['form feed', '\f'],
    ['vertical tab', '\v'],
    ['no-break space', ' '],
    ['line separator', ' '],
    ['paragraph separator', ' '],
    ['ideographic space', '　'],
    ['byte order mark', '﻿'],
  ])('refuses a line with a %s between tokens', (_name, blank) => {
    expect(goModTokens(`module a${blank}b`)).toBeNull();
    expect(goModTokens(`${blank}module a`)).toBeNull();
    expect(parseGoMod(`module a\ngo${blank}1.24\n`)).toEqual({ error: 'line 2 cannot be read' });
  });

  it('ends on any input', () => {
    // A seeded generator (mulberry32) over go.mod's punctuation, blanks and letters.
    let seed = 0x9c0ffee;
    const random = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const alphabet = [
      ...'ab1.()=>/"`\\ \t\r\n\f\v',
      ' ',
      ' ',
      ' ',
      ' ',
      ' ',
      ' ',
      ' ',
      '　',
      '﻿',
      '\u0085',
      '\0',
      'é',
      '😀',
      'module ',
      'replace ',
      'go ',
      '=> ',
      '//',
    ];
    for (let n = 0; n < 2000; n++) {
      const length = Math.floor(random() * 40);
      let text = '';
      for (let k = 0; k < length; k++) text += alphabet[Math.floor(random() * alphabet.length)];
      const result = parseGoMod(text);
      expect(result, JSON.stringify(text)).toBeTypeOf('object');
      for (const line of text.split('\n')) {
        const tokens = goModTokens(line);
        // Each token takes at least one character of the line, so a line never yields more.
        if (tokens !== null)
          expect(tokens.length, JSON.stringify(line)).toBeLessThanOrEqual(line.length);
      }
    }
  });

  it('orders Go versions as the go command does', () => {
    expect(compareGoVersions('1.24', '1.27.1')).toBeLessThan(0);
    expect(compareGoVersions('1.27', '1.27.1')).toBeLessThan(0);
    expect(compareGoVersions('1.27.1', '1.27.1')).toBe(0);
    expect(compareGoVersions('1.27.2', '1.27.1')).toBeGreaterThan(0);
    expect(compareGoVersions('1.28rc1', '1.27.1')).toBeGreaterThan(0);
    expect(compareGoVersions('1.27rc2', '1.27.0')).toBeLessThan(0);
    expect(compareGoVersions('1.27', '1.27rc1')).toBeLessThan(0);
  });
});

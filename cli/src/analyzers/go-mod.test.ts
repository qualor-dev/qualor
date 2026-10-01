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

import { describe, expect, it } from 'vitest';
import { canonicalJson, type AuditJson } from './canonical';

/** A backslash, built at run time so no escape sequence appears in this file's source. */
const BS = String.fromCharCode(92);
const ch = (code: number): string => String.fromCharCode(code);

describe('canonical JSON (rbac-audit.md §10.1)', () => {
  it('sorts keys at every level and writes no whitespace', () => {
    expect(canonicalJson({ b: 1, a: { d: [true, null], c: 'x' } })).toBe(
      '{"a":{"c":"x","d":[true,null]},"b":1}',
    );
  });

  it('sorts by UTF-16 code units, as a JSON reader in any language can reproduce', () => {
    expect(canonicalJson({ é: 1, z: 2, Z: 3 })).toBe('{"Z":3,"z":2,"é":1}');
  });

  it('sorts an astral key by its surrogates (UTF-16), not by its code point', () => {
    const astral = String.fromCodePoint(0x1f600); // surrogates D83D DE00
    const highBmp = ch(0xff61);
    // By code point U+FF61 < U+1F600; by UTF-16 code units 0xD83D < 0xFF61.
    expect(canonicalJson({ [highBmp]: 1, [astral]: 2 })).toBe(`{"${astral}":2,"${highBmp}":1}`);
  });

  it('sorts integer-like keys as strings, not in the engine’s numeric key order', () => {
    expect(canonicalJson({ 10: 'a', 9: 'b', a: 'c' })).toBe('{"10":"a","9":"b","a":"c"}');
  });

  it('escapes strings as JSON.stringify does', () => {
    expect(canonicalJson('a"b\n ')).toBe(JSON.stringify('a"b\n '));
  });

  it('escapes quote, backslash and control characters, and writes other characters as they are', () => {
    const input = `q"${BS}${ch(8)}${ch(9)}${ch(10)}${ch(12)}${ch(13)}${ch(1)}${ch(0x1f)}${ch(0x7f)}é€${String.fromCodePoint(0x1f600)}/${ch(0x2028)}`;
    const expected =
      `"q${BS}"${BS}${BS}${BS}b${BS}t${BS}n${BS}f${BS}r${BS}u0001${BS}u001f` +
      `${ch(0x7f)}é€${String.fromCodePoint(0x1f600)}/${ch(0x2028)}"`;
    expect(canonicalJson(input)).toBe(expected);
    expect(canonicalJson(input)).toBe(JSON.stringify(input));
  });

  it('escapes keys the same way as values', () => {
    expect(canonicalJson({ [`a${ch(10)}"`]: 1 })).toBe(`{"a${BS}n${BS}"":1}`);
  });

  it('refuses U+0000 and lone surrogates, which PostgreSQL text and jsonb cannot store', () => {
    expect(() => canonicalJson(`a${ch(0)}b`)).toThrow(TypeError);
    expect(() => canonicalJson(`a${ch(0xd83d)}`)).toThrow(TypeError);
    expect(() => canonicalJson(`${ch(0xde00)}a`)).toThrow(TypeError);
    expect(() => canonicalJson({ [`k${ch(0)}`]: 1 })).toThrow(TypeError);
    expect(() => canonicalJson({ [ch(0xd800)]: 1 })).toThrow(TypeError);
  });

  it('refuses floats and unsafe integers, which jsonb would not round-trip', () => {
    expect(() => canonicalJson(1.5)).toThrow(TypeError);
    expect(() => canonicalJson(2 ** 60)).toThrow(TypeError);
    expect(() => canonicalJson(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow(TypeError);
  });

  it('writes integers as JSON.stringify does, negative zero as 0', () => {
    expect(canonicalJson([0, -0, -42, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER])).toBe(
      '[0,0,-42,9007199254740991,-9007199254740991]',
    );
  });

  it('writes empty containers and nested arrays without whitespace', () => {
    expect(canonicalJson({ a: [], b: {}, c: [[], [{}]] })).toBe('{"a":[],"b":{},"c":[[],[{}]]}');
  });

  it('refuses values that are not JSON (undefined, class instances, functions, bigint)', () => {
    expect(() => canonicalJson(undefined as never)).toThrow(TypeError);
    expect(() => canonicalJson([undefined] as never)).toThrow(TypeError);
    expect(() => canonicalJson(new Date(0) as never)).toThrow(TypeError);
    expect(() => canonicalJson((() => 1) as never)).toThrow(TypeError);
    expect(() => canonicalJson(1n as never)).toThrow(TypeError);
  });

  it('leaves out an object key whose value is undefined, as JSON.stringify does', () => {
    expect(canonicalJson({ a: 1, b: undefined } as never)).toBe('{"a":1}');
  });

  it('round-trips through JSON.parse unchanged', () => {
    const value = { z: [1, { y: 'é', x: null }], a: false };
    expect(canonicalJson(JSON.parse(canonicalJson(value)) as AuditJson)).toBe(canonicalJson(value));
  });

  it('golden vector: a nested value with non-ASCII and control characters', () => {
    const value = {
      zeta: [3, -1, { 'b ': true, a: null }],
      É: `line1${ch(10)}tab${ch(9)}é`,
      A: {},
    };
    expect(canonicalJson(value)).toBe(
      `{"A":{},"zeta":[3,-1,{"a":null,"b ":true}],"É":"line1${BS}ntab${BS}té"}`,
    );
  });
});

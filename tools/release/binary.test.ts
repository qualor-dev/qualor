import { describe, expect, it } from 'vitest';
import { binaryFormat, EXPECTED_FORMAT } from './binary';

const bytes = (n: number, set: Record<number, number>): Uint8Array => {
  const b = new Uint8Array(n);
  for (const [i, v] of Object.entries(set)) b[Number(i)] = v;
  return b;
};
const elf = (machine: number) =>
  bytes(64, {
    0: 0x7f,
    1: 0x45,
    2: 0x4c,
    3: 0x46,
    4: 2,
    5: 1,
    18: machine & 0xff,
    19: machine >> 8,
  });
const macho = (cpu: number) =>
  bytes(32, {
    0: 0xcf,
    1: 0xfa,
    2: 0xed,
    3: 0xfe,
    4: cpu & 0xff,
    5: (cpu >> 8) & 0xff,
    6: (cpu >> 16) & 0xff,
    7: cpu >>> 24,
  });
const pe = (machine: number) =>
  bytes(0x100, {
    0: 0x4d,
    1: 0x5a,
    0x3c: 0x80,
    0x80: 0x50,
    0x81: 0x45,
    0x84: machine & 0xff,
    0x85: machine >> 8,
  });

describe('binary headers (release.md §4)', () => {
  it('recognises the five release targets', () => {
    expect(binaryFormat(elf(0x3e))).toEqual(EXPECTED_FORMAT['linux-x64']);
    expect(binaryFormat(elf(0xb7))).toEqual(EXPECTED_FORMAT['linux-arm64']);
    expect(binaryFormat(macho(0x01000007))).toEqual(EXPECTED_FORMAT['darwin-x64']);
    expect(binaryFormat(macho(0x0100000c))).toEqual(EXPECTED_FORMAT['darwin-arm64']);
    expect(binaryFormat(pe(0x8664))).toEqual(EXPECTED_FORMAT['windows-x64']);
  });

  it('refuses anything else', () => {
    expect(binaryFormat(new Uint8Array(0))).toBeNull();
    expect(binaryFormat(elf(0x28))).toBeNull(); // 32-bit ARM
    expect(binaryFormat(macho(0x7))).toBeNull(); // 32-bit x86
    expect(binaryFormat(bytes(0x100, { 0: 0x4d, 1: 0x5a, 0x3c: 0xf0 }))).toBeNull(); // no PE header
    expect(binaryFormat(new TextEncoder().encode('#!/bin/sh\necho qualor\n'))).toBeNull();
  });
});

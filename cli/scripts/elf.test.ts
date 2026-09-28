import { describe, expect, it } from 'vitest';
import { ELF_MACHINE, elfMachine } from './elf';

function header(machine: number): Uint8Array {
  const b = new Uint8Array(64);
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1], 0);
  b[18] = machine & 0xff;
  b[19] = machine >> 8;
  return b;
}

describe('elfMachine', () => {
  it('reads e_machine of 64-bit little-endian ELF files', () => {
    expect(elfMachine(header(ELF_MACHINE['linux-x64']))).toBe(0x3e);
    expect(elfMachine(header(ELF_MACHINE['linux-arm64']))).toBe(0xb7);
  });

  it('returns null for anything else', () => {
    expect(elfMachine(new Uint8Array([0x4d, 0x5a, 0, 0]))).toBeNull();
    expect(elfMachine(new Uint8Array(4))).toBeNull();
  });
});

import { elfMachine } from '../../cli/scripts/elf';
import type { ReleaseTarget } from '../../cli/scripts/targets';

/** release.md §4: what each release binary's header must say. */
export interface BinaryFormat {
  format: 'elf' | 'macho' | 'pe';
  arch: 'x64' | 'arm64';
}

export const EXPECTED_FORMAT: Record<ReleaseTarget, BinaryFormat> = {
  'linux-x64': { format: 'elf', arch: 'x64' },
  'linux-arm64': { format: 'elf', arch: 'arm64' },
  'darwin-x64': { format: 'macho', arch: 'x64' },
  'darwin-arm64': { format: 'macho', arch: 'arm64' },
  'windows-x64': { format: 'pe', arch: 'x64' },
};

const u16 = (b: Uint8Array, o: number): number => (b[o] ?? 0) | ((b[o + 1] ?? 0) << 8);
const u32 = (b: Uint8Array, o: number): number => (u16(b, o) | (u16(b, o + 2) << 16)) >>> 0;

export function binaryFormat(b: Uint8Array): BinaryFormat | null {
  const machine = elfMachine(b);
  if (machine === 0x3e) return { format: 'elf', arch: 'x64' };
  if (machine === 0xb7) return { format: 'elf', arch: 'arm64' };
  if (b.length >= 8 && b[0] === 0xcf && b[1] === 0xfa && b[2] === 0xed && b[3] === 0xfe) {
    const cpu = u32(b, 4);
    if (cpu === 0x01000007) return { format: 'macho', arch: 'x64' };
    if (cpu === 0x0100000c) return { format: 'macho', arch: 'arm64' };
    return null;
  }
  if (b.length >= 0x40 && b[0] === 0x4d && b[1] === 0x5a) {
    const off = u32(b, 0x3c);
    const pe =
      b.length >= off + 6 &&
      b[off] === 0x50 &&
      b[off + 1] === 0x45 &&
      b[off + 2] === 0 &&
      b[off + 3] === 0;
    if (pe && u16(b, off + 4) === 0x8664) return { format: 'pe', arch: 'x64' };
  }
  return null;
}

/** The release target this machine can run, if any. */
export function hostTarget(): ReleaseTarget | null {
  const os = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[process.platform as string];
  const arch = { x64: 'x64', arm64: 'arm64' }[process.arch as string];
  const t = `${os}-${arch}`;
  return t in EXPECTED_FORMAT ? (t as ReleaseTarget) : null;
}

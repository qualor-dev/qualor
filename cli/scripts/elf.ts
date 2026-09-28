/** ELF e_machine values of the targets. */
export const ELF_MACHINE = { 'linux-x64': 0x3e, 'linux-arm64': 0xb7 } as const;

/** e_machine of a 64-bit little-endian ELF header, or null for anything else. */
export function elfMachine(bytes: Uint8Array): number | null {
  if (bytes.length < 20) return null;
  const magic = bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
  if (!magic || bytes[4] !== 2 || bytes[5] !== 1) return null;
  return (bytes[18] ?? 0) | ((bytes[19] ?? 0) << 8);
}

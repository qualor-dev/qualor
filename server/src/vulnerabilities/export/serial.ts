import { createHash } from 'node:crypto';
import type { ExportPackage } from './types';

/** Code-unit order (not locale-dependent). */
function compare(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/**
 * D8-1: the serial number of a target's CycloneDX SBOM, a uuid that follows from the project, the
 * target and its packages, so every download of one inventory carries it. The CycloneDX VEX links
 * to it, and Trivy applies a VEX only to the SBOM whose serial its links name. The packages are
 * hashed in (purl, ecosystem, name, version, licences) order, each with its licences sorted. The
 * uuid is the first 16 bytes of the sha256, with the version (8) and variant bits of RFC 9562 set
 * as `uuidv7` sets them (`db/ids.ts`).
 */
export function sbomSerial(
  projectId: string,
  targetKey: string,
  packages: readonly ExportPackage[],
): string {
  const rows = packages
    .map(
      (p) => [p.purl ?? '', p.ecosystem, p.name, p.version, [...p.licenses].sort(compare)] as const,
    )
    .sort(
      (a, b) =>
        compare(a[0], b[0]) ||
        compare(a[1], b[1]) ||
        compare(a[2], b[2]) ||
        compare(a[3], b[3]) ||
        compare(a[4].join('\n'), b[4].join('\n')),
    );
  const bytes = createHash('sha256')
    .update(JSON.stringify([projectId, targetKey, rows]))
    .digest()
    .subarray(0, 16);
  bytes.writeUInt8(0x80 | (bytes.readUInt8(6) & 0x0f), 6);
  bytes.writeUInt8(0x80 | (bytes.readUInt8(8) & 0x3f), 8);
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

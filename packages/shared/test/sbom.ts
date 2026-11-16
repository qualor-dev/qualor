/** Helpers shared by the SBOM tests (`src/sbom/*.test.ts`); test-only, never part of the build. */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect } from 'vitest';
import { parseSbom } from '../src/sbom/parse';
import type { SbomEntry, SbomInventory, SbomRefusal } from '../src/sbom/types';

const SAMPLES = join(__dirname, 'sbom-samples');

/** The text of a file in `test/sbom-samples`. */
export const sample = (file: string): string => readFileSync(join(SAMPLES, file), 'utf8');

/** The parsed JSON of a sample. */
export const sampleJson = (file: string): Record<string, unknown> =>
  JSON.parse(sample(file)) as Record<string, unknown>;

/** The inventory of a text that must parse. */
export function inventory(text: string): SbomInventory {
  const result = parseSbom(text);
  if (!('inventory' in result)) throw new Error(`refused: ${JSON.stringify(result.refusal)}`);
  return result.inventory;
}

/** The refusal of a text that must be refused. */
export function refusal(text: string): SbomRefusal {
  const result = parseSbom(text);
  if (!('refusal' in result)) throw new Error('not refused');
  return result.refusal;
}

/** The one entry of an inventory with this name. */
export function entry(inv: SbomInventory, name: string): SbomEntry {
  const found = inv.entries.filter((e) => e.name === name);
  expect(found, name).toHaveLength(1);
  return found[0]!;
}

/** A CycloneDX 1.6 document holding these components (and any other top-level fields). */
export function bom(components: unknown[], extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components, ...extra });
}

/** A CycloneDX library component with this purl. */
export const lib = (purl: string, more: Record<string, unknown> = {}) => ({
  type: 'library',
  name: 'ignored',
  purl,
  ...more,
});

/** A CycloneDX operating-system component. */
export const os = (name: string, version: string) => ({
  type: 'operating-system',
  name,
  version,
});

/** An SPDX package with a PACKAGE-MANAGER purl reference. */
export const spdxPkg = (id: string, purl: string | null, more: Record<string, unknown> = {}) => ({
  SPDXID: `SPDXRef-${id}`,
  name: id,
  versionInfo: '1',
  ...(purl === null
    ? {}
    : {
        externalRefs: [
          { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: purl },
        ],
      }),
  ...more,
});

/** A relationship between two `SPDXRef-<id>` elements (`DOCUMENT` is the document itself). */
export const spdxRel = (from: string, type: string, to: string) => ({
  spdxElementId: from === 'DOCUMENT' ? 'SPDXRef-DOCUMENT' : `SPDXRef-${from}`,
  relationshipType: type,
  relatedSpdxElement: to === 'DOCUMENT' ? 'SPDXRef-DOCUMENT' : `SPDXRef-${to}`,
});

/** An SPDX 2.3 document with these packages and relationships (and any other top-level fields). */
export function spdx(
  packages: unknown[],
  relationships: unknown[] = [],
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    spdxVersion: 'SPDX-2.3',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'test',
    packages,
    relationships,
    ...extra,
  };
}

/* eslint-disable @typescript-eslint/no-explicit-any -- walks the built JSON documents */
import { describe, expect, it } from 'vitest';
import { validateAgainst } from '../../../test/export-schemas';
import { buildCycloneDxSbom, buildSpdxSbom } from './sbom-documents';
import { productId, type ExportDocument, type ExportPackage } from './types';

const SERIAL = '3e671687-395b-41f5-a30f-a58921a69b79';

function doc(overrides: Partial<ExportDocument> = {}): ExportDocument {
  return {
    project: { key: 'acme-web', name: 'Acme Web' },
    organization: 'Acme',
    target: { kind: 'branch', name: 'release/2.x' },
    generatedAt: new Date('2026-11-10T08:30:15.123Z'),
    serial: SERIAL,
    toolVersion: '0.15.0',
    ...overrides,
  };
}

const PACKAGES: ExportPackage[] = [
  {
    ecosystem: 'npm',
    name: 'left-pad',
    version: '1.3.0',
    purl: 'pkg:npm/left-pad@1.3.0',
    licenses: ['MIT'],
  },
  { ecosystem: 'pip', name: 'requests', version: '2.31.0', purl: null, licenses: ['Apache-2.0'] },
  {
    ecosystem: 'npm',
    name: '@angular/core',
    version: '19.0.0',
    purl: 'pkg:npm/%40angular/core@19.0.0',
    licenses: ['MIT OR Apache-2.0', 'BSD-3-Clause'],
  },
  {
    ecosystem: 'maven',
    name: 'org.apache.logging.log4j:log4j-core',
    version: '2.17.1',
    purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1',
    licenses: ['MIT', 'Some Custom Licence'],
  },
  { ecosystem: 'go', name: 'example.com/lib', version: 'v1.0.0', purl: null, licenses: [] },
];

describe('productId', () => {
  it('percent-encodes the key and the target', () => {
    expect(productId({ key: 'acme-web' }, { name: 'release/2.x' })).toBe(
      'pkg:generic/acme-web@release%2F2.x',
    );
    expect(productId({ key: 'a b' }, { name: '2.3.4+build.1' })).toBe(
      'pkg:generic/a%20b@2.3.4%2Bbuild.1',
    );
  });
});

describe('buildCycloneDxSbom', () => {
  it('validates against the CycloneDX 1.6 schema', () => {
    expect(validateAgainst('cyclonedx', buildCycloneDxSbom(doc(), PACKAGES))).toEqual([]);
    const version = doc({ target: { kind: 'version', name: '2.3.4+build.1' } });
    expect(validateAgainst('cyclonedx', buildCycloneDxSbom(version, PACKAGES))).toEqual([]);
    expect(validateAgainst('cyclonedx', buildCycloneDxSbom(doc(), []))).toEqual([]);
  });

  it('rejects an invalid document (the validator checks)', () => {
    expect(validateAgainst('cyclonedx', { bomFormat: 'CycloneDX' }).length).toBeGreaterThan(0);
  });

  it('describes the document, the tool and the product', () => {
    const bom = buildCycloneDxSbom(doc(), PACKAGES) as Record<string, any>;
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.serialNumber).toBe(`urn:uuid:${SERIAL}`);
    expect(bom.metadata.timestamp).toBe('2026-11-10T08:30:15.123Z');
    expect(bom.metadata.tools.components[0]).toMatchObject({ name: 'Qualor', version: '0.15.0' });
    expect(bom.metadata.component).toEqual({
      type: 'application',
      name: 'Acme Web',
      version: 'release/2.x',
      'bom-ref': 'pkg:generic/acme-web@release%2F2.x',
    });
  });

  it('keeps the order, uses the purl or ecosystem:name@version as bom-ref, and omits empty licences', () => {
    const bom = buildCycloneDxSbom(doc(), PACKAGES) as Record<string, any>;
    const refs = bom.components.map((c: any) => c['bom-ref']);
    expect(refs).toEqual([
      'pkg:npm/left-pad@1.3.0',
      'pip:requests@2.31.0',
      'pkg:npm/%40angular/core@19.0.0',
      'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1',
      'go:example.com/lib@v1.0.0',
    ]);
    const [, pip, , maven, go] = bom.components;
    expect(pip).not.toHaveProperty('purl');
    expect(maven.name).toBe('org.apache.logging.log4j:log4j-core');
    expect(maven).not.toHaveProperty('group');
    expect(maven.licenses).toEqual([
      { license: { name: 'MIT' } },
      { license: { name: 'Some Custom Licence' } },
    ]);
    expect(go).not.toHaveProperty('licenses');
  });
});

describe('buildSpdxSbom', () => {
  it('validates against the SPDX 2.3 schema', () => {
    expect(validateAgainst('spdx', buildSpdxSbom(doc(), PACKAGES))).toEqual([]);
    const version = doc({ target: { kind: 'version', name: '2.3.4+build.1' } });
    expect(validateAgainst('spdx', buildSpdxSbom(version, PACKAGES))).toEqual([]);
    expect(validateAgainst('spdx', buildSpdxSbom(doc(), []))).toEqual([]);
  });

  it('rejects an invalid document (the validator checks)', () => {
    expect(validateAgainst('spdx', { spdxVersion: 'SPDX-2.3' }).length).toBeGreaterThan(0);
  });

  it('describes the document', () => {
    const s = buildSpdxSbom(doc(), PACKAGES) as Record<string, any>;
    expect(s.spdxVersion).toBe('SPDX-2.3');
    expect(s.dataLicense).toBe('CC0-1.0');
    expect(s.SPDXID).toBe('SPDXRef-DOCUMENT');
    expect(s.creationInfo.created).toBe('2026-11-10T08:30:15Z');
    expect(s.creationInfo.creators).toEqual(['Tool: Qualor-0.15.0']);
    expect(s.documentNamespace).toBe(`https://qualor.dev/spdx/acme-web/release%2F2.x/${SERIAL}`);
    const other = buildSpdxSbom(doc({ serial: 'b0a8a1de-6c0b-4d8f-9b58-0d1d3f3b4a11' }), PACKAGES);
    expect((other as any).documentNamespace).not.toBe(s.documentNamespace);
  });

  it('gives the root and every package the fixed fields', () => {
    const s = buildSpdxSbom(doc(), PACKAGES) as Record<string, any>;
    const [root, ...rest] = s.packages;
    expect(root).toMatchObject({
      SPDXID: 'SPDXRef-Package-root',
      name: 'acme-web',
      versionInfo: 'release/2.x',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: 'pkg:generic/acme-web@release%2F2.x',
        },
      ],
    });
    expect(rest.map((p: any) => p.SPDXID)).toEqual(
      [1, 2, 3, 4, 5].map((n) => `SPDXRef-Package-${n}`),
    );
    for (const p of s.packages) {
      expect(p).toMatchObject({
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        copyrightText: 'NOASSERTION',
      });
      expect(p.SPDXID).toMatch(/^SPDXRef-[a-zA-Z0-9.-]+$/);
    }
    expect(rest[0].externalRefs).toEqual([
      {
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: 'pkg:npm/left-pad@1.3.0',
      },
    ]);
    expect(rest[1]).not.toHaveProperty('externalRefs');
    expect(rest[2].licenseDeclared).toBe('(MIT OR Apache-2.0) AND BSD-3-Clause');
    expect(rest[4].licenseDeclared).toBe('NOASSERTION');
  });

  it('declares the extracted licence text, sorted by id', () => {
    const s = buildSpdxSbom(doc(), PACKAGES) as Record<string, any>;
    expect(s.hasExtractedLicensingInfos).toHaveLength(1);
    const [info] = s.hasExtractedLicensingInfos;
    expect(info.licenseId).toMatch(/^LicenseRef-[0-9a-f]{12}$/);
    expect(info.extractedText).toBe('Some Custom Licence');
    expect(info.name).toBeTruthy();
    expect(s.packages[4].licenseDeclared).toBe(`MIT AND ${info.licenseId}`);
    const plain = buildSpdxSbom(doc(), [PACKAGES[0] as ExportPackage]) as Record<string, any>;
    expect(plain).not.toHaveProperty('hasExtractedLicensingInfos');
  });

  it('relates the document to the root and the root to each package', () => {
    const s = buildSpdxSbom(doc(), PACKAGES) as Record<string, any>;
    expect(s.relationships).toEqual([
      {
        spdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DESCRIBES',
        relatedSpdxElement: 'SPDXRef-Package-root',
      },
      ...[1, 2, 3, 4, 5].map((n) => ({
        spdxElementId: 'SPDXRef-Package-root',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: `SPDXRef-Package-${n}`,
      })),
    ]);
  });
});

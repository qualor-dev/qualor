import { cycloneDxLicenses, spdxLicense } from './licenses';
import { productId, type ExportDocument, type ExportPackage } from './types';

/** A CycloneDX 1.6 SBOM of a target. Packages keep the order they are given. */
export function buildCycloneDxSbom(
  doc: ExportDocument,
  packages: readonly ExportPackage[],
): object {
  const root = productId(doc.project, doc.target);
  const components = packages.map((p) => {
    const licenses = cycloneDxLicenses(p.licenses);
    return {
      type: 'library',
      'bom-ref': p.purl ?? `${p.ecosystem}:${p.name}@${p.version}`,
      name: p.name,
      version: p.version,
      ...(p.purl === null ? {} : { purl: p.purl }),
      ...(licenses === undefined ? {} : { licenses }),
    };
  });
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${doc.serial}`,
    version: 1,
    metadata: {
      timestamp: doc.generatedAt.toISOString(),
      tools: { components: [{ type: 'application', name: 'Qualor', version: doc.toolVersion }] },
      component: {
        type: 'application',
        name: doc.project.name,
        version: doc.target.name,
        'bom-ref': root,
      },
    },
    components,
    dependencies: [{ ref: root, dependsOn: components.map((c) => c['bom-ref']) }],
  };
}

function purlRef(locator: string): object {
  return { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: locator };
}

/** An SPDX 2.3 SBOM of a target. Packages keep the order they are given. */
export function buildSpdxSbom(doc: ExportDocument, packages: readonly ExportPackage[]): object {
  const extracted = new Map<string, string>();
  const rootId = 'SPDXRef-Package-root';
  const spdxPackages = [
    {
      SPDXID: rootId,
      name: doc.project.key,
      versionInfo: doc.target.name,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs: [purlRef(productId(doc.project, doc.target))],
    },
    ...packages.map((p, i) => ({
      SPDXID: `SPDXRef-Package-${i + 1}`,
      name: p.name,
      versionInfo: p.version,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: spdxLicense(p.licenses, extracted),
      copyrightText: 'NOASSERTION',
      ...(p.purl === null ? {} : { externalRefs: [purlRef(p.purl)] }),
    })),
  ];
  const infos = [...extracted.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([licenseId, extractedText]) => ({ licenseId, extractedText, name: extractedText }));
  const key = encodeURIComponent(doc.project.key);
  const target = encodeURIComponent(doc.target.name);
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${doc.project.name} ${doc.target.name}`,
    documentNamespace: `https://qualor.dev/spdx/${key}/${target}/${doc.serial}`,
    creationInfo: {
      created: doc.generatedAt.toISOString().replace(/\.\d{3}Z$/, 'Z'),
      creators: [`Tool: Qualor-${doc.toolVersion}`],
    },
    packages: spdxPackages,
    ...(infos.length === 0 ? {} : { hasExtractedLicensingInfos: infos }),
    relationships: [
      {
        spdxElementId: 'SPDXRef-DOCUMENT',
        relationshipType: 'DESCRIBES',
        relatedSpdxElement: rootId,
      },
      ...packages.map((_, i) => ({
        spdxElementId: rootId,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: `SPDXRef-Package-${i + 1}`,
      })),
    ],
  };
}

import { isOsPackageType, type SbomDistribution } from '@qualor/shared';
import { compare } from '../order';
import { splitOsVersion } from '../sbom';
import { cycloneDxLicenses, spdxLicense } from './licenses';
import { productId, SBOM_BOM_VERSION, type ExportDocument, type ExportPackage } from './types';

const TRIVY = 'aquasecurity:trivy:';

/**
 * Trivy's properties for an OS package's source (R9), so that Trivy reads the file as it reads its
 * own: `SrcEpoch` is always written (`0` for none), `SrcRelease` only when there is one. They say
 * what the `upstream` qualifier of the purl says.
 */
function trivyProperties(
  p: ExportPackage,
  distribution: SbomDistribution | null,
): { name: string; value: string }[] | undefined {
  if (p.source === null || distribution === null || !isOsPackageType(p.ecosystem)) return undefined;
  const source = splitOsVersion(p.ecosystem, p.source.version);
  return [
    { name: `${TRIVY}PkgType`, value: distribution.family },
    { name: `${TRIVY}SrcName`, value: p.source.name },
    { name: `${TRIVY}SrcVersion`, value: source.version },
    ...(source.release === '' ? [] : [{ name: `${TRIVY}SrcRelease`, value: source.release }]),
    { name: `${TRIVY}SrcEpoch`, value: source.epoch === '' ? '0' : source.epoch },
  ];
}

/** A CycloneDX 1.6 SBOM of a target. Packages keep the order they are given. */
export function buildCycloneDxSbom(
  doc: ExportDocument,
  packages: readonly ExportPackage[],
): object {
  const root = productId(doc.project, doc.target);
  const distribution = doc.distribution ?? null;
  const system =
    distribution === null
      ? []
      : [
          {
            type: 'operating-system',
            'bom-ref': 'operating-system',
            name: distribution.family,
            version: distribution.version,
          },
        ];
  const libraries = packages.map((p) => {
    const licenses = cycloneDxLicenses(p.licenses);
    const properties = trivyProperties(p, distribution);
    return {
      type: 'library',
      'bom-ref': p.purl ?? `${p.ecosystem}:${p.name}@${p.version}`,
      name: p.name,
      version: p.version,
      ...(p.purl === null ? {} : { purl: p.purl }),
      ...(licenses === undefined ? {} : { licenses }),
      ...(properties === undefined ? {} : { properties }),
    };
  });
  const components = [...system, ...libraries];
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${doc.serial}`,
    version: SBOM_BOM_VERSION,
    metadata: {
      timestamp: doc.generatedAt.toISOString(),
      tools: { components: [{ type: 'application', name: 'Qualor', version: doc.toolVersion }] },
      component: {
        type: 'application',
        name: doc.project.name,
        version: doc.target.name,
        'bom-ref': root,
        purl: root,
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
  const distribution = doc.distribution ?? null;
  const spdxPackages = [
    {
      SPDXID: rootId,
      name: doc.project.name,
      versionInfo: doc.target.name,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs: [purlRef(productId(doc.project, doc.target))],
    },
    ...(distribution === null
      ? []
      : [
          {
            SPDXID: 'SPDXRef-OperatingSystem-1',
            name: distribution.family,
            versionInfo: distribution.version,
            primaryPackagePurpose: 'OPERATING_SYSTEM',
            downloadLocation: 'NOASSERTION',
            filesAnalyzed: false,
            licenseConcluded: 'NOASSERTION',
            licenseDeclared: 'NOASSERTION',
            copyrightText: 'NOASSERTION',
          },
        ]),
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
      ...(p.source === null
        ? {}
        : { sourceInfo: `built package from: ${p.source.name} ${p.source.version}` }),
    })),
  ];
  const infos = [...extracted.entries()]
    .sort(([a], [b]) => compare(a, b))
    .map(([licenseId, extractedText]) => ({
      licenseId,
      extractedText,
      name: extractedText.length > 80 ? `${extractedText.slice(0, 79)}…` : extractedText,
    }));
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

export interface SbomPackage {
  purl: string;
  name: string;
  version: string;
}

/**
 * CycloneDX 1.6 JSON for Trivy. One component per distinct purl (Trivy reports the vulnerabilities
 * of a duplicate on one BOM reference only); `name` is the decoded purl path, `bom-ref` the purl.
 */
export function buildSbom(packages: readonly SbomPackage[]): string {
  const seen = new Set<string>();
  const components: object[] = [];
  for (const p of packages) {
    if (seen.has(p.purl)) continue;
    seen.add(p.purl);
    components.push({
      type: 'library',
      'bom-ref': p.purl,
      name: p.name,
      version: p.version,
      purl: p.purl,
    });
  }
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    components,
  });
}

import { describe, expect, it } from 'vitest';
import { cliDepsArgs, cliSbomArgs, SBOM_IMAGES, spdxProblems, syftArgs } from './sbom';

describe('SBOMs (release.md §8)', () => {
  it('asks Syft for SPDX JSON into the named file, quietly', () => {
    expect(syftArgs('dir:/work/x', '/work/out.spdx.json')).toEqual([
      'scan',
      'dir:/work/x',
      '-o',
      'spdx-json=/work/out.spdx.json',
      '--quiet',
    ]);
  });

  it('describes the three images that ship software, not the sources images', () => {
    expect(SBOM_IMAGES).toEqual(['server', 'scanner', 'scanner-dotnet']);
  });

  it('installs only the CLI production dependencies for its SBOM, from the store only', () => {
    expect(cliDepsArgs('/tmp/d')).toEqual([
      '--filter',
      '@qualor/cli',
      'deploy',
      '--prod',
      '--legacy',
      '--offline',
      '/tmp/d',
    ]);
  });

  it('reads the CLI install with the package.json cataloger, over its node_modules only', () => {
    expect(cliSbomArgs('/work/d', '/work/cli.spdx.json', '0.1.0')).toEqual([
      'scan',
      'dir:/work/d/node_modules',
      '-o',
      'spdx-json=/work/cli.spdx.json',
      '--quiet',
      '--override-default-catalogers',
      'javascript-package-cataloger',
      // Named after the binary, not the scanned directory.
      '--source-name',
      'qualor-cli',
      '--source-version',
      '0.1.0',
    ]);
  });

  it('checks an SPDX 2.3 document with packages', () => {
    const ok = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      documentNamespace: 'https://x',
      packages: [{ name: 'zod' }],
    });
    expect(spdxProblems(ok)).toEqual([]);
    expect(spdxProblems(JSON.stringify({ spdxVersion: 'SPDX-2.2', packages: [] }))).toEqual([
      'spdxVersion is SPDX-2.2, not SPDX-2.3',
      'no documentNamespace',
      'no packages',
    ]);
    expect(spdxProblems('not json')).toEqual(['not JSON']);
    expect(spdxProblems('null')).toEqual(['not an SPDX document']);
    expect(spdxProblems('[]')).toEqual(['not an SPDX document']);
  });
});

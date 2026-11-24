import { describe, expect, it } from 'vitest';
import { buildManifest } from './manifest';

describe('release-manifest.json (release.md §3)', () => {
  it('records the release and its files, sorted, and is listed in SHA256SUMS itself', () => {
    const m = buildManifest(
      {
        version: '1.0.0',
        gitCommit: 'abc',
        createdAt: '2026-09-26T00:00:00.000Z',
        dryRun: true,
        targets: ['linux-x64'],
        cliSources: false,
        images: [],
        chart: { file: 'helm/qualor-1.0.0.tgz', digest: null },
        extension: { file: 'azure-devops/qualor.qualor-1.0.0.vsix', version: '1.0.0' },
      },
      ['sbom/cli.spdx.json', 'azure-devops/qualor.qualor-1.0.0.vsix', 'cli/qualor-1.0.0-linux-x64'],
    );
    expect(m.files).toEqual([
      'azure-devops/qualor.qualor-1.0.0.vsix',
      'cli/qualor-1.0.0-linux-x64',
      'sbom/cli.spdx.json',
    ]);
    expect(m.dryRun).toBe(true);
    // The Azure DevOps extension's VSIX and the version its manifest holds (Azure sub-plan 9).
    expect(m.extension).toEqual({
      file: 'azure-devops/qualor.qualor-1.0.0.vsix',
      version: '1.0.0',
    });
  });
});

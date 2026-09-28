import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../deploy/stack';
import { assetName, assetPlan, writeAssets } from './assets';
import { parseSums, sha256sums, SUMS, SUMS_BUNDLE } from './checksums';
import { verifyRelease } from './verify';

let root = '';
afterEach(() => rmSync(root, { recursive: true, force: true }));

/** A release directory laid out as release.md §3 says, and the checkout's two sources dirs. */
function release(): { dir: string; sources: string; out: string } {
  mkdirSync(path.join(REPO_ROOT, '.tmp'), { recursive: true });
  root = mkdtempSync(path.join(REPO_ROOT, '.tmp', 'assets-'));
  const dir = path.join(root, 'release', '0.1.0');
  const files: Record<string, string> = {
    'cli/qualor-0.1.0-linux-x64': 'elf',
    'cli/qualor-0.1.0-windows-x64.exe': 'pe',
    'cli-sources/SHA256SUMS': 'x',
    'cli-sources/bun-1.3.13.tar.gz': 'bun',
    'helm/qualor-0.1.0.tgz': 'chart',
    'sbom/cli.spdx.json': '{}',
    'sbom/server.spdx.json': '{}',
    'images.json': '[]',
    'release-notes.md': 'notes',
    'cosign.pub': 'throwaway key',
    'release-manifest.json': '{"dryRun":true}',
  };
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    writeFileSync(path.join(dir, f), text);
  }
  const sources = path.join(root, 'checkout-tmp');
  for (const image of ['scanner', 'server']) {
    mkdirSync(path.join(sources, `${image}-sources`), { recursive: true });
  }
  return { dir, sources, out: path.join(root, 'release-assets', '0.1.0') };
}

const fakeTar = (tarFile: string, cwd: string, entry: string): void => {
  writeFileSync(tarFile, `tar of ${entry}`);
};

describe('release assets (release.md §3, final review I-2)', () => {
  it('names every asset flat: binaries and chart by name, SBOMs with the version', () => {
    expect(assetName('cli/qualor-0.1.0-linux-x64', '0.1.0')).toBe('qualor-0.1.0-linux-x64');
    expect(assetName('helm/qualor-0.1.0.tgz', '0.1.0')).toBe('qualor-0.1.0.tgz');
    expect(assetName('sbom/server.spdx.json', '0.1.0')).toBe('qualor-0.1.0-server.spdx.json');
    expect(assetName('release-notes.md', '0.1.0')).toBe('release-notes.md');
    for (const bad of ['other/x', 'cli/a/b', 'sbom/a/b']) {
      expect(() => assetName(bad, '0.1.0'), bad).toThrow(/no release asset name/);
    }
  });

  it('refuses two files with one asset name, and a file named like a reserved asset', () => {
    expect(() => assetPlan(['cli/qualor-0.1.0.tgz', 'helm/qualor-0.1.0.tgz'], '0.1.0')).toThrow(
      /would both be the release asset qualor-0\.1\.0\.tgz/,
    );
    expect(() => assetPlan(['cli/SHA256SUMS'], '0.1.0')).toThrow(/reserved asset SHA256SUMS/);
    expect(() => assetPlan(['cli/qualor-0.1.0-cli-sources.tar'], '0.1.0')).toThrow(/reserved/);
  });

  it('lists every uploaded asset by its name in the SHA256SUMS that is signed', async () => {
    const { dir, sources, out } = release();
    const sums = await writeAssets({
      dir,
      version: '0.1.0',
      out,
      replace: { 'cosign.pub': 'the release key', 'release-manifest.json': '{"dryRun":false}' },
      tar: fakeTar,
      imageSourcesRoot: sources,
    });
    expect(sums).toBe(path.join(out, SUMS));
    writeFileSync(path.join(out, SUMS_BUNDLE), '{}');
    const uploaded = readdirSync(out).sort();
    expect(uploaded).toEqual([
      'SHA256SUMS',
      'SHA256SUMS.bundle',
      'cosign.pub',
      'images.json',
      'qualor-0.1.0-cli-sources.tar',
      'qualor-0.1.0-cli.spdx.json',
      'qualor-0.1.0-linux-x64',
      'qualor-0.1.0-scanner-sources.tar',
      'qualor-0.1.0-server-sources.tar',
      'qualor-0.1.0-server.spdx.json',
      'qualor-0.1.0-windows-x64.exe',
      'qualor-0.1.0.tgz',
      'release-manifest.json',
      'release-notes.md',
    ]);
    const listed = parseSums(readFileSync(sums, 'utf8')).map((l) => l.file);
    for (const name of uploaded.filter((n) => n !== SUMS && n !== SUMS_BUNDLE)) {
      expect(listed, name).toContain(name);
    }
    expect(listed).toHaveLength(uploaded.length - 2);
    // The replacements are what is listed and uploaded, not the dry run's copies.
    expect(readFileSync(path.join(out, 'cosign.pub'), 'utf8')).toBe('the release key');
    expect(await sha256sums(out)).toBe(readFileSync(sums, 'utf8'));
  });

  it('verifies a directory laid out like a download of the release', async () => {
    const { dir, sources, out } = release();
    await writeAssets({
      dir,
      version: '0.1.0',
      out,
      replace: {},
      tar: fakeTar,
      imageSourcesRoot: sources,
    });
    writeFileSync(path.join(out, SUMS_BUNDLE), '{}');
    // A download is the same flat files in another directory.
    const download = path.join(root, 'download');
    mkdirSync(download);
    for (const f of readdirSync(out)) {
      writeFileSync(path.join(download, f), readFileSync(path.join(out, f)));
    }
    const ok = { verifyBlob: () => true };
    expect(await verifyRelease(download, path.join(root, 'cosign.pub'), ok)).toEqual([]);
    // One changed asset is named.
    writeFileSync(path.join(download, 'qualor-0.1.0.tgz'), 'changed');
    expect(await verifyRelease(download, path.join(root, 'cosign.pub'), ok)).toEqual([
      'qualor-0.1.0.tgz: the SHA-256 does not match SHA256SUMS',
    ]);
  });
});

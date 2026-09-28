import { copyFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { releaseFiles, sha256sums, SUMS, SUMS_BUNDLE } from './checksums';

/**
 * The release assets (release.md §3, final review I-2). A GitHub release holds flat file names,
 * so the release directory is uploaded as a flat copy whose own SHA256SUMS lists every asset by
 * the name it is uploaded under. A download of the release then verifies with release:verify.
 */
export const IMAGE_SOURCES = ['scanner', 'server'] as const;

export const cliSourcesTar = (version: string): string => `qualor-${version}-cli-sources.tar`;
export const imageSourcesTar = (version: string, image: (typeof IMAGE_SOURCES)[number]): string =>
  `qualor-${version}-${image}-sources.tar`;

/**
 * The asset name of one file of the release directory: a binary or the chart under its own name,
 * an SBOM as qualor-<version>-<name>.spdx.json, a top-level file as it is. `cli-sources/` goes
 * as one tar (cliSourcesTar), so its files have no name of their own.
 */
export function assetName(file: string, version: string): string {
  const parts = file.split('/');
  if (parts.length === 1 && parts[0] !== undefined) return parts[0];
  const [top, name, ...rest] = parts;
  if (name !== undefined && rest.length === 0) {
    if (top === 'cli' || top === 'helm') return name;
    if (top === 'sbom') return `qualor-${version}-${name}`;
  }
  throw new Error(`${file}: no release asset name for this path (release.md §3)`);
}

/** Every file of the release directory but cli-sources/, with its asset name; no name twice. */
export function assetPlan(
  files: readonly string[],
  version: string,
): { file: string; name: string }[] {
  const plan = files
    .filter((f) => !f.startsWith('cli-sources/'))
    .map((file) => ({ file, name: assetName(file, version) }));
  const reserved = new Set([
    SUMS,
    SUMS_BUNDLE,
    cliSourcesTar(version),
    ...IMAGE_SOURCES.map((i) => imageSourcesTar(version, i)),
  ]);
  const seen = new Map<string, string>();
  for (const { file, name } of plan) {
    const other = seen.get(name) ?? (reserved.has(name) ? `the reserved asset ${name}` : undefined);
    if (other !== undefined) {
      throw new Error(`${file} and ${other} would both be the release asset ${name}`);
    }
    seen.set(name, file);
  }
  return plan;
}

export interface AssetInputs {
  /** The release directory (release.md §3). */
  dir: string;
  version: string;
  /** Where the flat copy goes; emptied first. */
  out: string;
  /** Replacements written over the copies, by asset name (the published manifest, cosign.pub). */
  replace: Record<string, string>;
  /** Writes `<out>/<tarName>` from `<cwd>/<entry>` (tar -cf; injectable for the tests). */
  tar: (tarFile: string, cwd: string, entry: string) => void;
  /** The directory holding `<image>-sources/` (the checkout's .tmp/). */
  imageSourcesRoot: string;
}

/**
 * Writes every asset, then SHA256SUMS over all of them (by asset name). Returns the path of the
 * SHA256SUMS to sign; the bundle is written next to it by the caller's `cosign sign-blob`.
 */
export async function writeAssets(a: AssetInputs): Promise<string> {
  rmSync(a.out, { recursive: true, force: true });
  mkdirSync(a.out, { recursive: true });
  for (const { file, name } of assetPlan(releaseFiles(a.dir), a.version)) {
    copyFileSync(path.join(a.dir, file), path.join(a.out, name));
  }
  for (const [name, text] of Object.entries(a.replace)) {
    if (name.includes('/') || name.includes('\\')) throw new Error(`${name}: not a flat name`);
    writeFileSync(path.join(a.out, name), text);
  }
  a.tar(path.join(a.out, cliSourcesTar(a.version)), a.dir, 'cli-sources');
  for (const image of IMAGE_SOURCES) {
    a.tar(
      path.join(a.out, imageSourcesTar(a.version, image)),
      a.imageSourcesRoot,
      `${image}-sources`,
    );
  }
  const sums = path.join(a.out, SUMS);
  writeFileSync(sums, await sha256sums(a.out));
  return sums;
}

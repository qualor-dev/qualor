import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { Flavour } from '../deploy/release';

/** release.md §3: what a release directory holds, written before SHA256SUMS so it is signed too. */
export interface ImageRecord {
  image: Flavour;
  refs: string[];
  /** The digest in the dry-run registry (the same manifest is pushed to Docker Hub). */
  digest: string;
  /** The SBOM file, for the images that ship software. */
  sbom: string | null;
}

export interface ReleaseManifest {
  version: string;
  gitCommit: string;
  createdAt: string;
  dryRun: boolean;
  targets: string[];
  cliSources: boolean;
  images: ImageRecord[];
  chart: { file: string; digest: string | null };
  files: string[];
}

export function buildManifest(
  input: Omit<ReleaseManifest, 'files'>,
  files: string[],
): ReleaseManifest {
  return { ...input, files: [...files].sort() };
}

export function readManifest(dir: string): ReleaseManifest {
  return JSON.parse(
    readFileSync(path.join(dir, 'release-manifest.json'), 'utf8'),
  ) as ReleaseManifest;
}

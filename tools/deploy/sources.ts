import { createHash } from 'node:crypto';
import { createReadStream, readFileSync } from 'node:fs';
import path from 'node:path';
import { debianIndex, type DebManifest, type ImageName } from './debian-sources';
import { REPO_ROOT } from './stack';

/**
 * The complete corresponding source of the copyleft components of the images (rulings
 * L1 and L2). For qualor/scanner: OpenGrep (with its submodules and what its release binary
 * links: GMP, GNU Readline, certifi), SpotBugs, the JavaScriptCore/WebKit and TinyCC that Bun
 * links into the `qualor` binary, the Temurin JRE and the MPL-2.0 Go modules compiled into Trivy
 * (plan 2B) and into Gitleaks; for both images, every Debian source
 * package (debian-sources.ts). `pnpm deploy:sources` downloads them into sourcesDir(image), and
 * the companion images qualor/<image>-sources carry them.
 */
export const MANIFEST_PATH = 'deploy/scanner/sources.json';
export const indexPath = (image: ImageName): string => `deploy/${image}/SOURCES.md`;
export const readmePath = (image: ImageName): string => `deploy/${image}/sources-README.md`;
export const sourcesDir = (image: ImageName): string => `.tmp/${image}-sources`;
export const SOURCES_DOCKERFILE = 'deploy/sources.Dockerfile';

/** Files an output directory holds besides the archives and debian/. */
export function sideFiles(image: ImageName): string[] {
  const files = ['README.md', 'SHA256SUMS', 'SOURCES.md', 'debian-sources.json'];
  return image === 'scanner' ? [...files, 'sources.json'] : files;
}

export type Component =
  | 'opengrep'
  | 'spotbugs'
  | 'pmd'
  | 'bun'
  | 'temurin'
  | 'trivy'
  | 'gitleaks'
  | 'sonar-dotnet'
  | 'sonarjs';
const COMPONENTS: readonly Component[] = [
  'opengrep',
  'spotbugs',
  'pmd',
  'bun',
  'temurin',
  'trivy',
  'gitleaks',
  'sonar-dotnet',
  'sonarjs',
];

/** Where the manifest may download from: the SCM and each component's own upstream. */
export const ALLOWED_HOSTS = [
  'github.com', // archives and release assets (OpenGrep, SpotBugs, Bun, TinyCC, Temurin), Alpine aports' mirror
  'ftp.gnu.org', // GMP releases (the GNU distribution server; gmplib.org refuses cloud runners)
  'vault.almalinux.org', // AlmaLinux source RPMs
  'files.pythonhosted.org', // PyPI source distributions
  'repo1.maven.org', // Maven Central source jars
  'proxy.golang.org', // Go module zips (the MPL-2.0 modules inside Trivy and Gitleaks)
];

export type Fetch =
  | { type: 'https'; url: string }
  /**
   * `git archive` of one commit, without the named top-level directories, as an uncompressed
   * tar: for repositories GitHub generates no archive of (oven-sh/WebKit answers 422).
   */
  | { type: 'git-archive'; repository: string; commit: string; exclude: string[] };

export interface SourceEntry {
  file: string;
  name: string;
  component: Component;
  /** The version of the shipped component this source belongs to. */
  componentVersion: string;
  /** The tag or full commit archived. */
  ref: string;
  licence: string;
  fetch: Fetch;
  sha256: string;
  /** Where the ref comes from. */
  pinnedAt: string;
  why: string;
}

export type Pins = Record<Component, string>;

const FILE = /^[A-Za-z0-9][A-Za-z0-9._-]*\.(tar|tar\.gz|tar\.xz|zip|jar|src\.rpm|APKBUILD)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const GITHUB_REPO = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\.git$/;
const TOP_LEVEL = /^[A-Za-z0-9][\w.-]*$/;

function text(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== '';
}

function entryProblems(e: Record<string, unknown>, where: string): string[] {
  const problems: string[] = [];
  for (const key of ['name', 'componentVersion', 'ref', 'licence', 'pinnedAt', 'why']) {
    if (!text(e[key])) problems.push(`${where}: ${key} is missing`);
  }
  if (!text(e['file']) || !FILE.test(e['file'])) {
    problems.push(
      `${where}: file must be a plain .tar(.gz|.xz), .zip, .jar, .src.rpm or .APKBUILD name`,
    );
  }
  if (!text(e['sha256']) || !SHA256.test(e['sha256'])) {
    problems.push(`${where}: sha256 must be 64 lowercase hex digits`);
  }
  if (!COMPONENTS.includes(e['component'] as Component)) {
    problems.push(`${where}: component must be one of ${COMPONENTS.join(', ')}`);
  }
  const ref = typeof e['ref'] === 'string' ? e['ref'] : '';
  const fetch = (e['fetch'] ?? {}) as Record<string, unknown>;
  if (fetch['type'] === 'https') {
    const url = typeof fetch['url'] === 'string' ? fetch['url'] : '';
    if (!url.startsWith('https://')) problems.push(`${where}: the url must be https`);
    else if (!ALLOWED_HOSTS.includes(new URL(url).hostname)) {
      problems.push(`${where}: the url must be on github.com or an allowed upstream host`);
    }
    if (ref !== '' && !decodeURIComponent(url).includes(ref)) {
      problems.push(`${where}: the url does not fetch ${ref}`);
    }
  } else if (fetch['type'] === 'git-archive') {
    if (!text(fetch['repository']) || !GITHUB_REPO.test(fetch['repository'])) {
      problems.push(`${where}: the repository must be an https://github.com/…/….git URL`);
    }
    if (!text(fetch['commit']) || !COMMIT.test(fetch['commit']) || fetch['commit'] !== ref) {
      problems.push(`${where}: a git archive needs the full commit, equal to ref`);
    }
    const exclude = fetch['exclude'];
    if (!Array.isArray(exclude) || !exclude.every((d) => text(d) && TOP_LEVEL.test(d))) {
      problems.push(`${where}: exclude must list top-level directory names`);
    }
  } else {
    problems.push(`${where}: fetch.type must be https or git-archive`);
  }
  return problems;
}

/** Parses and validates the manifest; throws with every problem found. */
export function parseManifest(json: string): SourceEntry[] {
  const doc = JSON.parse(json) as { sources?: unknown };
  if (!Array.isArray(doc.sources) || doc.sources.length === 0) {
    throw new Error(`${MANIFEST_PATH}: sources must be a non-empty array`);
  }
  const problems: string[] = [];
  const files = new Set<string>();
  doc.sources.forEach((raw: unknown, i) => {
    const e = (raw ?? {}) as Record<string, unknown>;
    const where = `sources[${i}] (${String(e['file'])})`;
    problems.push(...entryProblems(e, where));
    if (typeof e['file'] === 'string') {
      if (files.has(e['file'])) problems.push(`${where}: duplicate file`);
      files.add(e['file']);
    }
  });
  if (problems.length > 0) throw new Error(`${MANIFEST_PATH}:\n  ${problems.join('\n  ')}`);
  return doc.sources as SourceEntry[];
}

export function loadManifest(root = REPO_ROOT): SourceEntry[] {
  return parseManifest(readFileSync(path.join(root, MANIFEST_PATH), 'utf8'));
}

/**
 * `<TOOL>_VERSION=` of the given install script's text: `tools/analyzers/install.sh` for every
 * tool but SONARANALYZER, which is pinned in `tools/analyzers/install-dotnet.sh` instead.
 */
export function installedVersion(
  installSh: string,
  tool: 'OPENGREP' | 'SPOTBUGS' | 'PMD' | 'TRIVY' | 'GITLEAKS' | 'SONARANALYZER' | 'SONARJS',
): string {
  const m = new RegExp(`^${tool}_VERSION=(\\S+)$`, 'm').exec(installSh);
  if (!m?.[1]) throw new Error(`an install script has no ${tool}_VERSION`);
  return m[1];
}

/**
 * axe-core's installed version from `node_modules/axe-core` of
 * `tools/analyzers/sonarjs/package-lock.json` (npm lockfile v3): eslint-plugin-jsx-a11y, a
 * dependency of the sonarjs pass, bundles it (MPL-2.0, controller ruling 8).
 */
export function axeCoreVersionOf(packageLockJson: string): string {
  const doc = JSON.parse(packageLockJson) as { packages?: Record<string, { version?: string }> };
  const version = doc.packages?.['node_modules/axe-core']?.version;
  if (!version) throw new Error('tools/analyzers/sonarjs/package-lock.json has no axe-core');
  return version;
}

/** `BUN_VERSION` of cli/scripts/targets.ts, the Bun every `qualor` binary is built with. */
export function bunVersionOf(targetsTs: string): string {
  const m = /^export const BUN_VERSION = '([^']+)';$/m.exec(targetsTs);
  if (!m?.[1]) throw new Error('cli/scripts/targets.ts has no BUN_VERSION');
  return m[1];
}

/** The scanner's `eclipse-temurin:<version>_<build>-jre…` base, as `<version>+<build>`. */
export function temurinVersionOf(dockerfile: string): string {
  const m = /^FROM eclipse-temurin:(\d+\.\d+\.\d+)_(\d+)-jre\S*@sha256:/m.exec(dockerfile);
  if (!m?.[1] || !m[2]) throw new Error('deploy/scanner/Dockerfile has no eclipse-temurin stage');
  return `${m[1]}+${m[2]}`;
}

/** The versions the scanner image ships. */
export function pinnedVersions(root = REPO_ROOT): Pins {
  const installSh = readFileSync(path.join(root, 'tools/analyzers/install.sh'), 'utf8');
  // SonarAnalyzer.CSharp is pinned in the .NET install script, not this one (phase 8A/8B).
  const installDotnetSh = readFileSync(
    path.join(root, 'tools/analyzers/install-dotnet.sh'),
    'utf8',
  );
  return {
    opengrep: installedVersion(installSh, 'OPENGREP'),
    spotbugs: installedVersion(installSh, 'SPOTBUGS'),
    pmd: installedVersion(installSh, 'PMD'),
    bun: bunVersionOf(readFileSync(path.join(root, 'cli/scripts/targets.ts'), 'utf8')),
    temurin: temurinVersionOf(readFileSync(path.join(root, 'deploy/scanner/Dockerfile'), 'utf8')),
    trivy: installedVersion(installSh, 'TRIVY'),
    // deploy/scanner/Dockerfile builds this version from source (tools/deploy/images.test.ts).
    gitleaks: installedVersion(installSh, 'GITLEAKS'),
    'sonar-dotnet': installedVersion(installDotnetSh, 'SONARANALYZER'),
    sonarjs: installedVersion(installSh, 'SONARJS'),
  };
}

/**
 * The tag of each component's own source archive. PMD itself is BSD-licensed, Trivy
 * Apache-2.0 and Gitleaks MIT: only the copyleft libraries they bundle are pinned, under their version.
 */
const TAG: Partial<Record<Component, (version: string) => string>> = {
  opengrep: (v) => `v${v}`,
  spotbugs: (v) => v,
  bun: (v) => `bun-v${v}`,
  temurin: (v) => `jdk-${v}`,
};

/** Why the manifest does not match the shipped versions (a bump without its sources). */
export function versionProblems(entries: readonly SourceEntry[], pins: Pins): string[] {
  const problems: string[] = [];
  for (const e of entries) {
    if (e.componentVersion !== pins[e.component]) {
      problems.push(
        `${e.file} is source of ${e.component} ${e.componentVersion}, the image ships ` +
          `${e.component} ${pins[e.component]}: update ${MANIFEST_PATH}`,
      );
    }
  }
  for (const component of COMPONENTS) {
    const tagOf = TAG[component];
    if (tagOf === undefined) continue;
    const tag = tagOf(pins[component]);
    if (!entries.some((e) => e.component === component && e.ref === tag)) {
      problems.push(`no source archive of ${component} ${pins[component]} (tag ${tag})`);
    }
  }
  return problems;
}

/** curl for one archive: https only (redirects too), TLS 1.2+, bounded retries, no output on 4xx. */
export function curlArgs(url: string, out: string): string[] {
  return [
    '--fail',
    '--silent',
    '--show-error',
    '--location',
    '--proto',
    '=https',
    '--proto-redir',
    '=https',
    '--tlsv1.2',
    '--retry',
    '3',
    '--retry-delay',
    '5',
    '--connect-timeout',
    '30',
    '--output',
    out,
    url,
  ];
}

export function upstreamOf(e: SourceEntry): string {
  return e.fetch.type === 'https'
    ? e.fetch.url
    : `${e.fetch.repository} at ${e.fetch.commit}, git archive without ${e.fetch.exclude.join(', ')}`;
}

const cell = (s: string): string => s.replaceAll('|', '\\|');

/** deploy/<image>/SOURCES.md (and /sources/SOURCES.md of the companion image). */
export function sourcesIndex(
  image: ImageName,
  entries: readonly SourceEntry[],
  debian: DebManifest,
): string {
  const from =
    image === 'scanner'
      ? `\`${MANIFEST_PATH}\` and \`deploy/scanner/debian-sources.json\``
      : `\`deploy/${image}/debian-sources.json\``;
  const lines = [
    `# Corresponding source of the qualor/${image} image`,
    '',
    `Generated from ${from} by \`pnpm deploy:sources --index\`; do not edit.`,
    '',
    `The complete corresponding source of the copyleft components of \`qualor/${image}\`.`,
    'Each release publishes these files, byte for byte, in the',
    `companion image \`qualor/${image}-sources:<same tag>\` (under \`/sources/\`) and on its release`,
    'page. `sha256sum -c SHA256SUMS` checks them: every file must have exactly this SHA-256.',
  ];
  if (entries.length > 0) {
    lines.push(
      '',
      '## Components',
      '',
      '| File | Name | Version | Licence | SHA-256 | Upstream | Why |',
      '| --- | --- | --- | --- | --- | --- | --- |',
    );
  }
  for (const e of entries) {
    const version =
      e.ref === e.componentVersion ? e.ref : `${e.ref} (${e.component} ${e.componentVersion})`;
    lines.push(
      `| \`${e.file}\` | ${cell(e.name)} | ${cell(version)} | ${cell(e.licence)} | \`${e.sha256}\` | ` +
        `${cell(upstreamOf(e))} | ${cell(`${e.why} Pinned by ${e.pinnedAt}.`)} |`,
    );
  }
  lines.push(...debianIndex(debian), '');
  return lines.join('\n');
}

/** The SHA256SUMS file next to the archives, in `sha256sum` format (Debian files in debian/). */
export function sha256sums(entries: readonly SourceEntry[], debian: DebManifest): string {
  const lines = entries.map((e) => `${e.sha256}  ${e.file}`);
  for (const p of debian.packages) {
    for (const f of p.files) lines.push(`${f.sha256}  debian/${f.name}`);
  }
  return lines.map((l) => `${l}\n`).join('');
}

/** A hex digest of a file, streamed (the WebKit tar is over 1 GB). */
export async function hashFile(file: string, algorithm: 'sha256' | 'sha1'): Promise<string> {
  const hash = createHash(algorithm);
  for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

/** `sha256sum`-style digest of a file. */
export function sha256File(file: string): Promise<string> {
  return hashFile(file, 'sha256');
}

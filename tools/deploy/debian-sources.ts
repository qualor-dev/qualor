import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { must, REPO_ROOT, run } from './stack';

/**
 * The Debian source packages of an image (ruling L2): every binary package installed in the
 * final image, mapped to its source package at the exact installed version, with the files of
 * that source package (the .dsc first) and their checksums. `pnpm deploy:debian-sources`
 * generates the manifest from a built image; `pnpm deploy:sources` downloads the files.
 */
export type ImageName = 'scanner' | 'server';
export const IMAGES: readonly ImageName[] = ['scanner', 'server'];

export const debianManifestPath = (image: ImageName): string =>
  `deploy/${image}/debian-sources.json`;
export const dockerfilePath = (image: ImageName): string => `deploy/${image}/Dockerfile`;

export interface DebFile {
  name: string;
  size: number;
  sha256: string;
  /** snapshot.debian.org addresses files by their SHA-1: the fallback download. */
  sha1: string;
}

export interface DebSource {
  source: string;
  version: string;
  /** The installed binary packages built from it. */
  binaries: string[];
  /** The archive the files were found in: deb.debian.org/<archive>/<directory>/. */
  archive: 'debian' | 'debian-security';
  directory: string;
  /** The .dsc first, then the files it lists. */
  files: DebFile[];
}

export interface DebManifest {
  image: string;
  /** The final stage's base image and the packages the Dockerfile apt-installs on it. */
  base: string;
  aptPackages: string[];
  /** Where each .dsc was verified: the Sources index URLs of the suites searched. */
  sourcesIndexes: string[];
  packages: DebSource[];
}

/** Stanzas of a deb822 file (dpkg status, Sources, a .dsc); continuation lines are kept. */
export function parseDeb822(text: string): Record<string, string>[] {
  const stanzas: Record<string, string>[] = [];
  let current: Record<string, string> = {};
  let last = '';
  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    if (line.trim() === '') {
      if (Object.keys(current).length > 0) stanzas.push(current);
      current = {};
      last = '';
    } else if (/^[ \t]/.test(line)) {
      if (last !== '') current[last] = `${current[last] ?? ''}\n${line.trim()}`;
    } else {
      const i = line.indexOf(':');
      if (i > 0) {
        last = line.slice(0, i);
        current[last] = line.slice(i + 1).trim();
      }
    }
  }
  if (Object.keys(current).length > 0) stanzas.push(current);
  return stanzas;
}

/** The body of a clearsigned .dsc (or the text itself when it is not signed). */
export function unsign(text: string): string {
  const t = text.replace(/\r\n/g, '\n');
  const start = t.indexOf('-----BEGIN PGP SIGNED MESSAGE-----');
  if (start === -1) return t;
  const body = t.slice(t.indexOf('\n\n', start) + 2);
  const end = body.indexOf('-----BEGIN PGP SIGNATURE-----');
  return end === -1 ? body : body.slice(0, end);
}

export interface Checksum {
  hash: string;
  size: number;
  name: string;
}

/** A Checksums-Sha1/Checksums-Sha256 field: one ` <hash> <size> <name>` per line. */
export function parseChecksums(field: string | undefined): Checksum[] {
  return (field ?? '')
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .filter((p) => p.length === 3)
    .map(([hash = '', size = '', name = '']) => ({ hash, size: Number(size), name }));
}

/** `source version` → the installed binary packages, from dpkg status stanzas. */
export function installedSources(
  stanzas: readonly Record<string, string>[],
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const s of stanzas) {
    const pkg = s['Package'];
    const version = s['Version'];
    if (pkg === undefined || version === undefined) continue;
    // dpkg's status file keeps removed packages too; distroless status.d has no Status field.
    const status = s['Status'];
    if (status !== undefined && !status.endsWith(' installed')) continue;
    const m = /^(\S+)(?:\s+\(([^)]+)\))?$/.exec(s['Source'] ?? pkg);
    const key = `${m?.[1] ?? pkg} ${m?.[2] ?? version}`;
    out.set(key, [...(out.get(key) ?? []), pkg].sort());
  }
  return new Map([...out.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

/** The base image and the apt-installed packages of the last stage of a Dockerfile. */
export function finalStage(dockerfile: string): { base: string; aptPackages: string[] } {
  const stages = dockerfile.split(/^FROM /m);
  const last = stages.at(-1) ?? '';
  const base = last.split(/\s/)[0] ?? '';
  const apt = /apt-get install[^\n]*?--no-install-recommends ((?:[a-z0-9][a-z0-9+.-]* ?)+)/.exec(
    last,
  );
  const aptPackages = (apt?.[1] ?? '').trim().split(/\s+/).filter(Boolean).sort();
  return { base, aptPackages };
}

export function loadDebianManifest(image: ImageName, root = REPO_ROOT): DebManifest {
  return parseDebianManifest(readFileSync(path.join(root, debianManifestPath(image)), 'utf8'));
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9+._~-]*$/;
const DIRECTORY =
  /^pool\/(?:updates\/)?(main|contrib|non-free|non-free-firmware)\/[a-z0-9+.-]+\/[a-z0-9+.-]+$/;

/** Parses and validates a Debian source manifest; throws with every problem found. */
export function parseDebianManifest(json: string): DebManifest {
  const doc = JSON.parse(json) as DebManifest;
  const problems: string[] = [];
  const names = new Set<string>();
  if (!Array.isArray(doc.packages) || doc.packages.length === 0) problems.push('no packages');
  for (const p of doc.packages ?? []) {
    const where = `${p.source} ${p.version}`;
    if (!NAME.test(p.source ?? '') || !/^[\w.+~:-]+$/.test(p.version ?? '')) {
      problems.push(`${where}: bad source or version`);
    }
    if (p.archive !== 'debian' && p.archive !== 'debian-security') {
      problems.push(`${where}: archive must be debian or debian-security`);
    }
    if (!DIRECTORY.test(p.directory ?? '')) problems.push(`${where}: bad directory`);
    if (!Array.isArray(p.binaries) || p.binaries.length === 0) {
      problems.push(`${where}: no binaries`);
    }
    if (!Array.isArray(p.files) || !p.files[0]?.name.endsWith('.dsc')) {
      problems.push(`${where}: the .dsc must come first`);
    }
    for (const f of p.files ?? []) {
      if (!NAME.test(f.name)) problems.push(`${where}: bad file name ${f.name}`);
      if (!/^[0-9a-f]{64}$/.test(f.sha256)) problems.push(`${where}: bad sha256 of ${f.name}`);
      if (!/^[0-9a-f]{40}$/.test(f.sha1)) problems.push(`${where}: bad sha1 of ${f.name}`);
      if (!Number.isInteger(f.size) || f.size <= 0)
        problems.push(`${where}: bad size of ${f.name}`);
      if (names.has(f.name)) problems.push(`${where}: duplicate file ${f.name}`);
      names.add(f.name);
    }
  }
  if (problems.length > 0) throw new Error(`Debian source manifest:\n  ${problems.join('\n  ')}`);
  return doc;
}

/** The URLs of one file: the archive, then snapshot.debian.org by content hash. */
export function debianUrls(p: DebSource, f: DebFile): string[] {
  return [
    `https://deb.debian.org/${p.archive}/${p.directory}/${f.name}`,
    `https://snapshot.debian.org/file/${f.sha1}`,
  ];
}

/** Checks the files of a downloaded .dsc against the manifest entry; returns the problems. */
export function dscProblems(p: DebSource, dscText: string): string[] {
  const dsc = parseDeb822(unsign(dscText))[0] ?? {};
  const problems: string[] = [];
  if (dsc['Source'] !== p.source || dsc['Version'] !== p.version) {
    problems.push(`${p.files[0]?.name}: is ${dsc['Source']} ${dsc['Version']}`);
  }
  const listed = parseChecksums(dsc['Checksums-Sha256']);
  const expected = p.files.slice(1);
  for (const f of expected) {
    const c = listed.find((l) => l.name === f.name);
    if (c?.hash !== f.sha256 || c.size !== f.size) {
      problems.push(`${f.name}: the .dsc lists ${c ? c.hash : 'nothing'} for it`);
    }
  }
  if (listed.length !== expected.length) {
    problems.push(
      `${p.files[0]?.name}: lists ${listed.length} files, the manifest ${expected.length}`,
    );
  }
  return problems;
}

/** The difference between the image's installed sources and the manifest's. */
export function driftProblems(installed: Map<string, string[]>, m: DebManifest): string[] {
  const problems: string[] = [];
  const pinned = new Map(m.packages.map((p) => [`${p.source} ${p.version}`, p.binaries]));
  for (const [key, binaries] of installed) {
    const have = pinned.get(key);
    if (have === undefined)
      problems.push(`installed but not pinned: ${key} (${binaries.join(', ')})`);
    else if (have.join(' ') !== binaries.join(' ')) {
      problems.push(`${key}: binaries ${binaries.join(', ')}, pinned ${have.join(', ')}`);
    }
  }
  for (const key of pinned.keys()) {
    if (!installed.has(key)) problems.push(`pinned but not installed: ${key}`);
  }
  return problems;
}

const cell = (s: string): string => s.replaceAll('|', '\\|');

/** The Debian table of SOURCES.md. */
export function debianIndex(m: DebManifest): string[] {
  const lines = [
    '',
    `## Debian source packages of \`${m.image}\``,
    '',
    `Every Debian binary package installed in \`${m.image}\` (base \`${m.base}\`` +
      (m.aptPackages.length > 0 ? `, plus \`${m.aptPackages.join(' ')}\`` : '') +
      '), by source package at the installed version, in `debian/`. Each `.dsc` was checked ' +
      'against the SHA-256 of the Debian Sources index, and every other file against its `.dsc`.',
    '',
    '| Source | Version | Binary packages | Files (SHA-256) |',
    '| --- | --- | --- | --- |',
  ];
  for (const p of m.packages) {
    const files = p.files.map((f) => `\`${f.name}\` \`${f.sha256}\``).join('<br>');
    lines.push(
      `| ${cell(p.source)} | ${cell(p.version)} | ${cell(p.binaries.join(', '))} | ${cell(files)} |`,
    );
  }
  return lines;
}

/** `source version` → binaries, from the image's /var/lib/dpkg (status, or distroless status.d). */
export function imageSources(image: string, dir: string): Map<string, string[]> {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const id = must(run('docker', ['create', image, 'none']), `docker create ${image}`).stdout.trim();
  try {
    must(run('docker', ['cp', `${id}:/var/lib/dpkg/.`, dir]), 'docker cp /var/lib/dpkg');
  } finally {
    // -v: the server image declares VOLUME /var/lib/qualor; plain rm leaves it behind.
    run('docker', ['rm', '-v', id]);
  }
  let text = '';
  if (existsSync(path.join(dir, 'status'))) text += readFileSync(path.join(dir, 'status'), 'utf8');
  const statusD = path.join(dir, 'status.d');
  if (existsSync(statusD)) {
    for (const f of readdirSync(statusD)
      .filter((n) => !n.endsWith('.md5sums'))
      .sort()) {
      text += `\n\n${readFileSync(path.join(statusD, f), 'utf8')}`;
    }
  }
  const installed = installedSources(parseDeb822(text));
  if (installed.size === 0) throw new Error(`${image}: no installed Debian packages found`);
  return installed;
}

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  debianUrls,
  dockerfilePath,
  driftProblems,
  dscProblems,
  finalStage,
  IMAGES,
  installedSources,
  loadDebianManifest,
  parseDeb822,
  parseDebianManifest,
  unsign,
  type DebManifest,
} from './debian-sources';

const STATUS = `Package: libc6
Status: install ok installed
Source: glibc
Version: 2.36-9+deb12u14

Package: git
Status: install ok installed
Version: 1:2.39.5-0+deb12u3
Description: fast
 continued

Package: libgcc-s1
Status: install ok installed
Source: gcc-12 (12.2.0-14+deb12u1)
Version: 12.2.0-14+deb12u1

Package: libstdc++6
Status: install ok installed
Source: gcc-12 (12.2.0-14+deb12u1)
Version: 12.2.0-14+deb12u1

Package: removed
Status: deinstall ok config-files
Version: 1.0
`;

const DSC = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: acl
Version: 2.3.1-3
Checksums-Sha1:
 ${'1'.repeat(40)} 355676 acl_2.3.1.orig.tar.xz
Checksums-Sha256:
 ${'a'.repeat(64)} 355676 acl_2.3.1.orig.tar.xz

-----BEGIN PGP SIGNATURE-----
xyz
-----END PGP SIGNATURE-----
`;

const pkg = {
  source: 'acl',
  version: '2.3.1-3',
  binaries: ['libacl1'],
  archive: 'debian' as const,
  directory: 'pool/main/a/acl',
  files: [
    { name: 'acl_2.3.1-3.dsc', size: 2508, sha256: 'b'.repeat(64), sha1: '2'.repeat(40) },
    { name: 'acl_2.3.1.orig.tar.xz', size: 355676, sha256: 'a'.repeat(64), sha1: '1'.repeat(40) },
  ],
};
const manifest = (packages = [pkg]): DebManifest => ({
  image: 'qualor/scanner',
  base: 'node:x@sha256:' + '0'.repeat(64),
  aptPackages: [],
  sourcesIndexes: [],
  packages,
});

describe('Debian source packages of an image (ruling L2)', () => {
  it('maps installed binary packages to source packages at the installed version', () => {
    const map = installedSources(parseDeb822(STATUS));
    expect([...map.entries()]).toEqual([
      ['gcc-12 12.2.0-14+deb12u1', ['libgcc-s1', 'libstdc++6']],
      ['git 1:2.39.5-0+deb12u3', ['git']],
      ['glibc 2.36-9+deb12u14', ['libc6']],
    ]);
  });

  it('reads a clearsigned .dsc and checks its files against the manifest', () => {
    expect(parseDeb822(unsign(DSC))[0]?.['Source']).toBe('acl');
    expect(dscProblems(pkg, DSC)).toEqual([]);
    const other = { ...pkg, files: [pkg.files[0]!, { ...pkg.files[1]!, sha256: 'c'.repeat(64) }] };
    expect(dscProblems(other, DSC).join()).toContain('acl_2.3.1.orig.tar.xz');
    expect(dscProblems({ ...pkg, version: '2.3.1-4' }, DSC)).not.toEqual([]);
  });

  it('downloads from the Debian archive, then from snapshot.debian.org by SHA-1', () => {
    expect(debianUrls(pkg, pkg.files[1]!)).toEqual([
      'https://deb.debian.org/debian/pool/main/a/acl/acl_2.3.1.orig.tar.xz',
      `https://snapshot.debian.org/file/${'1'.repeat(40)}`,
    ]);
  });

  it('reports drift between an image and its manifest', () => {
    const installed = new Map([['acl 2.3.1-3', ['libacl1']]]);
    expect(driftProblems(installed, manifest())).toEqual([]);
    expect(driftProblems(new Map([['acl 2.3.1-4', ['libacl1']]]), manifest())).toEqual([
      'installed but not pinned: acl 2.3.1-4 (libacl1)',
      'pinned but not installed: acl 2.3.1-3',
    ]);
    expect(driftProblems(new Map([['acl 2.3.1-3', ['acl', 'libacl1']]]), manifest())).toHaveLength(
      1,
    );
  });

  it('validates the manifest: file names, hashes, the .dsc first, the pool directory', () => {
    const parse = (p: object) => () =>
      parseDebianManifest(JSON.stringify(manifest([{ ...pkg, ...p }])));
    expect(parse({})).not.toThrow();
    expect(parse({ directory: '../../etc' })).toThrow(/directory/);
    expect(parse({ files: [pkg.files[1]] })).toThrow(/\.dsc/);
    expect(parse({ files: [pkg.files[0], { ...pkg.files[1], name: '../x' }] })).toThrow(
      /file name/,
    );
    expect(parse({ files: [pkg.files[0], { ...pkg.files[1], sha1: 'x' }] })).toThrow(/sha1/);
    expect(parse({ archive: 'ubuntu' })).toThrow(/archive/);
  });
});

describe('the committed Debian source manifests', () => {
  it('match the final stage of each Dockerfile (base digest and apt packages)', () => {
    for (const image of IMAGES) {
      const m = loadDebianManifest(image);
      const stage = finalStage(readFileSync(dockerfilePath(image), 'utf8'));
      expect(m.base, image).toBe(stage.base);
      expect(m.aptPackages, image).toEqual(stage.aptPackages);
      expect(m.base, image).toMatch(/@sha256:[0-9a-f]{64}$/);
    }
    expect(finalStage(readFileSync('deploy/scanner/Dockerfile', 'utf8')).aptPackages).toEqual([
      'ca-certificates',
      'git',
    ]);
  });

  it('cover the copyleft packages each image is known to contain', () => {
    const sources = (image: 'scanner' | 'server') =>
      loadDebianManifest(image).packages.map((p) => p.source);
    expect(sources('scanner')).toEqual(expect.arrayContaining(['glibc', 'git', 'bash', 'perl']));
    expect(sources('server')).toEqual(expect.arrayContaining(['glibc', 'gcc-12', 'openssl']));
    for (const image of IMAGES) {
      const m = loadDebianManifest(image);
      const keys = m.packages.map((p) => `${p.source} ${p.version}`);
      expect([...keys].sort(), image).toEqual(keys);
      expect(new Set(keys).size, image).toBe(keys.length);
    }
  });
});

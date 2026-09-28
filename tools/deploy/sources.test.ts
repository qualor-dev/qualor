import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { IMAGES, loadDebianManifest } from './debian-sources';
import {
  ALLOWED_HOSTS,
  bunVersionOf,
  curlArgs,
  indexPath,
  installedVersion,
  loadManifest,
  MANIFEST_PATH,
  parseManifest,
  pinnedVersions,
  sha256sums,
  sideFiles,
  SOURCES_DOCKERFILE,
  sourcesIndex,
  temurinVersionOf,
  versionProblems,
  type SourceEntry,
} from './sources';

const manifest = loadManifest();
const installSh = readFileSync('tools/analyzers/install.sh', 'utf8');
const byName = (name: string): SourceEntry | undefined => manifest.find((e) => e.name === name);
const scannerDebian = loadDebianManifest('scanner');

describe('the pinned source manifest of the scanner image (rulings L1 and L2)', () => {
  it('names every copyleft component of the image, and Bun, each with a SHA-256 and a reason', () => {
    for (const name of [
      'OpenGrep',
      'SpotBugs',
      'WebKit (JavaScriptCore), oven-sh fork',
      'TinyCC, oven-sh fork',
      'Bun',
      'GMP (linked into opengrep-core)',
      'Alpine build recipe of GMP 6.3.0-r3',
      'GNU Readline (bundled by the opengrep launcher)',
      'certifi (Python package in the opengrep launcher)',
      'Eclipse Temurin 17 (the JRE)',
      // Pinned once, under component `spotbugs`: a PMD bump fails through Rhino and jsr250-api,
      // not through Saxon, so a PMD whose lib/ holds another Saxon-HE must be re-derived by hand
      // (deploy/README.md, "Updating the sources").
      'Saxon-HE (bundled by SpotBugs and PMD)',
      'Rhino (bundled by PMD)',
      'JSR-250 annotations API (bundled by PMD)',
    ]) {
      const entry = byName(name);
      expect(entry, name).toBeDefined();
      expect(entry?.sha256, name).toMatch(/^[0-9a-f]{64}$/);
      expect(entry?.why.length, name).toBeGreaterThan(20);
    }
    expect(byName('OpenGrep')?.licence).toBe('LGPL-2.1');
    expect(byName('SpotBugs')?.licence).toBe('LGPL-2.1');
    expect(byName('TinyCC, oven-sh fork')?.licence).toBe('LGPL-2.1');
    expect(byName('WebKit (JavaScriptCore), oven-sh fork')?.licence).toMatch(/^LGPL-2\.0/);
    expect(byName('GMP (linked into opengrep-core)')?.licence).toContain('LGPL-3.0-or-later');
    expect(byName('GNU Readline (bundled by the opengrep launcher)')?.licence).toBe(
      'GPL-3.0-or-later',
    );
    expect(byName('certifi (Python package in the opengrep launcher)')?.licence).toBe('MPL-2.0');
    expect(byName('Eclipse Temurin 17 (the JRE)')?.licence).toContain('Classpath-exception');
  });

  it('carries the MPL-2.0 Go modules compiled into Trivy, from the Go module proxy (plan 2B)', () => {
    const modules = manifest.filter((e) => e.component === 'trivy');
    expect(modules.map((e) => e.name.replace(/^Go module (\S+) .*$/, '$1')).sort()).toEqual([
      'github.com/cyphar/filepath-securejoin',
      'github.com/hashicorp/aws-sdk-go-base/v2',
      'github.com/hashicorp/errwrap',
      'github.com/hashicorp/go-cleanhttp',
      'github.com/hashicorp/go-getter',
      'github.com/hashicorp/go-multierror',
      'github.com/hashicorp/go-retryablehttp',
      'github.com/hashicorp/go-uuid',
      'github.com/hashicorp/go-version',
      'github.com/hashicorp/golang-lru/v2',
      'github.com/hashicorp/hcl/v2',
    ]);
    for (const e of modules) {
      expect(e.licence, e.file).toContain('MPL-2.0');
      expect(e.fetch, e.file).toEqual({
        type: 'https',
        url: expect.stringMatching(
          /^https:\/\/proxy\.golang\.org\/github\.com\/[^@]+\/@v\/v[\w.-]+\.zip$/,
        ),
      });
      expect(e.componentVersion, e.file).toBe('0.74.0');
    }
  });

  it('pins WebKit and TinyCC to the full commits Bun pins, and SpotBugs to its release asset', () => {
    const webkit = byName('WebKit (JavaScriptCore), oven-sh fork');
    expect(webkit?.ref).toMatch(/^[0-9a-f]{40}$/);
    expect(webkit?.fetch).toMatchObject({
      type: 'git-archive',
      repository: 'https://github.com/oven-sh/WebKit.git',
      commit: webkit?.ref,
    });
    expect(webkit?.pinnedAt).toContain('WEBKIT_VERSION');
    const tinycc = byName('TinyCC, oven-sh fork');
    expect(tinycc?.ref).toMatch(/^[0-9a-f]{40}$/);
    expect(tinycc?.pinnedAt).toContain('TINYCC_COMMIT');
    expect(byName('SpotBugs')?.fetch).toEqual({
      type: 'https',
      url: 'https://github.com/spotbugs/spotbugs/releases/download/4.10.4/spotbugs-4.10.4-source.zip',
    });
  });

  it("carries OpenGrep's submodules, which GitHub's tag archive leaves out", () => {
    const submodules = manifest.filter((e) => e.name.startsWith('OpenGrep submodule '));
    expect(submodules.length).toBeGreaterThan(30);
    for (const s of submodules) {
      expect(s.ref, s.name).toMatch(/^[0-9a-f]{40}$/);
      expect(s.component, s.name).toBe('opengrep');
    }
    expect(submodules.map((s) => s.name)).toContain(
      'OpenGrep submodule libs/ocaml-tree-sitter-core',
    );
  });

  it('uses Adoptium’s published source archive of the exact Temurin build', () => {
    const jdk = byName('Eclipse Temurin 17 (the JRE)');
    expect(jdk?.ref).toBe('jdk-17.0.20+8');
    expect(jdk?.fetch).toEqual({
      type: 'https',
      url: 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20%2B8/OpenJDK17U-jdk-sources_17.0.20_8.tar.gz',
    });
  });
});

describe('consistency with the shipped versions', () => {
  it('reads the versions the image ships: install.sh, the CLI build and the JRE base', () => {
    expect(installedVersion(installSh, 'OPENGREP')).toBe('1.30.0');
    expect(installedVersion(installSh, 'SPOTBUGS')).toBe('4.10.4');
    expect(installedVersion(installSh, 'TRIVY')).toBe('0.74.0');
    expect(bunVersionOf(readFileSync('cli/scripts/targets.ts', 'utf8'))).toBe('1.3.13');
    expect(temurinVersionOf(readFileSync('deploy/scanner/Dockerfile', 'utf8'))).toBe('17.0.20+8');
    expect(pinnedVersions()).toEqual({
      opengrep: '1.30.0',
      spotbugs: '4.10.4',
      pmd: '7.27.0',
      bun: '1.3.13',
      temurin: '17.0.20+8',
      trivy: '0.74.0',
    });
  });

  it('matches every entry to those versions', () => {
    expect(versionProblems(manifest, pinnedVersions())).toEqual([]);
  });

  // A bump fails here until sources.json has the new sources. Updating the tag archives is not
  // enough: re-derive the WebKit and TinyCC commits from the new Bun tag
  // (scripts/build/deps/webkit.ts WEBKIT_VERSION, scripts/build/deps/tinycc.ts TINYCC_COMMIT),
  // the OpenGrep submodule commits from the gitlinks of the new OpenGrep tag, and what the new
  // OpenGrep release binary links or bundles (GMP, Readline, certifi): see deploy/README.md.
  it('fails when a version is bumped without its sources', () => {
    const bumped = installSh.replace('OPENGREP_VERSION=1.30.0', 'OPENGREP_VERSION=1.31.0');
    const pins = { ...pinnedVersions(), opengrep: installedVersion(bumped, 'OPENGREP') };
    expect(versionProblems(manifest, pins).join('\n')).toContain('opengrep 1.31.0');
    const bumps = [
      { spotbugs: '4.10.5' },
      { pmd: '7.28.0' },
      { bun: '1.3.14' },
      { temurin: '17.0.21+9' },
      { trivy: '0.75.0' },
    ];
    for (const bump of bumps) {
      expect(versionProblems(manifest, { ...pinnedVersions(), ...bump })).not.toEqual([]);
    }
  });

  it('fails when an entry claims the new version but still fetches the old tag', () => {
    const renamed = manifest.map((e) =>
      e.component === 'spotbugs' ? { ...e, componentVersion: '4.10.5', ref: '4.10.5' } : e,
    );
    expect(() => parseManifest(JSON.stringify({ sources: renamed }))).toThrow(/4\.10\.5/);
  });

  it('builds the image and runs CI with the same Bun as the CLI build', () => {
    const bun = pinnedVersions().bun;
    expect(readFileSync('deploy/scanner/Dockerfile', 'utf8')).toContain(
      `npm install -g bun@${bun}`,
    );
    for (const file of ['.github/workflows/ci.yml', '.github/workflows/nightly.yml']) {
      const versions = [...readFileSync(file, 'utf8').matchAll(/bun-version: ([\d.]+)/g)];
      expect(versions.length, file).toBeGreaterThan(0);
      for (const m of versions) expect(m[1], file).toBe(bun);
    }
    const gitlab = [...readFileSync('.gitlab-ci.yml', 'utf8').matchAll(/bun@([\d.]+)/g)];
    expect(gitlab.length).toBeGreaterThan(0);
    for (const m of gitlab) expect(m[1]).toBe(bun);
  });
});

describe('manifest validation', () => {
  const good = manifest[0];
  const reject = (patch: Partial<SourceEntry>) => () =>
    parseManifest(JSON.stringify({ sources: [{ ...good, ...patch }] }));

  it('accepts the committed manifest', () => {
    expect(good).toBeDefined();
    expect(() => parseManifest(readFileSync(MANIFEST_PATH, 'utf8'))).not.toThrow();
  });

  it('rejects anything but https downloads from GitHub and the named upstream hosts', () => {
    expect(
      reject({ fetch: { type: 'https', url: 'http://github.com/a/b/archive/x.tar.gz' } }),
    ).toThrow(/https/);
    expect(reject({ fetch: { type: 'https', url: 'https://example.com/v1.30.0.tar.gz' } })).toThrow(
      /allowed upstream host/,
    );
    expect(ALLOWED_HOSTS).toEqual([
      'github.com',
      'gmplib.org',
      'gitlab.alpinelinux.org',
      'vault.almalinux.org',
      'files.pythonhosted.org',
      'repo1.maven.org',
      'proxy.golang.org',
    ]);
    for (const e of manifest) {
      if (e.fetch.type === 'https')
        expect(ALLOWED_HOSTS, e.file).toContain(new URL(e.fetch.url).hostname);
    }
  });

  it('rejects a file name that could leave the output directory, and a malformed hash', () => {
    expect(reject({ file: '../escape.tar.gz' })).toThrow(/file/);
    expect(reject({ file: 'sub/dir.tar.gz' })).toThrow(/file/);
    expect(reject({ file: 'SOURCES.md' })).toThrow(/file/);
    expect(reject({ file: 'debian' })).toThrow(/file/);
    expect(reject({ sha256: 'abc' })).toThrow(/sha256/);
  });

  it('rejects duplicate files and a git archive of anything but a full commit', () => {
    expect(() => parseManifest(JSON.stringify({ sources: [good, good] }))).toThrow(/duplicate/);
    const webkit = byName('WebKit (JavaScriptCore), oven-sh fork');
    expect(() =>
      parseManifest(
        JSON.stringify({
          sources: [{ ...webkit, ref: 'main', fetch: { ...webkit?.fetch, commit: 'main' } }],
        }),
      ),
    ).toThrow(/commit/);
  });
});

describe('downloads, the index and the companion images', () => {
  it('downloads over https only, with bounded retries', () => {
    const args = curlArgs('https://github.com/a/b/archive/v1.tar.gz', 'out.part');
    expect(args.join(' ')).toContain('--proto =https --proto-redir =https --tlsv1.2');
    expect(args).toContain('--fail');
    expect(args[args.indexOf('--retry') + 1]).toBe('3');
    expect(args.at(-1)).toBe('https://github.com/a/b/archive/v1.tar.gz');
  });

  it('keeps deploy/<image>/SOURCES.md generated from the manifests (pnpm deploy:sources --index)', () => {
    for (const image of IMAGES) {
      const entries = image === 'scanner' ? manifest : [];
      const debian = loadDebianManifest(image);
      const index = sourcesIndex(image, entries, debian);
      expect(readFileSync(indexPath(image), 'utf8'), image).toBe(index);
      for (const e of entries) expect(index).toContain(e.sha256);
      for (const f of debian.packages.flatMap((p) => p.files)) expect(index).toContain(f.sha256);
    }
  });

  it('writes a SHA256SUMS file that sha256sum -c reads, Debian files under debian/', () => {
    const sums = sha256sums(manifest, scannerDebian).split('\n');
    expect(sums.at(-1)).toBe('');
    const debianFiles = scannerDebian.packages.flatMap((p) => p.files);
    expect(sums.slice(0, -1)).toEqual([
      ...manifest.map((e) => `${e.sha256}  ${e.file}`),
      ...debianFiles.map((f) => `${f.sha256}  debian/${f.name}`),
    ]);
    expect(sideFiles('scanner')).toEqual([
      'README.md',
      'SHA256SUMS',
      'SOURCES.md',
      'debian-sources.json',
      'sources.json',
    ]);
    expect(sideFiles('server')).not.toContain('sources.json');
  });

  it('defines the scripts and one companion image definition for both images', () => {
    const root = JSON.parse(readFileSync('package.json', 'utf8')) as {
      scripts: Record<string, string>;
    };
    expect(root.scripts['deploy:sources']).toBe('tsx tools/deploy/sources-fetch.ts');
    expect(root.scripts['deploy:debian-sources']).toBe('tsx tools/deploy/debian-sources-gen.ts');
    expect(root.scripts['deploy:release-images']).toBe('tsx tools/deploy/release-images.ts');
    expect(root.scripts['deploy:scanner-images']).toBeUndefined();
    const dockerfile = readFileSync(SOURCES_DOCKERFILE, 'utf8');
    expect([...dockerfile.matchAll(/^FROM (\S+)/gm)].map((m) => m[1])).toEqual(['scratch']);
    expect(dockerfile).toMatch(/^COPY \. \/sources\/$/m);
    expect(readFileSync('deploy/scanner/Dockerfile', 'utf8')).toContain(
      'COPY deploy/scanner/SOURCES.md /opt/qualor/SOURCES.md',
    );
    const server = readFileSync('deploy/server/Dockerfile', 'utf8');
    expect(server).toContain('COPY --chmod=0644 deploy/server/NOTICE.md ./NOTICE.md');
    expect(server).toContain('COPY --chmod=0644 deploy/server/SOURCES.md ./SOURCES.md');
    expect(server).toContain(
      'COPY --chmod=0644 deploy/scanner/licenses/NODE-LICENSE.txt ./NODE-LICENSE.txt',
    );
    expect(readFileSync('.gitignore', 'utf8')).toMatch(/^\.tmp\/$/m);
  });
});

describe('the notices (rulings L1 and L2)', () => {
  it('points the scanner NOTICE at the companion image for every copyleft part', () => {
    const notice = readFileSync('deploy/scanner/NOTICE.md', 'utf8');
    expect(notice).toContain('qualor/scanner-sources:<same tag>');
    expect(notice).toContain('SOURCES.md');
    for (const part of ['GMP', 'Readline', 'certifi', 'Temurin', 'Debian', 'Trivy', 'go-getter']) {
      expect(notice, part).toContain(part);
    }
    // Plan 2B: Trivy's licence and NOTICE ship, and the database's sources are attributed.
    expect(notice).toContain('`TRIVY-LICENSE.txt`, `TRIVY-NOTICE.txt`');
    for (const file of ['TRIVY-LICENSE.txt', 'TRIVY-NOTICE.txt']) {
      expect(readFileSync(`deploy/scanner/licenses/${file}`, 'utf8'), file).toMatch(
        /Apache License|Aqua Security/,
      );
    }
    expect(notice).toMatch(/GitHub Advisory\s+Database \(CC-BY-4\.0/);
    expect(notice).toMatch(/the NVD/);
    // Fix round 1: Canonical's Ubuntu data is possibly ShareAlike, and nothing claims a licence
    // list Aqua Security does not publish.
    expect(notice).toMatch(
      /Ubuntu security data\s+\(the Ubuntu CVE Tracker\) is possibly CC-BY-SA-4\.0/,
    );
    expect(notice).toContain('https://bugs.launchpad.net/bugs/1962128');
    expect(notice).not.toMatch(/sources and their licences are listed/);
    expect(notice).toContain('/opt/qualor/share/trivy/db/metadata.json');
    // The written offer stays, as a courtesy only.
    expect(notice).toMatch(/any third party/);
    expect(notice).toMatch(/courtesy/);
  });

  it('gives the server image a NOTICE with its Debian and Node.js parts', () => {
    const notice = readFileSync('deploy/server/NOTICE.md', 'utf8');
    expect(notice).toContain('qualor/server-sources:<same tag>');
    for (const part of ['glibc', 'gcc-12', 'openssl', 'Node.js', 'ICU', 'NODE-LICENSE.txt']) {
      expect(notice, part).toContain(part);
    }
  });

  it('names every bundled Java library in the README of the scanner sources image', () => {
    const readme = readFileSync('deploy/scanner/sources-README.md', 'utf8');
    const jars = manifest.filter((e) => e.file.endsWith('-sources.jar'));
    expect(jars.map((e) => e.ref)).toEqual(['12.10', '1.7.15.1', '1.0']);
    for (const entry of jars) {
      const library = entry.file.replace(/-[\d.]+-sources\.jar$/, '');
      expect(readme.toLowerCase(), entry.file).toContain(library.toLowerCase());
      expect(readme, entry.file).toContain(entry.ref);
    }
  });

  it('says the Debian Sources index is trusted over TLS, without a PGP check', () => {
    const readme = readFileSync('deploy/README.md', 'utf8');
    expect(readme).toMatch(
      /`Sources` index[\s\S]{0,200}over TLS[\s\S]{0,200}`InRelease`[\s\S]{0,40}no PGP check/,
    );
  });

  it('flags the WebKit exclusions as a judgement call, with the full tree as the fallback', () => {
    for (const file of ['deploy/README.md']) {
      const text = readFileSync(file, 'utf8');
      expect(text, file).toMatch(/not needed to build/);
      expect(text, file).toMatch(/judgement call/);
      expect(text, file).toMatch(/full tree/);
    }
  });

  it('attaches the manifests to the release page as well (deploy/README.md step 4)', () => {
    const readme = readFileSync('deploy/README.md', 'utf8');
    const step = /^4\. Attach [^\n]*(?:\n {3}[^\n]*)*/m.exec(readme)?.[0] ?? '';
    for (const file of [
      'SOURCES.md',
      'SHA256SUMS',
      'sources.json',
      'debian-sources.json',
      'debian/',
    ]) {
      expect(step, file).toContain(file);
    }
  });
});

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { ImageName } from './debian-sources';
import { parseVersion } from '../release/version';
import {
  alsoProblems,
  NAMESPACE,
  release,
  releaseArgs,
  dotnetBaseRef,
  STAGING,
  type ReleaseDocker,
  type ReleaseInputs,
} from './release';

const inputs: ReleaseInputs = {
  imageArgs: { scanner: ['scanner-args'], server: ['server-args'] },
  sourcesArgs: { scanner: ['scanner-sources-args'], server: ['server-sources-args'] },
  dotnetArgs: (scannerRef) => ['dotnet-args', `SCANNER_IMAGE=${scannerRef}`],
  driftMessage: (image, ref, problems) => `${image} ${ref}: ${problems.join(', ')}`,
};

/** A Docker that records every call and whose drift check fails for the images named. */
function fakeDocker(drifting: ImageName[] = []): ReleaseDocker & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    build: (ref, args) => calls.push(`build ${ref} ${args.join(' ')}`),
    drift: (ref, image) => {
      calls.push(`drift ${ref}`);
      return drifting.includes(image) ? ['git 1:2.39.5-0+deb12u2 != 1:2.39.5-0+deb12u3'] : [];
    },
    tag: (source, target) => calls.push(`tag ${source} ${target}`),
    untag: (ref) => calls.push(`untag ${ref}`),
  };
}

describe('pnpm deploy:release-images (rulings L1 and L2)', () => {
  it('names the images in Docker Hub’s qualor namespace, with the tag of --tag', () => {
    expect(NAMESPACE).toBe('qualor');
    expect(releaseArgs(['--tag', '0.1.0'])).toEqual({
      tag: '0.1.0',
      also: [],
      namespace: 'qualor',
    });
    expect(releaseArgs([])).toEqual({ tag: 'dev', also: [], namespace: 'qualor' });
    expect(releaseArgs(['--tag', '1', '--namespace', 'registry.test/team'])).toEqual({
      tag: '1',
      also: [],
      namespace: 'registry.test/team',
    });
    for (const bad of [['--tag'], ['--tag', '-x'], ['--tag', 'a:b'], ['--namespace', 'Qualor']]) {
      expect(() => releaseArgs(bad), bad.join(' ')).toThrow(/not a valid/);
    }
    expect(() => releaseArgs(['--namespace', STAGING])).toThrow(/not a valid namespace/);
  });

  it('checks everything under staging names, then tags each sources image before its image', () => {
    const docker = fakeDocker();
    const released = release({ tag: '0.1.0', also: [], namespace: 'qualor' }, inputs, docker);
    expect(released).toEqual([
      'qualor/scanner-sources:0.1.0',
      'qualor/scanner:0.1.0',
      'qualor/scanner-dotnet:0.1.0',
      'qualor/server-sources:0.1.0',
      'qualor/server:0.1.0',
    ]);
    const s = `${STAGING}/`;
    expect(docker.calls).toEqual([
      `build ${s}scanner:0.1.0 scanner-args`,
      `drift ${s}scanner:0.1.0`,
      `build ${s}scanner-sources:0.1.0 scanner-sources-args`,
      `tag ${s}scanner:0.1.0 localhost:1/${STAGING}-scanner:0.1.0`,
      `build ${s}scanner-dotnet:0.1.0 dotnet-args SCANNER_IMAGE=localhost:1/${STAGING}-scanner:0.1.0`,
      `untag localhost:1/${STAGING}-scanner:0.1.0`,
      `build ${s}server:0.1.0 server-args`,
      `drift ${s}server:0.1.0`,
      `build ${s}server-sources:0.1.0 server-sources-args`,
      `tag ${s}scanner-sources:0.1.0 qualor/scanner-sources:0.1.0`,
      `tag ${s}scanner:0.1.0 qualor/scanner:0.1.0`,
      `tag ${s}scanner-dotnet:0.1.0 qualor/scanner-dotnet:0.1.0`,
      `tag ${s}server-sources:0.1.0 qualor/server-sources:0.1.0`,
      `tag ${s}server:0.1.0 qualor/server:0.1.0`,
      `untag ${s}scanner-sources:0.1.0`,
      `untag ${s}scanner:0.1.0`,
      `untag ${s}scanner-dotnet:0.1.0`,
      `untag ${s}server-sources:0.1.0`,
      `untag ${s}server:0.1.0`,
    ]);
  });

  it('tags no release name when a Debian drift check fails, for either image', () => {
    for (const image of ['scanner', 'server'] as const) {
      const docker = fakeDocker([image]);
      expect(() =>
        release({ tag: '0.1.0', also: [], namespace: 'qualor' }, inputs, docker),
      ).toThrow(`${image} ${STAGING}/${image}:0.1.0: git`);
      // Nothing under qualor/ exists: no image can be pushed without its sources image.
      expect(docker.calls.filter((c) => /\bqualor\//.test(c))).toEqual([]);
      // No tag and no untag but scanner-dotnet's local-only base (the staging names stay).
      const retags = docker.calls.filter((c) => /^(un)?tag /.test(c));
      expect(retags.filter((c) => !c.endsWith(dotnetBaseRef('0.1.0')))).toEqual([]);
    }
  });

  it('tags no release name when a build fails', () => {
    const docker = fakeDocker();
    docker.build = (ref) => {
      docker.calls.push(`build ${ref}`);
      if (ref.includes('server-sources')) throw new Error('docker build failed');
    };
    expect(() => release({ tag: '1', also: [], namespace: 'qualor' }, inputs, docker)).toThrow(
      'docker build failed',
    );
    const tags = docker.calls.filter((c) => c.startsWith('tag '));
    expect(tags.filter((c) => !c.endsWith(dotnetBaseRef('1')))).toEqual([]);
  });

  it('reads --also for the moving tags, each a valid tag', () => {
    expect(releaseArgs(['--tag', '1.2.3', '--also', '1.2', '--also', '1'])).toEqual({
      tag: '1.2.3',
      also: ['1.2', '1'],
      namespace: 'qualor',
    });
    expect(() => releaseArgs(['--tag', '1.2.3', '--also', 'a:b'])).toThrow(/not a valid image tag/);
    expect(() => releaseArgs(['--tag', '1.2.3', '--also'])).toThrow(/not a valid image tag/);
    expect(() => releaseArgs(['--tag', '1.2.3', '--also', '1.2', '--also', '1.2'])).toThrow(
      /given twice/,
    );
    expect(() => releaseArgs(['--tag', '1.2.3', '--also', '1.2.3'])).toThrow(/given twice/);
  });

  it('refuses the tags never publishes: latest anywhere, and a floating 0', () => {
    const bad = [
      ['--tag', 'latest'],
      ['--tag', '0.1.0', '--also', 'latest'],
      ['--tag', '0.1.0', '--also', '0'],
      ['--tag', '0'],
    ];
    for (const argv of bad) {
      expect(() => releaseArgs(argv), argv.join(' ')).toThrow(/never published/);
    }
  });

  it('builds scanner-dotnet from the staging scanner, and tags it after the scanner, with every tag', () => {
    const docker = fakeDocker();
    const released = release({ tag: '1.2.3', also: ['1.2'], namespace: 'qualor' }, inputs, docker);
    expect(released).toEqual([
      'qualor/scanner-sources:1.2.3',
      'qualor/scanner-sources:1.2',
      'qualor/scanner:1.2.3',
      'qualor/scanner:1.2',
      'qualor/scanner-dotnet:1.2.3',
      'qualor/scanner-dotnet:1.2',
      'qualor/server-sources:1.2.3',
      'qualor/server-sources:1.2',
      'qualor/server:1.2.3',
      'qualor/server:1.2',
    ]);
    const s = `${STAGING}/`;
    expect(docker.calls.slice(0, 9)).toEqual([
      `build ${s}scanner:1.2.3 scanner-args`,
      `drift ${s}scanner:1.2.3`,
      `build ${s}scanner-sources:1.2.3 scanner-sources-args`,
      `tag ${s}scanner:1.2.3 localhost:1/${STAGING}-scanner:1.2.3`,
      `build ${s}scanner-dotnet:1.2.3 dotnet-args SCANNER_IMAGE=localhost:1/${STAGING}-scanner:1.2.3`,
      `untag localhost:1/${STAGING}-scanner:1.2.3`,
      `build ${s}server:1.2.3 server-args`,
      `drift ${s}server:1.2.3`,
      `build ${s}server-sources:1.2.3 server-sources-args`,
    ]);
    expect(docker.calls.filter((c) => c.startsWith('untag '))).toHaveLength(6);
  });

  it('never builds scanner-dotnet from a scanner whose Debian check failed', () => {
    const docker = fakeDocker(['scanner']);
    expect(() =>
      release({ tag: '1.2.3', also: [], namespace: 'qualor' }, inputs, docker),
    ).toThrow();
    expect(docker.calls.some((c) => c.includes('scanner-dotnet'))).toBe(false);
  });
});

describe('--also is checked against imageTags (release.md §2, §5)', () => {
  const released = ['0.1.0', '0.2.0', '1.2.5', '1.3.0'].map(parseVersion);

  it('accepts exactly the moving tags a version gets, or none of them', () => {
    expect(alsoProblems({ tag: '0.2.1', also: ['0.2'] }, released)).toEqual([]);
    expect(alsoProblems({ tag: '1.3.1', also: ['1.3', '1'] }, released)).toEqual([]);
    expect(alsoProblems({ tag: '1.3.1', also: [] }, released)).toEqual([]);
    expect(alsoProblems({ tag: 'dev', also: [] }, released)).toEqual([]);
  });

  it('refuses a moving tag that would go backwards or that the version never gets', () => {
    // 1.2.4 after 1.2.5: no 1.2, and never 1 (1.3.0 holds it).
    expect(alsoProblems({ tag: '1.2.4', also: ['1.2'] }, released)).toEqual([
      '--also 1.2: 1.2.4 gets no moving tag 1.2 (it would move backwards; allowed: none)',
    ]);
    expect(alsoProblems({ tag: '1.2.6', also: ['1.2', '1'] }, released)).toEqual([
      '--also 1: 1.2.6 gets no moving tag 1 (it would move backwards; allowed: 1.2)',
    ]);
    expect(alsoProblems({ tag: '0.2.1', also: ['0.3'] }, released)).toEqual([
      '--also 0.3: 0.2.1 gets no moving tag 0.3 (it would move backwards; allowed: 0.2)',
    ]);
    // A pre-release gets only its full tag.
    expect(alsoProblems({ tag: '2.0.0-rc.1', also: ['2.0'] }, released)).toHaveLength(1);
  });

  it('refuses --also with a tag that is not a version', () => {
    expect(alsoProblems({ tag: 'dev', also: ['dev2'] }, released)).toEqual([
      '--also needs a SemVer --tag (release.md §2); "dev" is not one',
    ]);
  });

  it('is checked by deploy:release-images before anything is built', () => {
    const source = readFileSync('tools/deploy/release-images.ts', 'utf8');
    const main = source.slice(source.indexOf('async function main('));
    expect(main.indexOf('alsoProblems(')).toBeGreaterThan(-1);
    expect(main.indexOf('alsoProblems(')).toBeLessThan(main.indexOf('checkSources('));
  });
});

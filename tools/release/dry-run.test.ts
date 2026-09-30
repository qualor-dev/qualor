import { parse } from 'yaml';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { VENDORED_GRAMMARS } from '../../cli/src/parse/vendored';
import { binaryNote, parseDryRunArgs, pinServerDigest } from './dry-run';
import { parseVersion } from './version';

const current = parseVersion('0.0.0');

describe("the release notes' binary line (plan 8F, final review minor 4)", () => {
  const g = (name: string) => ({ name, version: '1.0.0', licence: 'MIT' });

  it('names the Bun version and each vendored grammar, worded for any count', () => {
    expect(binaryNote('1.3.0', [])).toBe('The `qualor` binaries are built with Bun 1.3.0.');
    expect(binaryNote('1.3.0', [g('a')])).toBe(
      'The `qualor` binaries are built with Bun 1.3.0 and embed a 1.0.0 (MIT), a grammar that is not an npm package.',
    );
    expect(binaryNote('1.3.0', [g('a'), g('b')])).toBe(
      'The `qualor` binaries are built with Bun 1.3.0 and embed a 1.0.0 (MIT) and b 1.0.0 (MIT), grammars that are not npm packages.',
    );
    expect(binaryNote('1.3.0', [g('a'), g('b'), g('c')])).toBe(
      'The `qualor` binaries are built with Bun 1.3.0 and embed a 1.0.0 (MIT), b 1.0.0 (MIT) and c 1.0.0 (MIT), grammars that are not npm packages.',
    );
  });

  it('says what the binaries embed today', () => {
    const swift = VENDORED_GRAMMARS.swift;
    expect(binaryNote('1.3.0', Object.values(VENDORED_GRAMMARS))).toBe(
      `The \`qualor\` binaries are built with Bun 1.3.0 and embed ${swift.name} ${swift.version} (${swift.licence}), a grammar that is not an npm package.`,
    );
  });
});

describe('pnpm release:dry-run arguments (release.md §10)', () => {
  it('defaults to the checkout version, every target, images and CLI sources', () => {
    expect(parseDryRunArgs([], current)).toEqual({
      version: current,
      skipImages: false,
      skipCliSources: false,
      targets: ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'windows-x64'],
    });
  });

  it('reads --skip-images, --skip-cli-sources and --targets', () => {
    const o = parseDryRunArgs(
      ['--skip-images', '--skip-cli-sources', '--targets', 'linux-x64,windows-x64'],
      current,
    );
    expect(o).toMatchObject({
      skipImages: true,
      skipCliSources: true,
      targets: ['linux-x64', 'windows-x64'],
    });
  });

  it('refuses a version other than the checkout’s, and an unknown target', () => {
    expect(() => parseDryRunArgs(['--version', '1.0.0'], current)).toThrow(
      'the checkout is at 0.0.0, not 1.0.0: run pnpm release:version 1.0.0 first',
    );
    expect(() => parseDryRunArgs(['--targets', 'linux-x64,plan9-x64'], current)).toThrow(
      /unknown target plan9-x64/,
    );
  });
});

describe('the packaged chart pins the server image by digest (ruling R-DIGEST)', () => {
  const values = readFileSync('deploy/helm/qualor/values.yaml', 'utf8');
  const digest = `sha256:${'ab'.repeat(32)}`;

  it('sets image.digest and changes nothing else', () => {
    const before = parse(values) as { image: Record<string, unknown> };
    const after = parse(pinServerDigest(values, digest)) as { image: Record<string, unknown> };
    expect(after.image['digest']).toBe(digest);
    expect({ ...after, image: { ...after.image, digest: '' } }).toEqual(before);
  });

  it('refuses something that is not a sha256 digest', () => {
    expect(() => pinServerDigest(values, 'sha256:abc')).toThrow(/not a sha256 digest/);
  });
});

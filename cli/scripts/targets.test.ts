import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  bunBuildArgs,
  bunReleaseArgs,
  CLI_DIR,
  NO_AUTOLOAD,
  outputPath,
  parseTargets,
  RELEASE_TARGETS,
  releaseBinaryName,
} from './targets';

describe('build targets', () => {
  it('builds both linux targets by default and rejects unknown ones', () => {
    expect(parseTargets([])).toEqual(['linux-x64', 'linux-arm64']);
    expect(parseTargets(['linux-arm64'])).toEqual(['linux-arm64']);
    expect(() => parseTargets(['windows-x64'])).toThrow(/unknown target/);
  });

  it('compiles entry.bun.ts for the bun target into dist/', () => {
    expect(bunBuildArgs('linux-arm64')).toEqual([
      'build',
      '--compile',
      ...NO_AUTOLOAD,
      '--target=bun-linux-arm64',
      path.join(CLI_DIR, 'src', 'entry.bun.ts'),
      '--outfile',
      outputPath('linux-arm64'),
    ]);
    expect(outputPath('linux-x64')).toBe(path.join(CLI_DIR, 'dist', 'qualor-linux-x64'));
  });
});

describe('no autoload (ruling V8)', () => {
  it('turns off .env and bunfig.toml autoloading in every binary, shipped or released', () => {
    expect(NO_AUTOLOAD).toEqual([
      '--no-compile-autoload-dotenv',
      '--no-compile-autoload-bunfig',
      '--no-compile-autoload-tsconfig',
      '--no-compile-autoload-package-json',
    ]);
    for (const args of [bunBuildArgs('linux-x64'), bunReleaseArgs('windows-x64', '/q.exe')]) {
      expect(args).toContain('--no-compile-autoload-dotenv');
      expect(args).toContain('--no-compile-autoload-bunfig');
    }
  });
});

describe('release targets (release.md §4)', () => {
  it('adds macOS and Windows to the two Linux targets', () => {
    expect(Object.keys(RELEASE_TARGETS)).toEqual([
      'linux-x64',
      'linux-arm64',
      'darwin-x64',
      'darwin-arm64',
      'windows-x64',
    ]);
  });

  it('names each binary with the version, and .exe on Windows', () => {
    expect(releaseBinaryName('1.2.3', 'linux-arm64')).toBe('qualor-1.2.3-linux-arm64');
    expect(releaseBinaryName('1.2.3', 'windows-x64')).toBe('qualor-1.2.3-windows-x64.exe');
  });

  it('compiles entry.bun.ts for the bun target into the given file', () => {
    expect(bunReleaseArgs('darwin-arm64', '/out/q')).toEqual([
      'build',
      '--compile',
      ...NO_AUTOLOAD,
      '--target=bun-darwin-arm64',
      expect.stringMatching(/src[\\/]entry\.bun\.ts$/),
      '--outfile',
      '/out/q',
    ]);
  });
});

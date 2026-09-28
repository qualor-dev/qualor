import { spawnSync, type SpawnSyncOptions } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Pinned so every binary is built by the same bun (spike version). */
export const BUN_VERSION = '1.3.13';
/** linux-x64 and linux-arm64 in Phase 1. */
export const TARGETS = { 'linux-x64': 'bun-linux-x64', 'linux-arm64': 'bun-linux-arm64' } as const;
export type Target = keyof typeof TARGETS;

/**
 * the release also builds macOS and Windows binaries. `pnpm --filter @qualor/cli
 * build` keeps building TARGETS, the two Linux binaries CI smoke-tests; the macOS ones are
 * unverified until a Mac runs them. The release passes every
 * target's runtime, the host's own included, pinned by hash and checked, as
 * `--compile-executable-path` (ruling R-MAC, extended to all targets in the fix wave;
 * tools/release/runtimes.ts), so no release binary carries a runtime bun fetched or was itself.
 *
 * Known and accepted, not pinned by hash: the bun that compiles is installed by version only
 * (`oven-sh/setup-bun` in GitHub Actions, `npm install -g bun@1.3.13` in .gitlab-ci.yml), and
 * the scanner image's own `qualor` binary is built by `bun build --compile` in
 * deploy/scanner/Dockerfile from `npm install -g bun@1.3.13` (npm checks the registry's
 * integrity, but nothing in this repository pins it), with the running bun as its runtime.
 */
export const RELEASE_TARGETS = {
  ...TARGETS,
  'darwin-x64': 'bun-darwin-x64',
  'darwin-arm64': 'bun-darwin-arm64',
  'windows-x64': 'bun-windows-x64',
} as const;
export type ReleaseTarget = keyof typeof RELEASE_TARGETS;

export function releaseBinaryName(version: string, target: ReleaseTarget): string {
  return `qualor-${version}-${target}${target.startsWith('windows-') ? '.exe' : ''}`;
}

export const CLI_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Runs bun. On Windows, npm installs bun as a `.cmd` shim, which Node only starts through a shell. */
export function bun(args: readonly string[], options: SpawnSyncOptions) {
  if (process.platform !== 'win32') return spawnSync('bun', args, options);
  const quoted = args.map((a) => (/[\s"&|<>^]/.test(a) ? `"${a}"` : a)).join(' ');
  return spawnSync(`bun ${quoted}`, { ...options, shell: true });
}

export function outputPath(target: Target): string {
  return path.join(CLI_DIR, 'dist', `qualor-${target}`);
}

/**
 * A compiled bun binary loads .env and bunfig.toml from its working directory by default. The CLI
 * runs inside the scanned repository, which could then set QUALOR_CA_FILE or HTTPS_PROXY (ruling
 * V8), so every binary is built with all four autoloads off.
 */
export const NO_AUTOLOAD = [
  '--no-compile-autoload-dotenv',
  '--no-compile-autoload-bunfig',
  '--no-compile-autoload-tsconfig',
  '--no-compile-autoload-package-json',
] as const;

export function bunBuildArgs(target: Target): string[] {
  return [
    'build',
    '--compile',
    ...NO_AUTOLOAD,
    `--target=${TARGETS[target]}`,
    path.join(CLI_DIR, 'src', 'entry.bun.ts'),
    '--outfile',
    outputPath(target),
  ];
}

export function bunReleaseArgs(
  target: ReleaseTarget,
  outfile: string,
  executablePath?: string,
): string[] {
  return [
    'build',
    '--compile',
    ...NO_AUTOLOAD,
    `--target=${RELEASE_TARGETS[target]}`,
    ...(executablePath === undefined ? [] : [`--compile-executable-path=${executablePath}`]),
    path.join(CLI_DIR, 'src', 'entry.bun.ts'),
    '--outfile',
    outfile,
  ];
}

function isTarget(value: string): value is Target {
  return Object.hasOwn(TARGETS, value);
}

export function parseTargets(args: readonly string[]): Target[] {
  if (args.length === 0) return Object.keys(TARGETS).filter(isTarget);
  return args.map((a) => {
    if (!isTarget(a)) {
      throw new Error(`unknown target ${a}; expected one of ${Object.keys(TARGETS).join(', ')}`);
    }
    return a;
  });
}

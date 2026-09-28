/**
 * SBOMs (release.md §8): SPDX 2.3 JSON from Syft in the toolbox. Images are read from the
 * dry-run registry (plain HTTP on the internal network); the CLI from a production-only install of
 * @qualor/cli, which is what `bun build --compile` bundles.
 */
export const SBOM_IMAGES = ['server', 'scanner', 'scanner-dotnet'] as const;
/** For a `registry:` source on the dry-run registry only, which speaks plain HTTP. */
export const REGISTRY_SOURCE_ENV = { SYFT_REGISTRY_INSECURE_USE_HTTP: 'true' };

export const syftArgs = (source: string, out: string): string[] => [
  'scan',
  source,
  '-o',
  `spdx-json=${out}`,
  '--quiet',
];

/**
 * The CLI's SBOM: Syft's directory catalogers read lock files, not installed packages, so a plain
 * `dir:` scan of the production install lists none of the npm packages (and picks up the test
 * fixtures of cli/test instead). Only the package.json cataloger, over its node_modules, lists
 * exactly what `bun build --compile` bundles (checked with Syft 1.52.0 on 2026-09-26).
 */
export const CLI_CATALOGERS = ['--override-default-catalogers', 'javascript-package-cataloger'];
/** The SBOM names the binary (`qualor-cli` at the release version), not the scanned directory. */
export const CLI_SBOM_NAME = 'qualor-cli';
export const cliSbomArgs = (depsDir: string, out: string, version: string): string[] => [
  ...syftArgs(`dir:${depsDir}/node_modules`, out),
  ...CLI_CATALOGERS,
  '--source-name',
  CLI_SBOM_NAME,
  '--source-version',
  version,
];

/**
 * pnpm 10 needs --legacy to deploy without inject-workspace-packages. --offline: only the
 * lockfile and the local store, which `pnpm install` filled; nothing is fetched.
 */
export const cliDepsArgs = (dir: string): string[] => [
  '--filter',
  '@qualor/cli',
  'deploy',
  '--prod',
  '--legacy',
  '--offline',
  dir,
];

/** pnpm through its own JS entry (npm_execpath), which also works on Windows without a shell. */
export function pnpmCommand(): { command: string; args: string[] } {
  const entry = process.env['npm_execpath'];
  if (!entry) {
    throw new Error('run this through pnpm (pnpm release:dry-run), which sets npm_execpath');
  }
  return { command: process.execPath, args: [entry] };
}

export function spdxProblems(json: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return ['not JSON'];
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return ['not an SPDX document'];
  }
  const doc = parsed as { spdxVersion?: unknown; documentNamespace?: unknown; packages?: unknown };
  const problems: string[] = [];
  if (doc.spdxVersion !== 'SPDX-2.3') {
    problems.push(`spdxVersion is ${String(doc.spdxVersion)}, not SPDX-2.3`);
  }
  if (typeof doc.documentNamespace !== 'string' || doc.documentNamespace === '') {
    problems.push('no documentNamespace');
  }
  if (!Array.isArray(doc.packages) || doc.packages.length === 0) problems.push('no packages');
  return problems;
}

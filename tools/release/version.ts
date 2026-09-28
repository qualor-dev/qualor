import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { REPO_ROOT } from '../deploy/stack';

/** release.md §2: one SemVer version for every package, constant and the chart. */
const IDENT = '(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)';
const SEMVER = new RegExp(
  `^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-(${IDENT}(?:\\.${IDENT})*))?$`,
);

export interface Version {
  text: string;
  major: number;
  minor: number;
  patch: number;
  prerelease: string | null;
}

/** Build metadata (`+…`) is refused: image tags cannot hold a "+". */
export function parseVersion(text: string): Version {
  const m = SEMVER.exec(text);
  if (!m) throw new Error(`not a SemVer version (x.y.z or x.y.z-pre.N): "${text}"`);
  return {
    text,
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] ?? null,
  };
}

/** `pnpm release:version <x.y.z>`: exactly one argument (after pnpm's optional `--`). */
export function versionArgument(args: readonly string[]): Version {
  const rest = args[0] === '--' ? args.slice(1) : args;
  if (rest.length !== 1) throw new Error('usage: pnpm release:version <x.y.z>');
  return parseVersion(rest[0] ?? '');
}

export const gitTag = (v: Version): string => `v${v.text}`;

/**
 * Decided 2026-09-26: 0.x gets 0.y.z and 0.y, never a floating 0 (0.x promises no
 * compatibility across minors); from 1.0, x.y.z, x.y and x. A pre-release gets only its full
 * version. Never latest. The moving tags follow the newest stable release of their line and never
 * go backwards: `released` is every version already released (the `v*` git tags,
 * releasedVersions), and a moving tag is dropped when a newer release of its line holds it, so
 * a backport 1.2.4 after 1.3.0 gets 1.2.4 and 1.2, not 1.
 */
export function imageTags(v: Version, released: readonly Version[]): string[] {
  if (v.prerelease !== null) return [v.text];
  const newer = released.filter((r) => r.prerelease === null && compareVersions(r, v) > 0);
  const tags = [v.text];
  if (!newer.some((r) => r.major === v.major && r.minor === v.minor)) {
    tags.push(`${v.major}.${v.minor}`);
  }
  if (v.major > 0 && !newer.some((r) => r.major === v.major)) tags.push(`${v.major}`);
  return tags;
}

/** Orders stable versions by major, minor, patch; a pre-release sorts before its release. */
export function compareVersions(a: Version, b: Version): number {
  const d = a.major - b.major || a.minor - b.minor || a.patch - b.patch;
  if (d !== 0) return d;
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  return a.prerelease < b.prerelease ? -1 : 1;
}

/** The released versions: the `v<SemVer>` git tags of the checkout (others are ignored). */
export function releasedVersions(
  root = REPO_ROOT,
  git: (args: string[]) => string = (args) =>
    execFileSync('git', args, { cwd: root, encoding: 'utf8' }),
): Version[] {
  const out: Version[] = [];
  for (const tag of git(['tag', '--list', 'v*']).split(/\r?\n/)) {
    try {
      if (tag.startsWith('v')) out.push(parseVersion(tag.slice(1)));
    } catch {
      // not a release tag
    }
  }
  return out;
}

export const PACKAGE_FILES = [
  'cli/package.json',
  'server/package.json',
  'ui/package.json',
  'packages/shared/package.json',
  'enterprise/package.json',
];
export const CONSTANT_FILES = [
  'server/src/index.ts',
  'cli/src/index.ts',
  'packages/shared/src/index.ts',
];
export const CHART_FILE = 'deploy/helm/qualor/Chart.yaml';
/** The committed OpenAPI document carries VERSION in `info.version` (openapi.test.ts compares). */
export const OPENAPI_FILE = 'server/openapi.json';

const PACKAGE_VERSION = /^(\s*"version":\s*")([^"]*)(")/m;
const CONSTANT = /^(export const VERSION = ')([^']*)(';)$/m;
const CHART_VERSION = /^(version: )(\S+)()$/m;
/**
 * Prettier writes the chart's appVersion single-quoted (singleQuote); either quote is accepted, as
 * long as it closes with the quote it opened with (the lookahead).
 */
const CHART_APP_VERSION = /^(appVersion: (?:'(?=[^']*'$)|"(?=[^"]*"$)))([^"']*)(["'])$/m;
/** The first "version" inside the top-level "info" object, as serializeOpenApi writes it. */
const OPENAPI_INFO_VERSION = /^( {2}"info": \{\n(?: {4}.*\n)*? {4}"version": ")([^"]*)(")/m;

const read = (root: string, file: string): string => readFileSync(path.join(root, file), 'utf8');

export function readVersions(root = REPO_ROOT): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of PACKAGE_FILES) out[f] = PACKAGE_VERSION.exec(read(root, f))?.[2] ?? '(none)';
  for (const f of CONSTANT_FILES) out[f] = CONSTANT.exec(read(root, f))?.[2] ?? '(none)';
  out[OPENAPI_FILE] = OPENAPI_INFO_VERSION.exec(read(root, OPENAPI_FILE))?.[2] ?? '(none)';
  // Required (ruling RE6): a checkout without the chart fails here, naming the file.
  const chart = read(root, CHART_FILE);
  out[`${CHART_FILE} version`] = CHART_VERSION.exec(chart)?.[2] ?? '(none)';
  out[`${CHART_FILE} appVersion`] = CHART_APP_VERSION.exec(chart)?.[2] ?? '(none)';
  return out;
}

export function versionProblems(versions: Record<string, string>): string[] {
  if (new Set(Object.values(versions)).size <= 1) return [];
  const list = Object.entries(versions).map(([where, v]) => `${where} ${v}`);
  return [`the versions differ: ${list.join(', ')}`];
}

export function currentVersion(root = REPO_ROOT): Version {
  const versions = readVersions(root);
  const problems = versionProblems(versions);
  if (problems.length > 0)
    throw new Error(`${problems.join('\n')}\nrun pnpm release:version <x.y.z>`);
  return parseVersion(Object.values(versions)[0] ?? '');
}

function replaced(root: string, file: string, patterns: RegExp[], v: Version): string {
  let text = read(root, file);
  for (const p of patterns) {
    if (!p.test(text)) throw new Error(`${file}: no version found (${p.source})`);
    text = text.replace(p, (_m, a: string, _old: string, b: string) => `${a}${v.text}${b}`);
  }
  return text;
}

/**
 * Sets every location of release.md §2, and `info.version` of server/openapi.json; returns the
 * files changed. Atomic in effect: every file is read and checked before the first is written,
 * so a file without its version changes nothing.
 */
export function setVersion(root: string, v: Version): string[] {
  const plan: [string, RegExp[]][] = [
    ...PACKAGE_FILES.map((f): [string, RegExp[]] => [f, [PACKAGE_VERSION]]),
    ...CONSTANT_FILES.map((f): [string, RegExp[]] => [f, [CONSTANT]]),
    [OPENAPI_FILE, [OPENAPI_INFO_VERSION]],
    [CHART_FILE, [CHART_VERSION, CHART_APP_VERSION]],
  ];
  const texts = plan.map(([f, patterns]) => [f, replaced(root, f, patterns, v)] as const);
  for (const [f, text] of texts) writeFileSync(path.join(root, f), text);
  return texts.map(([f]) => f);
}

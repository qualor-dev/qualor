import { spawnSync } from 'node:child_process';
import { cpSync, readdirSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  engineMapping,
  parseConfig,
  splitSourceLines,
  type QualorConfig,
  type QualorConfigInput,
} from '@qualor/shared';
import { parse } from 'yaml';
import { describe, expect } from 'vitest';
import { findRepoBinary, resolveBinary } from '../src/analyzers/binary';
import { fileLines, normalizeCaptures, type NormalizedEngines } from '../src/analyzers/normalize';
import type { ProcessResult } from '../src/analyzers/process';
import { runAnalyzers } from '../src/analyzers/runner';
import type { Analyzer, AnalyzerContext, ExecOptions, SarifCapture } from '../src/analyzers/types';
import { discoverFiles } from '../src/discovery/discover';
import { silentLogger } from '../src/log';
import { Warnings } from '../src/warnings';
import { FIXTURES_DIR, loadFixture } from './fixtures';

const here = path.dirname(fileURLToPath(import.meta.url));
/** Recorded real tool output that is not SARIF, or SARIF only the CLI tests use. */
export const ANALYZER_OUTPUT_DIR = path.join(here, 'analyzer-output');
/** The real SARIF samples of Phase 0 (rebased to `file:///fixture-root`), shared with the golden tests. */
export const SARIF_SAMPLES_DIR = path.resolve(here, '../../packages/shared/test/sarif-samples');

export function recorded(name: string): unknown {
  return JSON.parse(readFileSync(path.join(ANALYZER_OUTPUT_DIR, name), 'utf8')) as unknown;
}

export function sarifSample(engineId: string): unknown {
  return JSON.parse(
    readFileSync(path.join(SARIF_SAMPLES_DIR, `${engineId}.sarif`), 'utf8'),
  ) as unknown;
}

/**
 * Ruling T4 of plan 1B, extended by plan 1D: a test that needs a real analyzer binary runs where
 * the binary is installed and skips elsewhere (a Windows laptop), but CI sets
 * `QUALOR_REQUIRE_ANALYZERS=1`, which makes it run, and fail, when the tool is missing.
 */
export const REQUIRE_ANALYZERS = requireAnalyzers(process.env['QUALOR_REQUIRE_ANALYZERS']);

/** Only `1` turns the gate on; any other non-empty value is a typo worth a warning, not a skip. */
export function requireAnalyzers(
  value: string | undefined,
  warn: (message: string) => void = console.warn,
): boolean {
  if (value !== undefined && value !== '' && value !== '1') {
    warn(`QUALOR_REQUIRE_ANALYZERS=${value} is ignored: set it to 1 to require the analyzers`);
  }
  return value === '1';
}

export function toolInstalled(name: string): boolean {
  return resolveBinary(name, { root: process.cwd(), env: process.env }) !== null;
}

/** `describe` that runs when every tool of every group (any one of a group) is installed. */
export function describeWithTools(
  groups: readonly (string | readonly string[])[],
): typeof describe {
  const ok = groups.every((g) => (typeof g === 'string' ? [g] : g).some(toolInstalled));
  return describe.runIf(REQUIRE_ANALYZERS || ok) as typeof describe;
}

/**
 * Plan 2D (probe P6), Linux only (ruling R8): a real `dotnet build` writes the hook into
 * MSBuild's user directory, and only Linux lets a test isolate it there (`XDG_DATA_HOME`). Never
 * on Windows, where it would land in the developer's real profile. Never on macOS either: since
 * .NET 8, MSBuild's user extensions path there ignores `XDG_DATA_HOME` (ruling R6), and
 * `QUALOR_MSBUILD_USER_DIR` only steers the CLI's own write, not the real MSBuild process a test
 * spawns — nothing here would keep a real build off the developer's actual profile.
 */
export function describeWithDotnet(): typeof describe {
  const ok = process.platform === 'linux' && (REQUIRE_ANALYZERS || toolInstalled('dotnet'));
  return describe.runIf(ok) as typeof describe;
}

export interface FakeContextOptions {
  config?: Omit<QualorConfigInput, 'version'>;
  binaries?: Readonly<Record<string, string>>;
  exec?: (command: string, args: readonly string[], options: ExecOptions) => ProcessResult;
  workDir?: string;
  /**
   * With `env` and without `binaries`, binaries resolve for real (`resolveBinary` and
   * `findRepoBinary` with this PATH). `env` is also the context's analyzer environment.
   */
  env?: Readonly<Record<string, string | undefined>>;
}

/** An `AnalyzerContext` for `prepare()` unit tests: no process is ever started. */
export function fakeContext(root: string, o: FakeContextOptions = {}): AnalyzerContext {
  const config: QualorConfig = parseConfig({ version: 1, ...o.config });
  const exec =
    o.exec ?? (() => ({ exitCode: 0, timedOut: false, durationMs: 1, stdout: '', stderr: '' }));
  return {
    root,
    config,
    languages: new Set(['typescript', 'javascript', 'java']),
    files: [],
    workDir: o.workDir ?? path.join(root, '.work'),
    log: silentLogger,
    dotnet: null,
    resolveBinary: (name) =>
      o.env === undefined || o.binaries !== undefined
        ? (o.binaries?.[name] ?? null)
        : resolveBinary(name, { root, env: o.env }),
    repoBinary: (name) =>
      o.env === undefined || o.binaries !== undefined
        ? null
        : findRepoBinary(name, { root, env: o.env }),
    env: o.env ?? {},
    exec: (command, args, options) => Promise.resolve(exec(command, args, options)),
  };
}

function filesUnder(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => path.relative(dir, path.join(d.parentPath, d.name)).split(path.sep).join('/'));
}

/**
 * Normalises recorded SARIF (paths under `/fixture-root`) against a fixture's sources exactly as
 * `runScan` does, through `normalizeCaptures`, with the analyzer's mapping, source roots and rule
 * languages.
 */
export function normalizeRecorded(
  sarif: unknown,
  analyzer: Pick<Analyzer, 'id' | 'ruleLanguages'>,
  fixture: string,
  sourceRoots: readonly string[] = [],
): NormalizedEngines {
  const dir = path.join(FIXTURES_DIR, fixture);
  const mapping = engineMapping(analyzer.id);
  const capture: SarifCapture = {
    engineId: analyzer.id,
    kind: 'builtin',
    status: 'ok',
    reason: null,
    durationMs: 1,
    version: null,
    required: false,
    sarif,
    sourceRoots,
    ...(mapping !== undefined && { mapping }),
    ...(analyzer.ruleLanguages !== undefined && { ruleLanguages: analyzer.ruleLanguages }),
  };
  return normalizeCaptures([capture], {
    repoRoot: '/fixture-root',
    readLines: (p) => {
      try {
        return splitSourceLines(readFileSync(path.join(dir, p), 'utf8'));
      } catch {
        return null;
      }
    },
    knownPaths: new Set(filesUnder(dir)),
    log: silentLogger,
  });
}

type FindingLike = {
  engineId: string;
  ruleId: string;
  severity?: string | undefined;
  location: { path: string; startLine: number } | null;
};

/** `ruleKey path:line [severity]`, the same key `compareFixture` matches on. */
export function findingKeys(findings: readonly FindingLike[]): string[] {
  return findings
    .map(
      (f) =>
        `${f.engineId}:${f.ruleId} ${f.location?.path ?? '(project)'}:${f.location?.startLine ?? 1} [${f.severity}]`,
    )
    .sort();
}

/** The fixture's `expected.json` findings of one engine, in `findingKeys` form. */
export function expectedKeys(fixture: string, engineId: string): string[] {
  return loadFixture(fixture)
    .expected.findings.filter((f) => f.ruleKey.startsWith(`${engineId}:`))
    .map((f) => `${f.ruleKey} ${f.path}:${f.startLine} [${f.severity}]`)
    .sort();
}

/** `javac` of every `src/main/java` file into `target/classes`, as a Maven build would. */
export function compileJava(root: string): void {
  const src = path.join(root, 'src', 'main', 'java');
  const sources = filesUnder(src)
    .filter((p) => p.endsWith('.java'))
    .map((p) => path.join(src, p));
  const javac = resolveBinary('javac', { root, env: process.env });
  if (javac === null) throw new Error('javac is not installed');
  const r = spawnSync(
    javac,
    [
      '--release',
      '17',
      '-encoding',
      'UTF-8',
      '-d',
      path.join(root, 'target', 'classes'),
      ...sources,
    ],
    { encoding: 'utf8' },
  );
  if (r.status !== 0) throw new Error(`javac failed: ${r.stderr}`);
}

/**
 * Copies a fixture to `dir`, lets `prepareCopy` add what the tool needs (compiled classes, a
 * node_modules link, another qualor.yml), then runs the real adapter through the runner and the
 * normaliser with the copy's own qualor.yml.
 */
export async function scanFixtureWith(
  analyzer: Analyzer,
  fixture: string,
  dir: string,
  prepareCopy: (root: string) => void = () => undefined,
): Promise<{ capture: SarifCapture; out: NormalizedEngines; keys: string[] }> {
  cpSync(path.join(FIXTURES_DIR, fixture), dir, { recursive: true });
  prepareCopy(dir);
  const config = parseConfig(parse(readFileSync(path.join(dir, 'qualor.yml'), 'utf8')));
  const files = discoverFiles({ root: dir, config, warnings: new Warnings(), log: silentLogger });
  const [capture] = await runAnalyzers([analyzer], { root: dir, config, files, log: silentLogger });
  if (capture === undefined) throw new Error('no capture');
  const out = normalizeCaptures([capture], {
    repoRoot: dir,
    readLines: fileLines(dir),
    knownPaths: new Set(files.map((f) => f.path)),
    log: silentLogger,
  });
  expect(out.engines[0]?.status, out.engines[0]?.reason ?? '').toBe('ok');
  return { capture, out, keys: findingKeys(out.findings) };
}

/**
 * An HTTP listener on 127.0.0.1 that records every request (ruling V5 probes: an analyzer must
 * never reach it). Loopback works under `docker run --network none` too.
 */
export async function startListener(): Promise<{
  url: string;
  hits: string[];
  close: () => Promise<void>;
}> {
  const hits: string[] = [];
  const server = createServer((req, res) => {
    hits.push(`${req.method ?? ''} ${req.url ?? ''}`);
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no port');
  return {
    url: `http://127.0.0.1:${address.port}`,
    hits,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

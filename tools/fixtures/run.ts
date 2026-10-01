import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import {
  compareFixture,
  cppcheckVersionSupported,
  DEPENDENCY_ENGINES,
  engineRuleDefaults,
  expectedSchema,
  reportFingerprints,
  reportSchema,
  splitSourceLines,
  type Expected,
  type Mismatch,
  type Report,
} from '@qualor/shared';
import { codeQualityValidator, dependencyScanningValidator, sastValidator } from '../../cli/test/gitlab-schema';
import { checkLlmFixture } from './llm-check';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const fixturesDir = path.join(root, 'fixtures');

export type ProblemKind = Mismatch['kind'] | 'static' | 'scan';
export interface Problem {
  kind: ProblemKind;
  detail: string;
}
export interface FixtureOutcome {
  name: string;
  problems: Problem[];
  /** Expected engines whose tool is not installed here (ruling T4): their findings are not checked. */
  unavailable?: string[];
}
/** A fixture that cannot pass yet: only mismatches of `kinds` are tolerated (ruling C17). */
export interface PendingEntry {
  reason: string;
  kinds: Mismatch['kind'][];
}
export type ScanFn = (fixtureDir: string, name: string, expected: Expected) => Problem[];

/** A pseudo-tool: Trivy's vulnerability database in the scanner image's place (config.md §6). */
export const TRIVY_DATABASE = 'trivy-db';
const TRIVY_DATABASE_FILE = '/opt/qualor/share/trivy/db/trivy.db';

/**
 * A pseudo-tool: Qualor's own sonarjs pass in the scanner image's place (config.md §6). Like
 * Trivy's database above, its absence is a normal skip (a plain host without the qualor/scanner
 * image), not a configuration problem, and the scan environment of a fixture drops every QUALOR_
 * variable (QUALOR_SONARJS_DIR included), so only the default path is ever checked here.
 */
export const SONARJS_PASS = 'sonarjs-pass';
const SONARJS_PASS_FILE = '/opt/qualor/sonarjs/run.mjs';

/**
 * A pseudo-tool: Qualor's HTML and CSS passes in the scanner image's place (config.md §6), a skip
 * when absent like sonarjs's; the scan environment drops QUALOR_WEBLINT_DIR, so only the default
 * path is ever checked here.
 */
export const WEBLINT_PASS = 'weblint-pass';
const WEBLINT_PASS_FILES = ['/opt/qualor/weblint/stylelint.mjs', '/opt/qualor/weblint/htmlhint.mjs'];

/**
 * A pseudo-tool: detekt's jar in the scanner image's place (config.md §6, plan 8E). Like the
 * sonarjs pass, its absence is a normal skip on a plain host, and a fixture's scan environment
 * drops QUALOR_DETEKT_JAR, so only the default path is ever checked here.
 */
export const DETEKT_JAR = 'detekt-jar';
const DETEKT_JAR_FILE = '/opt/qualor/lib/detekt/detekt-cli.jar';

/**
 * Plan 9D: the fixtures' cppcheck findings are cppcheck 2.22's (fact F12), and the engine skips
 * another minor: this pseudo-tool is present only for a cppcheck of the pinned minor.
 */
export const CPPCHECK_PINNED = 'cppcheck-pinned';

/** Plan 9D: present only for a clang-tidy of the major install-clang-tidy.sh pins (22). */
export const CLANG_TIDY_PINNED = 'clang-tidy-pinned';

function pinnedClangTidyMajor(): string | null {
  const script = readFileSync(path.join(root, 'tools/analyzers/install-clang-tidy.sh'), 'utf8');
  return /^CLANG_TIDY_VERSION=(\d+)\./m.exec(script)?.[1] ?? null;
}

/** What `<tool> --version` prints, matched by `re`'s first group; null without the tool. */
function toolVersion(tool: string, re: RegExp, env: Record<string, string | undefined>): string | null {
  const bin = findTool(tool, env);
  if (bin === null) return null;
  const r = spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: 30_000 });
  return r.status === 0 ? (re.exec(r.stdout ?? '')?.[1] ?? null) : null;
}

/**
 * The binaries each built-in engine needs (any one of an inner list). The harness checks the same
 * places the CLI does: PATH and the scanner image's /opt/qualor/bin.
 */
const ENGINE_TOOLS: Readonly<Record<string, readonly (readonly string[])[]>> = {
  eslint: [['node']],
  pmd: [['pmd']],
  spotbugs: [['spotbugs'], ['javac']],
  semgrep: [['opengrep', 'semgrep']],
  gitleaks: [['gitleaks']],
  // Plan 2B: the binary and its database, where the scanner image keeps it (the scan environment
  // of a fixture drops every QUALOR_ variable, QUALOR_TRIVY_CACHE_DIR included).
  trivy: [['trivy'], [TRIVY_DATABASE]],
  // Plan 2D: a real build writes the MSBuild hook into the user profile. Linux only (ruling R8):
  // the harness isolates it there with XDG_DATA_HOME (probe P6). Never on Windows, where it would
  // land in the developer's real profile; never on macOS either, since .NET 8 (ruling R6) moved
  // MSBuild's user extensions path off XDG_DATA_HOME there and QUALOR_MSBUILD_USER_DIR only steers
  // the CLI's own write, not the real MSBuild process the fixture spawns.
  roslyn: [['dotnet']],
  // Plan 8A/8B: needs node and, like trivy above, its image-bundled resource.
  sonarjs: [['node'], [SONARJS_PASS]],
  // Plan 8C: the Ruff binary (install.sh).
  ruff: [['ruff']],
  // Plan 8D: node and, like sonarjs above, the image-bundled weblint pass.
  stylelint: [['node'], [WEBLINT_PASS]],
  htmlhint: [['node'], [WEBLINT_PASS]],
  // Plan 8E: java and, like sonarjs above, the image-bundled detekt jar.
  detekt: [['java'], [DETEKT_JAR]],
  // Plan 8F: SwiftLint's static binary, from install.sh (/opt/qualor/bin).
  swiftlint: [['swiftlint']],
  // Plan 9D: cppcheck of the pinned minor, built by install-cppcheck.sh (/opt/qualor/bin).
  cppcheck: [[CPPCHECK_PINNED]],
  // Plan 9D: clang-tidy of the pinned major, from install-clang-tidy.sh (tests only, decision 2).
  'clang-tidy': [[CLANG_TIDY_PINNED]],
};

/**
 * The absolute path of a tool in an absolute PATH entry or the scanner image's /opt/qualor/bin,
 * as the CLI resolves it (ruling V3: a relative PATH entry is never used).
 */
export function findTool(name: string, env: Record<string, string | undefined> = process.env): string | null {
  const win = process.platform === 'win32';
  const dirs = [...(env['PATH'] ?? env['Path'] ?? '').split(win ? ';' : ':'), '/opt/qualor/bin'].filter((d) => path.isAbsolute(d));
  for (const d of dirs) {
    for (const f of win ? [`${name}.exe`] : [name]) {
      if (existsSync(path.join(d, f))) return path.join(d, f);
    }
  }
  return null;
}

export function toolOnPath(name: string, env: Record<string, string | undefined> = process.env): boolean {
  if (name === TRIVY_DATABASE) return existsSync(TRIVY_DATABASE_FILE);
  if (name === SONARJS_PASS) return existsSync(SONARJS_PASS_FILE);
  if (name === DETEKT_JAR) return existsSync(DETEKT_JAR_FILE);
  if (name === WEBLINT_PASS) return WEBLINT_PASS_FILES.every((f) => existsSync(f));
  if (name === CPPCHECK_PINNED) {
    const v = toolVersion('cppcheck', /^Cppcheck (\S+)$/m, env);
    return v !== null && cppcheckVersionSupported(v);
  }
  if (name === CLANG_TIDY_PINNED) {
    const major = toolVersion('clang-tidy', /LLVM version (\d+)\./, env);
    return major !== null && major === pinnedClangTidyMajor();
  }
  return findTool(name, env) !== null;
}

/**
 * Expected engines that cannot run here because a tool they need is not installed, or, for
 * roslyn, because the host is not Linux (ruling R8): on Windows the hook would land in the real
 * user profile; on macOS, since .NET 8 changed the MSBuild user extensions path away from
 * `XDG_DATA_HOME` (ruling R6), nothing this harness sets isolates a real build there either —
 * `QUALOR_MSBUILD_USER_DIR` only steers the CLI's own write, not the real MSBuild process the
 * fixture spawns, which still reads the developer's actual profile.
 */
export function unavailableEngines(
  engines: readonly string[],
  has: (tool: string) => boolean = toolOnPath,
  platform: NodeJS.Platform = process.platform,
): string[] {
  return engines.filter(
    (e) =>
      (e === 'roslyn' && platform !== 'linux') ||
      (ENGINE_TOOLS[e] ?? []).some((anyOf) => !anyOf.some((tool) => has(tool))),
  );
}

/** A .NET fixture: a solution file (`.slnx` or `.sln`) at its root. */
export function isDotnetFixture(dir: string): boolean {
  return readdirSync(dir).some((n) => n.endsWith('.slnx') || n.endsWith('.sln'));
}

/** CI sets this: a missing analyzer is then a failure, never a skip. */
export const REQUIRE_ANALYZERS = requireAnalyzers(process.env['QUALOR_REQUIRE_ANALYZERS']);

/** Only `1` turns the gate on; any other non-empty value is a typo worth a warning, not a skip. */
export function requireAnalyzers(value: string | undefined, warn: (message: string) => void = console.warn): boolean {
  if (value !== undefined && value !== '' && value !== '1') {
    warn(`QUALOR_REQUIRE_ANALYZERS=${value} is ignored: set it to 1 to require the analyzers`);
  }
  return value === '1';
}

/** Ruling C17: only analyzer output may stay pending until the adapters land (CLI steps 8-12). */
const PENDABLE: readonly Mismatch['kind'][] = ['engine', 'missing-finding'];

export function parsePending(raw: unknown): Record<string, PendingEntry> {
  const fail = (why: string): never => {
    throw new Error(`tools/fixtures/known-pending.json: ${why}`);
  };
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) fail('expected an object');
  const out: Record<string, PendingEntry> = {};
  for (const [name, entry] of Object.entries(raw as Record<string, unknown>)) {
    const e = entry as { reason?: unknown; kinds?: unknown };
    if (typeof e !== 'object' || e === null || typeof e.reason !== 'string' || e.reason === '') {
      fail(`${name}: needs a non-empty "reason"`);
    }
    const kinds = Array.isArray(e.kinds) ? e.kinds : [];
    if (kinds.length === 0 || !kinds.every((k) => (PENDABLE as readonly unknown[]).includes(k))) {
      fail(`${name}: "kinds" must list some of ${PENDABLE.join(', ')}`);
    }
    out[name] = { reason: e.reason as string, kinds: kinds as Mismatch['kind'][] };
  }
  return out;
}

/** Static checks that must hold even before the CLI exists. */
export function checkFixtureStatic(dir: string, expected: Expected): string[] {
  const problems: string[] = [];
  const lineCount = (p: string) => splitSourceLines(readFileSync(path.join(dir, p), 'utf8')).length;
  const exists = (p: string) => existsSync(path.join(dir, p)) && statSync(path.join(dir, p)).isFile();
  for (const f of expected.findings) {
    if (!exists(f.path)) problems.push(`finding path missing: ${f.path}`);
    else if (f.startLine > lineCount(f.path)) problems.push(`finding line out of range: ${f.path}:${f.startLine}`);
  }
  for (const p of Object.keys(expected.files)) if (!exists(p)) problems.push(`file missing: ${p}`);
  for (const g of expected.duplications) {
    for (const b of g.blocks) {
      if (!exists(b.path)) problems.push(`duplication path missing: ${b.path}`);
      else if (b.endLine > lineCount(b.path) || b.startLine > b.endLine) {
        problems.push(`duplication range invalid: ${b.path}:${b.startLine}-${b.endLine}`);
      }
    }
  }
  if (!exists('qualor.yml')) problems.push('qualor.yml missing');
  return problems;
}

const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*)$/i;

/** The scan must not see the harness's own CI (it would try to diff against origin). */
export function scanEnv(
  env: Record<string, string | undefined>,
  emptyGitConfig: string,
): Record<string, string | undefined> {
  return {
    ...Object.fromEntries(Object.entries(env).filter(([key]) => !CI_VARIABLE.test(key))),
    // Isolated from the user's and the system's git configuration, like the CLI tests' GIT_TEST_ENV.
    GIT_CONFIG_GLOBAL: emptyGitConfig,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Qualor Fixtures',
    GIT_AUTHOR_EMAIL: 'fixtures@qualor.invalid',
    GIT_COMMITTER_NAME: 'Qualor Fixtures',
    GIT_COMMITTER_EMAIL: 'fixtures@qualor.invalid',
    QUALOR_LOG_LEVEL: 'warn',
  };
}

/** `QUALOR_BIN` runs a compiled binary (the cli-binary CI job); otherwise the TypeScript sources. */
export function scanCommand(): { command: string; args: string[] } {
  const bin = process.env['QUALOR_BIN'];
  if (bin !== undefined && bin !== '') return { command: path.resolve(root, bin), args: [] };
  return {
    command: process.execPath,
    args: ['--import', import.meta.resolve('tsx'), path.join(root, 'cli', 'src', 'cli.ts')],
  };
}

/** Every `.java` file under `dir`, absolute. */
function javaSources(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile() && d.name.endsWith('.java'))
    .map((d) => path.join(d.parentPath, d.name));
}

/**
 * What a CI job has in the workspace before `qualor scan` runs, and a fixture cannot commit: the
 * project's `node_modules` for ESLint (a link to the repo's own devDependencies, which include
 * ESLint, `@eslint/js` and `typescript-eslint`) and, for a Maven fixture, its compiled classes
 * (`javac` into `target/classes`, which the scan's built-in excludes keep out of scope). Added
 * after the fixture commit and excluded from git, like a real CI checkout plus a build. Returns
 * a problem when the build step fails; a missing `javac` is left to the capability check.
 */
export function prepareCopy(repo: string, javac: string | null = findTool('javac')): string | null {
  if (existsSync(path.join(repo, 'eslint.config.js'))) {
    symlinkSync(path.join(root, 'node_modules'), path.join(repo, 'node_modules'), 'junction');
    appendFileSync(path.join(repo, '.git', 'info', 'exclude'), '/node_modules\n');
  }
  const sources = javaSources(path.join(repo, 'src', 'main', 'java'));
  if (existsSync(path.join(repo, 'pom.xml')) && sources.length > 0 && javac !== null) {
    const classes = path.join(repo, 'target', 'classes');
    const r = spawnSync(javac, ['--release', '17', '-encoding', 'UTF-8', '-d', classes, ...sources], {
      encoding: 'utf8',
      timeout: 300_000,
    });
    if (r.status !== 0) return `javac failed: ${(r.stderr ?? '').trim()}`;
  }
  return null;
}

/** The last `lines` lines of a process's output, for a problem's detail. */
function tail(text: string, lines = 20): string {
  return text.trim().split(/\r?\n/).slice(-lines).join('\n');
}

/**
 * Plan 2D: what a CI job runs for a .NET repository before `qualor dotnet end`: `qualor dotnet
 * begin`, then the project's own build of the solution at the root, `--no-incremental` so every
 * project compiles inside the session. `env` must point XDG_DATA_HOME into the work directory, so
 * the hook and its leases (beside it, config.md §6.1) never touch the user's profile. Returns a
 * problem when a step fails.
 */
export function prepareDotnet(repo: string, env: Record<string, string | undefined>): string | null {
  const { command, args } = scanCommand();
  const begin = spawnSync(command, [...args, 'dotnet', 'begin'], { cwd: repo, env, encoding: 'utf8', timeout: 120_000 });
  if (begin.status !== 0) {
    return `qualor dotnet begin exited ${begin.status ?? begin.signal}: ${tail(begin.stderr ?? '')}`;
  }
  const solution = readdirSync(repo)
    .filter((n) => n.endsWith('.slnx') || n.endsWith('.sln'))
    .sort()[0];
  if (solution === undefined) return 'no .slnx or .sln at the root to build';
  const dotnet = findTool('dotnet', env) ?? 'dotnet';
  const build = spawnSync(dotnet, ['build', '--no-incremental', '-nologo', solution], {
    cwd: repo,
    env,
    encoding: 'utf8',
    timeout: 900_000,
  });
  if (build.status !== 0) {
    return `dotnet build exited ${build.status ?? build.signal}: ${tail(`${build.stdout ?? ''}\n${build.stderr ?? ''}`)}`;
  }
  return null;
}

/**
 * Ruling A6: `qualor scan` exits 3 when a required analyzer fails, and Gitleaks is required by
 * default. Outside CI that exit is acceptable only when every failed engine failed because its
 * tool is not installed here; with QUALOR_REQUIRE_ANALYZERS=1 it never is.
 */
export function exit3Acceptable(
  engines: readonly { id: string; status: string; reason?: string | null | undefined }[],
  o: { requireAnalyzers?: boolean; has?: (tool: string) => boolean } = {},
): boolean {
  if (o.requireAnalyzers ?? REQUIRE_ANALYZERS) return false;
  const failed = engines.filter((e) => e.status === 'failed' || e.status === 'timeout');
  return (
    failed.length > 0 &&
    failed.every((e) => (e.reason ?? '').includes('not installed') && unavailableEngines([e.id], o.has).length === 1)
  );
}

/** Source lines at least this long must never appear in the GitLab report files (scm.md §9). */
const SOURCE_LINE_PROBE_CHARS = 16;

/**
 * Ruling G6, from the report alone: an engine failed, timed out, or was skipped because its tool
 * cannot run here (the adapters' `unavailable` reasons: "… is not installed", "… needs java",
 * "… needs node"). Every other skip did what the configuration asked.
 */
function incompleteEngine(e: { status: string; reason?: string | null | undefined }): boolean {
  return (
    e.status === 'failed' ||
    e.status === 'timeout' ||
    (e.status === 'skipped' && /is not installed|needs (java|node)|database in .* cannot be read/.test(e.reason ?? ''))
  );
}

/**
 * scm.md §9: the GitLab files of a fixture scan (`null`: the file was not written; the Dependency
 * Scanning file is checked when `dependencyText` is given, plan 2B). Ruling G6: the
 * Code Quality file is missing exactly when the SAST scan is a `failure`, which is exactly when an
 * engine failed, timed out or was unavailable. Code Quality has GitLab's documented fields and one entry per located finding
 * with the server's fingerprint (most severe first, so compared as a multiset); SAST validates
 * against the vendored schema 15.1.4 and has one vulnerability per located security finding; and
 * no source line of the fixture (so no secret, whatever the analyzers found) appears in either
 * file. Anything unreadable is a problem, never a crash.
 */
export function checkGitLabReports(
  report: Report,
  codeQualityText: string | null,
  sastText: string | null,
  readSource: (path: string) => string,
  dependencyText?: string | null,
): Problem[] {
  const problems: Problem[] = [];
  const fail = (detail: string) => problems.push({ kind: 'scan', detail: `gitlab: ${detail}` });
  const parse = (what: string, text: string): unknown => {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      fail(`${what} is not JSON`);
      return undefined;
    }
  };
  const fingerprints = reportFingerprints(report.findings);
  const sastProblems: string[] = [];
  let sast: unknown;
  if (sastText === null) sastProblems.push('the SAST file was not written');
  else {
    try {
      sast = JSON.parse(sastText) as unknown;
      const validate = sastValidator();
      if (!validate(sast)) {
        sastProblems.push(`SAST is not valid: ${JSON.stringify(validate.errors).slice(0, 400)}`);
      }
    } catch {
      sastProblems.push('SAST is not JSON');
    }
  }
  const { scan, vulnerabilities } = (sast ?? {}) as {
    scan?: { status?: unknown };
    vulnerabilities?: unknown[];
  };
  const failed = scan?.status === 'failure';
  const incomplete = report.engines.some(incompleteEngine);
  if (codeQualityText === null) {
    if (!failed) fail('the Code Quality file is missing, but the SAST scan did not fail (ruling G6)');
    if (!incomplete) {
      fail('the Code Quality file is missing, but no engine failed, timed out or was unavailable (ruling G6)');
    }
  } else {
    if (failed) fail('the SAST scan failed, but the Code Quality file was written (ruling G6)');
    if (incomplete) {
      fail('the Code Quality file was written, but an engine failed, timed out or was unavailable (ruling G6)');
    }
    const entries = parse('Code Quality', codeQualityText);
    if (entries !== undefined) {
      const validateCodeQuality = codeQualityValidator();
      if (!validateCodeQuality(entries)) {
        fail(`Code Quality is not valid: ${JSON.stringify(validateCodeQuality.errors).slice(0, 400)}`);
      }
      const located = report.findings.flatMap((f, i) => (f.location ? [fingerprints[i] ?? ''] : []));
      const written = Array.isArray(entries)
        ? entries.map((e) => String((e as { fingerprint?: unknown }).fingerprint))
        : [];
      if (JSON.stringify([...written].sort()) !== JSON.stringify([...located].sort())) {
        fail(`Code Quality has ${written.length} entries, the report ${located.length} located findings`);
      }
    }
  }
  for (const problem of sastProblems) fail(problem);
  if (Array.isArray(vulnerabilities)) {
    const quality = new Map(
      report.engines.flatMap((e) => e.rules.map((r) => [`${e.id}:${r.id}`, r.quality] as const)),
    );
    const security = report.findings.filter(
      (f) =>
        f.location &&
        !DEPENDENCY_ENGINES.has(f.engineId) &&
        (quality.get(`${f.engineId}:${f.ruleId}`) ?? engineRuleDefaults(f.engineId).quality) === 'security',
    ).length;
    if (vulnerabilities.length !== security) {
      fail(`SAST has ${vulnerabilities.length} vulnerabilities, the report ${security} security findings`);
    }
  }
  if (dependencyText !== undefined) {
    if (dependencyText === null) fail('the Dependency Scanning file was not written');
    else {
      const ds = parse('Dependency Scanning', dependencyText) as
        | { scan?: { status?: unknown }; vulnerabilities?: unknown[] }
        | undefined;
      if (ds !== undefined) {
        const validate = dependencyScanningValidator();
        if (!validate(ds)) {
          fail(`Dependency Scanning is not valid: ${JSON.stringify(validate.errors).slice(0, 400)}`);
        }
        if ((ds.scan?.status === 'failure') !== incomplete) {
          fail('the Dependency Scanning scan status does not follow the engines (ruling G6)');
        }
        const dependencies = report.findings.filter((f) => f.location && DEPENDENCY_ENGINES.has(f.engineId)).length;
        if (!Array.isArray(ds.vulnerabilities) || ds.vulnerabilities.length !== dependencies) {
          fail(
            `Dependency Scanning has ${Array.isArray(ds.vulnerabilities) ? ds.vulnerabilities.length : 'no'} vulnerabilities, the report ${dependencies} dependency findings`,
          );
        }
      }
    }
  }
  const texts = [codeQualityText ?? '', sastText ?? '', dependencyText ?? ''];
  for (const file of report.files) {
    let source: string;
    try {
      source = readSource(file.path);
    } catch {
      fail(`the source of ${file.path} cannot be read to check the GitLab files`);
      continue;
    }
    for (const line of splitSourceLines(source)) {
      const probe = line.trim();
      if (probe.length < SOURCE_LINE_PROBE_CHARS) continue;
      if (texts.some((t) => t.includes(probe))) {
        fail(`a source line of ${file.path} is in a GitLab report file`);
      }
    }
  }
  return problems;
}

/** The file's text, or null when it does not exist. */
function readIfExists(file: string): string | null {
  return existsSync(file) ? readFileSync(file, 'utf8') : null;
}

/**
 * Plan 3A: a fixture with `sonarqube/data.json` also checks `qualor import sonarqube`'s mapping
 * and matching of that data against the scan's findings (`sonarqube-check.ts`, in a child process
 * of its own, since it serves the fake SonarQube and the harness runs synchronously). Nothing for
 * a fixture without it.
 */
export function checkSonarFixture(fixtureDir: string, report: string): Problem[] {
  if (!existsSync(path.join(fixtureDir, 'sonarqube', 'data.json'))) return [];
  const check = spawnSync(
    process.execPath,
    ['--import', import.meta.resolve('tsx'), path.join(root, 'tools', 'fixtures', 'sonarqube-check.ts'), fixtureDir, report],
    { cwd: root, encoding: 'utf8', timeout: 120_000 },
  );
  if (check.status === 0) return [];
  const lines = `${check.stdout ?? ''}${check.stderr ?? ''}`
    .trim()
    .split(/\r?\n/)
    .filter((l) => l !== '');
  const details = lines.length === 0 ? [`exited ${check.status ?? check.signal} without a message`] : lines;
  return details.map((detail) => ({ kind: 'scan' as const, detail: `sonarqube: ${detail}` }));
}

/**
 * Plan 3B: a fixture with `llm/expected.json` also checks what the server would send to a model
 * for its findings and how it judges canned answers (`llm-check.ts`, pure shared code over the
 * report). Without a Gitleaks run the CLI redacts nothing in the snippets (report-format.md §7),
 * so the differences then count as Gitleaks' findings: "not checked here" like them where Gitleaks
 * is not installed (ruling T4), a failure anywhere else.
 */
export function checkLlmProblems(fixtureDir: string, report: Report): Problem[] {
  if (!existsSync(path.join(fixtureDir, 'llm', 'expected.json'))) return [];
  const gitleaksRan = report.engines.some((e) => e.id === 'gitleaks' && e.status === 'ok');
  return checkLlmFixture(fixtureDir, report).map((d) =>
    gitleaksRan
      ? { kind: 'scan' as const, detail: `llm: ${d}` }
      : { kind: 'missing-finding' as const, detail: `gitleaks: llm: ${d}` },
  );
}

/**
 * Copies the fixture into a fresh one-commit git repo and runs `qualor scan --dry-run` on it (for a
 * .NET fixture where dotnet runs: `qualor dotnet begin`, the build, `qualor dotnet end --dry-run`).
 */
function scanFixture(fixtureDir: string, name: string, expected: Expected): Problem[] {
  const work = mkdtempSync(path.join(os.tmpdir(), `qualor-fixture-${name}-`));
  try {
    const repo = path.join(work, 'repo');
    cpSync(fixtureDir, repo, { recursive: true });
    const emptyGitConfig = path.join(work, 'empty.gitconfig');
    writeFileSync(emptyGitConfig, '');
    const env = scanEnv(process.env, emptyGitConfig);
    for (const args of [
      ['init', '-q', '-b', 'main'],
      ['add', '-A'],
      ['commit', '-q', '--no-verify', '-m', 'fixture'],
    ]) {
      const r = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', ...args], {
        cwd: repo,
        env,
        encoding: 'utf8',
      });
      if (r.status !== 0) return [{ kind: 'scan', detail: `git ${args[0]} failed: ${r.stderr.trim()}` }];
    }
    const prepared = prepareCopy(repo);
    if (prepared !== null) return [{ kind: 'scan', detail: prepared }];
    // Plan 2D: on Linux (ruling R8), a real build between begin and end; otherwise a plain scan,
    // which skips roslyn, and the capability check reports it "not checked here".
    const dotnet = isDotnetFixture(repo) && unavailableEngines(['roslyn']).length === 0;
    if (dotnet) {
      // Set after scanEnv, which drops every QUALOR_ variable.
      env['XDG_DATA_HOME'] = path.join(work, 'xdg');
      env['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1';
      env['DOTNET_NOLOGO'] = '1';
      const built = prepareDotnet(repo, env);
      if (built !== null) return [{ kind: 'scan', detail: built }];
    }
    const out = path.join(work, 'report.json.gz');
    // In the checkout, where the CI component writes them (the CLI refuses a place outside it).
    const codeQuality = 'gl-code-quality-report.json';
    const sast = 'gl-sast-report.json';
    const dependencies = 'gl-dependency-scanning-report.json';
    const { command, args } = scanCommand();
    const r = spawnSync(
      command,
      [
        ...args,
        ...(dotnet ? ['dotnet', 'end'] : ['scan']),
        '--dry-run',
        '--output',
        out,
        '--project-key',
        `fixtures/${name}`,
        '--gitlab-code-quality',
        codeQuality,
        '--gitlab-sast',
        sast,
        '--gitlab-dependency-scanning',
        dependencies,
      ],
      { cwd: repo, env, encoding: 'utf8', timeout: 600_000 },
    );
    const exited = { kind: 'scan' as const, detail: `qualor ${dotnet ? 'dotnet end' : 'scan'} exited ${r.status ?? r.signal}: ${(r.stderr ?? '').trim()}` };
    // Exit 3 still writes the report. It is acceptable only when every failed engine is a required
    // one whose tool is not installed here (Gitleaks is required by default), never in CI.
    if (r.status !== 0 && !(r.status === 3 && existsSync(out))) return [exited];
    const parsed = reportSchema.safeParse(JSON.parse(gunzipSync(readFileSync(out)).toString('utf8')));
    if (!parsed.success) return [{ kind: 'scan', detail: `the report is invalid: ${parsed.error.message}` }];
    if (r.status === 3 && !exit3Acceptable(parsed.data.engines)) return [exited];
    return [
      ...checkSonarFixture(fixtureDir, out),
      ...checkLlmProblems(fixtureDir, parsed.data),
      ...compareFixture(expected, parsed.data).map((m) => ({ kind: m.kind, detail: m.detail })),
      ...checkGitLabReports(
        parsed.data,
        readIfExists(path.join(repo, codeQuality)),
        readIfExists(path.join(repo, sast)),
        (p) => readFileSync(path.join(repo, p), 'utf8'),
        readIfExists(path.join(repo, dependencies)),
      ),
    ];
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

export function runFixtures(
  dir: string = fixturesDir,
  scan: ScanFn = scanFixture,
  o: { has?: (tool: string) => boolean; requireAnalyzers?: boolean } = {},
): FixtureOutcome[] {
  return readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => {
      const fixtureDir = path.join(dir, d.name);
      const staticProblem = (detail: string): FixtureOutcome => ({
        name: d.name,
        problems: [{ kind: 'static', detail }],
      });
      const file = path.join(fixtureDir, 'expected.json');
      if (!existsSync(file)) return staticProblem('expected.json missing');
      let raw: unknown;
      try {
        raw = JSON.parse(readFileSync(file, 'utf8'));
      } catch (err) {
        return staticProblem(`expected.json is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
      }
      const parsed = expectedSchema.safeParse(raw);
      if (!parsed.success) return staticProblem(`expected.json invalid: ${parsed.error.message}`);
      const problems: Problem[] = checkFixtureStatic(fixtureDir, parsed.data).map((detail) => ({
        kind: 'static',
        detail,
      }));
      problems.push(...scan(fixtureDir, d.name, parsed.data));
      const unavailable = unavailableEngines(parsed.data.engines, o.has);
      if (unavailable.length === 0) return { name: d.name, problems };
      if (o.requireAnalyzers ?? REQUIRE_ANALYZERS) {
        problems.push({ kind: 'scan', detail: `not installed: ${unavailable.join(', ')} (QUALOR_REQUIRE_ANALYZERS=1)` });
        return { name: d.name, problems };
      }
      return { name: d.name, problems, unavailable };
    });
}

export function verdict(
  outcomes: FixtureOutcome[],
  pending: Record<string, PendingEntry>,
): { ok: boolean; lines: string[] } {
  const lines: string[] = [];
  let ok = true;
  for (const outcome of outcomes) {
    const entry = pending[outcome.name];
    const unavailable = outcome.unavailable ?? [];
    const skippedHere = (p: Problem) =>
      (p.kind === 'engine' || p.kind === 'missing-finding') && unavailable.some((id) => p.detail.startsWith(`${id}:`));
    const o = { ...outcome, problems: outcome.problems.filter((p) => !skippedHere(p)) };
    if (o.problems.length === 0 && unavailable.length > 0) {
      // Ruling T4: without the tool its findings cannot be checked here; CI installs every tool.
      lines.push(`~ ${o.name}: not checked here for ${unavailable.join(', ')} (not installed; CI checks them)`);
      continue;
    }
    if (o.problems.length === 0) {
      if (entry !== undefined) {
        ok = false;
        lines.push(`✗ ${o.name}: passes but is listed in known-pending.json; remove it`);
      } else lines.push(`✓ ${o.name}`);
      continue;
    }
    const tolerated = (p: Problem) => entry !== undefined && (entry.kinds as ProblemKind[]).includes(p.kind);
    if (o.problems.every(tolerated)) {
      const kinds = [...new Set(o.problems.map((p) => p.kind))].join(', ');
      lines.push(`… ${o.name}: pending (${entry?.reason}); ${o.problems.length} expected mismatches (${kinds})`);
    } else {
      ok = false;
      lines.push(`✗ ${o.name}:`, ...o.problems.filter((p) => !tolerated(p)).map((p) => `    ${p.kind}: ${p.detail}`));
    }
  }
  for (const name of Object.keys(pending)) {
    if (!outcomes.some((o) => o.name === name)) {
      ok = false;
      lines.push(`✗ ${name}: listed in known-pending.json but there is no such fixture`);
    }
  }
  return { ok, lines };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const pending = parsePending(JSON.parse(readFileSync(path.join(root, 'tools/fixtures/known-pending.json'), 'utf8')));
  const { ok, lines } = verdict(runFixtures(), pending);
  console.log(lines.join('\n'));
  process.exit(ok ? 0 : 1);
}

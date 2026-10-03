import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { expectedSchema, reportFingerprints, type Report } from '@qualor/shared';
import { afterEach, describe, expect, it } from 'vitest';
import {
  checkGitLabReports,
  checkFixtureStatic,
  checkSonarFixture,
  CLANG_TIDY_PINNED,
  CPPCHECK_PINNED,
  exit3Acceptable,
  findTool,
  FINDSECBUGS_PLUGIN,
  isDotnetFixture,
  parsePending,
  prepareCopy,
  REQUIRE_ANALYZERS,
  requireAnalyzers,
  runFixtures,
  scanEnv,
  DETEKT_JAR,
  PHPSTAN_PHAR,
  GO_RUNNER,
  SONARJS_PASS,
  toolOnPath,
  TRIVY_DATABASE,
  unavailableEngines,
  verdict,
  type Problem,
} from './run';

const repoRoot = path.resolve(import.meta.dirname, '../..');
const pending = { a: { reason: 'adapters pending', kinds: ['engine' as const, 'missing-finding' as const] } };
const p = (kind: Problem['kind'], detail = 'x'): Problem => ({ kind, detail });

describe('fixture harness verdict', () => {
  it('accepts a pending fixture whose problems all have listed kinds', () => {
    const v = verdict([{ name: 'a', problems: [p('engine'), p('missing-finding')] }], pending);
    expect(v.ok).toBe(true);
    expect(v.lines[0]).toContain('pending (adapters pending)');
  });
  it('fails a pending fixture with a problem of another kind', () => {
    expect(verdict([{ name: 'a', problems: [p('engine'), p('coverage')] }], pending).ok).toBe(false);
    expect(verdict([{ name: 'a', problems: [p('static')] }], pending).ok).toBe(false);
    expect(verdict([{ name: 'a', problems: [p('scan')] }], pending).ok).toBe(false);
  });
  it('fails an unlisted failing fixture', () => {
    expect(verdict([{ name: 'a', problems: [p('engine')] }], {}).ok).toBe(false);
  });
  it('fails a listed fixture that passes, and a listed fixture that does not exist', () => {
    expect(verdict([{ name: 'a', problems: [] }], pending).ok).toBe(false);
    expect(verdict([], pending).ok).toBe(false);
  });
  it('accepts a passing unlisted fixture', () => {
    expect(verdict([{ name: 'a', problems: [] }], {}).ok).toBe(true);
  });
});

describe('analyzer capabilities (ruling T4)', () => {
  it('names the expected engines whose tools are missing', () => {
    const has = (t: string) => ['node', 'semgrep', 'spotbugs'].includes(t);
    expect(unavailableEngines(['eslint', 'pmd', 'spotbugs', 'semgrep', 'gitleaks', 'ext'], has)).toEqual([
      'pmd',
      'spotbugs',
      'gitleaks',
    ]);
    // Plan 2B: Trivy needs its binary and the scanner image's database.
    expect(unavailableEngines(['trivy'], (t) => t === 'trivy')).toEqual(['trivy']);
    expect(unavailableEngines(['trivy'], (t) => t === TRIVY_DATABASE)).toEqual(['trivy']);
    expect(unavailableEngines(['trivy'], (t) => ['trivy', TRIVY_DATABASE].includes(t))).toEqual([]);
    // Plan 8A/8B: sonarjs needs node and the image's own pass, like Trivy above.
    expect(unavailableEngines(['sonarjs'], (t) => t === 'node')).toEqual(['sonarjs']);
    expect(unavailableEngines(['sonarjs'], (t) => t === SONARJS_PASS)).toEqual(['sonarjs']);
    expect(unavailableEngines(['sonarjs'], (t) => ['node', SONARJS_PASS].includes(t))).toEqual([]);
    // Plan 9D: cppcheck counts only at the pinned minor (the harness's has() runs --version).
    expect(unavailableEngines(['cppcheck'], () => false)).toEqual(['cppcheck']);
    expect(unavailableEngines(['cppcheck'], (t) => t === 'cppcheck')).toEqual(['cppcheck']);
    expect(unavailableEngines(['cppcheck'], (t) => t === CPPCHECK_PINNED)).toEqual([]);
    // Plan 9D: clang-tidy counts only at the major install-clang-tidy.sh pins.
    expect(unavailableEngines(['clang-tidy'], () => false)).toEqual(['clang-tidy']);
    expect(unavailableEngines(['clang-tidy'], (t) => t === 'clang-tidy')).toEqual(['clang-tidy']);
    expect(unavailableEngines(['clang-tidy'], (t) => t === CLANG_TIDY_PINNED)).toEqual([]);
    // Plan 8E: detekt needs java and the image's jar.
    expect(unavailableEngines(['detekt'], (t) => t === 'java')).toEqual(['detekt']);
    expect(unavailableEngines(['detekt'], (t) => t === DETEKT_JAR)).toEqual(['detekt']);
    expect(unavailableEngines(['detekt'], (t) => ['java', DETEKT_JAR].includes(t))).toEqual([]);
    // Plan 6A: SpotBugs counts only with the FindSecBugs plugin in its home.
    expect(unavailableEngines(['spotbugs'], (t) => ['spotbugs', 'javac'].includes(t))).toEqual(['spotbugs']);
    expect(unavailableEngines(['spotbugs'], (t) => ['spotbugs', 'javac', FINDSECBUGS_PLUGIN].includes(t))).toEqual([]);
    // Plan 8F: SwiftLint's static binary only.
    expect(unavailableEngines(['swiftlint'], () => false)).toEqual(['swiftlint']);
    expect(unavailableEngines(['swiftlint'], (t) => t === 'swiftlint')).toEqual([]);
    // Plan 9A: phpstan needs php and the image's phar.
    expect(unavailableEngines(['phpstan'], (t) => t === 'php')).toEqual(['phpstan']);
    expect(unavailableEngines(['phpstan'], (t) => t === PHPSTAN_PHAR)).toEqual(['phpstan']);
    expect(unavailableEngines(['phpstan'], (t) => ['php', PHPSTAN_PHAR].includes(t))).toEqual([]);
    // Plan 9C: node, go, the tool and Qualor's Go runner.
    expect(unavailableEngines(['staticcheck', 'govet', 'gosec'], () => false)).toEqual(['staticcheck', 'govet', 'gosec']);
    expect(unavailableEngines(['staticcheck', 'govet', 'gosec'], (t) => t !== GO_RUNNER)).toEqual(['staticcheck', 'govet', 'gosec']);
    expect(unavailableEngines(['staticcheck', 'govet', 'gosec'], (t) => t !== 'gosec')).toEqual(['gosec']);
    expect(unavailableEngines(['staticcheck', 'govet', 'gosec'], () => true)).toEqual([]);
  });
  it('needs node and the weblint pass for stylelint and htmlhint (plan 8D)', () => {
    expect(unavailableEngines(['stylelint', 'htmlhint'], (t) => t === 'node', 'linux')).toEqual(['stylelint', 'htmlhint']);
    expect(unavailableEngines(['stylelint', 'htmlhint'], () => true, 'linux')).toEqual([]);
  });
  it('needs dotnet on a Linux host for roslyn; win32 and darwin are always unavailable (ruling R8)', () => {
    expect(unavailableEngines(['roslyn'], (t) => t === 'dotnet', 'linux')).toEqual([]);
    expect(unavailableEngines(['roslyn'], () => false, 'linux')).toEqual(['roslyn']);
    // Neither platform can isolate a real MSBuild build here: Windows would use the developer's
    // real profile; macOS ignores XDG_DATA_HOME since .NET 8 (ruling R6), and the CLI's own
    // QUALOR_MSBUILD_USER_DIR does not steer the real MSBuild process the fixture spawns.
    expect(unavailableEngines(['roslyn'], () => true, 'win32')).toEqual(['roslyn']);
    expect(unavailableEngines(['roslyn'], () => true, 'darwin')).toEqual(['roslyn']);
  });
  it('recognises a C# fixture by its .slnx or .sln at the root', () => {
    expect(isDotnetFixture(path.join(repoRoot, 'fixtures', 'csharp-basic'))).toBe(true);
    expect(isDotnetFixture(path.join(repoRoot, 'fixtures', 'java-basic'))).toBe(false);
  });
  it('does not check the findings of an unavailable engine, and says so', () => {
    const outcome = {
      name: 'a',
      problems: [p('engine', 'pmd: expected status ok, got skipped'), p('missing-finding', 'pmd:X a.java:1')],
      unavailable: ['pmd'],
    };
    const v = verdict([outcome], {});
    expect(v.ok).toBe(true);
    expect(v.lines).toEqual(['~ a: not checked here for pmd (not installed; CI checks them)']);
    // ...even while the fixture is still listed as pending for another engine.
    expect(verdict([outcome], pending).ok).toBe(true);
  });
  it('still fails other problems of a fixture with an unavailable engine', () => {
    const v = verdict(
      [{ name: 'a', problems: [p('engine', 'pmd: x'), p('missing-finding', 'eslint:no-var a.ts:1')], unavailable: ['pmd'] }],
      {},
    );
    expect(v.ok).toBe(false);
    expect(v.lines).toEqual(['✗ a:', '    missing-finding: eslint:no-var a.ts:1']);
  });
  it('accepts only 1 for QUALOR_REQUIRE_ANALYZERS and warns about any other value', () => {
    const warnings: string[] = [];
    const warn = (m: string) => warnings.push(m);
    expect(requireAnalyzers('1', warn)).toBe(true);
    expect(requireAnalyzers(undefined, warn)).toBe(false);
    expect(requireAnalyzers('', warn)).toBe(false);
    expect(warnings).toEqual([]);
    expect(requireAnalyzers('true', warn)).toBe(false);
    expect(warnings).toEqual(['QUALOR_REQUIRE_ANALYZERS=true is ignored: set it to 1 to require the analyzers']);
  });
  it('turns a missing tool into a failure when QUALOR_REQUIRE_ANALYZERS=1', () => {
    const root = makeTempDir();
    mkdirSync(path.join(root, 'f'));
    writeFileSync(path.join(root, 'f', 'expected.json'), JSON.stringify({ ...minimalExpected, engines: ['pmd'] }));
    writeFileSync(path.join(root, 'f', 'qualor.yml'), 'version: 1\n');
    const [lax] = runFixtures(root, () => [], { has: () => false, requireAnalyzers: false });
    expect(lax).toEqual({ name: 'f', problems: [], unavailable: ['pmd'] });
    const [strict] = runFixtures(root, () => [], { has: () => false, requireAnalyzers: true });
    expect(strict?.problems).toEqual([{ kind: 'scan', detail: 'not installed: pmd (QUALOR_REQUIRE_ANALYZERS=1)' }]);
  });
});

describe('exit 3 outside CI (ruling A6: Gitleaks is required by default)', () => {
  const missing = { id: 'gitleaks', status: 'failed', reason: 'Gitleaks is not installed (gitleaks on PATH or in the scanner image)' };
  const noGitleaks = (t: string) => t !== 'gitleaks';
  it('accepts only failures of required tools that are not installed here', () => {
    expect(exit3Acceptable([missing, { id: 'eslint', status: 'ok' }], { requireAnalyzers: false, has: noGitleaks })).toBe(true);
  });
  it('rejects it in CI, for a tool that is installed, for any other failure and with no failure', () => {
    expect(exit3Acceptable([missing], { requireAnalyzers: true, has: noGitleaks })).toBe(false);
    expect(exit3Acceptable([missing], { requireAnalyzers: false, has: () => true })).toBe(false);
    expect(
      exit3Acceptable([missing, { id: 'pmd', status: 'failed', reason: 'exited with code 1' }], {
        requireAnalyzers: false,
        has: () => false,
      }),
    ).toBe(false);
    expect(exit3Acceptable([{ ...missing, status: 'timeout', reason: 'timed out after 300 s' }], { requireAnalyzers: false, has: noGitleaks })).toBe(false);
    expect(exit3Acceptable([{ id: 'gitleaks', status: 'ok' }], { requireAnalyzers: false, has: noGitleaks })).toBe(false);
  });
});

describe('tool lookup and build step', () => {
  it('finds tools only in absolute PATH entries (ruling V3)', () => {
    // Below the working directory, so that a relative PATH entry can name it.
    mkdirSync(path.join(process.cwd(), '.tmp'), { recursive: true });
    const dir = mkdtempSync(path.join(process.cwd(), '.tmp', 'qualor-tool-'));
    tempDirs.push(dir);
    const name = process.platform === 'win32' ? 'qtool.exe' : 'qtool';
    writeFileSync(path.join(dir, name), '');
    const sep = process.platform === 'win32' ? ';' : ':';
    const rel = path.relative(process.cwd(), dir);
    expect(path.isAbsolute(rel)).toBe(false);
    expect(findTool('qtool', { PATH: dir })).toBe(path.join(dir, name));
    expect(toolOnPath('qtool', { PATH: `${rel}${sep}.` })).toBe(false);
  });
  it('builds nothing for a fixture without pom.xml or without javac', () => {
    const repo = makeTempDir();
    mkdirSync(path.join(repo, 'src', 'main', 'java'), { recursive: true });
    writeFileSync(path.join(repo, 'src', 'main', 'java', 'A.java'), 'class A {}\n');
    expect(prepareCopy(repo, '/no/javac')).toBeNull();
    writeFileSync(path.join(repo, 'pom.xml'), '<project/>');
    expect(prepareCopy(repo, null)).toBeNull();
    expect(existsSync(path.join(repo, 'target'))).toBe(false);
  });
  it.runIf(REQUIRE_ANALYZERS || toolOnPath('javac'))('compiles a Maven fixture into target/classes and reports a failing build', { timeout: 120_000 }, () => {
    const repo = makeTempDir();
    mkdirSync(path.join(repo, 'src', 'main', 'java', 'p'), { recursive: true });
    writeFileSync(path.join(repo, 'pom.xml'), '<project/>');
    writeFileSync(path.join(repo, 'src', 'main', 'java', 'p', 'A.java'), 'package p; class A {}\n');
    expect(prepareCopy(repo)).toBeNull();
    expect(existsSync(path.join(repo, 'target', 'classes', 'p', 'A.class'))).toBe(true);
    writeFileSync(path.join(repo, 'src', 'main', 'java', 'p', 'B.java'), 'package p; class B {\n');
    expect(prepareCopy(repo)).toMatch(/^javac failed: .*B\.java/s);
  });
});

describe('parsePending', () => {
  it('accepts the structured format and rejects anything else', () => {
    expect(parsePending(pending)).toEqual(pending);
    expect(() => parsePending({ a: 'old string format' })).toThrow(/known-pending/);
    expect(() => parsePending({ a: { reason: 'r', kinds: ['static'] } })).toThrow(/known-pending/);
    // Only analyzer output may stay pending: files, metrics, duplication and coverage are enforced.
    for (const kind of ['file', 'duplication', 'coverage', 'unexpected-finding']) {
      expect(() => parsePending({ a: { reason: 'r', kinds: [kind] } }), kind).toThrow(/known-pending/);
    }
    expect(() => parsePending({ a: { reason: '', kinds: ['engine'] } })).toThrow(/known-pending/);
  });
});

describe('scanEnv', () => {
  it('drops CI and QUALOR variables and sets a git identity', () => {
    const env = scanEnv(
      { PATH: '/bin', CI: 'true', CI_COMMIT_SHA: 'x', GITHUB_ACTIONS: 'true', GITLAB_CI: 'true', QUALOR_TOKEN: 't', GIT_CONFIG_GLOBAL: '/home/u/.gitconfig' },
      '/tmp/empty.gitconfig',
    );
    expect(env['PATH']).toBe('/bin');
    for (const k of ['CI', 'CI_COMMIT_SHA', 'GITHUB_ACTIONS', 'GITLAB_CI', 'QUALOR_TOKEN']) expect(env[k]).toBeUndefined();
    expect(env['GIT_AUTHOR_NAME']).toBeDefined();
    // Isolated from the user's and the system's git configuration (hooks, signing, autocrlf).
    expect(env['GIT_CONFIG_GLOBAL']).toBe('/tmp/empty.gitconfig');
    expect(env['GIT_CONFIG_NOSYSTEM']).toBe('1');
  });
});

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-fixtures-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const minimalExpected = {
  description: 'x',
  engines: [],
  findingsExhaustive: false,
  findings: [],
  files: {},
  duplications: [],
  coverage: null,
};

describe('runFixtures', () => {
  const noScan = () => [];

  it('reports malformed JSON per fixture instead of crashing the whole run', () => {
    const root = makeTempDir();
    mkdirSync(path.join(root, 'bad'));
    writeFileSync(path.join(root, 'bad', 'expected.json'), '{ "description": "x", }');
    mkdirSync(path.join(root, 'good'));
    writeFileSync(path.join(root, 'good', 'expected.json'), JSON.stringify(minimalExpected));

    const outcomes = runFixtures(root, noScan);

    const bad = outcomes.find((o) => o.name === 'bad')!;
    expect(bad.problems).toHaveLength(1);
    expect(bad.problems[0]!.detail).toMatch(/^expected\.json is not valid JSON/);
    expect(outcomes.find((o) => o.name === 'good')).toBeDefined();
  });

  it('reports a missing expected.json', () => {
    const root = makeTempDir();
    mkdirSync(path.join(root, 'nofile'));
    expect(runFixtures(root, noScan)).toEqual([
      { name: 'nofile', problems: [{ kind: 'static', detail: 'expected.json missing' }] },
    ]);
  });

  it('adds the scan problems after the static ones', () => {
    const root = makeTempDir();
    mkdirSync(path.join(root, 'f'));
    writeFileSync(path.join(root, 'f', 'expected.json'), JSON.stringify(minimalExpected));
    const outcomes = runFixtures(root, () => [p('coverage', 'coverage expected, but the report has none')]);
    expect(outcomes[0]!.problems).toEqual([
      { kind: 'static', detail: 'qualor.yml missing' },
      { kind: 'coverage', detail: 'coverage expected, but the report has none' },
    ]);
  });
});

describe('checkFixtureStatic', () => {
  it('reports a missing finding path, a finding line out of range, and a missing qualor.yml', () => {
    const dir = makeTempDir();
    mkdirSync(path.join(dir, 'src'));
    writeFileSync(path.join(dir, 'src', 'exists.ts'), 'line1\nline2\n');

    const expected = expectedSchema.parse({
      ...minimalExpected,
      findings: [
        { ruleKey: 'eslint:no-console', path: 'src/missing.ts', startLine: 1 },
        { ruleKey: 'eslint:no-console', path: 'src/exists.ts', startLine: 99 },
      ],
    });

    expect(checkFixtureStatic(dir, expected)).toEqual([
      'finding path missing: src/missing.ts',
      'finding line out of range: src/exists.ts:99',
      'qualor.yml missing',
    ]);
  });
});

describe('checkGitLabReports (scm.md §9)', () => {
  const report: Report = {
    schemaVersion: 1,
    scanner: { name: 'qualor-cli', version: '0.0.0' },
    project: { key: 'fixtures/x', name: 'x' },
    scm: {
      provider: 'none',
      revision: 'a'.repeat(40),
      branch: 'main',
      mainBranch: 'main',
      mergeRequest: null,
      baseline: { revision: null, kind: 'none', status: 'unavailable' },
      renames: [],
    },
    analysisDate: '2026-09-22T10:15:00Z',
    engines: [
      { id: 'gitleaks', kind: 'builtin', version: '8', status: 'ok', durationMs: 1, rules: [] },
    ],
    files: [
      {
        path: 'src/config.ts',
        language: 'typescript',
        kind: 'main',
        sha256: 'c'.repeat(64),
        lines: 2,
      },
    ],
    findings: [
      {
        engineId: 'gitleaks',
        ruleId: 'generic-api-key',
        message: 'Detected a Generic API Key.',
        location: { path: 'src/config.ts', startLine: 2 },
        lineHash: 'd'.repeat(32),
        contextHash: 'e'.repeat(32),
      },
    ],
    duplications: [],
    warnings: [],
  };
  const source = "export const a = 1;\nconst apiKey = 'Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1';\n";
  const [fingerprint] = reportFingerprints(report.findings);
  const entry = {
    description: 'Detected a Generic API Key.',
    check_name: 'gitleaks:generic-api-key',
    fingerprint,
    severity: 'blocker',
    location: { path: 'src/config.ts', lines: { begin: 2 } },
  };
  const codeQuality = JSON.stringify([entry]);
  const sast = (extra: object = {}) =>
    JSON.stringify({
      version: '15.1.4',
      scan: {
        type: 'sast',
        status: 'success',
        start_time: '2026-09-22T10:15:00',
        end_time: '2026-09-22T10:15:00',
        analyzer: { id: 'qualor', name: 'Qualor', version: '0', vendor: { name: 'Qualor' } },
        scanner: { id: 'qualor', name: 'Qualor', version: '0', vendor: { name: 'Qualor' } },
      },
      vulnerabilities: [
        {
          id: 'v1',
          identifiers: [{ type: 'qualor_rule', name: 'gitleaks:generic-api-key', value: 'x' }],
          location: { file: 'src/config.ts', start_line: 2 },
          ...extra,
        },
      ],
    });

  it('accepts matching files without source lines', () => {
    expect(checkGitLabReports(report, codeQuality, sast(), () => source)).toEqual([]);
  });

  it('names a count mismatch, an invalid SAST file and a leaked source line', () => {
    const details = checkGitLabReports(
      report,
      '[]',
      sast({ description: "const apiKey = 'Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1';", severity: 'Severe' }),
      () => source,
    ).map((p) => p.detail);
    expect(details).toEqual([
      'gitlab: Code Quality has 0 entries, the report 1 located findings',
      expect.stringMatching(/^gitlab: SAST is not valid: /),
      'gitlab: a source line of src/config.ts is in a GitLab report file',
    ]);
  });

  it('accepts a missing Code Quality file with a failed SAST scan when an engine did not complete (ruling G6)', () => {
    const failedScan = (status: string) => {
      const doc = JSON.parse(sast()) as { scan: Record<string, unknown> };
      doc.scan['status'] = status;
      return JSON.stringify(doc);
    };
    const incomplete: Report = {
      ...report,
      engines: [
        ...report.engines,
        {
          ...report.engines[0]!,
          id: 'pmd',
          status: 'skipped',
          reason: 'PMD is not installed (pmd on PATH or in the scanner image)',
        },
      ],
    };
    // A configuration skip is complete: the Code Quality file must be there.
    const configured: Report = {
      ...report,
      engines: [
        ...report.engines,
        { ...report.engines[0]!, id: 'eslint', status: 'skipped', reason: 'no ESLint configuration' },
      ],
    };
    expect(
      checkGitLabReports(configured, null, failedScan('failure'), () => source).map(
        (p) => p.detail,
      ),
    ).toEqual([
      'gitlab: the Code Quality file is missing, but no engine failed, timed out or was unavailable (ruling G6)',
    ]);
    expect(checkGitLabReports(configured, codeQuality, sast(), () => source)).toEqual([]);
    expect(
      checkGitLabReports(incomplete, codeQuality, sast(), () => source).map((p) => p.detail),
    ).toEqual([
      'gitlab: the Code Quality file was written, but an engine failed, timed out or was unavailable (ruling G6)',
    ]);
    expect(checkGitLabReports(incomplete, null, failedScan('failure'), () => source)).toEqual([]);
    expect(
      checkGitLabReports(report, null, failedScan('failure'), () => source).map((p) => p.detail),
    ).toEqual([
      'gitlab: the Code Quality file is missing, but no engine failed, timed out or was unavailable (ruling G6)',
    ]);
    expect(
      checkGitLabReports(incomplete, null, sast(), () => source).map((p) => p.detail),
    ).toEqual([
      'gitlab: the Code Quality file is missing, but the SAST scan did not fail (ruling G6)',
    ]);
    expect(
      checkGitLabReports(report, codeQuality, failedScan('failure'), () => source).map(
        (p) => p.detail,
      ),
    ).toEqual(['gitlab: the SAST scan failed, but the Code Quality file was written (ruling G6)']);
  });

  it('reports what it cannot read instead of crashing', () => {
    const details = checkGitLabReports(report, 'not json', null, () => {
      throw new Error('ENOENT: src/«redacted».ts');
    }).map((p) => p.detail);
    expect(details).toEqual([
      'gitlab: Code Quality is not JSON',
      'gitlab: the SAST file was not written',
      'gitlab: the source of src/config.ts cannot be read to check the GitLab files',
    ]);
  });

  it('checks the Dependency Scanning file: written, valid, one entry per Trivy finding, and SAST without them (plan 2B)', () => {
    const withTrivy: Report = {
      ...report,
      engines: [
        ...report.engines,
        { id: 'trivy', kind: 'builtin', version: '0.74.0', status: 'ok', durationMs: 1, rules: [] },
      ],
      files: [
        ...report.files,
        { path: 'package-lock.json', language: 'other', kind: 'main', sha256: 'f'.repeat(64), lines: 20 },
      ],
      findings: [
        ...report.findings,
        {
          engineId: 'trivy',
          ruleId: 'CVE-2021-44906',
          message: 'minimist 1.2.5: CVE-2021-44906',
          location: { path: 'package-lock.json', startLine: 14 },
          lineHash: 'a'.repeat(32),
          contextHash: 'a'.repeat(32),
        },
      ],
    };
    const [, depFingerprint] = reportFingerprints(withTrivy.findings);
    const cq = JSON.stringify([
      entry,
      {
        description: 'minimist 1.2.5: CVE-2021-44906',
        check_name: 'trivy:CVE-2021-44906',
        fingerprint: depFingerprint,
        severity: 'major',
        location: { path: 'package-lock.json', lines: { begin: 14 } },
      },
    ]);
    const ds = (vulnerabilities: unknown[], status = 'success') =>
      JSON.stringify({
        version: '15.1.4',
        scan: {
          type: 'dependency_scanning',
          status,
          start_time: '2026-09-22T10:15:00',
          end_time: '2026-09-22T10:15:00',
          analyzer: { id: 'qualor', name: 'Qualor', version: '0', vendor: { name: 'Qualor' } },
          scanner: { id: 'qualor', name: 'Qualor', version: '0', vendor: { name: 'Qualor' } },
        },
        vulnerabilities,
      });
    const vulnerability = {
      id: 'v2',
      identifiers: [{ type: 'cve', name: 'CVE-2021-44906', value: 'CVE-2021-44906' }],
      location: { file: 'package-lock.json', dependency: { package: { name: 'minimist' }, version: '1.2.5' } },
    };
    const read = (p: string) => (p === 'package-lock.json' ? '{}' : source);
    // SAST holds the Gitleaks finding only; Dependency Scanning the Trivy one.
    expect(checkGitLabReports(withTrivy, cq, sast(), read, ds([vulnerability]))).toEqual([]);
    const details = (text: string | null) =>
      checkGitLabReports(withTrivy, cq, sast(), read, text).map((p) => p.detail);
    expect(details(null)).toEqual(['gitlab: the Dependency Scanning file was not written']);
    expect(details(ds([]))).toEqual([
      'gitlab: Dependency Scanning has 0 vulnerabilities, the report 1 dependency findings',
    ]);
    expect(details(ds([vulnerability], 'failure'))).toEqual([
      'gitlab: the Dependency Scanning scan status does not follow the engines (ruling G6)',
    ]);
    expect(details(ds([{ ...vulnerability, location: { file: 'package-lock.json' } }]))).toEqual([
      expect.stringMatching(/^gitlab: Dependency Scanning is not valid: /),
    ]);
    // Without the argument, the file is not checked (callers before plan 2B).
    expect(checkGitLabReports(withTrivy, cq, sast(), read)).toEqual([]);
  });

  it("names a Code Quality entry outside GitLab's documented fields", () => {
    const details = checkGitLabReports(
      report,
      JSON.stringify([{ ...entry, severity: 'high' }]),
      sast(),
      () => source,
    ).map((p) => p.detail);
    expect(details).toEqual([expect.stringMatching(/^gitlab: Code Quality is not valid: /)]);
  });
});

describe('checkSonarFixture', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it('checks nothing for a fixture without SonarQube data', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-sonar-check-'));
    dirs.push(dir);
    expect(checkSonarFixture(dir, path.join(dir, 'report.json.gz'))).toEqual([]);
  });

  it('turns every line of a failed check into a scan problem', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-sonar-check-'));
    dirs.push(dir);
    mkdirSync(path.join(dir, 'sonarqube'));
    writeFileSync(path.join(dir, 'sonarqube', 'data.json'), '{}');
    writeFileSync(path.join(dir, 'sonarqube-expected.json'), '{}');
    const problems = checkSonarFixture(dir, path.join(dir, 'no-report.json.gz'));
    expect(problems.length).toBeGreaterThan(0);
    for (const problem of problems) {
      expect(problem.kind).toBe('scan');
      expect(problem.detail).toMatch(/^sonarqube: /);
    }
  }, 60_000);
});

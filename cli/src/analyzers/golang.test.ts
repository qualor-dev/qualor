import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  GO_MIN_VERSION,
  GO_VERSION,
  GOSEC_VERSION,
  parseConfig,
  STATICCHECK_VERSION,
  type QualorConfigInput,
} from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { fakeContext, scanWithRecordedSarif } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import {
  GO_RUNNER_MAX_WARNINGS,
  goFailureDetail,
  goWarnings,
  gosecAnalyzer,
  govetAnalyzer,
  parseGosecVersion,
  parseGoVersion,
  parseStaticcheckVersion,
  staticcheckAnalyzer,
} from './golang';
import { runAnalyzers } from './runner';
import type { AnalyzerCommand, AnalyzerContext } from './types';

const tmp = useTempDirs();
const BIN = path.resolve('/opt/qualor/bin');
const NODE = path.resolve('/usr/local/bin/node');

function scope(root: string, rel: string): ScopeFile {
  const go = rel.endsWith('.go');
  return {
    path: rel,
    absPath: path.join(root, ...rel.split('/')),
    language: go ? 'go' : 'other',
    grammar: go ? 'go' : null,
    kind: 'main',
    size: 1,
  };
}

interface Versions {
  go?: string;
  staticcheck?: string;
  gosec?: string;
}

function context(
  files: Record<string, string>,
  o: {
    config?: Omit<QualorConfigInput, 'version'>;
    versions?: Versions;
    binaries?: Record<string, string>;
    env?: Record<string, string>;
    lines?: string[];
  } = {},
): { ctx: AnalyzerContext; root: string; work: string; runner: string } {
  const root = tmp();
  const work = tmp();
  const runnerDir = tmp();
  writeTree(root, files);
  writeFileSync(path.join(runnerDir, 'run.mjs'), '// runner\n');
  const v = {
    go: `go version go${GO_VERSION} linux/amd64\n`,
    staticcheck: `staticcheck ${STATICCHECK_VERSION} (0.8.1)\n`,
    gosec: `Version: ${GOSEC_VERSION}\nGit tag: v${GOSEC_VERSION}\n`,
    ...o.versions,
  };
  const base = fakeContext(root, {
    binaries: o.binaries ?? {
      node: NODE,
      go: path.join(BIN, 'go'),
      staticcheck: path.join(BIN, 'staticcheck'),
      gosec: path.join(BIN, 'gosec'),
    },
    workDir: work,
    config: o.config ?? {},
    exec: (command) => {
      const name = path.basename(command);
      const byName: Record<string, string | undefined> = { go: v.go, staticcheck: v.staticcheck };
      const stdout = byName[name] ?? v.gosec;
      return { exitCode: 0, timedOut: false, durationMs: 1, stdout, stderr: '' };
    },
  });
  const lines = o.lines ?? [];
  return {
    ctx: {
      ...base,
      files: Object.keys(files).map((f) => scope(root, f)),
      env: { PATH: path.resolve('/usr/bin'), QUALOR_GO_DIR: runnerDir, ...o.env },
      log: createLogger('debug', (t) => lines.push(t)),
    },
    root,
    work,
    runner: path.join(runnerDir, 'run.mjs'),
  };
}

const MODULE = {
  'go.mod': 'module ex/m\n\ngo 1.24\n',
  'store/a.go': 'package store\n',
  'README.md': '# x\n',
};

async function run(ctx: AnalyzerContext, analyzer = staticcheckAnalyzer): Promise<AnalyzerCommand> {
  const p = await analyzer.prepare(ctx);
  if (!('run' in p)) throw new Error(JSON.stringify(p));
  return p.run;
}

describe('the Go analyzers prepare a runner spec (config.md §6, plan 9C)', () => {
  it("runs Qualor's runner with node on the scan's modules and Go files, never the checkout's tools", async () => {
    const { ctx, root, work, runner } = context(MODULE);
    const cmd = await run(ctx);
    const spec = path.join(work, 'staticcheck-spec.json');
    expect(cmd.command).toBe(NODE);
    expect(cmd.args).toEqual([runner, '--spec', spec]);
    expect(cmd.cwd).toBe(work);
    expect(cmd.okExitCodes).toEqual([0]);
    expect(cmd.version).toBe(STATICCHECK_VERSION);
    expect(cmd.sarifPath).toBe(path.join(work, 'staticcheck.sarif'));
    expect(JSON.parse(readFileSync(spec, 'utf8'))).toEqual({
      tool: 'staticcheck',
      toolPath: path.join(BIN, 'staticcheck'),
      go: path.join(BIN, 'go'),
      version: STATICCHECK_VERSION,
      root,
      workDir: work,
      out: path.join(work, 'staticcheck.sarif'),
      files: ['store/a.go'],
      modules: [{ dir: root, rel: '' }],
      gosecExclude: [],
    });
    expect(cmd.env).toMatchObject({
      GOTOOLCHAIN: 'local',
      GOPROXY: 'off',
      GOFLAGS: '',
      GOWORK: 'off',
      CGO_ENABLED: '0',
      GOPACKAGESDRIVER: 'off',
      HOME: work,
      PATH: `${BIN}${path.delimiter}${path.resolve('/usr/bin')}`,
      HTTPS_PROXY: 'http://127.0.0.1:9',
    });
  });

  it('keeps only an allowlist of inherited variables: no CI Go setting, token or gosec AI key', async () => {
    const { ctx } = context(MODULE);
    const cmd = await run(ctx);
    const keep = (name: string) => !cmd.dropEnv!(name);
    for (const name of [
      'CI_JOB_TOKEN',
      'GITHUB_TOKEN',
      'GOROOT',
      'GOPRIVATE',
      'GOINSECURE',
      'GOEXPERIMENT',
      'GOSEC_AI_API_KEY',
      'GOSUMDB',
      'GONOSUMDB',
      'CC',
    ]) {
      expect(keep(name), name).toBe(false);
    }
    for (const name of ['PATH', 'TMPDIR', 'LANG', 'GOFLAGS', 'GOTOOLCHAIN', 'GOMODCACHE', 'HOME']) {
      expect(keep(name), name).toBe(true);
    }
  });

  it('runs go vet with the go command and reports the Go version; gosec gets the configured exclusions', async () => {
    const vet = await run(context(MODULE).ctx, govetAnalyzer);
    expect(vet.version).toBe(GO_VERSION);
    const { ctx, work } = context(MODULE, {
      config: { analyzers: { gosec: { exclude: ['G104'] } } },
    });
    const gs = await run(ctx, gosecAnalyzer);
    expect(gs.version).toBe(GOSEC_VERSION);
    const spec = JSON.parse(readFileSync(path.join(work, 'gosec-spec.json'), 'utf8')) as {
      toolPath: string;
      gosecExclude: string[];
    };
    expect(spec.gosecExclude).toEqual(['G104']);
    expect(spec.toolPath).toBe(path.join(BIN, 'gosec'));
  });

  it("uses the CI's module cache, and warns about one inside the repository", async () => {
    const outside = path.resolve('/cache/mod');
    const a = context(MODULE, { env: { GOMODCACHE: outside } });
    expect((await run(a.ctx)).env).toMatchObject({ GOMODCACHE: outside });
    const lines: string[] = [];
    const b = context(MODULE, { lines });
    const inside = path.join(b.root, '.gomod');
    const cmd = await run({ ...b.ctx, env: { ...b.ctx.env, GOMODCACHE: inside } });
    expect(cmd.env).toMatchObject({ GOMODCACHE: path.join(b.work, 'gomodcache') });
    expect(lines.join('')).toContain('is inside the repository and is not used');
  });

  it('names the modules it leaves out and the Go files outside every module', async () => {
    const lines: string[] = [];
    const { ctx } = context(
      { ...MODULE, 'tools/go.mod': 'module ex/t\n\ngo 1.99\n', 'tools/t.go': 'package t\n' },
      { lines },
    );
    const cmd = await run(ctx);
    expect(cmd.args.length).toBe(3);
    expect(lines.join('')).toContain('go: tools is not analysed: tools/go.mod needs Go 1.99');
    const loose = context({ 'a.go': 'package a\n' }, { lines });
    expect(await staticcheckAnalyzer.prepare(loose.ctx)).toEqual({
      skip: 'no Go module in scope: Qualor analyses Go modules (a go.mod above the files)',
    });
    expect(lines.join('')).toContain(
      'go: 1 Go file(s) outside every module (no go.mod above them) are not analysed',
    );
  });

  it('analyses a module whose go.mod a narrow sources.include leaves out of scope (ruling G9-19)', async () => {
    const lines: string[] = [];
    const { ctx, root, work } = context(
      { 'go.mod': 'module ex/m\n\ngo 1.24\n', 'services/billing/b.go': 'package billing\n' },
      { lines },
    );
    // `sources.include: ['**/*.go']`: the go.mod is on disk but not in scope.
    const narrow = { ...ctx, files: ctx.files.filter((f) => f.path.endsWith('.go')) };
    await run(narrow);
    const spec = JSON.parse(readFileSync(path.join(work, 'staticcheck-spec.json'), 'utf8')) as {
      modules: { dir: string; rel: string }[];
    };
    expect(spec.modules).toEqual([{ dir: root, rel: '' }]);
    expect(lines.join('')).not.toContain('outside every module');
  });

  it('logs a left-out module and a refused module cache once per scan, not once per Go engine', async () => {
    const lines: string[] = [];
    const { ctx, root } = context(
      { ...MODULE, 'tools/go.mod': 'module ex/t\n\ngo 1.99\n', 'tools/t.go': 'package t\n' },
      { lines },
    );
    const scan = { ...ctx, env: { ...ctx.env, GOMODCACHE: path.join(root, '.gomod') } };
    for (const analyzer of [staticcheckAnalyzer, govetAnalyzer, gosecAnalyzer])
      await run(scan, analyzer);
    const count = (text: string) => lines.join('').split(text).length - 1;
    expect(count('tools is not analysed')).toBe(1);
    expect(count('is inside the repository and is not used')).toBe(1);
  });

  it('skips, never unavailable, when the image-only pieces are missing or of another version (ruling G6)', async () => {
    const noRunner = context(MODULE);
    expect(
      await staticcheckAnalyzer.prepare({
        ...noRunner.ctx,
        env: { ...noRunner.ctx.env, QUALOR_GO_DIR: tmp() },
      }),
    ).toEqual({
      skip: "Qualor's Go runner is not installed (qualor/scanner image)",
    });
    const noGo = context(MODULE, {
      binaries: { node: NODE, staticcheck: path.join(BIN, 'staticcheck') },
    });
    expect(
      await staticcheckAnalyzer.prepare({ ...noGo.ctx, repoBinary: () => '/r/bin/go' }),
    ).toEqual({
      skip: "go is not installed (go on PATH or in the qualor/scanner image); the repository's own go is never run",
    });
    const [major, minor] = GO_MIN_VERSION.split('.').map(Number) as [number, number];
    const tooOld = `${major}.${minor - 1}.4`;
    expect(
      await staticcheckAnalyzer.prepare(
        context(MODULE, { versions: { go: `go version go${tooOld} linux/amd64\n` } }).ctx,
      ),
    ).toEqual({
      skip: `Go ${tooOld} is not supported: the Go analyzers need Go ${GO_MIN_VERSION} or newer (the qualor/scanner image has Go ${GO_VERSION})`,
    });
    const [y, m] = STATICCHECK_VERSION.split('.').map(Number) as [number, number];
    const old = `${y - 1}.${m}.0`;
    expect(
      await staticcheckAnalyzer.prepare(
        context(MODULE, { versions: { staticcheck: `staticcheck ${old} (0.6.0)\n` } }).ctx,
      ),
    ).toEqual({
      skip: `staticcheck ${old} is not supported: this Qualor runs staticcheck ${y}.${m}.x (the qualor/scanner image's ${STATICCHECK_VERSION})`,
    });
    const noGosec = context(MODULE, { binaries: { node: NODE, go: path.join(BIN, 'go') } });
    expect(await gosecAnalyzer.prepare(noGosec.ctx)).toEqual({
      skip: 'gosec is not installed (gosec on PATH or in the qualor/scanner image)',
    });
  });

  it('is unavailable for a silent version probe, no node, or a runner directory inside the repository', async () => {
    expect(
      await staticcheckAnalyzer.prepare(context(MODULE, { versions: { go: 'oops' } }).ctx),
    ).toEqual({
      unavailable: '`go version` printed no version',
    });
    expect(await gosecAnalyzer.prepare(context(MODULE, { versions: { gosec: '' } }).ctx)).toEqual({
      unavailable: '`gosec -version` printed no version',
    });
    expect(
      await staticcheckAnalyzer.prepare(
        context(MODULE, {
          binaries: { go: path.join(BIN, 'go'), staticcheck: path.join(BIN, 'staticcheck') },
        }).ctx,
      ),
    ).toEqual({
      unavailable: 'the Go analyzers need node on PATH',
    });
    const inRepo = context(MODULE);
    expect(
      await staticcheckAnalyzer.prepare({
        ...inRepo.ctx,
        env: { ...inRepo.ctx.env, QUALOR_GO_DIR: path.join(inRepo.root, 'tools') },
      }),
    ).toEqual({
      unavailable: 'QUALOR_GO_DIR must be an absolute path outside the repository',
    });
  });

  it('turns a skip into a failure under enabled: true, without marking the engine unavailable', async () => {
    const root = tmp();
    writeTree(root, MODULE);
    const [capture] = await runAnalyzers([staticcheckAnalyzer], {
      root,
      config: parseConfig({ version: 1, analyzers: { staticcheck: { enabled: true } } }),
      files: Object.keys(MODULE).map((f) => scope(root, f)),
      log: silentLogger,
      env: { ...process.env, QUALOR_GO_DIR: tmp() },
    });
    expect(capture).toMatchObject({
      status: 'failed',
      reason: "Qualor's Go runner is not installed (qualor/scanner image)",
    });
    expect(capture?.unavailable ?? false).toBe(false);
  });

  it('probes the versions with GOTOOLCHAIN=local, GOENV=off and an empty GOFLAGS (ruling G9-15)', async () => {
    const seen: [string, Readonly<Record<string, string>> | undefined][] = [];
    for (const analyzer of [staticcheckAnalyzer, govetAnalyzer, gosecAnalyzer]) {
      const { ctx } = context(MODULE);
      const exec = ctx.exec;
      await run(
        {
          ...ctx,
          exec: (command, args, options) => {
            seen.push([path.basename(command), options.env]);
            return exec(command, args, options);
          },
        },
        analyzer,
      );
    }
    expect(seen.map(([name]) => name)).toEqual(['go', 'staticcheck', 'go', 'go', 'gosec']);
    for (const [name, env] of seen) {
      expect(env, name).toEqual({ GOTOOLCHAIN: 'local', GOENV: 'off', GOFLAGS: '' });
    }
  });

  it('reads the versions the tools print', () => {
    expect(parseGoVersion('go version go1.27.1 linux/amd64\n')).toBe('1.27.1');
    expect(parseGoVersion('go version go1.28rc1 linux/arm64')).toBe('1.28rc1');
    expect(parseGoVersion('go version devel +abc linux/amd64')).toBeNull();
    expect(parseStaticcheckVersion('staticcheck 2026.2.1 (0.8.1)\n')).toBe('2026.2.1');
    expect(parseStaticcheckVersion('staticcheck (devel)')).toBeNull();
    expect(parseGosecVersion('Version: 2.29.0\nGit tag: v2.29.0\nBuild date: \n')).toBe('2.29.0');
    expect(parseGosecVersion('Version: dev')).toBeNull();
  });

  it("logs the runner's warnings and fatal line, bounded, and nothing else of its stderr", () => {
    const stderr =
      'go: downloading x\ngo: warning: the root module: 2 package(s) not analysed\nnoise\ngo: fatal: cannot run go: ENOENT\n';
    expect(goWarnings(stderr)).toEqual(['the root module: 2 package(s) not analysed']);
    expect(goFailureDetail(stderr)).toBe('cannot run go: ENOENT');
    expect(goFailureDetail('')).toBeNull();
    expect(goWarnings('go: warning: x\n'.repeat(GO_RUNNER_MAX_WARNINGS + 20))).toHaveLength(
      GO_RUNNER_MAX_WARNINGS + 1,
    );
  });
});

/** The tool version a recording holds: a pin bump then needs only the re-recording (Step 6). */
const recordedVersion = (file: string) =>
  (JSON.parse(readFileSync(file, 'utf8')) as { runs: { tool: { driver: { version: string } } }[] })
    .runs[0]!.tool.driver.version;

describe('the recorded go-basic runs normalise into Go issues (report-format.md §7.1, plan 9C)', () => {
  it('staticcheck', () => {
    const file = 'cli/test/analyzer-output/staticcheck/basic.sarif';
    const r = scanWithRecordedSarif('staticcheck', file);
    const by = (k: string) =>
      r.issues
        .filter((i) => i.ruleKey === k)
        .map((i) => [i.location?.path, i.location?.startLine, i.severity, i.quality]);
    expect(by('staticcheck:SA5009')).toEqual([['store/store.go', 45, 'high', 'reliability']]);
    expect(by('staticcheck:SA4000')).toEqual([['store/store.go', 50, 'medium', 'reliability']]);
    expect(by('staticcheck:S1008')).toEqual([['tools/next.go', 5, 'low', 'maintainability']]);
    // The recording's own version, not the pin: a bump re-records instead of editing this test.
    expect(r.engines[0]?.version).toBe(recordedVersion(file));
  });

  it('govet', () => {
    const r = scanWithRecordedSarif('govet', 'cli/test/analyzer-output/govet/basic.sarif');
    expect(
      r.issues.map((i) => `${i.ruleKey} ${i.location?.startLine} ${i.severity}`).sort(),
    ).toEqual([
      'govet:bools 50 medium',
      'govet:copylocks 39 medium',
      'govet:copylocks 40 medium',
      'govet:printf 45 medium',
    ]);
  });

  it('gosec', () => {
    const r = scanWithRecordedSarif('gosec', 'cli/test/analyzer-output/gosec/basic.sarif');
    expect(
      r.issues.map((i) => [i.ruleKey, i.location?.startLine, i.severity, i.quality]).sort(),
    ).toEqual([
      ['gosec:G401', 60, 'medium', 'security'],
      ['gosec:G501', 4, 'medium', 'security'],
    ]);
    const g401 = r.engines[0]?.rules.find((x) => x.id === 'G401');
    expect(g401?.cwe).toEqual([328]);
  });
});

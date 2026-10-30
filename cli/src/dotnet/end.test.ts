import { existsSync, mkdirSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { EXIT } from '../errors';
import { createLogger, silentLogger } from '../log';
import { captureIO } from '../../test/io';
import { commitAll, initRepo } from '../../test/git';
import { testParsers } from '../../test/parsers';
import { engineSarif, writeEnginePack } from '../../test/taint';
import { useTempDirs } from '../../test/tmp';
import type { SarifLog } from '@qualor/shared';
import type { TaintRun } from '../analyzers/types';
import { runDotnetBegin } from './begin';
import { releaseHook, runDotnetEnd, type DotnetEndDeps } from './end';
import type { TaintEngineOptions } from './engine';
import { hookPath, installHook, removeHook } from './hook';
import { addLease, leaseDir } from './leases';

const tmp = useTempDirs();

const SARIF = (root: string) =>
  JSON.stringify({
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Microsoft (R) Visual C# Compiler',
            semanticVersion: '5.9.0',
            rules: [{ id: 'CA5351', properties: { category: 'Security' } }],
          },
        },
        results: [
          {
            ruleId: 'CA5351',
            ruleIndex: 0,
            level: 'warning',
            message: { text: 'Fingerprint uses a broken cryptographic algorithm MD5' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: `file:///${root.replace(/\\/g, '/').replace(/^\//, '')}/src/Hashing.cs`,
                  },
                  region: { startLine: 3, startColumn: 1, endLine: 3, endColumn: 10 },
                },
              },
            ],
          },
        ],
      },
    ],
  });

/** Gitleaks off; the qualor engine stays on (the taint engine's tests). */
const WITH_QUALOR = 'version: 1\nanalyzers:\n  gitleaks: { enabled: false }\n';

/**
 * Also the qualor engine off: the hook, lease and log tests need none of its work, and where a
 * rules pack is installed (CI, the analyzers image) it would scan the C# file with OpenGrep and
 * the whole pack, about 8 s a scan, and run the real taint engine on a collected session.
 */
const WITHOUT_QUALOR = `${WITH_QUALOR}  qualor: { enabled: false }\n`;

function setup(config: string = WITHOUT_QUALOR) {
  const root = tmp();
  initRepo(root);
  mkdirSync(path.join(root, 'src'));
  writeFileSync(
    path.join(root, 'src', 'Hashing.cs'),
    'class H {\n  byte[] F() {\n    return System.Security.Cryptography.MD5.HashData(new byte[0]);\n  }\n}\n',
  );
  writeFileSync(path.join(root, 'qualor.yml'), config);
  commitAll(root, 'init');
  const env = {
    QUALOR_MSBUILD_USER_DIR: tmp(),
    QUALOR_CACHE_DIR: tmp(),
    QUALOR_DOTNET_ANALYZERS: tmp(),
    DOTNET_CLI_TELEMETRY_OPTOUT: '1',
    PATH: process.env['PATH'] ?? '',
  };
  return { root, env };
}

/** What the hook writes for one compiled project and target framework. */
function build(root: string, name: string, tfm: string, withLog = true) {
  const dir = path.join(root, '.qualor', 'dotnet');
  const log = path.join(dir, 'sarif', `${name}-1-${tfm}.sarif`);
  writeFileSync(
    path.join(dir, 'projects', `${name}-${tfm}.txt`),
    `${path.join(root, `${name}.csproj`)}\n${tfm}\n${log}\n`,
  );
  if (withLog) writeFileSync(log, SARIF(root));
}

async function end(
  root: string,
  env: Record<string, string>,
  lines: string[] = [],
  deps: Pick<DotnetEndDeps, 'runTaint'> = {},
) {
  const out = path.join(tmp(), 'r.json.gz');
  const code = await runDotnetEnd(
    { sarif: [], coverage: [], wait: true, dryRun: true, output: out, projectKey: 'p' },
    captureIO({ cwd: root, env }).io,
    createLogger('warn', (t) => lines.push(t)),
    { parsers: await testParsers(), baselineClient: null, ...deps },
  );
  const report = existsSync(out)
    ? JSON.parse(gunzipSync(readFileSync(out)).toString('utf8'))
    : null;
  return { code, report };
}

describe('qualor dotnet end (config.md §6.1, ruling D7)', () => {
  it('removes the hook, reads the logs once each across target frameworks, deletes the session and scans', async () => {
    const { root, env } = setup();
    runDotnetBegin({}, captureIO({ cwd: root, env }).io, silentLogger);
    build(root, 'Lib', 'net8.0');
    build(root, 'Lib', 'net10.0');
    const { code, report } = await end(root, env);
    expect(code).toBe(EXIT.OK);
    expect(existsSync(hookPath(env.QUALOR_MSBUILD_USER_DIR))).toBe(false);
    expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
    const roslyn = report.engines.find((e: { id: string }) => e.id === 'roslyn');
    expect(roslyn).toMatchObject({ status: 'ok', version: '5.9.0' });
    expect(
      report.findings.filter((f: { engineId: string }) => f.engineId === 'roslyn'),
    ).toMatchObject([{ ruleId: 'CA5351', location: { path: 'src/Hashing.cs', startLine: 3 } }]);
  });

  it('keeps the hook while another session holds a lease, whatever each job sets QUALOR_CACHE_DIR to (final review R9)', async () => {
    const a = setup();
    const b = setup();
    // Two checkouts of one shell runner: one MSBuild user directory, a cache directory each (on
    // GitLab the cache lies inside each checkout).
    const shared = { ...b.env, QUALOR_MSBUILD_USER_DIR: a.env.QUALOR_MSBUILD_USER_DIR };
    runDotnetBegin({}, captureIO({ cwd: a.root, env: a.env }).io, silentLogger);
    runDotnetBegin({}, captureIO({ cwd: b.root, env: shared }).io, silentLogger);
    await end(a.root, a.env);
    expect(existsSync(hookPath(a.env.QUALOR_MSBUILD_USER_DIR))).toBe(true);
    await end(b.root, shared);
    expect(existsSync(hookPath(a.env.QUALOR_MSBUILD_USER_DIR))).toBe(false);
  });

  it('end without a session still prunes a stale lease and removes the hook it guarded (fix round 1, R5.2)', async () => {
    const { root, env } = setup();
    installHook(env.QUALOR_MSBUILD_USER_DIR);
    const dir = leaseDir(env.QUALOR_MSBUILD_USER_DIR);
    const staleId = 'a'.repeat(32);
    const old = new Date(Date.now() - 25 * 3600_000);
    addLease(dir, staleId, '/some/other/checkout', old);
    utimesSync(path.join(dir, staleId), old, old);

    const { report } = await end(root, env);
    expect(report.engines.find((e: { id: string }) => e.id === 'roslyn')).toMatchObject({
      status: 'skipped',
      reason: 'qualor dotnet begin was not run',
    });
    expect(existsSync(path.join(dir, staleId))).toBe(false);
    expect(existsSync(hookPath(env.QUALOR_MSBUILD_USER_DIR))).toBe(false);
  });

  it('end without a session keeps the hook while a live foreign lease remains (fix round 1, R5.2)', async () => {
    const { root, env } = setup();
    installHook(env.QUALOR_MSBUILD_USER_DIR);
    const dir = leaseDir(env.QUALOR_MSBUILD_USER_DIR);
    const liveId = 'b'.repeat(32);
    addLease(dir, liveId, '/some/other/checkout', new Date());

    const { report } = await end(root, env);
    expect(report.engines.find((e: { id: string }) => e.id === 'roslyn')).toMatchObject({
      status: 'skipped',
      reason: 'qualor dotnet begin was not run',
    });
    expect(existsSync(hookPath(env.QUALOR_MSBUILD_USER_DIR))).toBe(true);
    expect(existsSync(path.join(dir, liveId))).toBe(true);
  });

  it("ignores a session.json whose root names another checkout, but still cleans up here and keeps that checkout's lease (fix round 1, R5.3)", async () => {
    const other = setup();
    runDotnetBegin({}, captureIO({ cwd: other.root, env: other.env }).io, silentLogger);
    const foreignSession = readFileSync(
      path.join(other.root, '.qualor', 'dotnet', 'session.json'),
      'utf8',
    );
    const foreignId = (JSON.parse(foreignSession) as { id: string }).id;

    const { root, env } = setup();
    const shared = { ...env, QUALOR_MSBUILD_USER_DIR: other.env.QUALOR_MSBUILD_USER_DIR };
    mkdirSync(path.join(root, '.qualor', 'dotnet', 'sarif'), { recursive: true });
    mkdirSync(path.join(root, '.qualor', 'dotnet', 'projects'), { recursive: true });
    writeFileSync(path.join(root, '.qualor', 'dotnet', 'session.json'), foreignSession);
    build(root, 'Lib', 'net8.0');

    const { report } = await end(root, shared);
    expect(report.engines.find((e: { id: string }) => e.id === 'roslyn')).toMatchObject({
      status: 'skipped',
      reason: 'qualor dotnet begin was not run',
    });
    expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
    // The foreign session's own lease and hook are untouched: end(root) never learned its id.
    expect(existsSync(path.join(leaseDir(shared.QUALOR_MSBUILD_USER_DIR), foreignId))).toBe(true);
    expect(existsSync(hookPath(shared.QUALOR_MSBUILD_USER_DIR))).toBe(true);
  });

  it('reinstalls the hook when a live lease appeared while it was being removed (final review R9)', () => {
    const userDir = tmp();
    const now = new Date();
    const own = 'a'.repeat(32);
    addLease(leaseDir(userDir), own, '/checkout/a', now);
    installHook(userDir);
    // Job B's begin runs between A's count and A's removal: it records its lease, and its hook
    // install finds the file still there. A's removal then deletes the hook B needs.
    const removeWhileBBegins = (dir: string) => {
      addLease(leaseDir(dir), 'b'.repeat(32), '/checkout/b', now);
      return removeHook(dir);
    };
    releaseHook(userDir, own, now, silentLogger, removeWhileBBegins);
    expect(existsSync(hookPath(userDir))).toBe(true);
    expect(existsSync(path.join(leaseDir(userDir), own))).toBe(false);
    // With nothing appearing meanwhile, the hook goes.
    releaseHook(userDir, 'b'.repeat(32), now, silentLogger);
    expect(existsSync(hookPath(userDir))).toBe(false);
  });

  it('is unavailable, not skipped, when begin could not install the hook under auto (final review R10)', async () => {
    const { root, env } = setup();
    const importBefore = path.dirname(hookPath(env.QUALOR_MSBUILD_USER_DIR));
    mkdirSync(path.dirname(importBefore), { recursive: true });
    writeFileSync(importBefore, 'a file where ImportBefore/ must go');
    expect(runDotnetBegin({}, captureIO({ cwd: root, env }).io, silentLogger)).toBe(EXIT.OK);
    const { report } = await end(root, env);
    const roslyn = report.engines.find((e: { id: string }) => e.id === 'roslyn');
    expect(roslyn.status).toBe('skipped');
    expect(roslyn.reason).toMatch(
      /^the MSBuild hook could not be installed \(cannot install the MSBuild hook in /,
    );
    expect(report.warnings.map((w: { code: string }) => w.code)).not.toContain(
      'ROSLYN_PROJECT_NOT_ANALYZED',
    );
    expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
  });

  it('skips without begin, and without a build', async () => {
    const { root, env } = setup();
    const none = await end(root, env);
    expect(none.report.engines.find((e: { id: string }) => e.id === 'roslyn')).toMatchObject({
      status: 'skipped',
      reason: 'qualor dotnet begin was not run',
    });
    runDotnetBegin({}, captureIO({ cwd: root, env }).io, silentLogger);
    const empty = await end(root, env);
    expect(empty.report.engines.find((e: { id: string }) => e.id === 'roslyn')).toMatchObject({
      status: 'skipped',
      reason: 'no C# project was built between qualor dotnet begin and end',
    });
  });

  it('warns about a project record without a fresh log, and is unavailable when no log is fresh (Review Focus 4)', async () => {
    const { root, env } = setup();
    runDotnetBegin({}, captureIO({ cwd: root, env }).io, silentLogger);
    build(root, 'Lib', 'net8.0');
    build(root, 'Other', 'net8.0', false);
    const lines: string[] = [];
    const partial = await end(root, env, lines);
    expect(partial.report.warnings.map((w: { code: string }) => w.code)).toContain(
      'ROSLYN_PROJECT_NOT_ANALYZED',
    );
    runDotnetBegin({}, captureIO({ cwd: root, env }).io, silentLogger);
    build(root, 'Other', 'net8.0', false);
    const none = await end(root, env);
    expect(none.report.engines.find((e: { id: string }) => e.id === 'roslyn')).toMatchObject({
      status: 'skipped',
      reason:
        'no C# project was compiled between qualor dotnet begin and end (build with --no-incremental)',
    });
  });
});

describe('qualor dotnet end on a tag', () => {
  it('records a version without reading the Roslyn logs or running the taint engine', async () => {
    const { root, env } = setup();
    runDotnetBegin({}, captureIO({ cwd: root, env }).io, silentLogger);
    build(root, 'Lib', 'net8.0');
    let taintRuns = 0;
    const out = path.join(tmp(), 'r.json.gz');
    const code = await runDotnetEnd(
      {
        sarif: [],
        coverage: [],
        wait: true,
        dryRun: true,
        output: out,
        projectKey: 'p',
        tag: 'v1.0.0',
      },
      captureIO({ cwd: root, env }).io,
      silentLogger,
      {
        parsers: await testParsers(),
        baselineClient: null,
        licensePass: { resolveBinary: () => null },
        runTaint: () => {
          taintRuns += 1;
          return Promise.reject(new Error('must not run'));
        },
      },
    );
    expect(code).toBe(EXIT.OK);
    expect(taintRuns).toBe(0);
    const report = JSON.parse(gunzipSync(readFileSync(out)).toString('utf8'));
    expect(report.scm.tag).toBe('v1.0.0');
    expect(report.findings).toEqual([]);
    expect(report.files).toEqual([]);
    expect(report.engines.some((e: { id: string }) => e.id === 'roslyn')).toBe(false);
    // The session is still cleaned up.
    expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
  });
});

describe("qualor dotnet end with Qualor's Roslyn taint engine (6B-C# R, spec §4.2, R-4)", () => {
  /** A session whose build recorded one project's compiler inputs, with a pack that has the engine. */
  function session(o: { config?: string; engine?: boolean } = {}) {
    const { root, env } = setup(o.config ?? WITH_QUALOR);
    const withPack = {
      ...env,
      QUALOR_RULES_DIR: writeEnginePack(tmp(), { engine: o.engine ?? true, severity: 'blocker' }),
      QUALOR_TAINT_TIME_LIMIT: '120',
    };
    runDotnetBegin({}, captureIO({ cwd: root, env: withPack }).io, silentLogger);
    build(root, 'Lib', 'net8.0');
    const compilations = path.join(root, '.qualor', 'dotnet', 'compilations');
    mkdirSync(compilations, { recursive: true });
    writeFileSync(path.join(compilations, 'a1b2.txt'), 'format=1\n');
    return { root, env: withPack };
  }

  /** A fake engine run: records what it was given and whether the inputs were still there. */
  function fakeTaint(answer: (o: TaintEngineOptions) => TaintRun) {
    const calls: { o: TaintEngineOptions; inputs: boolean }[] = [];
    const runTaint = (o: TaintEngineOptions) => {
      calls.push({ o, inputs: existsSync(path.join(o.sessionDir, 'compilations', 'a1b2.txt')) });
      return Promise.resolve(answer(o));
    };
    return { calls, runTaint };
  }

  it('runs the engine on the recorded inputs before the session is deleted, and its findings are the C# findings of the qualor engine', async () => {
    const { root, env } = session();
    const taint = fakeTaint((o) => ({
      kind: 'ok',
      sources: ['src/Hashing.cs'],
      sarif: engineSarif(o.root, [
        {
          rule: 'csharp.sql-injection',
          uri: 'src/Hashing.cs',
          line: 3,
          steps: [['src/Hashing.cs', 2, 'request data']],
        },
      ]) as SarifLog,
    }));
    const { code, report } = await end(root, env, [], { runTaint: taint.runTaint });
    expect(code).toBe(EXIT.OK);
    expect(taint.calls).toHaveLength(1);
    expect(taint.calls[0]).toMatchObject({
      inputs: true,
      o: {
        root,
        sessionDir: path.join(root, '.qualor', 'dotnet'),
        timeLimitS: 120,
        memoryLimitMb: expect.any(Number) as unknown,
      },
    });
    expect(taint.calls[0]?.o.pack?.manifest.dotnetEngine).toMatchObject({ version: '2026.10.4' });
    expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
    expect(report.engines.find((e: { id: string }) => e.id === 'qualor')).toMatchObject({
      status: 'ok',
      version: 'qualor-taint 2026.10.4 + qualor-rules 2026.10.4',
    });
    const findings = report.findings.filter((f: { engineId: string }) => f.engineId === 'qualor');
    expect(findings).toMatchObject([
      {
        ruleId: 'csharp/sql-injection',
        severity: 'blocker',
        location: { path: 'src/Hashing.cs', startLine: 3 },
        secondaryLocations: [{ path: 'src/Hashing.cs', startLine: 2, message: 'request data' }],
      },
    ]);
    expect(report.warnings.map((w: { code: string }) => w.code)).not.toContain(
      'TAINT_ENGINE_FALLBACK',
    );
  });

  it('falls back on a crash when the engine step throws, and still scans (fix round 1, I1)', async () => {
    const { root, env } = session();
    const lines: string[] = [];
    const runTaint = () => Promise.reject(new Error('ENOSPC: no space left on device, mkdtemp'));
    const { code, report } = await end(root, env, lines, { runTaint });
    expect(code).toBe(EXIT.OK);
    expect(report).not.toBeNull();
    expect(report.engines.find((e: { id: string }) => e.id === 'roslyn')).toMatchObject({
      status: 'ok',
    });
    expect(lines.join('\n')).toContain(
      "Qualor's Roslyn taint engine did not run (crash: ENOSPC: no space left on device, mkdtemp); the OpenGrep C# rules run in its place",
    );
    expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
  });

  it('on a fallback logs why, deletes the session and keeps the exit code (Review Focus 3)', async () => {
    const { root, env } = session();
    const taint = fakeTaint(() => ({
      kind: 'fallback',
      reason: 'budget',
      detail: 'time limit of 120 s exceeded',
    }));
    const lines: string[] = [];
    const { code } = await end(root, env, lines, { runTaint: taint.runTaint });
    expect(code).toBe(EXIT.OK);
    expect(taint.calls).toHaveLength(1);
    expect(lines.join('\n')).toContain(
      "Qualor's Roslyn taint engine did not run (budget: time limit of 120 s exceeded); the OpenGrep C# rules run in its place",
    );
    expect(existsSync(path.join(root, '.qualor', 'dotnet'))).toBe(false);
  });

  it('does not run the engine when the qualor engine is disabled or no rules are installed', async () => {
    const disabled = session({
      config:
        'version: 1\nanalyzers:\n  gitleaks: { enabled: false }\n  qualor: { enabled: false }\n',
    });
    const taint = fakeTaint(() => ({ kind: 'fallback', reason: 'crash', detail: 'x' }));
    expect((await end(disabled.root, disabled.env, [], { runTaint: taint.runTaint })).code).toBe(
      EXIT.OK,
    );
    const none = session();
    expect(
      (
        await end(none.root, { ...none.env, QUALOR_RULES_DIR: path.join(tmp(), 'gone') }, [], {
          runTaint: taint.runTaint,
        })
      ).code,
    ).toBe(EXIT.OK);
    expect(taint.calls).toEqual([]);
  });
});

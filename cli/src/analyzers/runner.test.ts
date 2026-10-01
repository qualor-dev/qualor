import { spawn } from 'node:child_process';
import { chmodSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseConfig, type Language, type QualorConfigInput } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import type { Logger } from '../log';
import { silentLogger } from '../log';
import { createDetektAnalyzer } from './detekt';
import { builtinAnalyzers } from './registry';
import {
  emergencyCleanup,
  execEnv,
  mapLimit,
  removeActiveWorkDirs,
  requiredFailures,
  runAnalyzers,
  spawnFailureReason,
} from './runner';
import type { Analyzer, AnalyzerId, SarifCapture } from './types';

const tmp = useTempDirs();

const SARIF = {
  version: '2.1.0',
  runs: [
    {
      tool: { driver: { name: 'Fake', version: '9.9.9', rules: [{ id: 'r1' }] } },
      results: [
        {
          ruleId: 'r1',
          message: { text: 'found it' },
          locations: [
            {
              physicalLocation: { artifactLocation: { uri: 'src/a.ts' }, region: { startLine: 1 } },
            },
          ],
        },
      ],
    },
  ],
};

const FAKE_SECRET = 'ghp_SUPERSECRETTOKENVALUE1234567890';

const TOOL = `
import { truncateSync, writeFileSync } from 'node:fs';
const [mode, out] = process.argv.slice(2);
if (mode === 'ok') writeFileSync(out, JSON.stringify(${JSON.stringify(SARIF)}));
else if (mode === 'crash') { process.stderr.write('boom\\n'); process.exit(2); }
else if (mode === 'okwarn') { process.stderr.write('warning: setting ignored\\n'); writeFileSync(out, JSON.stringify(${JSON.stringify(SARIF)})); }
else if (mode === 'garbage') writeFileSync(out, '{"runs": ${FAKE_SECRET}');
else if (mode === 'hang') setInterval(() => {}, 1000);
else if (mode === 'huge') { writeFileSync(out, ''); truncateSync(out, 256 * 1024 * 1024 + 1); }
else if (mode === 'env') writeFileSync(out, JSON.stringify({
  token: process.env.QUALOR_TOKEN ?? null,
  tokenFile: process.env.QUALOR_TOKEN_FILE ?? null,
  otherSecret: process.env.QUALOR_OTHER_SECRET ?? null,
  safe: process.env.SAFE_VAR ?? null,
}));
else if (mode === 'dropped') writeFileSync(out, JSON.stringify(Object.fromEntries(
  Object.entries(process.env).filter(([k]) => /^(TRIVY_|HTTP_PROXY$|SAFE_VAR$)/i.test(k)),
)));
else if (mode === 'paths') writeFileSync(out, JSON.stringify(Object.fromEntries(
  Object.entries(process.env).filter(([k]) => ['PATH', 'CLASSPATH'].includes(k.toUpperCase())),
)));
`;

function setup(): { root: string; files: ScopeFile[]; toolPath: string } {
  const root = tmp();
  writeTree(root, { 'src/a.ts': 'console.log(1);\n', 'tool.mjs': TOOL });
  const files: ScopeFile[] = [
    {
      path: 'src/a.ts',
      absPath: path.join(root, 'src', 'a.ts'),
      language: 'typescript',
      grammar: 'typescript',
      kind: 'main',
      size: 16,
    },
  ];
  return { root, files, toolPath: path.join(root, 'tool.mjs') };
}

function fake(
  id: AnalyzerId,
  toolPath: string,
  mode: string,
  languages: Language[] = [],
): Analyzer {
  return {
    id,
    languages,
    prepare: (ctx) => {
      const sarifPath = path.join(ctx.workDir, 'out.sarif');
      return Promise.resolve({
        run: {
          command: process.execPath,
          args: [toolPath, mode, sarifPath],
          cwd: ctx.root,
          sarifPath,
          okExitCodes: [0],
          version: '1.2.3',
        },
      });
    },
  };
}

const config = (analyzers: QualorConfigInput['analyzers'] = {}) =>
  parseConfig({ version: 1, analyzers });

describe('runAnalyzers', () => {
  it('captures SARIF of a successful run', async () => {
    const { root, files, toolPath } = setup();
    const [c] = await runAnalyzers([fake('eslint', toolPath, 'ok')], {
      root,
      files,
      config: config(),
      log: silentLogger,
    });
    expect(c).toMatchObject({
      engineId: 'eslint',
      kind: 'builtin',
      status: 'ok',
      reason: null,
      version: '1.2.3',
      required: false,
    });
    expect(c?.sarif).toEqual(SARIF);
    expect(c?.mapping).toBeDefined();
  });

  it('logs the configuration warnings an adapter reads from stderr at warn, only for a run that ended fine', async () => {
    const { root, files, toolPath } = setup();
    const seen: string[] = [];
    const withWarnings = (id: AnalyzerId, mode: string): Analyzer => {
      const base = fake(id, toolPath, mode);
      return {
        ...base,
        prepare: async (ctx) => {
          const prep = await base.prepare(ctx);
          if (!('run' in prep)) throw new Error('unexpected');
          return {
            run: {
              ...prep.run,
              configWarnings: (stderr: string) => {
                seen.push(stderr);
                return stderr.includes('ignored') ? ['a setting was ignored'] : [];
              },
            },
          };
        },
      };
    };
    const warnings: string[] = [];
    const log = { ...silentLogger, warn: (m: string) => warnings.push(m) };
    const captures = await runAnalyzers(
      [withWarnings('eslint', 'okwarn'), withWarnings('pmd', 'crash')],
      { root, files, config: config(), log },
    );
    expect(captures.map((c) => c.status)).toEqual(['ok', 'failed']);
    expect(seen).toEqual(['warning: setting ignored\n']);
    expect(warnings).toContain('eslint: a setting was ignored');
  });

  it('records failures: exit code, missing output, invalid JSON', async () => {
    const { root, files, toolPath } = setup();
    const captures = await runAnalyzers(
      [
        fake('eslint', toolPath, 'crash'),
        fake('pmd', toolPath, 'silent'),
        fake('semgrep', toolPath, 'garbage'),
      ],
      { root, files, config: config({ eslint: { enabled: true } }), log: silentLogger },
    );
    expect(captures.map((c) => [c.engineId, c.status])).toEqual([
      ['eslint', 'failed'],
      ['pmd', 'failed'],
      ['semgrep', 'failed'],
    ]);
    // Fix-round finding 4: the reason is a fixed message, never the analyzer's own stderr.
    expect(captures[0]?.reason).toBe('exited with code 2');
    expect(captures[1]?.reason).toBe('produced no SARIF output');
    // Fix-round-2 finding 1: V8's JSON.parse SyntaxError quotes the malformed input (which here
    // contains a fake secret), so the reason must be the fixed message, never that raw text.
    expect(captures[2]?.reason).toBe('SARIF output is not valid JSON');
    expect(JSON.stringify(captures)).not.toContain(FAKE_SECRET);
    expect(requiredFailures(captures)).toEqual(['eslint']);
  });

  it('counts a required engine whose normalisation failed as a required failure', () => {
    const captures = [
      { engineId: 'gitleaks', required: true, status: 'ok' },
      { engineId: 'pmd', required: false, status: 'ok' },
    ] as unknown as SarifCapture[];
    // The capture ran, but its SARIF could not be normalised: the report records it as failed.
    const engines = [
      { id: 'gitleaks', status: 'failed' as const },
      { id: 'pmd', status: 'failed' as const },
    ];
    expect(requiredFailures(captures)).toEqual([]);
    expect(requiredFailures(captures, engines)).toEqual(['gitleaks']);
  });

  it('converts tool output with transform, and records a throwing transform as failed', async () => {
    const { root, files, toolPath } = setup();
    const withTransform = (id: AnalyzerId, transform: (o: unknown) => unknown): Analyzer => {
      const base = fake(id, toolPath, 'ok');
      return {
        ...base,
        prepare: async (ctx) => {
          const prep = await base.prepare(ctx);
          if (!('run' in prep)) throw new Error('unexpected');
          return { run: { ...prep.run, transform } };
        },
      };
    };
    const captures = await runAnalyzers(
      [
        withTransform('eslint', (o) => ({ ...(o as object), converted: true })),
        withTransform('pmd', () => {
          throw new Error(`cannot convert ${FAKE_SECRET}`);
        }),
      ],
      { root, files, config: config(), log: silentLogger },
    );
    expect(captures[0]).toMatchObject({ status: 'ok', sarif: { ...SARIF, converted: true } });
    expect(captures[1]).toMatchObject({
      status: 'failed',
      reason: 'output could not be converted to SARIF',
    });
    expect(JSON.stringify(captures)).not.toContain(FAKE_SECRET);
  });

  it('never hands an adapter a binary the repository planted (ruling V3)', async () => {
    const { root, files } = setup();
    const exe = process.platform === 'win32' ? '.exe' : '';
    writeTree(root, { [`node_modules/.bin/gitleaks${exe}`]: '#!/bin/sh\n' });
    chmodSync(path.join(root, 'node_modules', '.bin', `gitleaks${exe}`), 0o755);
    const bin = path.join(root, 'node_modules', '.bin');
    const seen: { resolved: string | null; repo: string | null; env: unknown }[] = [];
    const probe: Analyzer = {
      id: 'gitleaks',
      languages: [],
      prepare: (ctx) => {
        seen.push({
          resolved: ctx.resolveBinary('gitleaks'),
          repo: ctx.repoBinary('gitleaks'),
          env: ctx.env['QUALOR_TOKEN'],
        });
        return Promise.resolve({ skip: 'probe' });
      },
    };
    await runAnalyzers([probe], {
      root,
      files,
      config: config(),
      log: silentLogger,
      env: { PATH: bin, Path: bin, QUALOR_TOKEN: FAKE_SECRET },
    });
    // Null here, or the scanner image's own copy on a Linux image: never the planted one.
    expect(seen).toEqual([
      {
        resolved: process.platform === 'win32' ? null : expect.not.stringContaining(root),
        repo: path.join(bin, `gitleaks${exe}`),
        env: undefined,
      },
    ]);
  });

  it('carries the analyzer rule languages into the capture', async () => {
    const { root, files, toolPath } = setup();
    const [c] = await runAnalyzers([{ ...fake('pmd', toolPath, 'ok'), ruleLanguages: ['java'] }], {
      root,
      files,
      config: config(),
      log: silentLogger,
    });
    expect(c?.ruleLanguages).toEqual(['java']);
  });

  it('refuses SARIF output larger than 256 MiB without reading it', async () => {
    const { root, files, toolPath } = setup();
    const [c] = await runAnalyzers([fake('eslint', toolPath, 'huge')], {
      root,
      files,
      config: config(),
      log: silentLogger,
    });
    expect(c).toMatchObject({ status: 'failed', reason: 'SARIF output is larger than 256 MiB' });
  });

  it('times out a hanging analyzer and carries on', { timeout: 20_000 }, async () => {
    const { root, files, toolPath } = setup();
    const captures = await runAnalyzers(
      [fake('gitleaks', toolPath, 'hang'), fake('eslint', toolPath, 'ok')],
      { root, files, config: config({ gitleaks: { timeoutSeconds: 1 } }), log: silentLogger },
    );
    expect(captures.map((c) => [c.engineId, c.status, c.reason])).toEqual([
      ['gitleaks', 'timeout', 'timed out after 1 s'],
      ['eslint', 'ok', null],
    ]);
    expect(requiredFailures(captures)).toEqual(['gitleaks']);
  });

  it('skips disabled analyzers and analyzers whose languages are absent', async () => {
    const { root, files, toolPath } = setup();
    const captures = await runAnalyzers(
      [fake('eslint', toolPath, 'ok'), fake('pmd', toolPath, 'ok', ['java'])],
      { root, files, config: config({ eslint: { enabled: false } }), log: silentLogger },
    );
    expect(captures.map((c) => [c.engineId, c.status, c.reason, c.required])).toEqual([
      ['eslint', 'skipped', 'disabled in qualor.yml', false],
      ['pmd', 'skipped', 'no java files in scope', false],
    ]);
  });

  it('turns a prepare-time skip into a failure only when the analyzer is required', async () => {
    const { root, files } = setup();
    const missing = (id: AnalyzerId): Analyzer => ({
      id,
      languages: [],
      prepare: () => Promise.resolve({ skip: `${id} binary not found` }),
    });
    const captures = await runAnalyzers([missing('pmd'), missing('semgrep')], {
      root,
      files,
      config: config({ pmd: { enabled: true } }),
      log: silentLogger,
    });
    expect(captures.map((c) => [c.engineId, c.status, c.required])).toEqual([
      ['pmd', 'failed', true],
      ['semgrep', 'skipped', false],
    ]);
    expect(requiredFailures(captures)).toEqual(['pmd']);
  });

  it('marks a tool that cannot run here as unavailable, and fails it only when required (ruling G6)', async () => {
    const { root, files } = setup();
    const absent = (id: AnalyzerId): Analyzer => ({
      id,
      languages: [],
      prepare: () => Promise.resolve({ unavailable: `${id} is not installed` }),
    });
    const configured = (id: AnalyzerId): Analyzer => ({
      id,
      languages: [],
      prepare: () => Promise.resolve({ skip: `no ${id} configuration` }),
    });
    const captures = await runAnalyzers(
      [absent('pmd'), absent('semgrep'), configured('eslint'), absent('spotbugs')],
      {
        root,
        files,
        config: config({ pmd: { enabled: true }, spotbugs: { enabled: false } }),
        log: silentLogger,
      },
    );
    expect(captures.map((c) => [c.engineId, c.status, c.required, c.unavailable ?? false])).toEqual(
      [
        ['pmd', 'failed', true, true],
        ['semgrep', 'skipped', false, true],
        // A configuration skip did what the configuration asked: complete.
        ['eslint', 'skipped', false, false],
        // Disabled is never unavailable, even for a tool that is not installed.
        ['spotbugs', 'skipped', false, false],
      ],
    );
    expect(requiredFailures(captures)).toEqual(['pmd']);
  });

  it('skips detekt without the image under auto and fails it under enabled: true (plan 8E Review Focus 5)', async () => {
    const root = tmp();
    writeTree(root, { 'src/A.kt': 'class A\n' });
    const analyzer = createDetektAnalyzer({ defaultJar: path.join(tmp(), 'missing.jar') });
    const files: ScopeFile[] = [
      {
        path: 'src/A.kt',
        absPath: path.join(root, 'src', 'A.kt'),
        language: 'kotlin',
        grammar: 'kotlin',
        kind: 'main',
        size: 8,
      },
    ];
    const [auto] = await runAnalyzers([analyzer], {
      root,
      files,
      config: config({}),
      log: silentLogger,
      env: { PATH: '' },
    });
    // A plain host keeps a complete scan (ruling G6): a skip, not unavailable.
    expect([auto?.status, auto?.reason, auto?.required, auto?.unavailable ?? false]).toEqual([
      'skipped',
      'detekt is not installed (qualor/scanner image)',
      false,
      false,
    ]);
    const required = await runAnalyzers([analyzer], {
      root,
      files,
      config: config({ detekt: { enabled: true } }),
      log: silentLogger,
      env: { PATH: '' },
    });
    expect(required.map((c) => [c.engineId, c.status, c.required])).toEqual([
      ['detekt', 'failed', true],
    ]);
    expect(requiredFailures(required)).toEqual(['detekt']);
  });

  it('lists the built-in adapters in config order (ruling C8 ended with CLI step 12; plan 2D, 8D, 8E, 8F, 9A)', () => {
    const ids = builtinAnalyzers().map((a) => a.id);
    const order = [
      'eslint',
      'sonarjs',
      'ruff',
      'pmd',
      'spotbugs',
      'detekt',
      'swiftlint',
      'semgrep',
      'gitleaks',
      'trivy',
      'roslyn',
      'stylelint',
      'htmlhint',
      'phpstan',
    ] as const;
    // Membership and relative order (config.md §3), never the whole list.
    expect(ids).toEqual(expect.arrayContaining([...order]));
    const at = order.map((id) => ids.indexOf(id));
    expect(at).toEqual([...at].sort((a, b) => a - b));
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('gives adapters ctx.exec, which always sanitizes the environment, defaults cwd to the root and kills on timeout', async () => {
    const { root, files, toolPath } = setup();
    let seen: unknown;
    let hung: { timedOut: boolean; durationMs: number } | undefined;
    let cwdOut: string | undefined;
    const probe: Analyzer = {
      id: 'eslint',
      languages: [],
      prepare: async (ctx) => {
        const out = path.join(ctx.workDir, 'env.json');
        const r = await ctx.exec(process.execPath, [toolPath, 'env', out], { timeoutMs: 10_000 });
        expect(r.exitCode).toBe(0);
        seen = JSON.parse(readFileSync(out, 'utf8'));
        const cwd = await ctx.exec(
          process.execPath,
          ['-e', 'process.stdout.write(process.cwd())'],
          {
            timeoutMs: 10_000,
          },
        );
        cwdOut = cwd.stdout;
        hung = await ctx.exec(process.execPath, [toolPath, 'hang', out], { timeoutMs: 300 });
        return { unavailable: 'probe only' };
      },
    };
    await runAnalyzers([probe], {
      root,
      files,
      config: config(),
      log: silentLogger,
      env: {
        ...process.env,
        QUALOR_TOKEN: 'super-secret',
        QUALOR_TOKEN_FILE: '/tmp/token',
        QUALOR_OTHER_SECRET: 'also-secret',
        SAFE_VAR: 'kept',
      },
    });
    expect(seen).toEqual({ token: null, tokenFile: null, otherSecret: null, safe: 'kept' });
    expect(cwdOut).toBe(root);
    expect(hung?.timedOut).toBe(true);
    expect(hung?.durationMs).toBeLessThan(5_000);
  });

  it('strips QUALOR_TOKEN and QUALOR_*-secret vars from the analyzer child process (fix-round finding 3)', async () => {
    const { root, files, toolPath } = setup();
    const captures = await runAnalyzers([fake('eslint', toolPath, 'env')], {
      root,
      files,
      config: config(),
      log: silentLogger,
      env: {
        ...process.env,
        QUALOR_TOKEN: 'super-secret',
        QUALOR_TOKEN_FILE: '/tmp/token',
        QUALOR_OTHER_SECRET: 'also-secret',
        SAFE_VAR: 'kept',
      },
    });
    expect(captures[0]?.status).toBe('ok');
    expect(captures[0]?.sarif).toEqual({
      token: null,
      tokenFile: null,
      otherSecret: null,
      safe: 'kept',
    });
  });

  it('drops the variables an adapter names, after its own, and carries its database and warnings (plan 2B)', async () => {
    const { root, files, toolPath } = setup();
    const analyzer: Analyzer = {
      id: 'trivy',
      languages: [],
      prepare: (ctx) => {
        const sarifPath = path.join(ctx.workDir, 'out.sarif');
        return Promise.resolve({
          run: {
            command: process.execPath,
            args: [toolPath, 'dropped', sarifPath],
            cwd: ctx.root,
            env: { HTTP_PROXY: 'http://127.0.0.1:9', TRIVY_OWN: 'x' },
            dropEnv: (name) => /^TRIVY_/i.test(name),
            sarifPath,
            okExitCodes: [0],
            database: { name: 'trivy-db', updatedAt: '2026-09-25T06:36:11Z' },
            warnings: [{ code: 'VULNERABILITY_DB_STALE', message: 'old', count: 1 }],
          },
        });
      },
    };
    const [c] = await runAnalyzers([analyzer], {
      root,
      files,
      config: config(),
      log: silentLogger,
      env: {
        ...process.env,
        TRIVY_SERVER: 'http://evil.example',
        TRIVY_DB_REPOSITORY: 'evil.example/db',
        trivy_config: 'x.yaml',
        SAFE_VAR: 'kept',
      },
    });
    expect(c?.status).toBe('ok');
    // Every TRIVY_ variable is gone, the CI's and the adapter's alike, in any case.
    expect(c?.sarif).toEqual({ HTTP_PROXY: 'http://127.0.0.1:9', SAFE_VAR: 'kept' });
    expect(c?.database).toEqual({ name: 'trivy-db', updatedAt: '2026-09-25T06:36:11Z' });
    expect(c?.warnings).toEqual([{ code: 'VULNERABILITY_DB_STALE', message: 'old', count: 1 }]);
  });

  it('confines PATH and CLASSPATH of the analyzer and of ctx.exec to absolute entries outside the repository (ruling V3)', async () => {
    const { root, files, toolPath } = setup();
    const outside = tmp();
    const d = path.delimiter;
    let execSeen: unknown;
    const analyzer: Analyzer = {
      id: 'pmd',
      languages: [],
      prepare: async (ctx) => {
        const probe = path.join(ctx.workDir, 'exec.json');
        await ctx.exec(process.execPath, [toolPath, 'paths', probe], { timeoutMs: 10_000 });
        execSeen = JSON.parse(readFileSync(probe, 'utf8'));
        const sarifPath = path.join(ctx.workDir, 'out.sarif');
        return {
          run: {
            command: process.execPath,
            args: [toolPath, 'paths', sarifPath],
            cwd: ctx.root,
            // An adapter cannot put the repository back on the PATH either.
            env: { CLASSPATH: `.${d}${root}${d}${outside}` },
            sarifPath,
            okExitCodes: [0],
          },
        };
      },
    };
    const pathKey = process.platform === 'win32' ? 'Path' : 'PATH';
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([k]) => !['PATH', 'CLASSPATH'].includes(k.toUpperCase())),
    );
    const [c] = await runAnalyzers([analyzer], {
      root,
      files,
      config: config(),
      log: silentLogger,
      env: {
        ...env,
        [pathKey]: ['bin', '', path.join(root, 'bin'), outside].join(d),
        CLASSPATH: '.',
      },
    });
    expect(c?.status).toBe('ok');
    expect(execSeen).toEqual({ [pathKey]: outside });
    expect(c?.sarif).toEqual({ [pathKey]: outside, CLASSPATH: outside });
  });

  it('records a spawn failure as a fixed "not installed" reason, never the raw error text (fix-round finding 4)', async () => {
    const { root, files } = setup();
    const broken: Analyzer = {
      id: 'eslint',
      languages: [],
      prepare: (ctx) =>
        Promise.resolve({
          run: {
            command: path.join(root, 'does-not-exist-binary'),
            args: [],
            cwd: ctx.root,
            sarifPath: path.join(ctx.workDir, 'out.sarif'),
            okExitCodes: [0],
          },
        }),
    };
    const captures = await runAnalyzers([broken], {
      root,
      files,
      config: config(),
      log: silentLogger,
    });
    expect(captures[0]).toMatchObject({ status: 'failed', reason: 'not installed' });
  });

  it('records a throwing prepare() as failed and lets other analyzers continue (fix-round finding 9)', async () => {
    const { root, files, toolPath } = setup();
    const throwing: Analyzer = {
      id: 'pmd',
      languages: [],
      prepare: () => {
        throw new Error('boom');
      },
    };
    const captures = await runAnalyzers([throwing, fake('eslint', toolPath, 'ok')], {
      root,
      files,
      config: config({ pmd: { enabled: true } }),
      log: silentLogger,
    });
    expect(captures.map((c) => [c.engineId, c.status, c.reason])).toEqual([
      ['pmd', 'failed', 'failed to prepare'],
      ['eslint', 'ok', null],
    ]);
    expect(requiredFailures(captures)).toEqual(['pmd']);
  });

  it('removes each analyzer work directory afterwards', async () => {
    const { root, files, toolPath } = setup();
    let workDir = '';
    const spy: Analyzer = {
      ...fake('eslint', toolPath, 'ok'),
      prepare: (ctx) => {
        workDir = ctx.workDir;
        return fake('eslint', toolPath, 'ok').prepare(ctx);
      },
    };
    await runAnalyzers([spy], { root, files, config: config(), log: silentLogger });
    expect(workDir).not.toBe('');
    expect(existsSync(workDir)).toBe(false);
  });

  it('installs SIGINT/SIGTERM (and on POSIX SIGHUP) handlers only for the duration of the call (fix-round-2 finding 3)', async () => {
    const { root, files, toolPath } = setup();
    const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'] as const;
    const count = () => signals.map((signal) => process.listenerCount(signal));
    const before = count();
    const extra = process.platform === 'win32' ? [1, 1, 0] : [1, 1, 1];
    let during: number[] = [];
    const spy: Analyzer = {
      ...fake('eslint', toolPath, 'ok'),
      prepare: (ctx) => {
        during = count();
        return fake('eslint', toolPath, 'ok').prepare(ctx);
      },
    };
    await runAnalyzers([spy], { root, files, config: config(), log: silentLogger });
    expect(during).toEqual(before.map((n, i) => n + extra[i]!));
    expect(count()).toEqual(before);
  });

  it.runIf(process.platform !== 'win32')(
    'kills the analyzers and removes their work directories on SIGHUP (exit 129)',
    { timeout: 30_000 },
    async () => {
      const { root, files, toolPath } = setup();
      const script = path.join(tmp(), 'hold.mts');
      const runner = pathToFileURL(path.join(import.meta.dirname, 'runner.ts')).href;
      const shared = pathToFileURL(
        path.join(import.meta.dirname, '..', '..', '..', 'packages', 'shared', 'src', 'index.ts'),
      ).href;
      writeFileSync(
        script,
        `import { runAnalyzers } from ${JSON.stringify(runner)};\n` +
          `import { parseConfig } from ${JSON.stringify(shared)};\n` +
          'const log = { error() {}, warn() {}, info() {}, debug() {} };\n' +
          'await runAnalyzers([{ id: "gitleaks", languages: [], prepare: (ctx) => {\n' +
          '  console.log(ctx.workDir);\n' +
          `  return Promise.resolve({ run: { command: process.execPath, args: [${JSON.stringify(toolPath)}, "hang", "x"], cwd: ctx.root, sarifPath: "x", okExitCodes: [0] } });\n` +
          `} }], { root: ${JSON.stringify(root)}, files: ${JSON.stringify(files)}, config: parseConfig({ version: 1 }), log });\n`,
      );
      const child = spawn(process.execPath, ['--import', 'tsx', script], {
        cwd: path.join(import.meta.dirname, '..', '..'),
        stdio: ['ignore', 'pipe', 'inherit'],
      });
      const exited = new Promise<number | null>((resolve) => child.on('exit', (c) => resolve(c)));
      const workDir = await new Promise<string>((resolve, reject) => {
        let out = '';
        child.stdout.on('data', (d: Buffer) => {
          out += d.toString('utf8');
          if (out.includes('\n')) resolve(out.trim());
        });
        void exited.then((c) => reject(new Error(`the child exited early (${String(c)})`)));
      });
      expect(existsSync(workDir)).toBe(true);
      // Let the analyzer start before the hang-up.
      await sleep(500);
      child.kill('SIGHUP');
      expect(await exited).toBe(129);
      expect(existsSync(workDir)).toBe(false);
    },
  );

  it(
    'removeActiveWorkDirs deletes every currently active analyzer work directory (fix-round-2 finding 2)',
    { timeout: 10_000 },
    async () => {
      const { root, files, toolPath } = setup();
      let workDir = '';
      const hangAndTrack: Analyzer = {
        id: 'gitleaks',
        languages: [],
        prepare: (ctx) => {
          workDir = ctx.workDir;
          return fake('gitleaks', toolPath, 'hang').prepare(ctx);
        },
      };
      const promise = runAnalyzers([hangAndTrack], {
        root,
        files,
        config: config({ gitleaks: { timeoutSeconds: 1 } }),
        log: silentLogger,
      });
      await sleep(300); // let prepare() run and the process actually spawn
      expect(workDir).not.toBe('');
      expect(existsSync(workDir)).toBe(true);
      removeActiveWorkDirs();
      expect(existsSync(workDir)).toBe(false);
      // The analyzer still times out on its own; capture()'s own finally-block rmSync
      // (force: true) is then a safe no-op on the already-removed directory.
      await promise;
    },
  );

  it(
    'removeActiveWorkDirs continues with the remaining directories when one fails to delete (fix-round-3 finding 2)',
    { timeout: 10_000 },
    async () => {
      const { root, files, toolPath } = setup();
      const workDirs: string[] = [];
      const track = (id: AnalyzerId): Analyzer => ({
        id,
        languages: [],
        prepare: (ctx) => {
          workDirs.push(ctx.workDir);
          return fake(id, toolPath, 'hang').prepare(ctx);
        },
      });
      const promise = runAnalyzers([track('gitleaks'), track('semgrep')], {
        root,
        files,
        config: config({ gitleaks: { timeoutSeconds: 1 }, semgrep: { timeoutSeconds: 1 } }),
        log: silentLogger,
      });
      await sleep(300);
      expect(workDirs).toHaveLength(2);
      const [failingDir, okDir] = workDirs as [string, string];
      expect(() =>
        removeActiveWorkDirs(silentLogger, (dir) => {
          if (dir === failingDir) throw new Error('EBUSY: resource busy or locked');
          rmSync(dir, { recursive: true, force: true });
        }),
      ).not.toThrow();
      expect(existsSync(okDir)).toBe(false);
      await promise;
    },
  );
});

describe('emergencyCleanup', () => {
  it('always returns an exit code and never throws, even if a cleanup step (here, logging) does (fix-round-3 finding 2)', () => {
    const throwingLog: Logger = {
      ...silentLogger,
      debug: () => {
        throw new Error('logger exploded');
      },
    };
    expect(() => emergencyCleanup('SIGINT', throwingLog)).not.toThrow();
    expect(emergencyCleanup('SIGINT', silentLogger)).toBe(130);
    expect(emergencyCleanup('SIGTERM', silentLogger)).toBe(143);
    expect(emergencyCleanup('SIGHUP', silentLogger)).toBe(129);
  });
});

describe('spawnFailureReason', () => {
  it('is "not installed" only for ENOENT, "could not start" for anything else (fix-round-2 finding 5)', () => {
    expect(spawnFailureReason('ENOENT')).toBe('not installed');
    expect(spawnFailureReason('EACCES')).toBe('could not start');
    expect(spawnFailureReason(undefined)).toBe('could not start');
  });
});

describe('the collected preparation (plan 2D)', () => {
  it('records a collected preparation as ok without starting a process (plan 2D)', async () => {
    const sarif = { version: '2.1.0', runs: [] };
    const analyzer: Analyzer = {
      id: 'roslyn',
      languages: ['csharp'],
      prepare: () => Promise.resolve({ collected: { sarif, version: '5.9.0' } }),
    };
    const [capture] = await runAnalyzers([analyzer], {
      root: tmp(),
      config: parseConfig({ version: 1, analyzers: { roslyn: { enabled: true } } }),
      files: [],
      log: silentLogger,
    });
    expect(capture).toMatchObject({
      engineId: 'roslyn',
      status: 'ok',
      version: '5.9.0',
      sarif,
      required: true,
    });
  });

  it('passes the dotnet run to the context', async () => {
    let seen: unknown = 'unset';
    const analyzer: Analyzer = {
      id: 'roslyn',
      languages: [],
      prepare: (ctx) => {
        seen = ctx.dotnet;
        return Promise.resolve({ skip: 'x' });
      },
    };
    await runAnalyzers([analyzer], {
      root: tmp(),
      config: parseConfig({ version: 1 }),
      files: [],
      log: silentLogger,
      dotnet: { kind: 'no-build' },
    });
    expect(seen).toEqual({ kind: 'no-build' });
  });
});

describe('mapLimit', () => {
  it('never runs more than the limit at once and keeps the order', async () => {
    let active = 0;
    let peak = 0;
    const out = await mapLimit([1, 2, 3, 4, 5, 6], 2, async (n) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 10));
      active--;
      return n * 10;
    });
    expect(out).toEqual([10, 20, 30, 40, 50, 60]);
    expect(peak).toBe(2);
  });
});

describe('execEnv (ruling A9-18)', () => {
  const root = path.resolve('/repo');
  const base = { PATH: '/usr/bin', PHPRC: '/repo', KEEP: 'k' };
  it('is the analyzer environment itself without env or dropEnv', () => {
    expect(execEnv(base, {}, root)).toBe(base);
  });
  it('drops names, adds env, and sanitizes again', () => {
    const env = execEnv(
      base,
      { env: { LC_ALL: 'C.UTF-8', QUALOR_SERVER_TOKEN: 'secret' }, dropEnv: (n) => n === 'PHPRC' },
      root,
    );
    expect(env).toMatchObject({ PATH: '/usr/bin', KEEP: 'k', LC_ALL: 'C.UTF-8' });
    expect(env).not.toHaveProperty('PHPRC');
    expect(env).not.toHaveProperty('QUALOR_SERVER_TOKEN');
  });
});

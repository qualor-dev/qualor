import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  fakeContext,
  fakeSonarjsDir,
  ROOT,
  scanWithRecordedSarif,
  WORK,
} from '../../test/analyzers';
import { useTempDirs } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import { logSonarjsSummary, sonarjsAnalyzer } from './sonarjs';
import { runAnalyzers } from './runner';

const tmp = useTempDirs();

/** A placeholder node command: `prepare()` only ever returns it as `run.command`, never runs it. */
const NODE = path.join(path.dirname(ROOT), 'bin', 'node');

const ctx = (o: Parameters<typeof fakeContext>[1] = {}) =>
  fakeContext(ROOT, { binaries: { node: NODE }, workDir: WORK, ...o });

const scopeFile = (p: string, language: ScopeFile['language']): ScopeFile => ({
  path: p,
  absPath: path.join(ROOT, p),
  language,
  grammar: null,
  kind: 'main',
  size: 1,
});

describe('sonarjsAnalyzer.prepare', () => {
  // Fix round 1 (controller ruling 12): a missing pass is a normal, image-bundled resource
  // absent on a plain host — `skip`, not `unavailable`, like a missing Trivy database
  // (trivy.ts) or Semgrep's missing `qualor-default` rules (semgrep.ts). `unavailable` would
  // make ruling G6 count the engine incomplete (dropping the Code Quality file and failing the
  // SAST scan) on every host run of a JS/TS project outside the qualor/scanner image.
  it('is skipped, not unavailable, without /opt/qualor/sonarjs', async () => {
    const p = await sonarjsAnalyzer.prepare(ctx({ env: { QUALOR_SONARJS_DIR: '/nonexistent' } }));
    expect(p).toEqual({ skip: 'the sonarjs pass is not installed (qualor/scanner image)' });
  });

  it('still fails (not merely skips) under enabled: true when the pass is not installed', async () => {
    const root = tmp();
    const config = parseConfig({ version: 1, analyzers: { sonarjs: { enabled: true } } });
    const [capture] = await runAnalyzers([sonarjsAnalyzer], {
      root,
      config,
      files: [],
      log: silentLogger,
      env: { QUALOR_SONARJS_DIR: '/nonexistent' },
    });
    expect(capture).toMatchObject({
      status: 'failed',
      reason: 'the sonarjs pass is not installed (qualor/scanner image)',
    });
    expect(capture?.unavailable ?? false).toBe(false);
  });

  it('leaves the engine skipped and NOT unavailable under enabled: auto, a host-style context without the pass (ruling G6 completeness)', async () => {
    const root = tmp();
    const config = parseConfig({ version: 1 }); // analyzers.sonarjs.enabled defaults to 'auto'
    const files: ScopeFile[] = [
      {
        path: 'src/a.ts',
        absPath: path.join(root, 'src', 'a.ts'),
        language: 'typescript',
        grammar: 'typescript',
        kind: 'main',
        size: 1,
      },
    ];
    const [capture] = await runAnalyzers([sonarjsAnalyzer], {
      root,
      config,
      files,
      log: silentLogger,
      env: { QUALOR_SONARJS_DIR: '/nonexistent' },
    });
    expect(capture).toMatchObject({ engineId: 'sonarjs', status: 'skipped', required: false });
    expect(capture?.unavailable ?? false).toBe(false);
  });

  it("runs Qualor's node on run.mjs with the root, the in-scope JS/TS files and the type-checking mode", async () => {
    const dir = fakeSonarjsDir();
    const work = tmp();
    const p = await sonarjsAnalyzer.prepare({
      ...ctx({
        env: { QUALOR_SONARJS_DIR: dir },
        workDir: work,
        config: {
          sources: { exclude: ['dist/**'] },
          analyzers: { sonarjs: { typeChecking: false } },
        },
      }),
      files: [
        scopeFile('src/a.ts', 'typescript'),
        scopeFile('src/b.jsx', 'javascript'),
        scopeFile('src/C.java', 'java'),
      ],
    });
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const out = path.join(work, 'sonarjs.sarif');
    const list = path.join(work, 'sonarjs-files.json');
    const script = path.join(dir, 'run.mjs');
    expect(p.run.args).toEqual([
      script,
      '--root',
      ROOT,
      '--out',
      out,
      '--files',
      list,
      '--type-checking',
      'off',
    ]);
    // Only the discovered JS/TS files: discovery already applied sources.include, the excludes
    // and .gitignore, so run.mjs needs no --exclude and never walks the checkout itself.
    expect(JSON.parse(readFileSync(list, 'utf8'))).toEqual([
      path.join(ROOT, 'src/a.ts'),
      path.join(ROOT, 'src/b.jsx'),
    ]);
    expect(p.run.command).toBe(NODE);
    expect(p.run.cwd).toBe(ROOT);
    expect(p.run.sarifPath).toBe(out);
    expect(p.run.okExitCodes).toEqual([0]);
    expect(p.run.version).toBe('2.0.4');
  });

  it('is skipped when no JavaScript or TypeScript file is in scope', async () => {
    const p = await sonarjsAnalyzer.prepare({
      ...ctx({ env: { QUALOR_SONARJS_DIR: fakeSonarjsDir() }, workDir: tmp() }),
      files: [scopeFile('src/C.java', 'java')],
    });
    expect(p).toEqual({ skip: 'no JavaScript or TypeScript files in scope' });
  });

  it('passes --type-checking on for typeChecking auto or true (run.mjs decides from tsconfig.json)', async () => {
    const dir = fakeSonarjsDir();
    for (const typeChecking of ['auto', true] as const) {
      const p = await sonarjsAnalyzer.prepare({
        ...ctx({
          env: { QUALOR_SONARJS_DIR: dir },
          workDir: tmp(),
          config: { analyzers: { sonarjs: { typeChecking } } },
        }),
        files: [scopeFile('a.ts', 'typescript')],
      });
      if (!('run' in p)) throw new Error(JSON.stringify(p));
      const i = p.run.args.indexOf('--type-checking');
      expect(p.run.args[i + 1], String(typeChecking)).toBe('on');
    }
  });

  it('never takes run.mjs from inside the repository', async () => {
    const p = await sonarjsAnalyzer.prepare(
      ctx({ env: { QUALOR_SONARJS_DIR: path.join(ROOT, 'evil') } }),
    );
    expect(p).toEqual({ unavailable: expect.stringContaining('outside the repository') });
  });

  it('rejects a QUALOR_SONARJS_DIR that is not an absolute path', async () => {
    const p = await sonarjsAnalyzer.prepare(ctx({ env: { QUALOR_SONARJS_DIR: 'relative/dir' } }));
    expect(p).toEqual({ unavailable: expect.stringContaining('absolute path') });
  });

  it('is unavailable when node is not on PATH', async () => {
    const dir = fakeSonarjsDir();
    const p = await sonarjsAnalyzer.prepare(
      ctx({ env: { QUALOR_SONARJS_DIR: dir }, binaries: {} }),
    );
    expect(p).toEqual({ unavailable: 'the sonarjs pass needs node on PATH' });
  });
});

describe('logSonarjsSummary', () => {
  it('notes a fallback to non-type-aware rules, at debug level, without calling it "tsconfig broken"', () => {
    const lines: string[] = [];
    const log = createLogger('debug', (t) => lines.push(t));
    logSonarjsSummary(
      log,
      `${JSON.stringify({ typeChecking: 'fallback', files: 3, parseErrors: 0, disabledRules: [] })}\n`,
    );
    const text = lines.join('');
    expect(text).toContain('some files were analysed without type information');
    expect(text).not.toContain('tsconfig broken');
  });

  it('logs parse errors at debug level, like eslint.ts treats dropped fatal messages', () => {
    const lines: string[] = [];
    const log = createLogger('debug', (t) => lines.push(t));
    logSonarjsSummary(
      log,
      JSON.stringify({ typeChecking: 'on', files: 5, parseErrors: 2, disabledRules: [] }),
    );
    expect(lines.join('')).toContain('sonarjs: 2 file(s) did not parse');
  });

  it('warns about rules the crash guard disabled for the run', () => {
    const lines: string[] = [];
    const log = createLogger('warn', (t) => lines.push(t));
    logSonarjsSummary(
      log,
      JSON.stringify({ typeChecking: 'on', files: 5, parseErrors: 0, disabledRules: ['S1234'] }),
    );
    expect(lines.join('')).toContain(
      'sonarjs: rule(s) S1234 crashed and were disabled for this run',
    );
  });

  it('says nothing for a normal run, and never throws on a missing or malformed line', () => {
    const log = createLogger('debug', () => {
      throw new Error('must not log anything here');
    });
    expect(() =>
      logSonarjsSummary(
        log,
        JSON.stringify({ typeChecking: 'on', files: 5, parseErrors: 0, disabledRules: [] }),
      ),
    ).not.toThrow();
    expect(() => logSonarjsSummary(log, '')).not.toThrow();
    expect(() => logSonarjsSummary(log, 'not json')).not.toThrow();
  });
});

describe('sonarjs SARIF normalisation (recorded run.mjs output)', () => {
  it('normalises a recorded run into sonarjs:S#### issues with the category mapping', () => {
    // Recorded from a real `docker run qualor/scanner:8ab-t6` of run.mjs (task-7-report.md); no
    // SonarSource text, only rule ids/names/helpUri/category and locations (ruling 1). S1192 (the
    // brief's own example) is off in the plugin's recommended config, so S1186 stands in for it:
    // "Critical Code Smell" maps the same way — maintainability / high.
    const report = scanWithRecordedSarif('sonarjs', 'cli/test/analyzer-output/sonarjs/basic.sarif');
    const issue = report.issues.find((i) => i.ruleKey === 'sonarjs:S1186');
    expect(issue).toMatchObject({ quality: 'maintainability', severity: 'high' });
    // Also present: S1871 (Major Code Smell → maintainability/medium) and S3923 (Major Bug →
    // reliability/medium), the other findings of that same recorded run.
    expect(report.issues.map((i) => i.ruleKey).sort()).toEqual([
      'sonarjs:S1186',
      'sonarjs:S1871',
      'sonarjs:S3923',
    ]);
  });
});

describe('sonarjsAnalyzer identity', () => {
  it('declares its id, languages and rule languages', () => {
    expect(sonarjsAnalyzer.id).toBe('sonarjs');
    expect(sonarjsAnalyzer.languages).toEqual(['typescript', 'javascript']);
    expect(sonarjsAnalyzer.ruleLanguages).toEqual(['typescript', 'javascript']);
  });
});

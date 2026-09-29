import path from 'node:path';
import { BUILTIN_EXCLUDES } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  fakeContext,
  fakeSonarjsDir,
  ROOT,
  scanWithRecordedSarif,
  WORK,
} from '../../test/analyzers';
import { createLogger } from '../log';
import { logSonarjsSummary, sonarjsAnalyzer } from './sonarjs';

/** A placeholder node command: `prepare()` only ever returns it as `run.command`, never runs it. */
const NODE = path.join(path.dirname(ROOT), 'bin', 'node');

const ctx = (o: Parameters<typeof fakeContext>[1] = {}) =>
  fakeContext(ROOT, { binaries: { node: NODE }, workDir: WORK, ...o });

/** The index where `seq` starts inside `args` as a contiguous run, or -1 (ruling 4: "a contained
 * sequence", not necessarily the whole `args` array — the excludes can fall anywhere around it). */
function indexOfSubsequence(args: readonly string[], seq: readonly string[]): number {
  outer: for (let i = 0; i + seq.length <= args.length; i++) {
    for (let j = 0; j < seq.length; j++) if (args[i + j] !== seq[j]) continue outer;
    return i;
  }
  return -1;
}

describe('sonarjsAnalyzer.prepare', () => {
  it('is unavailable without /opt/qualor/sonarjs', async () => {
    const p = await sonarjsAnalyzer.prepare(ctx({ env: { QUALOR_SONARJS_DIR: '/nonexistent' } }));
    expect(p).toEqual({ unavailable: 'the sonarjs pass is not installed (qualor/scanner image)' });
  });

  it("runs Qualor's node on run.mjs with the root, the excludes and the type-checking mode", async () => {
    const dir = fakeSonarjsDir();
    const p = await sonarjsAnalyzer.prepare(
      ctx({
        env: { QUALOR_SONARJS_DIR: dir },
        config: {
          sources: { exclude: ['dist/**'] },
          analyzers: { sonarjs: { typeChecking: false } },
        },
      }),
    );
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const out = path.join(WORK, 'sonarjs.sarif');
    const script = path.join(dir, 'run.mjs');
    expect(
      indexOfSubsequence(p.run.args, [
        script,
        '--root',
        ROOT,
        '--out',
        out,
        '--type-checking',
        'off',
      ]),
    ).toBeGreaterThanOrEqual(0);
    // The built-in excludes (config.md §3.1) and the configured one are all passed as --exclude
    // (ruling 4), whatever order they fall in relative to the fixed arguments above.
    for (const glob of [...BUILTIN_EXCLUDES, 'dist/**']) {
      const i = p.run.args.indexOf(glob);
      expect(i, `${glob} missing from ${JSON.stringify(p.run.args)}`).toBeGreaterThan(0);
      expect(p.run.args[i - 1]).toBe('--exclude');
    }
    expect(p.run.command).toBe(NODE);
    expect(p.run.cwd).toBe(ROOT);
    expect(p.run.sarifPath).toBe(out);
    expect(p.run.okExitCodes).toEqual([0]);
    expect(p.run.version).toBe('2.0.4');
  });

  it('passes --type-checking on for typeChecking auto or true (run.mjs decides from tsconfig.json)', async () => {
    const dir = fakeSonarjsDir();
    for (const typeChecking of ['auto', true] as const) {
      const p = await sonarjsAnalyzer.prepare(
        ctx({
          env: { QUALOR_SONARJS_DIR: dir },
          config: { analyzers: { sonarjs: { typeChecking } } },
        }),
      );
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

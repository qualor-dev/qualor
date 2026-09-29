import { existsSync } from 'node:fs';
import path from 'node:path';
import { BUILTIN_EXCLUDES } from '@qualor/shared';
import { z } from 'zod';
import type { Logger } from '../log';
import { isInside } from './binary';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Where the `qualor/scanner` image installs Qualor's own sonarjs pass (config.md §4). */
const DEFAULT_DIR = '/opt/qualor/sonarjs';

/** global-constraints.md: the pinned eslint-plugin-sonarjs version, never read from the tool. */
export const SONARJS_VERSION = '2.0.4';

/** The scan's exclude globs (config.md §3.1), in the form run.mjs's `--exclude` expects. */
function excludes(ctx: AnalyzerContext): string[] {
  return [...BUILTIN_EXCLUDES, ...ctx.config.sources.exclude];
}

const summarySchema = z.object({
  typeChecking: z.enum(['on', 'off', 'fallback']),
  files: z.number(),
  parseErrors: z.number(),
  disabledRules: z.array(z.string()),
});

/**
 * run.mjs's one stdout JSON line (tools/analyzers/sonarjs/run.mjs's `summary()`): never thrown
 * from here, and never surfaced anywhere but the debug/warn log (config.md §6: a report `reason`
 * stays a fixed string, never a tool's own output). A missing or malformed line is silently
 * ignored — `capture()` in runner.ts already treats a non-zero/timeout/bad-SARIF run as failed by
 * itself, so this is purely extra operator detail, not a correctness signal.
 */
export function logSonarjsSummary(log: Logger, stdout: string): void {
  const lines = stdout.split('\n').filter((l) => l.trim() !== '');
  const last = lines.at(-1);
  if (last === undefined) return;
  let parsed: z.infer<typeof summarySchema>;
  try {
    parsed = summarySchema.parse(JSON.parse(last));
  } catch {
    return;
  }
  if (parsed.typeChecking === 'fallback') {
    log.debug('sonarjs: some files were analysed without type information');
  }
  if (parsed.parseErrors > 0) {
    // Debug, like eslint.ts's own dropped-fatal-message log: a parse error is not a finding.
    log.debug(`sonarjs: ${parsed.parseErrors} file(s) did not parse`);
  }
  if (parsed.disabledRules.length > 0) {
    log.warn(
      `sonarjs: rule(s) ${parsed.disabledRules.join(', ')} crashed and were disabled for this run`,
    );
  }
}

/** config.md §6: Qualor's own ESLint pass with eslint-plugin-sonarjs 2.0.4 (never the project's config). */
async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers.sonarjs;
  const dir = ctx.env['QUALOR_SONARJS_DIR'] || DEFAULT_DIR;
  if (!path.isAbsolute(dir) || isInside(ctx.root, dir)) {
    return { unavailable: 'QUALOR_SONARJS_DIR must be an absolute path outside the repository' };
  }
  const script = path.join(dir, 'run.mjs');
  if (!existsSync(script)) {
    return { unavailable: 'the sonarjs pass is not installed (qualor/scanner image)' };
  }
  const node = ctx.resolveBinary('node');
  if (node === null) return { unavailable: 'the sonarjs pass needs node on PATH' };
  const out = path.join(ctx.workDir, 'sonarjs.sarif');
  const args = [
    script,
    '--root',
    ctx.root,
    '--out',
    out,
    '--type-checking',
    settings.typeChecking === false ? 'off' : 'on',
    ...excludes(ctx).flatMap((g) => ['--exclude', g]),
  ];
  return {
    run: {
      command: node,
      args,
      cwd: ctx.root,
      sarifPath: out,
      // run.mjs (tools/analyzers/sonarjs/run.mjs): exit 0 whenever it wrote the log, 2 on an
      // internal error.
      okExitCodes: [0],
      version: SONARJS_VERSION,
      // run.mjs already writes SARIF 2.1.0 at `out`: `transform` is used only to surface its one
      // stdout summary line, never to convert the output itself.
      transform: (output, stdout) => {
        logSonarjsSummary(ctx.log, stdout);
        return output;
      },
    },
  };
}

export const sonarjsAnalyzer: Analyzer = {
  id: 'sonarjs',
  languages: ['typescript', 'javascript'],
  ruleLanguages: ['typescript', 'javascript'],
  prepare,
};

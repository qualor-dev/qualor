import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type { Logger } from '../log';
import { isInside } from './binary';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Where the `qualor/scanner` image installs Qualor's own sonarjs pass (config.md §4). */
const DEFAULT_DIR = '/opt/qualor/sonarjs';

/** global-constraints.md: the pinned eslint-plugin-sonarjs version, never read from the tool. */
export const SONARJS_VERSION = '2.0.4';

/**
 * The scan's in-scope JavaScript and TypeScript files (discovery already applied
 * `sources.include`, the excludes and .gitignore, config.md §3.1), as absolute paths: what
 * run.mjs lints, and nothing else.
 */
function sourceFiles(ctx: AnalyzerContext): string[] {
  return ctx.files
    .filter((f) => f.language === 'javascript' || f.language === 'typescript')
    .map((f) => f.absPath);
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
  // Unlike an invalid QUALOR_SONARJS_DIR (below) or a missing `node`, a missing pass is not a
  // configuration problem: it is a normal, image-bundled resource absent on a plain host, the same
  // as Trivy's vulnerability database (trivy.ts) or Semgrep's `qualor-default` rules (semgrep.ts).
  // `skip`, not `unavailable`, so ruling G6 does not count the engine incomplete for it.
  const script = path.join(dir, 'run.mjs');
  if (!existsSync(script)) {
    return { skip: 'the sonarjs pass is not installed (qualor/scanner image)' };
  }
  const node = ctx.resolveBinary('node');
  if (node === null) return { unavailable: 'the sonarjs pass needs node on PATH' };
  const files = sourceFiles(ctx);
  if (files.length === 0) return { skip: 'no JavaScript or TypeScript files in scope' };
  // A JSON list in the private work directory (any path, any repo size): run.mjs lints exactly
  // these, after checking each again (a regular file inside the root, no link, no node_modules).
  const list = path.join(ctx.workDir, 'sonarjs-files.json');
  writeFileSync(list, JSON.stringify(files));
  const out = path.join(ctx.workDir, 'sonarjs.sarif');
  const args = [
    script,
    '--root',
    ctx.root,
    '--out',
    out,
    '--files',
    list,
    '--type-checking',
    settings.typeChecking === false ? 'off' : 'on',
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

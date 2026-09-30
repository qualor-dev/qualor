import { lstatSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { RUFF_VERSION, ruffSelection, ruffVersionSupported } from '@qualor/shared';
import type { Logger } from '../log';
import { staysInside } from './binary';
import { deadProxyEnv } from './offline';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** `ruff --version` prints `ruff 0.16.9`. */
export function parseRuffVersion(stdout: string): string | null {
  return /^ruff (\d+\.\d+\.\d+)\b/m.exec(stdout.trim())?.[1] ?? null;
}

/** config.md §6: `RUFF_*` variables would configure Ruff behind the command line's back. */
export const isRuffVariable = (name: string): boolean => /^RUFF_/i.test(name);

/** A Ruff rule code as SARIF `ruleId`. */
const RULE_CODE = /^[A-Z]{1,5}[0-9]{1,4}$/;
/** Codes that report on the file, not the code: E902 (the file could not be read). */
const NOT_FINDINGS = new Set(['E902']);

/**
 * config.md §6: a result that is not a rule finding is dropped (`invalid-syntax`, the parse
 * errors of a file Ruff cannot read; `E902`), and only its count reaches the debug log, like
 * ESLint's fatal parse errors.
 */
export function dropNonRuleResults(output: unknown, log: Logger): unknown {
  if (typeof output !== 'object' || output === null) return output;
  const runs = (output as { runs?: unknown }).runs;
  if (!Array.isArray(runs)) return output;
  let dropped = 0;
  for (const run of runs as { results?: unknown }[]) {
    if (!Array.isArray(run.results)) continue;
    run.results = run.results.filter((r: unknown) => {
      const id = (r as { ruleId?: unknown } | null)?.ruleId;
      const keep = typeof id === 'string' && RULE_CODE.test(id) && !NOT_FINDINGS.has(id);
      if (!keep) dropped++;
      return keep;
    });
  }
  if (dropped > 0) log.debug(`ruff: ${dropped} result(s) that are not rule findings dropped`);
  return output;
}

/**
 * The in-scope `.py` files as absolute paths for Ruff's argfile (one per line, read verbatim).
 * Discovery never follows links; each file is checked again here (a regular file, not a link,
 * inside the repository after resolving links) so nothing that changed since reaches Ruff.
 */
function listedFiles(ctx: AnalyzerContext): { files: string[]; unlisted: number } {
  const files: string[] = [];
  let unlisted = 0;
  for (const f of ctx.files) {
    if (f.language !== 'python') continue;
    if (/[\r\n]/.test(f.absPath)) {
      unlisted++;
      continue;
    }
    try {
      if (!lstatSync(f.absPath).isFile() || !staysInside(ctx.root, f.absPath)) continue;
    } catch {
      continue;
    }
    files.push(f.absPath);
  }
  return { files, unlisted };
}

/** config.md §6: Ruff with Qualor's own rule selection, never the project's configuration. */
async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers.ruff;
  const { files, unlisted } = listedFiles(ctx);
  if (files.length === 0) {
    return {
      skip:
        unlisted > 0
          ? 'no Python file in scope has a path Ruff can read from a file list (line break)'
          : 'no Python files in scope',
    };
  }
  if (unlisted > 0) {
    ctx.log.warn(
      `ruff: ${unlisted} Python file(s) with a line break in their path are not analysed`,
    );
  }
  const ruff = ctx.resolveBinary('ruff');
  if (ruff === null) {
    // Ruling G6: a tool that comes with the qualor/scanner image is a skip on a plain host.
    return {
      skip:
        ctx.repoBinary('ruff') === null
          ? 'Ruff is not installed (ruff on PATH or in the qualor/scanner image)'
          : 'Ruff is not installed (ruff on PATH or in the qualor/scanner image; a ruff inside the repository is not used)',
    };
  }
  const probe = await ctx.exec(ruff, ['--version'], { timeoutMs: 30_000 });
  const version = probe.exitCode === 0 ? parseRuffVersion(probe.stdout) : null;
  if (version === null) return { unavailable: 'ruff --version did not report a version' };
  if (!ruffVersionSupported(version)) {
    const [major, minor] = RUFF_VERSION.split('.');
    return {
      skip: `Ruff ${version} is not supported (Qualor runs Ruff ${major}.${minor}.x; the qualor/scanner image has ${RUFF_VERSION})`,
    };
  }
  const list = path.join(ctx.workDir, 'ruff-files.txt');
  writeFileSync(list, `${files.join('\n')}\n`);
  const out = path.join(ctx.workDir, 'ruff.sarif');
  const { select, ignore } = ruffSelection(settings.select, settings.ignore);
  return {
    run: {
      command: ruff,
      args: [
        'check',
        // No configuration file of the checkout, its parents or the user is read (config.md §6).
        '--isolated',
        '--no-cache',
        '--no-fix',
        '--no-preview',
        '--quiet',
        '--output-format',
        'sarif',
        '--output-file',
        out,
        '--select',
        select.join(','),
        ...(ignore.length > 0 ? ['--ignore', ignore.join(',')] : []),
        `@${list}`,
      ],
      cwd: ctx.root,
      env: deadProxyEnv(),
      dropEnv: isRuffVariable,
      sarifPath: out,
      // 0: nothing found, 1: findings; 2 is an error (an unknown selector, a crash).
      okExitCodes: [0, 1],
      version,
      transform: (output) => dropNonRuleResults(output, ctx.log),
    },
  };
}

export const ruffAnalyzer: Analyzer = {
  id: 'ruff',
  languages: ['python'],
  ruleLanguages: ['python'],
  prepare,
};

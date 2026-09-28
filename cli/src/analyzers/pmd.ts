import { lstatSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { isUrl, type QualorConfig } from '@qualor/shared';
import { staysInside, within } from './binary';
import { DEAD_PROXY_PROPERTIES } from './jvm';
import { checkRulesetTree, isClasspathRuleset } from './pmd-ruleset';
import { shown } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/**
 * The built-in ruleset id (config.md §3 `rulesets: [qualor-default]`): PMD's own "quickstart"
 * ruleset, which ships inside the PMD distribution. Qualor adds no rules of its own (brief §1).
 */
export const PMD_DEFAULT_RULESET = 'rulesets/java/quickstart.xml';

/** PMD splits `--rulesets` on commas and `--file-list` on commas and line breaks. */
const LIST_SEPARATOR = /[,\r\n]/;

/**
 * config.md §3: `qualor-default`, a repo file, or a PMD classpath ruleset. Returns the argument
 * for `--rulesets`, a skip reason (a missing file), or a configuration error (ruling V4: a URL,
 * which PMD would download, or a path outside the repository, as written or after resolving
 * symlinks).
 */
export function resolveRuleset(
  root: string,
  entry: string,
): string | { skip: string } | { error: string } {
  if (entry === 'qualor-default') return PMD_DEFAULT_RULESET;
  const name = `ruleset ${shown(entry)}`;
  if (isUrl(entry)) return { error: `${name} is a URL (PMD would download it)` };
  const file = path.resolve(root, entry);
  if (!within(path.resolve(root), file)) return { error: `${name} is outside the repository` };
  let exists = true;
  try {
    lstatSync(file);
  } catch {
    exists = false;
  }
  if (exists) {
    // Anything at that path is the repository's ruleset (PMD would read the file first), so a
    // link out of the checkout is refused rather than treated as a classpath name.
    if (!staysInside(root, file)) return { error: `${name} is outside the repository` };
    try {
      if (!statSync(file).isFile()) return { skip: `${name} is not a file` };
    } catch {
      return { skip: `${name} does not exist` };
    }
    return file;
  }
  // PMD resolves a classpath name as a file relative to the working directory first, so a
  // name with `..` segments could still reach a file; only plain names are classpath rulesets.
  if (isClasspathRuleset(entry)) return entry;
  return { skip: `${name} does not exist` };
}

/**
 * The PMD configuration errors of config.md §6 (exit 2, ruling V4): a ruleset entry that is a
 * URL or outside the repository, or a repository ruleset that references (directly or through
 * other repository rulesets) a URL, an absolute path or a file outside the repository.
 */
export function checkPmdConfig(root: string, config: QualorConfig): string | null {
  for (const entry of config.analyzers.pmd.rulesets) {
    const r = resolveRuleset(root, entry);
    if (typeof r !== 'string') {
      if ('error' in r) return r.error;
      continue;
    }
    if (path.isAbsolute(r)) {
      const problem = checkRulesetTree(root, r);
      if (problem !== null) return problem;
    }
  }
  return null;
}

/**
 * Ruling V5: PMD_JAVA_OPTS with the dead proxy appended after the CI's own options, so a later
 * duplicate `-D` (the last one wins) cannot be ours to lose.
 */
function javaOpts(env: AnalyzerContext['env']): string {
  const ci = (env['PMD_JAVA_OPTS'] ?? '').trim();
  return [...(ci === '' ? [] : [ci]), ...DEAD_PROXY_PROPERTIES].join(' ');
}

async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers.pmd;
  if (settings.rulesets.length === 0) return { skip: 'no PMD rulesets configured' };
  // `qualor scan` stops with exit 2 on these before any analyzer runs (checkConfig); this is
  // the same check for any other caller of the runner.
  const problem = checkPmdConfig(ctx.root, ctx.config);
  if (problem !== null) return { skip: problem };
  const rulesets: string[] = [];
  for (const entry of settings.rulesets) {
    const r = resolveRuleset(ctx.root, entry);
    if (typeof r !== 'string') return 'skip' in r ? r : { skip: r.error };
    if (LIST_SEPARATOR.test(r)) {
      // A comma in the entry itself is already a schema error (exit 2); a line break in the
      // entry, or either in the checkout's own path, is a skip.
      return {
        skip: LIST_SEPARATOR.test(entry)
          ? `ruleset ${shown(entry)} has a line break in its name, which PMD would split`
          : `ruleset ${shown(entry)} is in a directory whose path has a comma or line break, which PMD would split`,
      };
    }
    rulesets.push(r);
  }
  const java = ctx.files.filter((f) => f.language === 'java');
  if (java.length === 0) return { skip: 'no Java files in scope' };
  // PMD reads the file list split on commas and line breaks: such a path would become two
  // missing files and fail the whole run, so it is left out (and logged).
  const sources = java.filter((f) => !LIST_SEPARATOR.test(f.absPath));
  if (sources.length < java.length) {
    ctx.log.warn(
      `pmd: ${java.length - sources.length} Java file(s) not analysed (comma or line break in the path)`,
    );
  }
  if (sources.length === 0) {
    return {
      skip: 'no Java file in scope has a path PMD can read from a file list (comma or line break)',
    };
  }
  const pmd = ctx.resolveBinary('pmd');
  if (pmd === null) {
    return { unavailable: 'PMD is not installed (pmd on PATH or in the scanner image)' };
  }
  // Only in-scope files, so excludes and .gitignore apply and generated code is not analysed. A
  // file list (in the private work directory) keeps the command line short on any repo size.
  const fileList = path.join(ctx.workDir, 'files.txt');
  writeFileSync(fileList, `${sources.map((f) => f.absPath).join('\n')}\n`);
  const out = path.join(ctx.workDir, 'pmd.sarif');
  return {
    run: {
      command: pmd,
      args: [
        'check',
        '--file-list',
        fileList,
        '--rulesets',
        rulesets.join(','),
        '--format',
        'sarif',
        '--report-file',
        out,
        '--no-cache',
        '--no-progress',
        // Violations and recoverable per-file errors (parse errors) still exit 0; the SARIF
        // log carries the findings. 1 (unexpected error) and 2 (usage error) are failures.
        '--no-fail-on-violation',
        '--no-fail-on-error',
      ],
      cwd: ctx.root,
      env: { PMD_JAVA_OPTS: javaOpts(ctx.env) },
      sarifPath: out,
      okExitCodes: [0],
      // The version comes from the SARIF log (tool.driver.version), no extra `pmd --version` run.
      version: null,
    },
  };
}

export const pmdAnalyzer: Analyzer = {
  id: 'pmd',
  languages: ['java'],
  ruleLanguages: ['java'],
  prepare,
  checkConfig: checkPmdConfig,
};

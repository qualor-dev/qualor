import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { resolveStylelintConfig } from './stylelint-config';
import type { Analyzer, AnalyzerContext, Preparation } from './types';
import { logWeblintSummary, weblintScript } from './weblint';

/**
 * config.md §6: Qualor's stylelint pass (tools/analyzers/weblint/stylelint.mjs) over the scan's
 * in-scope CSS and SCSS files, with the project's JSON/YAML configuration or Qualor's default.
 */
async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const found = weblintScript(ctx, 'stylelint.mjs');
  if (!('script' in found)) return found;
  const node = ctx.resolveBinary('node');
  if (node === null) return { unavailable: 'stylelint needs node on PATH' };
  // Discovery already applied sources.include, the excludes and .gitignore (config.md §3.1): the
  // pass lints these and nothing else, after checking each again (regular, inside, no link).
  const files = ctx.files.filter((f) => f.language === 'css').map((f) => f.absPath);
  if (files.length === 0) return { skip: 'no CSS or SCSS files in scope' };
  const resolved = resolveStylelintConfig(ctx.root, ctx.config.analyzers.stylelint.configFile);
  if ('skip' in resolved) return resolved;
  ctx.log.debug(`stylelint: configuration from ${resolved.source}`);
  const list = path.join(ctx.workDir, 'stylelint-files.json');
  const config = path.join(ctx.workDir, 'stylelint-config.json');
  const out = path.join(ctx.workDir, 'stylelint.sarif');
  writeFileSync(list, JSON.stringify(files));
  writeFileSync(config, JSON.stringify(resolved.config));
  return {
    run: {
      command: node,
      args: [
        found.script,
        '--root',
        ctx.root,
        '--out',
        out,
        '--files',
        list,
        '--config',
        config,
        ...(resolved.ignoreFile === null ? [] : ['--ignore-file', resolved.ignoreFile]),
      ],
      // Never the checkout: nothing the pass or stylelint resolves relative to the working
      // directory can start there.
      cwd: path.dirname(found.script),
      sarifPath: out,
      // stylelint.mjs: exit 0 whenever it wrote the log, 2 on a configuration or internal error.
      okExitCodes: [0],
      // The version comes from the SARIF driver the pass writes.
      transform: (output, stdout) => {
        logWeblintSummary(ctx.log, 'stylelint', stdout);
        return output;
      },
    },
  };
}

export const stylelintAnalyzer: Analyzer = {
  id: 'stylelint',
  languages: ['css'],
  ruleLanguages: ['css'],
  prepare,
};

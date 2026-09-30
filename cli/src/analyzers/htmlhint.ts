import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { resolveHtmlhintRules } from './htmlhint-config';
import type { Analyzer, AnalyzerContext, Preparation } from './types';
import { logWeblintSummary, weblintScript } from './weblint';

/**
 * config.md §6: Qualor's HTMLHint pass (tools/analyzers/weblint/htmlhint.mjs) over the scan's
 * in-scope HTML files, with the root .htmlhintrc or Qualor's rule set.
 */
async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const found = weblintScript(ctx, 'htmlhint.mjs');
  if (!('script' in found)) return found;
  const node = ctx.resolveBinary('node');
  if (node === null) return { unavailable: 'htmlhint needs node on PATH' };
  // Discovery already applied sources.include, the excludes and .gitignore (config.md §3.1).
  const files = ctx.files.filter((f) => f.language === 'html').map((f) => f.absPath);
  if (files.length === 0) return { skip: 'no HTML files in scope' };
  const resolved = resolveHtmlhintRules(ctx.root, ctx.config.analyzers.htmlhint.configFile);
  if ('skip' in resolved) return resolved;
  ctx.log.debug(`htmlhint: rules from ${resolved.source}`);
  const list = path.join(ctx.workDir, 'htmlhint-files.json');
  const rules = path.join(ctx.workDir, 'htmlhint-rules.json');
  const out = path.join(ctx.workDir, 'htmlhint.sarif');
  writeFileSync(list, JSON.stringify(files));
  writeFileSync(rules, JSON.stringify(resolved.rules));
  return {
    run: {
      command: node,
      args: [found.script, '--root', ctx.root, '--out', out, '--files', list, '--rules', rules],
      // Never the checkout, like stylelint.
      cwd: path.dirname(found.script),
      sarifPath: out,
      // htmlhint.mjs: exit 0 whenever it wrote the log, 2 on an internal error.
      okExitCodes: [0],
      transform: (output, stdout) => {
        logWeblintSummary(ctx.log, 'htmlhint', stdout);
        return output;
      },
    },
  };
}

export const htmlhintAnalyzer: Analyzer = {
  id: 'htmlhint',
  languages: ['html'],
  ruleLanguages: ['html'],
  prepare,
};

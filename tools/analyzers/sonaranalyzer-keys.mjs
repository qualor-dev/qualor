// Writes packages/shared/rules/sonaranalyzer-csharp-keys.json: the RSPEC rule ids (`S####`) that
// the bundled SonarAnalyzer.CSharp 9.32.0.97167 actually reports, read from the `runs[].tool.
// driver.rules[].id` of one or more real SARIF logs (a Task 3/4 image build of fixtures/
// csharp-basic inside qualor/scanner-dotnet, or whatever `qualor dotnet begin` + `dotnet build`
// leaves under .qualor/dotnet/sarif/ — see tools/deploy/scanner-dotnet-sonar-check.ts and
// tools/fixtures/run.ts for how that image is driven). A driver's `rules` array also lists the
// compiler's own and Microsoft's CA#### diagnostics; only ids matching ^S\d+$ (SonarAnalyzer's
// own) are kept. Never reads SonarSource's rule metadata or documentation: the file holds bare
// rule ids only (spec §6.4).
// Also writes sonaranalyzer-csharp-default-keys.json next to it: the subset Roslyn runs without
// configuration, the rules whose `defaultConfiguration.enabled` is not false (qualor dotnet begin
// passes the analyzer no ruleset or .globalconfig). The import plan reports a profile rule mapped
// to any other key as "mapped, not run by the bundled configuration".
//   node tools/analyzers/sonaranalyzer-keys.mjs <sarif file>... [--out <file>] [--default-out <file>]
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const RULE_ID = /^S\d+$/;

/**
 * Every `S####` id of `runs[].tool.driver.rules` across `sarifPaths`, deduplicated, sorted by
 * number; with `enabledOnly`, only the rules enabled by default (`defaultConfiguration.enabled` is
 * not false in any of the logs).
 */
export function sonarAnalyzerKeys(sarifPaths, { enabledOnly = false } = {}) {
  const ids = new Set();
  const disabled = new Set();
  for (const sarifPath of sarifPaths) {
    const log = JSON.parse(readFileSync(sarifPath, 'utf8'));
    for (const run of log.runs ?? []) {
      for (const rule of run.tool?.driver?.rules ?? []) {
        if (typeof rule.id !== 'string' || !RULE_ID.test(rule.id)) continue;
        ids.add(rule.id);
        if (rule.defaultConfiguration?.enabled === false) disabled.add(rule.id);
      }
    }
  }
  return [...ids]
    .filter((id) => !enabledOnly || !disabled.has(id))
    .sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const option = (name) => {
    const i = args.indexOf(name);
    if (i < 0) return undefined;
    const value = args[i + 1];
    args.splice(i, 2);
    return value;
  };
  const here = path.dirname(fileURLToPath(import.meta.url));
  const out =
    option('--out') ??
    path.join(here, '../../packages/shared/rules/sonaranalyzer-csharp-keys.json');
  const defaultOut =
    option('--default-out') ??
    path.join(here, '../../packages/shared/rules/sonaranalyzer-csharp-default-keys.json');
  const sarifPaths = args;
  if (sarifPaths.length === 0) {
    process.stderr.write(
      'usage: node sonaranalyzer-keys.mjs <sarif file>... [--out <file>] [--default-out <file>]\n',
    );
    process.exit(2);
  }
  const keys = sonarAnalyzerKeys(sarifPaths);
  if (keys.length === 0) {
    process.stderr.write(
      'sonaranalyzer-keys.mjs: no S#### rule ids found in the given SARIF logs\n',
    );
    process.exit(1);
  }
  const defaults = sonarAnalyzerKeys(sarifPaths, { enabledOnly: true });
  writeFileSync(out, `${JSON.stringify(keys, null, 2)}\n`);
  writeFileSync(defaultOut, `${JSON.stringify(defaults, null, 2)}\n`);
  process.stdout.write(
    `sonaranalyzer-keys.mjs: ${keys.length} rule ids written to ${out}, ${defaults.length} enabled by default to ${defaultOut}\n`,
  );
}

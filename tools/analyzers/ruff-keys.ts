// Generates the Ruff rule tables Qualor commits (plan 8C, import-sonarqube.md §6.4), all
// Ruff's own facts (MIT), keys and category words only:
//   packages/shared/rules/ruff-keys.json          every rule code of the pinned Ruff (removed ones left out)
//   packages/shared/rules/ruff-default-keys.json  the codes qualor-default runs
//   packages/shared/rules/ruff-categories.json    each code's Ruff category (report-format.md §7.1)
// Run with the pinned Ruff (tools/analyzers/install.sh RUFF_VERSION), e.g. in the toolbox image:
//   pnpm exec tsx tools/analyzers/ruff-keys.ts [path to ruff]
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { RUFF_DEFAULT_IGNORE, RUFF_DEFAULT_SELECT } from '../../packages/shared/src/rules/ruff';

export interface RuffRule {
  code: string;
  category: string;
  preview: boolean;
  removed: boolean;
}

/** `ruff rule --all --output-format json` → the rules that have a code. */
export function rulesFrom(json: unknown): RuffRule[] {
  if (!Array.isArray(json)) throw new Error('ruff rule --all did not print a JSON array');
  return json
    .filter(
      (r): r is { code: string; category: string; preview: boolean; status: object } =>
        typeof (r as { code?: unknown }).code === 'string',
    )
    .map((r) => ({
      code: r.code,
      category: String(r.category),
      preview: r.preview === true,
      removed: typeof r.status === 'object' && r.status !== null && 'Removed' in r.status,
    }));
}

/** The codes inside `linter.rules.enabled = [ … ]` of `ruff check --show-settings`, sorted. */
export function enabledCodes(showSettings: string): string[] {
  const block = /^linter\.rules\.enabled = \[\n([\s\S]*?)^\]/m.exec(showSettings)?.[1] ?? '';
  return [...block.matchAll(/\(([A-Z]+[0-9]+)\)/g)].map((m) => m[1] as string).sort();
}

function run(ruff: string, args: string[]): string {
  const r = spawnSync(ruff, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`ruff ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
  return r.stdout;
}

export function ruffTables(ruff: string): {
  keys: string[];
  defaultKeys: string[];
  categories: Record<string, string>;
} {
  const rules = rulesFrom(JSON.parse(run(ruff, ['rule', '--all', '--output-format', 'json'])));
  const live = rules.filter((r) => !r.removed).sort((a, b) => (a.code < b.code ? -1 : 1));
  const dir = mkdtempSync(path.join(os.tmpdir(), 'ruff-keys-'));
  const file = path.join(dir, 'x.py');
  writeFileSync(file, 'x = 1\n');
  const settings = run(ruff, [
    'check',
    '--isolated',
    '--no-cache',
    '--select',
    RUFF_DEFAULT_SELECT.join(','),
    '--ignore',
    RUFF_DEFAULT_IGNORE.join(','),
    '--show-settings',
    file,
  ]);
  return {
    keys: live.map((r) => r.code),
    defaultKeys: enabledCodes(settings),
    categories: Object.fromEntries(live.map((r) => [r.code, r.category])),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const t = ruffTables(process.argv[2] ?? 'ruff');
  const out = (name: string, value: unknown) =>
    writeFileSync(path.join('packages/shared/rules', name), `${JSON.stringify(value, null, 2)}\n`);
  out('ruff-keys.json', t.keys);
  out('ruff-default-keys.json', t.defaultKeys);
  out('ruff-categories.json', t.categories);
  console.log(`${t.keys.length} codes, ${t.defaultKeys.length} run by qualor-default`);
}

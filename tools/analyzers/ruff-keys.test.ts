import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { RUFF_VERSION } from '../../packages/shared/src/rules/ruff';
import { findTool } from '../fixtures/run';
import { enabledCodes, ruffTables, rulesFrom } from './ruff-keys';

const committed = (name: string) =>
  JSON.parse(readFileSync(`packages/shared/rules/${name}`, 'utf8')) as unknown;

describe('ruff-keys.ts', () => {
  it('reads codes, categories, preview and removed rules from ruff rule --all', () => {
    const rules = rulesFrom([
      {
        code: 'F401',
        category: 'suspicious',
        preview: false,
        status: { Stable: { since: 'v0.0.1' } },
      },
      {
        code: 'S320',
        category: 'security',
        preview: false,
        status: { Removed: { since: '0.13.0' } },
      },
      {
        code: 'S404',
        category: 'security',
        preview: true,
        status: { Preview: { since: '0.1.0' } },
      },
      { code: null, category: 'pedantic', preview: true, status: { Preview: { since: '0.16.5' } } },
    ]);
    expect(rules).toEqual([
      { code: 'F401', category: 'suspicious', preview: false, removed: false },
      { code: 'S320', category: 'security', preview: false, removed: true },
      { code: 'S404', category: 'security', preview: true, removed: false },
    ]);
  });

  it('reads the enabled rule codes of ruff check --show-settings', () => {
    const text =
      'x = 1\nlinter.rules.enabled = [\n\texec-builtin (S102),\n\tunused-import (F401),\n]\nlinter.rules.should_fix = [\n\tunused-import (F401),\n]\n';
    expect(enabledCodes(text)).toEqual(['F401', 'S102']);
  });
});

const ruff = findTool('ruff');
const version =
  ruff === null
    ? null
    : /ruff (\S+)/.exec(spawnSync(ruff, ['--version'], { encoding: 'utf8' }).stdout)?.[1];
describe.runIf(ruff !== null || process.env['QUALOR_REQUIRE_ANALYZERS'] === '1')(
  'the committed Ruff rule tables',
  () => {
    it('are what the pinned Ruff says', () => {
      expect(version).toBe(RUFF_VERSION);
      const t = ruffTables(ruff!);
      expect(committed('ruff-keys.json')).toEqual(t.keys);
      expect(committed('ruff-default-keys.json')).toEqual(t.defaultKeys);
      expect(committed('ruff-categories.json')).toEqual(t.categories);
    });
  },
);

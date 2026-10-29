import { parseConfig, type QualorConfig } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import type { AnalyzerId } from '../analyzers/types';
import { incompleteSecretScans } from './run';

/**
 * `qualor.yml` as parsed, with `enabled` set for the named analyzers and, when given, the rule
 * files `analyzers.semgrep.configs` names.
 */
const config = (
  enabled: Partial<Record<AnalyzerId, boolean | 'auto'>> = {},
  semgrepConfigs?: string[],
): QualorConfig =>
  parseConfig({
    version: 1,
    analyzers: {
      ...Object.fromEntries(Object.entries(enabled).map(([id, e]) => [id, { enabled: e }])),
      ...(semgrepConfigs !== undefined && {
        semgrep: {
          ...(enabled.semgrep !== undefined && { enabled: enabled.semgrep }),
          configs: semgrepConfigs,
        },
      }),
    },
  });

const analyzers = (...ids: AnalyzerId[]) => ids.map((id) => ({ id }));
/** The three engines whose findings mask secrets, and one that masks none. */
const ENGINES = analyzers('gitleaks', 'semgrep', 'qualor', 'eslint');
const engines = (...records: [string, 'ok' | 'failed' | 'skipped' | 'timeout'][]) =>
  records.map(([id, status]) => ({ id, status }));

describe('the secret scans that did not complete (6I-2 Review Focus 2, ruling G6)', () => {
  it('finds none when every secret engine ran to the end', () => {
    const ok = engines(['gitleaks', 'ok'], ['semgrep', 'ok'], ['qualor', 'ok'], ['eslint', 'ok']);
    expect(incompleteSecretScans(ENGINES, ok, config(), [])).toEqual([]);
  });

  it.each(['failed', 'timeout'] as const)(
    'counts an engine that %s, whether or not ruling G6 lists it',
    (status) => {
      const records = engines(['gitleaks', status], ['semgrep', status], ['qualor', status]);
      const all = ['gitleaks', 'semgrep', 'qualor'];
      expect(incompleteSecretScans(ENGINES, records, config(), all)).toEqual(all);
      // The function is right on its own: the list is not what makes a failure a failure.
      expect(incompleteSecretScans(ENGINES, records, config(), [])).toEqual(all);
    },
  );

  it('counts a Semgrep or Qualor engine whose tool is unavailable (ruling G6 lists it)', () => {
    const records = engines(['gitleaks', 'ok'], ['semgrep', 'skipped'], ['qualor', 'skipped']);
    expect(incompleteSecretScans(ENGINES, records, config(), ['semgrep', 'qualor'])).toEqual([
      'semgrep',
      'qualor',
    ]);
  });

  it('does not count a Semgrep or Qualor engine that was skipped with nothing to run', () => {
    // Not in ruling G6's list: no rule files (Semgrep on its defaults), no pack, no file of its
    // languages.
    const records = engines(['gitleaks', 'ok'], ['semgrep', 'skipped'], ['qualor', 'skipped']);
    expect(incompleteSecretScans(ENGINES, records, config(), [])).toEqual([]);
  });

  it.each([
    ['a rule file the configuration names', ['rules/secrets.yml']],
    [
      'qualor-default next to a rule file the configuration names',
      ['qualor-default', 'rules/a.yml'],
    ],
    ['a rule file named before qualor-default', ['rules/a.yml', 'qualor-default']],
  ])('counts a skipped Semgrep whose configs name %s: those rules never ran', (_name, configs) => {
    const records = engines(['gitleaks', 'ok'], ['semgrep', 'skipped'], ['qualor', 'ok']);
    expect(incompleteSecretScans(ENGINES, records, config({}, configs), [])).toEqual(['semgrep']);
  });

  it('does not count a skipped Semgrep whose configs are only qualor-default, however often', () => {
    const records = engines(['gitleaks', 'ok'], ['semgrep', 'skipped'], ['qualor', 'ok']);
    const twice = config({}, ['qualor-default', 'qualor-default']);
    expect(incompleteSecretScans(ENGINES, records, twice, [])).toEqual([]);
  });

  it('counts an ok Semgrep that ran without a rule file the configuration names', () => {
    const records = engines(['gitleaks', 'ok'], ['semgrep', 'ok'], ['qualor', 'ok']);
    const named = config({}, ['rules/a.yml', 'rules/gone.yml']);
    const missing = [{ code: 'SEMGREP_CONFIG_MISSING' }];
    expect(incompleteSecretScans(ENGINES, records, named, [], missing)).toEqual(['semgrep']);
    // Complete when every named file ran; other warnings do not matter.
    expect(incompleteSecretScans(ENGINES, records, named, [], [])).toEqual([]);
    expect(
      incompleteSecretScans(ENGINES, records, named, [], [{ code: 'FILE_UNREADABLE' }]),
    ).toEqual([]);
  });

  it('counts Gitleaks whenever it is not ok, a skip included: it scans every repository', () => {
    const skipped = engines(['gitleaks', 'skipped'], ['semgrep', 'ok'], ['qualor', 'ok']);
    expect(incompleteSecretScans(ENGINES, skipped, config(), [])).toEqual(['gitleaks']);
  });

  it('does not count an engine that qualor.yml switches off', () => {
    const records = engines(['gitleaks', 'skipped'], ['semgrep', 'skipped'], ['qualor', 'failed']);
    const off = config({ gitleaks: false, semgrep: false, qualor: false }, ['rules/secrets.yml']);
    expect(incompleteSecretScans(ENGINES, records, off, ['semgrep', 'qualor'])).toEqual([]);
  });

  it('counts an engine with no record at all, whatever the list says', () => {
    expect(incompleteSecretScans(ENGINES, engines(['gitleaks', 'ok']), config(), [])).toEqual([
      'semgrep',
      'qualor',
    ]);
  });

  it('never counts an engine that masks no secrets', () => {
    expect(
      incompleteSecretScans(analyzers('eslint'), engines(['eslint', 'failed']), config(), [
        'eslint',
      ]),
    ).toEqual([]);
  });
});

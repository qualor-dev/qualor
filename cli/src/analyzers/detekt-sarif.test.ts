import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { normalizedRuleKey } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { detektRuleId, detektSarif } from './detekt-sarif';

const raw = {
  version: '2.1.0',
  runs: [
    {
      originalUriBaseIds: { '%SRCROOT%': { uri: 'file:///work/detekt-input/' } },
      tool: {
        driver: {
          name: 'detekt',
          version: '1.23.8',
          rules: [
            {
              id: 'detekt.style.MagicNumber',
              name: 'MagicNumber',
              helpUri: 'https://detekt.dev/style.html#magicnumber',
              defaultConfiguration: { level: 'error' },
            },
            { id: 'detekt.potential-bugs.UnsafeCast', name: 'UnsafeCast' },
            { id: 'custom-rule' },
          ],
        },
      },
      results: [
        {
          ruleId: 'detekt.style.MagicNumber',
          level: 'warning',
          message: { text: 'm' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: 'src/A b/100%20#x?.kt', uriBaseId: '%SRCROOT%' },
                region: { startLine: 3 },
              },
            },
          ],
        },
        { ruleId: 'custom-rule', level: 'warning', message: { text: 'c' } },
      ],
    },
  ],
};

describe('detektSarif (report-format.md §5)', () => {
  it('turns detekt.<rule set>.<Rule> into <Rule> with the rule set as a property', () => {
    const log = detektSarif(raw);
    const run = log.runs[0]!;
    expect(run.tool.driver.rules?.map((r) => [r.id, r.properties?.['ruleset']])).toEqual([
      ['MagicNumber', 'style'],
      ['UnsafeCast', 'potential-bugs'],
      ['custom-rule', undefined],
    ]);
    expect(run.results?.map((r) => r.ruleId)).toEqual(['MagicNumber', 'custom-rule']);
    // Everything else is kept without a source root: the base URI, helpUri, levels.
    expect(run.originalUriBaseIds).toEqual({ '%SRCROOT%': { uri: 'file:///work/detekt-input/' } });
    expect(run.tool.driver.rules?.[0]?.helpUri).toBe('https://detekt.dev/style.html#magicnumber');
    expect(run.results?.[0]?.locations?.[0]?.physicalLocation?.artifactLocation).toEqual({
      uri: 'src/A b/100%20#x?.kt',
      uriBaseId: '%SRCROOT%',
    });
  });

  it('rebases the locations from the copy detekt read onto the repository, encoding the raw paths', () => {
    const root = path.resolve('/repo with space');
    const log = detektSarif(raw, root);
    const run = log.runs[0]!;
    expect(run.originalUriBaseIds).toEqual({
      '%SRCROOT%': { uri: `${pathToFileURL(root).href}/` },
    });
    // detekt writes the relative path unencoded; decoding it again must give the same name.
    const uri = run.results?.[0]?.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
    expect(uri).toBe('src/A%20b/100%2520%23x%3F.kt');
    expect(decodeURIComponent(uri!)).toBe('src/A b/100%20#x?.kt');
  });

  it('parses detekt rule ids strictly, with the shared normaliser of ext-detekt (ruling E5)', () => {
    expect(detektRuleId('detekt.empty-blocks.EmptyCatchBlock')).toEqual({
      ruleset: 'empty-blocks',
      rule: 'EmptyCatchBlock',
    });
    for (const id of [
      'MagicNumber',
      'detekt.style',
      'detekt.Style.MagicNumber',
      'detekt.style.Magic.Number',
      'x.style.MagicNumber',
    ]) {
      expect(detektRuleId(id), id).toBeNull();
      expect(normalizedRuleKey(`ext-detekt:${id}`), id).toBe(`ext-detekt:${id}`);
    }
    // The built-in key and an imported detekt SARIF's key pair on the same rule name.
    expect(normalizedRuleKey('ext-detekt:detekt.style.MagicNumber')).toBe('ext-detekt:MagicNumber');
  });

  it('throws on output that is not SARIF 2.1.0 (the engine then fails with a fixed reason)', () => {
    expect(() => detektSarif({ version: '2.0.0', runs: [] })).toThrow();
    expect(() => detektSarif('not sarif')).toThrow();
  });
});

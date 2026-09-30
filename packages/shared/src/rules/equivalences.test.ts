import { describe, expect, it } from 'vitest';
import sonarjsKeys from '../../rules/sonarjs-keys.json' with { type: 'json' };
import {
  effectiveCwe,
  ENGINE_PRIORITY,
  enginePriority,
  EQUIVALENCES,
  equivalentPartners,
  EXTERNAL_BUILTIN_ALIASES,
  normalizedRuleKey,
  rulesEquivalent,
} from './equivalences';

const rule = (key: string, cwe: number[] = []) => ({ key, engineId: key.split(':')[0]!, cwe });

describe('cross-engine equivalences (data-model.md §5.3)', () => {
  it('loads the curated list, with a reason for every entry', () => {
    expect(EQUIVALENCES.pairs.length).toBeGreaterThan(0);
    for (const p of EQUIVALENCES.pairs) {
      expect(p.rules[0].split(':')[0]).not.toBe(p.rules[1].split(':')[0]);
    }
    expect(effectiveCwe(rule('gitleaks:generic-api-key'))).toEqual([798]);
  });

  it('ranks gitleaks > semgrep > spotbugs > pmd > eslint > any external engine', () => {
    const order = ['my-tool', 'eslint', 'pmd', 'spotbugs', 'semgrep', 'gitleaks'].map(
      enginePriority,
    );
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(new Set(order).size).toBe(order.length);
  });

  it('matches on a shared CWE, including the Gitleaks engine default', () => {
    expect(
      rulesEquivalent(rule('gitleaks:generic-api-key'), rule('semgrep:hardcoded-api-key', [798])),
    ).toBe(true);
    expect(
      rulesEquivalent(rule('spotbugs:COMMAND_INJECTION', [78]), rule('semgrep:x', [78, 95])),
    ).toBe(true);
    expect(rulesEquivalent(rule('spotbugs:A', [78]), rule('semgrep:B', [95]))).toBe(false);
  });

  it('matches a listed pair in either order, and never two rules of one engine', () => {
    const eval1 = rule('eslint:no-eval');
    const eval2 = rule('semgrep:javascript.browser.security.eval-detected.eval-detected');
    expect(rulesEquivalent(eval1, eval2)).toBe(true);
    expect(rulesEquivalent(eval2, eval1)).toBe(true);
    expect(rulesEquivalent(rule('semgrep:a', [798]), rule('semgrep:b', [798]))).toBe(false);
  });

  it('lists the curated partners of a rule key in both directions', () => {
    const semgrepEval = 'semgrep:javascript.browser.security.eval-detected.eval-detected';
    expect(equivalentPartners('eslint:no-eval')).toEqual([semgrepEval]);
    expect(equivalentPartners(semgrepEval)).toEqual(['eslint:no-eval']);
    expect(equivalentPartners('eslint:no-console')).toEqual([]);
    expect(equivalentPartners('__proto__')).toEqual([]);
  });

  it('ranks roslyn between spotbugs and pmd (data-model.md §5.3)', () => {
    expect(enginePriority('spotbugs')).toBeGreaterThan(enginePriority('roslyn'));
    expect(enginePriority('roslyn')).toBeGreaterThan(enginePriority('pmd'));
  });

  it('ranks sonarjs right below eslint, still above any external engine (config.md §6)', () => {
    expect(enginePriority('eslint')).toBeGreaterThan(enginePriority('sonarjs'));
    expect(enginePriority('sonarjs')).toBeGreaterThan(enginePriority('my-tool'));
  });

  it('ranks ruff right after sonarjs, above any external engine (data-model.md §5.3)', () => {
    expect(enginePriority('sonarjs')).toBeGreaterThan(enginePriority('ruff'));
    expect(enginePriority('ruff')).toBeGreaterThan(enginePriority('my-tool'));
  });

  it('pairs every sonarjs rule that decorates an ESLint rule with that rule', () => {
    expect(equivalentPartners('sonarjs:S2376')).toContain('eslint:accessor-pairs');
    expect(equivalentPartners('sonarjs:S1186')).toEqual(
      expect.arrayContaining([
        'eslint:no-empty-function',
        'eslint:@typescript-eslint/no-empty-function',
      ]),
    );
    const pairs = EQUIVALENCES.pairs.filter((p) => p.rules.some((r) => r.startsWith('sonarjs:')));
    expect(pairs.length).toBeGreaterThanOrEqual(50);
  });

  it("pairs every sonarjs key with the project's own eslint-plugin-sonarjs rule, ESLint first", () => {
    // A project whose ESLint config already runs eslint-plugin-sonarjs reports the same problem as
    // eslint:sonarjs/<name>; the pair dedupes it with the ESLint issue primary (ENGINE_PRIORITY).
    const own = EQUIVALENCES.pairs.filter((p) => p.rules[0].startsWith('eslint:sonarjs/'));
    expect(own).toHaveLength(sonarjsKeys.length);
    for (const key of sonarjsKeys) {
      const partners = equivalentPartners(`sonarjs:${key}`).filter((r) =>
        r.startsWith('eslint:sonarjs/'),
      );
      expect(partners, key).toHaveLength(1);
    }
    for (const p of own) expect(sonarjsKeys).toContain(p.rules[1].replace(/^sonarjs:/, ''));
    expect(equivalentPartners('eslint:sonarjs/no-duplicated-branches')).toEqual(['sonarjs:S1871']);
    expect(
      rulesEquivalent(rule('eslint:sonarjs/cognitive-complexity'), rule('sonarjs:S3776')),
    ).toBe(true);
    expect(enginePriority('eslint')).toBeGreaterThan(enginePriority('sonarjs'));
  });

  it('pairs an externally imported Ruff rule with the built-in Ruff rule of the same code, ruff primary', () => {
    expect(EXTERNAL_BUILTIN_ALIASES).toEqual({
      'ext-ruff': 'ruff',
      'ext-stylelint': 'stylelint',
      'ext-htmlhint': 'htmlhint',
      'ext-detekt': 'detekt',
    });
    expect(equivalentPartners('ext-ruff:F401')).toEqual(['ruff:F401']);
    expect(equivalentPartners('ruff:F401')).toEqual(['ext-ruff:F401']);
    expect(rulesEquivalent(rule('ext-ruff:F401'), rule('ruff:F401'))).toBe(true);
    expect(rulesEquivalent(rule('ruff:S602'), rule('ext-ruff:S602'))).toBe(true);
    expect(rulesEquivalent(rule('ext-ruff:F401'), rule('ruff:F811'))).toBe(false);
    expect(rulesEquivalent(rule('ext-bandit:F401'), rule('ruff:F401'))).toBe(false);
    expect(equivalentPartners('ext-ruff:')).toEqual([]);
    expect(equivalentPartners('ruff')).toEqual([]);
    expect(enginePriority('ruff')).toBeGreaterThan(enginePriority('ext-ruff'));
  });

  it('ranks stylelint and htmlhint below ruff and above any external engine (plan 8D ruling D5)', () => {
    const p = (e: string) => ENGINE_PRIORITY.indexOf(e);
    expect(p('ruff')).toBeGreaterThanOrEqual(0);
    expect(p('stylelint')).toBeGreaterThan(p('ruff'));
    expect(p('htmlhint')).toBeGreaterThan(p('stylelint'));
    expect(enginePriority('htmlhint')).toBeGreaterThan(enginePriority('my-tool'));
    expect(enginePriority('stylelint')).toBeGreaterThan(enginePriority('ext-stylelint'));
    expect(enginePriority('htmlhint')).toBeGreaterThan(enginePriority('ext-htmlhint'));
  });

  it('pairs an externally imported stylelint rule with the built-in stylelint rule of the same id, stylelint primary (plan 8D ruling D4)', () => {
    expect(equivalentPartners('ext-stylelint:block-no-empty')).toEqual([
      'stylelint:block-no-empty',
    ]);
    expect(equivalentPartners('stylelint:block-no-empty')).toEqual([
      'ext-stylelint:block-no-empty',
    ]);
    expect(
      rulesEquivalent(rule('ext-stylelint:block-no-empty'), rule('stylelint:block-no-empty')),
    ).toBe(true);
    expect(
      rulesEquivalent(rule('ext-stylelint:block-no-empty'), rule('stylelint:length-zero-no-unit')),
    ).toBe(false);
    expect(
      rulesEquivalent(rule('ext-bandit:block-no-empty'), rule('stylelint:block-no-empty')),
    ).toBe(false);
  });

  it('pairs an externally imported HTMLHint rule with the built-in HTMLHint rule of the same id, htmlhint primary (plan 8D ruling D4)', () => {
    expect(equivalentPartners('ext-htmlhint:tag-pair')).toEqual(['htmlhint:tag-pair']);
    expect(equivalentPartners('htmlhint:tag-pair')).toEqual(['ext-htmlhint:tag-pair']);
    expect(rulesEquivalent(rule('ext-htmlhint:tag-pair'), rule('htmlhint:tag-pair'))).toBe(true);
    expect(rulesEquivalent(rule('ext-htmlhint:tag-pair'), rule('htmlhint:alt-require'))).toBe(
      false,
    );
    expect(rulesEquivalent(rule('ext-bandit:tag-pair'), rule('htmlhint:tag-pair'))).toBe(false);
  });

  it('ranks detekt last of the built-ins and above any external engine (plan 8E ruling E4)', () => {
    const p = (e: string) => ENGINE_PRIORITY.indexOf(e);
    expect(p('detekt')).toBeGreaterThan(p('htmlhint'));
    expect(enginePriority('htmlhint')).toBeGreaterThan(enginePriority('detekt'));
    expect(enginePriority('detekt')).toBeGreaterThan(enginePriority('my-tool'));
    expect(enginePriority('detekt')).toBeGreaterThan(enginePriority('ext-detekt'));
  });

  it("pairs detekt's own SARIF ids (detekt.<ruleset>.<Rule>) with the built-in rule (plan 8E ruling E5)", () => {
    expect(normalizedRuleKey('ext-detekt:detekt.style.MagicNumber')).toBe('ext-detekt:MagicNumber');
    expect(normalizedRuleKey('ext-detekt:MagicNumber')).toBe('ext-detekt:MagicNumber');
    expect(normalizedRuleKey('ext-detekt:detekt.a.b.C')).toBe('ext-detekt:detekt.a.b.C');
    expect(normalizedRuleKey('ext-ruff:F401')).toBe('ext-ruff:F401');
    expect(normalizedRuleKey('detekt:MagicNumber')).toBe('detekt:MagicNumber');
    expect(equivalentPartners('ext-detekt:detekt.style.MagicNumber')).toEqual([
      'detekt:MagicNumber',
    ]);
    expect(equivalentPartners('ext-detekt:MagicNumber')).toEqual(['detekt:MagicNumber']);
    expect(equivalentPartners('detekt:MagicNumber')).toEqual(['ext-detekt:MagicNumber']);
    expect(
      rulesEquivalent(rule('ext-detekt:detekt.style.MagicNumber'), rule('detekt:MagicNumber')),
    ).toBe(true);
    expect(
      rulesEquivalent(rule('detekt:MagicNumber'), rule('ext-detekt:detekt.style.MagicNumber')),
    ).toBe(true);
    expect(
      rulesEquivalent(rule('ext-detekt:detekt.style.MagicNumber'), rule('detekt:ReturnCount')),
    ).toBe(false);
    expect(
      rulesEquivalent(rule('ext-bandit:detekt.style.MagicNumber'), rule('detekt:MagicNumber')),
    ).toBe(false);
  });
});

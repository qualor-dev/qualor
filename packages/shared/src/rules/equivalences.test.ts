import { describe, expect, it } from 'vitest';
import ruffKeys from '../../rules/ruff-keys.json' with { type: 'json' };
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
  sameEnginePrimaries,
  sameEngineRank,
} from './equivalences';
import { FINDSECBUGS_PATTERNS } from './findsecbugs';
import { GOSEC_RULES } from './golang';
import { QUALOR_RULE_ID } from './qualor';

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
    expect(equivalentPartners('eslint:no-eval')).toEqual([semgrepEval, 'qualor:js/code-injection']);
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

  it('aliases every built-in engine that has an imported-SARIF twin, and no other', () => {
    // The whole alias table, strictly: plans 8C-8F and every Phase 9 engine (9A-9D; go vet has none).
    expect(EXTERNAL_BUILTIN_ALIASES).toEqual({
      'ext-ruff': 'ruff',
      'ext-stylelint': 'stylelint',
      'ext-htmlhint': 'htmlhint',
      'ext-detekt': 'detekt',
      'ext-swiftlint': 'swiftlint',
      'ext-phpstan': 'phpstan',
      'ext-rubocop': 'rubocop',
      'ext-staticcheck': 'staticcheck',
      'ext-gosec': 'gosec',
      'ext-cppcheck': 'cppcheck',
      'ext-clang-tidy': 'clang-tidy',
    });
  });

  it('pairs an externally imported Ruff rule with the built-in Ruff rule of the same code, ruff primary', () => {
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

  it('ranks swiftlint below every built-in engine listed before it, above any external one (data-model.md §5.3)', () => {
    for (const engine of ENGINE_PRIORITY.slice(0, ENGINE_PRIORITY.indexOf('swiftlint'))) {
      expect(enginePriority(engine), engine).toBeGreaterThan(enginePriority('swiftlint'));
    }
    expect(enginePriority('swiftlint')).toBeGreaterThan(enginePriority('my-tool'));
    expect(enginePriority('swiftlint')).toBeGreaterThan(enginePriority('ext-swiftlint'));
  });

  it('ranks phpstan below every built-in engine listed before it and above any external engine (plan 9A)', () => {
    expect(ENGINE_PRIORITY.indexOf('phpstan')).toBeGreaterThan(
      ENGINE_PRIORITY.indexOf('swiftlint'),
    );
    for (const engine of ENGINE_PRIORITY.slice(0, ENGINE_PRIORITY.indexOf('phpstan'))) {
      expect(enginePriority(engine), engine).toBeGreaterThan(enginePriority('phpstan'));
    }
    expect(enginePriority('phpstan')).toBeGreaterThan(enginePriority('my-tool'));
    expect(enginePriority('phpstan')).toBeGreaterThan(enginePriority('ext-phpstan'));
  });

  it('pairs an imported PHPStan SARIF (ext-phpstan, identical ids) with the built-in rule (plan 9A)', () => {
    expect(EXTERNAL_BUILTIN_ALIASES['ext-phpstan']).toBe('phpstan');
    expect(equivalentPartners('ext-phpstan:variable.undefined')).toEqual([
      'phpstan:variable.undefined',
    ]);
    expect(equivalentPartners('phpstan:variable.undefined')).toEqual([
      'ext-phpstan:variable.undefined',
    ]);
    expect(
      rulesEquivalent(rule('ext-phpstan:arguments.count'), rule('phpstan:arguments.count')),
    ).toBe(true);
    expect(rulesEquivalent(rule('ext-phpstan:arguments.count'), rule('phpstan:method.void'))).toBe(
      false,
    );
  });

  it('ranks cppcheck above clang-tidy, both below the earlier built-in engines and above any external one (plan 9D)', () => {
    const at = (e: string) => ENGINE_PRIORITY.indexOf(e);
    expect(at('cppcheck')).toBeGreaterThan(at('swiftlint'));
    expect(at('clang-tidy')).toBe(at('cppcheck') + 1);
    expect(enginePriority('cppcheck')).toBeGreaterThan(enginePriority('clang-tidy'));
    expect(enginePriority('clang-tidy')).toBeGreaterThan(enginePriority('my-tool'));
    expect(EXTERNAL_BUILTIN_ALIASES['ext-cppcheck']).toBe('cppcheck');
    expect(EXTERNAL_BUILTIN_ALIASES['ext-clang-tidy']).toBe('clang-tidy');
  });

  it('pairs an imported SwiftLint SARIF (ext-swiftlint, identical ids) with the built-in rule (plan 8F ruling F4)', () => {
    expect(EXTERNAL_BUILTIN_ALIASES['ext-swiftlint']).toBe('swiftlint');
    expect(normalizedRuleKey('ext-swiftlint:force_cast')).toBe('ext-swiftlint:force_cast');
    expect(equivalentPartners('ext-swiftlint:force_cast')).toEqual(['swiftlint:force_cast']);
    expect(equivalentPartners('swiftlint:force_cast')).toEqual(['ext-swiftlint:force_cast']);
    expect(rulesEquivalent(rule('ext-swiftlint:force_cast'), rule('swiftlint:force_cast'))).toBe(
      true,
    );
    expect(rulesEquivalent(rule('ext-swiftlint:force_cast'), rule('swiftlint:force_try'))).toBe(
      false,
    );
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

  it('ranks rubocop below every built-in engine listed before it and above any external engine (plan 9B)', () => {
    expect(ENGINE_PRIORITY.indexOf('rubocop')).toBeGreaterThan(
      ENGINE_PRIORITY.indexOf('swiftlint'),
    );
    for (const engine of ENGINE_PRIORITY.slice(0, ENGINE_PRIORITY.indexOf('rubocop'))) {
      expect(enginePriority(engine), engine).toBeGreaterThan(enginePriority('rubocop'));
    }
    expect(enginePriority('rubocop')).toBeGreaterThan(enginePriority('my-tool'));
    expect(enginePriority('rubocop')).toBeGreaterThan(enginePriority('ext-rubocop'));
  });

  it('pairs an imported RuboCop SARIF (ext-rubocop, identical ids) with the built-in rule (plan 9B)', () => {
    expect(EXTERNAL_BUILTIN_ALIASES['ext-rubocop']).toBe('rubocop');
    expect(equivalentPartners('ext-rubocop:Lint/UselessAssignment')).toEqual([
      'rubocop:Lint/UselessAssignment',
    ]);
    expect(equivalentPartners('rubocop:Lint/UselessAssignment')).toEqual([
      'ext-rubocop:Lint/UselessAssignment',
    ]);
    expect(rulesEquivalent(rule('ext-rubocop:Security/Eval'), rule('rubocop:Security/Eval'))).toBe(
      true,
    );
    expect(rulesEquivalent(rule('ext-rubocop:Security/Eval'), rule('rubocop:Security/Open'))).toBe(
      false,
    );
  });

  it('ranks the Go engines after swiftlint, staticcheck above govet above gosec, all above external ones (plan 9C)', () => {
    const at = (e: string) => ENGINE_PRIORITY.indexOf(e);
    expect(at('staticcheck')).toBeGreaterThan(at('swiftlint'));
    expect(at('govet')).toBeGreaterThan(at('staticcheck'));
    expect(at('gosec')).toBeGreaterThan(at('govet'));
    expect(enginePriority('gosec')).toBeGreaterThan(enginePriority('my-tool'));
  });

  it('pairs go vet with staticcheck where both report the same mistake, and imported staticcheck/gosec SARIF with the built-in rules (plan 9C)', () => {
    expect(rulesEquivalent(rule('govet:printf'), rule('staticcheck:SA5009'))).toBe(true);
    expect(rulesEquivalent(rule('govet:bools'), rule('staticcheck:SA4000'))).toBe(true);
    expect(rulesEquivalent(rule('govet:printf'), rule('staticcheck:SA4000'))).toBe(false);
    expect(equivalentPartners('ext-staticcheck:SA4006')).toEqual(['staticcheck:SA4006']);
    expect(equivalentPartners('gosec:G401')).toEqual(['ext-gosec:G401']);
    expect(enginePriority('staticcheck')).toBeGreaterThan(enginePriority('govet'));
    expect(enginePriority('gosec')).toBeGreaterThan(enginePriority('ext-gosec'));
  });

  it('pairs the cppcheck and clang-tidy rules that report the same defect (plan 9D)', () => {
    for (const [a, b] of [
      ['cppcheck:zerodiv', 'clang-tidy:clang-analyzer-core.DivideZero'],
      ['cppcheck:nullPointer', 'clang-tidy:clang-analyzer-core.NullDereference'],
      ['cppcheck:mismatchAllocDealloc', 'clang-tidy:clang-analyzer-unix.MismatchedDeallocator'],
      ['cppcheck:memleak', 'clang-tidy:clang-analyzer-unix.Malloc'],
      ['cppcheck:doubleFree', 'clang-tidy:clang-analyzer-unix.Malloc'],
      ['cppcheck:deallocuse', 'clang-tidy:clang-analyzer-unix.Malloc'],
      ['cppcheck:arrayIndexOutOfBounds', 'clang-tidy:clang-analyzer-security.ArrayBound'],
      ['cppcheck:duplicateBranch', 'clang-tidy:bugprone-branch-clone'],
      ['cppcheck:duplicateExpression', 'clang-tidy:misc-redundant-expression'],
      ['cppcheck:accessMoved', 'clang-tidy:bugprone-use-after-move'],
    ] as const) {
      expect(rulesEquivalent(rule(a), rule(b)), `${a} ~ ${b}`).toBe(true);
      expect(rulesEquivalent(rule(b), rule(a)), `${b} ~ ${a}`).toBe(true);
      expect(equivalentPartners(a), a).toContain(b);
    }
  });
});

describe('curated same-engine pairs (data-model.md §5.3, plan 6A)', () => {
  const CORE_SPOTBUGS_SECURITY = new Set([
    'SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE',
    'SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING',
    'DMI_CONSTANT_DB_PASSWORD',
    'DMI_EMPTY_DB_PASSWORD',
    'HRS_REQUEST_PARAMETER_TO_HTTP_HEADER',
    'HRS_REQUEST_PARAMETER_TO_COOKIE',
    'PT_RELATIVE_PATH_TRAVERSAL',
    'PT_ABSOLUTE_PATH_TRAVERSAL',
    'XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER',
  ]);

  it('pairs core SpotBugs rules (primary) with FindSecBugs rules, within one engine, never chained', () => {
    const pairs = EQUIVALENCES.sameEngine;
    expect(pairs.length).toBeGreaterThan(0);
    const primaries = new Set(pairs.map((p) => p.primary));
    const duplicates = new Set(pairs.map((p) => p.duplicate));
    for (const p of pairs) {
      expect(p.primary.split(':')[0], p.primary).toBe(p.duplicate.split(':')[0]);
      expect(duplicates.has(p.primary), p.primary).toBe(false);
      expect(primaries.has(p.duplicate), p.duplicate).toBe(false);
      expect(CORE_SPOTBUGS_SECURITY.has(p.primary.slice('spotbugs:'.length)), p.primary).toBe(true);
      expect(FINDSECBUGS_PATTERNS.has(p.duplicate.slice('spotbugs:'.length)), p.duplicate).toBe(
        true,
      );
    }
  });

  it('makes a listed pair equivalent in either order, and nothing else of one engine', () => {
    const core = rule('spotbugs:SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE', [89]);
    const fsb = rule('spotbugs:SQL_INJECTION_JDBC', [89]);
    expect(rulesEquivalent(core, fsb)).toBe(true);
    expect(rulesEquivalent(fsb, core)).toBe(true);
    expect(rulesEquivalent(rule('spotbugs:SQL_INJECTION_JPA', [89]), core)).toBe(false);
    expect(rulesEquivalent(rule('spotbugs:SQL_INJECTION_JPA', [89]), fsb)).toBe(false);
    expect(sameEnginePrimaries('spotbugs:SQL_INJECTION_JDBC')).toEqual([
      'spotbugs:SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE',
      'spotbugs:SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING',
    ]);
    expect(sameEnginePrimaries('spotbugs:SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE')).toEqual([]);
    expect(sameEnginePrimaries('__proto__')).toEqual([]);
    expect(sameEngineRank('spotbugs:SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE')).toBe(1);
    expect(sameEngineRank('spotbugs:SQL_INJECTION_JDBC')).toBe(0);
  });

  it('ranks qualor right after gitleaks, above every other engine (plan 6B-1)', () => {
    expect(ENGINE_PRIORITY.slice(0, 2)).toEqual(['gitleaks', 'qualor']);
    for (const engine of ENGINE_PRIORITY.slice(2)) {
      expect(enginePriority('qualor'), engine).toBeGreaterThan(enginePriority(engine));
    }
    expect(enginePriority('gitleaks')).toBeGreaterThan(enginePriority('qualor'));
    // A user's own Semgrep rule on the same line and CWE becomes the qualor issue's duplicate.
    expect(
      rulesEquivalent(
        { key: 'qualor:java/sql-injection', engineId: 'qualor', cwe: [89] },
        { key: 'semgrep:my-sqli', engineId: 'semgrep', cwe: [89] },
      ),
    ).toBe(true);
  });
});

describe("Qualor's own rules paired with the other engines' (plan 6B)", () => {
  const QUALOR_PAIRS = EQUIVALENCES.pairs.filter((p) => p.rules[0].startsWith('qualor:'));
  const OWN_ESLINT_SONARJS = new Set(
    EQUIVALENCES.pairs.map((p) => p.rules[0]).filter((r) => r.startsWith('eslint:sonarjs/')),
  );
  const CORE_SPOTBUGS = new Set(EQUIVALENCES.sameEngine.map((p) => p.primary));

  /** Whether the bundled analyzer behind `key` has that rule (its committed catalog). */
  const known = (key: string): boolean => {
    const colon = key.indexOf(':');
    const engine = key.slice(0, colon);
    const id = key.slice(colon + 1);
    if (engine === 'ruff') return (ruffKeys as string[]).includes(id);
    if (engine === 'sonarjs') return (sonarjsKeys as string[]).includes(id);
    if (engine === 'gosec') return GOSEC_RULES.has(id);
    if (engine === 'spotbugs') return FINDSECBUGS_PATTERNS.has(id) || CORE_SPOTBUGS.has(key);
    if (engine === 'eslint') return OWN_ESLINT_SONARJS.has(key) || key === 'eslint:no-eval';
    return false;
  };

  it('names a qualor rule first and a rule of a bundled analyzer second, each pair once', () => {
    expect(QUALOR_PAIRS.length).toBeGreaterThanOrEqual(30);
    for (const { rules } of QUALOR_PAIRS) {
      expect(QUALOR_RULE_ID.test(rules[0].slice('qualor:'.length)), rules[0]).toBe(true);
      expect(rules[1].startsWith('qualor:'), rules[1]).toBe(false);
      expect(known(rules[1]), rules[1]).toBe(true);
      expect(enginePriority('qualor'), rules[1]).toBeGreaterThan(
        enginePriority(rules[1].split(':')[0]!),
      );
    }
    const keys = QUALOR_PAIRS.map((p) => p.rules.join(' '));
    expect(new Set(keys).size).toBe(keys.length);
    // No other pair names a qualor rule second.
    expect(EQUIVALENCES.pairs.filter((p) => p.rules[1].startsWith('qualor:'))).toEqual([]);
  });

  it.each([
    // Python: Ruff's rules carry no CWE (the 2026-10-06 merge request: S608, S307).
    ['qualor:python/sql-injection', [89], 'ruff:S608', []],
    ['qualor:python/code-injection', [94, 95], 'ruff:S307', []],
    ['qualor:python/command-injection', [78], 'ruff:S602', []],
    ['qualor:python/command-injection', [78], 'ruff:S605', []],
    ['qualor:python/unsafe-deserialization', [502], 'ruff:S301', []],
    ['qualor:python/tls-verification-disabled', [295], 'ruff:S501', []],
    // JavaScript: the SonarJS hotspots on the same sink (S2077, S4721).
    ['qualor:js/sql-injection', [89], 'sonarjs:S2077', []],
    ['qualor:js/command-injection', [78], 'sonarjs:S4721', []],
    ['qualor:js/sql-injection', [89], 'eslint:sonarjs/sql-queries', []],
    // Go: gosec's CWE differs or is missing.
    ['qualor:go/ssrf', [918], 'gosec:G107', [88]],
    ['qualor:go/open-redirect', [601], 'gosec:G710', []],
    // Java: a core SpotBugs rule without CWE-79, FindSecBugs' SpEL rule with CWE-94.
    ['qualor:java/xss', [79], 'spotbugs:XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER', []],
    ['qualor:java/expression-injection', [917], 'spotbugs:SPEL_INJECTION', [94]],
  ] as const)('%s ~ %s, which shares no CWE with it', (q, qCwe, other, otherCwe) => {
    const a = rule(q, [...qCwe]);
    const b = rule(other, [...otherCwe]);
    expect(effectiveCwe(b).some((c) => (qCwe as readonly number[]).includes(c))).toBe(false);
    expect(rulesEquivalent(a, b)).toBe(true);
    expect(rulesEquivalent(b, a)).toBe(true);
    expect(equivalentPartners(other)).toContain(q);
    expect(enginePriority('qualor')).toBeGreaterThan(enginePriority(b.engineId));
  });

  it('leaves the rules that report another problem on the line apart', () => {
    for (const [q, qCwe, other] of [
      ['qualor:python/ssrf', [918], 'ruff:S113'], // a request without a timeout
      ['qualor:python/ssrf', [918], 'ruff:S310'], // urlopen of a file: or custom scheme
      ['qualor:python/template-injection', [94, 1336], 'ruff:S701'], // Jinja2 autoescape off
      ['qualor:js/command-injection', [78], 'sonarjs:S4036'], // a command looked up in PATH
      ['qualor:js/tls-verification-disabled', [295], 'sonarjs:S5332'], // a clear-text protocol
      ['qualor:js/sql-injection', [89], 'sonarjs:S5689'], // Express discloses its version
      ['qualor:java/open-redirect', [601], 'spotbugs:HRS_REQUEST_PARAMETER_TO_HTTP_HEADER'],
      ['qualor:python/sql-injection', [89], 'ruff:S307'], // a pair is per qualor rule
      ['qualor:python/command-injection', [78], 'ruff:S604'], // shell=True outside subprocess
    ] as const) {
      expect(rulesEquivalent(rule(q, [...qCwe]), rule(other)), `${q} ~ ${other}`).toBe(false);
    }
  });

  it('keeps the CWE match for the engines that carry one (gosec, FindSecBugs): no pair needed', () => {
    expect(rulesEquivalent(rule('qualor:go/sql-injection', [89]), rule('gosec:G201', [89]))).toBe(
      true,
    );
    expect(
      rulesEquivalent(
        rule('qualor:java/sql-injection', [89]),
        rule('spotbugs:SQL_INJECTION_JDBC', [89]),
      ),
    ).toBe(true);
    expect(QUALOR_PAIRS.some((p) => p.rules[1] === 'gosec:G201')).toBe(false);
  });
});

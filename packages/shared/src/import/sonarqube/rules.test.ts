import { describe, expect, it } from 'vitest';
import ruffKeys from '../../../rules/ruff-keys.json' with { type: 'json' };
import sonaranalyzerDefaultKeys from '../../../rules/sonaranalyzer-csharp-default-keys.json' with { type: 'json' };
import sonaranalyzerKeys from '../../../rules/sonaranalyzer-csharp-keys.json' with { type: 'json' };
import sonarjsDefaultKeys from '../../../rules/sonarjs-default-keys.json' with { type: 'json' };
import sonarjsKeys from '../../../rules/sonarjs-keys.json' with { type: 'json' };
import raw from '../../../rules/sonarqube.json' with { type: 'json' };
import { engineOf, loadSonarMapping, SONAR_MAPPING } from './rules';

const table = (patch: Record<string, unknown>) =>
  loadSonarMapping({ ...structuredClone(raw), ...patch });

describe('the SonarQube mapping table (import-sonarqube.md §6)', () => {
  it('loads the shipped table', () => {
    expect(SONAR_MAPPING.language('ts')).toEqual({
      language: 'typescript',
      engines: ['eslint', 'sonarjs'],
    });
    expect(SONAR_MAPPING.language('java')?.engines).toEqual(['pmd', 'spotbugs']);
  });

  it('knows no language it does not list', () => {
    expect(SONAR_MAPPING.language('go')).toBeNull();
  });

  it('maps py to the python profile, governed by ruff (plan 8C)', () => {
    expect(SONAR_MAPPING.language('py')).toEqual({ language: 'python', engines: ['ruff'] });
  });

  it('maps the swift language and the statuses of SwiftLint issues SonarQube imported (plan 8F)', () => {
    expect(SONAR_MAPPING.language('swift')).toEqual({ language: 'swift', engines: ['swiftlint'] });
    expect(SONAR_MAPPING.targets('external_swiftlint:force_cast')).toEqual([
      { key: 'swiftlint:force_cast', relation: 'equivalent', reviewed: true, source: 'repository' },
    ]);
    expect(SONAR_MAPPING.targets('swift:S1481')).toEqual([]); // SonarSource's own Swift rules: unmapped
  });

  it('maps external_ruff statuses one to one, for codes the pinned Ruff has only', () => {
    expect(SONAR_MAPPING.targets('external_ruff:SIM113')).toEqual([
      { key: 'ruff:SIM113', relation: 'equivalent', reviewed: true, source: 'repository' },
    ]);
    expect(SONAR_MAPPING.targets('external_ruff:ZZZ999')).toEqual([]);
    expect(SONAR_MAPPING.targets('python:S9999')).toEqual([]);
  });

  it('maps python:S1128 to ruff:F401 through the curated table', () => {
    expect(SONAR_MAPPING.targets('python:S1128')).toContainEqual(
      expect.objectContaining({ key: 'ruff:F401', relation: 'equivalent', source: 'table' }),
    );
  });

  it('knows which Ruff targets qualor-default runs', () => {
    expect(SONAR_MAPPING.runByBundledConfig('ruff:F401')).toBe(true);
    expect(SONAR_MAPPING.runByBundledConfig('ruff:S608')).toBe(true);
    expect(SONAR_MAPPING.runByBundledConfig('ruff:ERA001')).toBe(false);
    expect(SONAR_MAPPING.runByBundledConfig('ruff:S101')).toBe(false);
  });

  it('names only codes the pinned Ruff has in every python row, with our own short reasons', () => {
    const codes = new Set(ruffKeys);
    const rows = raw.rules.filter((r) => r.sonar.some((s) => s.startsWith('python:')));
    expect(rows.length).toBeGreaterThanOrEqual(40);
    for (const row of rows) {
      for (const q of row.qualor) {
        expect(q.startsWith('ruff:'), q).toBe(true);
        expect(codes.has(q.slice('ruff:'.length)), q).toBe(true);
      }
      expect(
        row.sonar.every((s) => s.startsWith('python:')),
        row.sonar.join(),
      ).toBe(true);
    }
  });

  it('maps csharpsquid rules the bundled SonarAnalyzer has to roslyn, one to one', () => {
    expect(SONAR_MAPPING.language('cs')).toEqual({ language: 'csharp', engines: ['roslyn'] });
    expect(SONAR_MAPPING.targets('csharpsquid:S1481')).toEqual([
      { key: 'roslyn:S1481', relation: 'equivalent', reviewed: true, source: 'repository' },
    ]);
    expect(SONAR_MAPPING.targets('csharpsquid:S9999')).toEqual([]); // not in 9.32
  });

  it('maps javascript and typescript rules sonarjs 2.0.4 has to sonarjs, and nothing else', () => {
    expect(SONAR_MAPPING.targets('typescript:S1192')).toContainEqual({
      key: 'sonarjs:S1192',
      relation: 'equivalent',
      reviewed: true,
      source: 'repository',
    });
    expect(SONAR_MAPPING.targets('javascript:S1440').map((t) => t.key)).toEqual(['eslint:eqeqeq']); // not in the plugin
  });

  it('maps external_roslyn to the roslyn engine by the analyzer id, for issue statuses (§6.1)', () => {
    expect(SONAR_MAPPING.targets('external_roslyn:CA1822')).toEqual([
      { key: 'roslyn:CA1822', relation: 'equivalent', reviewed: true, source: 'repository' },
    ]);
    expect(SONAR_MAPPING.targets('external_roslyn:RCS1036')[0]?.key).toBe('roslyn:RCS1036');
    expect(SONAR_MAPPING.component('external_roslyn:CA1822')).toBe('roslyn:CA1822');
    expect(SONAR_MAPPING.componentRules('roslyn:CA1822')).toEqual(['external_roslyn:CA1822']);
    expect(SONAR_MAPPING.competingRules(['external_roslyn:CA1822'])).toEqual([
      'external_roslyn:CA1822',
    ]);
  });

  it('maps repositories whose rule ids are the analyzer own, exactly', () => {
    expect(
      SONAR_MAPPING.targets('external_eslint_repo:@typescript-eslint/no-explicit-any'),
    ).toEqual([
      {
        key: 'eslint:@typescript-eslint/no-explicit-any',
        relation: 'equivalent',
        reviewed: true,
        source: 'repository',
      },
    ]);
    expect(SONAR_MAPPING.targets('findbugs:NP_NULL_ON_SOME_PATH')[0]?.key).toBe(
      'spotbugs:NP_NULL_ON_SOME_PATH',
    );
    expect(SONAR_MAPPING.targets('pmd:UnusedLocalVariable')[0]?.key).toBe(
      'pmd:UnusedLocalVariable',
    );
  });

  it('maps curated rules with their relation and review flag, and the squid alias', () => {
    // S3504 is both curated (eslint:no-var) and, since Phase 8, a real sonarjs key: the union of
    // both sources (§6.2).
    expect(SONAR_MAPPING.targets('typescript:S3504')).toEqual([
      { key: 'eslint:no-var', relation: 'equivalent', reviewed: false, source: 'table' },
      { key: 'sonarjs:S3504', relation: 'equivalent', reviewed: true, source: 'repository' },
    ]);
    expect(SONAR_MAPPING.targets('squid:S1481')).toEqual(SONAR_MAPPING.targets('java:S1481'));
    expect(SONAR_MAPPING.targets('java:S4973').map((t) => t.relation)).toEqual([
      'overlap',
      'overlap',
      'overlap',
    ]);
  });

  it('has no target for an unmapped rule or a key without a repository', () => {
    // S9999 is in neither the curated table nor the bundled sonarjs plugin.
    expect(SONAR_MAPPING.targets('typescript:S9999')).toEqual([]);
    expect(SONAR_MAPPING.targets('no-colon')).toEqual([]);
    expect(SONAR_MAPPING.targets(`external_eslint_repo:${'x'.repeat(513)}`)).toEqual([]);
  });

  it('refuses a table with a duplicate SonarQube key, an unknown engine or an empty reason', () => {
    const rules = structuredClone(raw.rules);
    expect(() => table({ rules: [...rules, rules[0]] })).toThrow(/twice/);
    expect(() =>
      table({ repositories: [{ repository: 'x', engine: 'nope', reason: 'r' }] }),
    ).toThrow();
    expect(() => table({ rules: [{ ...rules[0], sonar: ['java:S9'], reason: '' }] })).toThrow();
    expect(() =>
      table({ rules: [{ ...rules[0], sonar: ['java:S9'], qualor: ['nope:CA1'] }] }),
    ).toThrow();
  });

  it('refuses a repository row whose keysFile names no shipped keys file', () => {
    expect(() =>
      table({
        repositories: [
          { repository: 'x', engine: 'roslyn', reason: 'r', keysFile: 'unknown-keys.json' },
        ],
      }),
    ).toThrow(/unknown keysFile/);
  });

  it('knows which bundled SonarQube-compatible rules the bundled configuration runs', () => {
    expect(SONAR_MAPPING.runByBundledConfig('sonarjs:S1871')).toBe(true);
    expect(SONAR_MAPPING.runByBundledConfig('sonarjs:S1192')).toBe(false);
    expect(SONAR_MAPPING.runByBundledConfig('roslyn:S1481')).toBe(true);
    expect(SONAR_MAPPING.runByBundledConfig('roslyn:S107')).toBe(false);
    // Not a bundled SonarSource-derived rule: the project's own analyzers decide.
    expect(SONAR_MAPPING.runByBundledConfig('roslyn:RCS1001')).toBe(true);
    expect(SONAR_MAPPING.runByBundledConfig('eslint:eqeqeq')).toBe(true);
    expect(SONAR_MAPPING.runByBundledConfig('sonarjs:S9999')).toBe(true);
    // Every default key is a bundled key.
    for (const [all, run] of [
      [sonarjsKeys, sonarjsDefaultKeys],
      [sonaranalyzerKeys, sonaranalyzerDefaultKeys],
    ] as const) {
      expect(run.length).toBeGreaterThan(0);
      expect(run.length).toBeLessThan(all.length);
      for (const k of run) expect(all).toContain(k);
    }
  });

  it('refuses a defaultKeysFile without a keysFile, or one that names no shipped file', () => {
    expect(() =>
      table({
        repositories: [
          {
            repository: 'x',
            engine: 'sonarjs',
            reason: 'r',
            defaultKeysFile: 'sonarjs-default-keys.json',
          },
        ],
      }),
    ).toThrow(/without a keysFile/);
    expect(() =>
      table({
        repositories: [
          {
            repository: 'x',
            engine: 'sonarjs',
            reason: 'r',
            keysFile: 'sonarjs-keys.json',
            defaultKeysFile: 'unknown-default-keys.json',
          },
        ],
      }),
    ).toThrow(/unknown keysFile or defaultKeysFile/);
  });

  it('holds no SonarSource text: reasons are one short line each', () => {
    for (const entry of [...raw.repositories, ...raw.rules]) {
      expect(entry.reason.length).toBeLessThanOrEqual(120);
      expect(entry.reason).not.toContain('\n');
    }
  });

  it('names the engine of a Qualor key, and none for a key without a colon', () => {
    expect(engineOf('eslint:@typescript-eslint/no-unused-vars')).toBe('eslint');
    expect(engineOf('no-colon')).toBe('');
    expect(engineOf('')).toBe('');
  });

  it('maps S1186 per language: the TypeScript profile gets only the typescript-eslint rule', () => {
    // S1186 is also a real sonarjs key (Phase 8), shared by both languages' repository rows.
    expect(SONAR_MAPPING.targets('javascript:S1186').map((t) => t.key)).toEqual([
      'eslint:no-empty-function',
      'sonarjs:S1186',
    ]);
    expect(SONAR_MAPPING.targets('typescript:S1186').map((t) => t.key)).toEqual([
      'eslint:@typescript-eslint/no-empty-function',
      'sonarjs:S1186',
    ]);
  });

  it.each(['javascript:S1440', 'typescript:S1440', 'java:S108', 'java:S1068', 'java:S1481'])(
    'marks %s as an overlap, never reviewed',
    (key) => {
      const targets = SONAR_MAPPING.targets(key);
      expect(targets.length).toBeGreaterThan(0);
      for (const t of targets) expect(t).toMatchObject({ relation: 'overlap', reviewed: false });
    },
  );

  it('ships every curated entry unreviewed', () => {
    for (const entry of raw.rules) expect(entry.reviewed).toBe(false);
  });

  it('maps the unit-test PMD rules and the JSP Find Security Bugs patterns', () => {
    expect(SONAR_MAPPING.targets('pmd-unit-tests:JUnitTestsShouldIncludeAssert')[0]?.key).toBe(
      'pmd:JUnitTestsShouldIncludeAssert',
    );
    expect(SONAR_MAPPING.targets('findsecbugs-jsp:XSS_JSP_PRINT')[0]?.key).toBe(
      'spotbugs:XSS_JSP_PRINT',
    );
  });

  /** The SonarQube repositories of the curated table and the analyser-owned rows, by the
   * SonarQube language they analyse. */
  const REPOSITORY_LANGUAGE: Record<string, string> = {
    javascript: 'js',
    typescript: 'ts',
    java: 'java',
    squid: 'java',
    csharpsquid: 'cs',
    python: 'py',
  };

  it("keeps every curated target, and every repository row's engine, to an engine of its SonarQube rule's language", () => {
    for (const entry of raw.rules) {
      for (const sonar of entry.sonar) {
        const language = REPOSITORY_LANGUAGE[engineOf(sonar)];
        expect(language, sonar).toBeDefined();
        const engines = SONAR_MAPPING.language(language ?? '')?.engines ?? [];
        for (const q of entry.qualor) {
          expect(engines as readonly string[], `${sonar} -> ${q}`).toContain(engineOf(q));
        }
      }
    }
    for (const row of raw.repositories) {
      const language = REPOSITORY_LANGUAGE[row.repository];
      if (language === undefined) continue; // external_* and community rows analyse no SonarQube language
      const engines = SONAR_MAPPING.language(language)?.engines ?? [];
      expect(engines as readonly string[], row.repository).toContain(row.engine);
    }
  });

  it('gives no key, in any spelling, more targets than one import item carries (8, spec §10.2)', () => {
    // An item with more is marked with its whole mapping component (fix 12c); the shipped table
    // must never need that.
    const aliases = Object.entries(raw.aliases as Record<string, string>);
    for (const entry of raw.rules) {
      for (const sonar of entry.sonar) {
        const [repository = '', id = ''] = [
          sonar.slice(0, sonar.indexOf(':')),
          sonar.slice(sonar.indexOf(':') + 1),
        ];
        const spellings = [
          sonar,
          ...aliases.filter(([, to]) => to === repository).map(([a]) => `${a}:${id}`),
        ];
        for (const k of spellings) {
          expect(SONAR_MAPPING.targets(k).length, k).toBeLessThanOrEqual(8);
        }
      }
    }
  });
});

describe('competing rules (import-sonarqube.md §10.1, ruling S7)', () => {
  it('lists every SonarQube rule sharing a target, through the table and the repositories', () => {
    const rules = SONAR_MAPPING.competingRules(['typescript:S1440']);
    expect(rules).toEqual(['external_eslint_repo:eqeqeq', 'javascript:S1440', 'typescript:S1440']);
    // And the other way round.
    expect(SONAR_MAPPING.competingRules(['external_eslint_repo:eqeqeq'])).toEqual(rules);
  });

  it('spells table keys with their aliases and repository targets with every repository', () => {
    expect(SONAR_MAPPING.competingRules(['java:S108'])).toEqual([
      'external_pmd:EmptyCatchBlock',
      'external_pmd:EmptyControlStatement',
      'java:S108',
      'pmd-unit-tests:EmptyCatchBlock',
      'pmd-unit-tests:EmptyControlStatement',
      'pmd:EmptyCatchBlock',
      'pmd:EmptyControlStatement',
      'squid:S108',
    ]);
  });

  it('adds nothing for an unmapped rule, and every key it lists overlaps', () => {
    expect(SONAR_MAPPING.competingRules(['typescript:S9999', 'nokey'])).toEqual([]);
    const keys = raw.rules.flatMap((e) => e.sonar);
    for (const k of keys) {
      const own = new Set(SONAR_MAPPING.targets(k).map((t) => t.key));
      const listed = SONAR_MAPPING.competingRules([k]);
      expect(listed, k).toContain(k);
      for (const other of listed) {
        expect(
          SONAR_MAPPING.targets(other).some((t) => own.has(t.key)),
          `${k} ~ ${other}`,
        ).toBe(true);
      }
      // Every table key that overlaps is listed.
      for (const other of keys) {
        if (SONAR_MAPPING.targets(other).some((t) => own.has(t.key)))
          expect(listed).toContain(other);
      }
    }
  });
});

describe('mapping components (import-sonarqube.md §10.1, ruling S14)', () => {
  /** The reviewers' probes: U → t; O → t, t2; J → t2; K → t2, t3; L → t3; and a lone S. */
  const chain = loadSonarMapping({
    languages: { ts: { language: 'typescript', engines: ['eslint'] } },
    aliases: { tslegacy: 'typescript' },
    repositories: [
      { repository: 'external_eslint_repo', engine: 'eslint', reason: 'ESLint' },
      { repository: 'eslint_mirror', engine: 'eslint', reason: 'ESLint' },
    ],
    rules: [
      {
        sonar: ['typescript:U'],
        qualor: ['eslint:t'],
        relation: 'overlap',
        reviewed: false,
        reason: 'u',
      },
      {
        sonar: ['typescript:O'],
        qualor: ['eslint:t', 'eslint:t2'],
        relation: 'overlap',
        reviewed: false,
        reason: 'o',
      },
      {
        sonar: ['typescript:J'],
        qualor: ['eslint:t2'],
        relation: 'overlap',
        reviewed: false,
        reason: 'j',
      },
      {
        sonar: ['typescript:K'],
        qualor: ['eslint:t2', 'eslint:t3'],
        relation: 'overlap',
        reviewed: false,
        reason: 'k',
      },
      {
        sonar: ['typescript:L'],
        qualor: ['eslint:t3'],
        relation: 'overlap',
        reviewed: false,
        reason: 'l',
      },
      {
        sonar: ['typescript:S'],
        qualor: ['eslint:s'],
        relation: 'overlap',
        reviewed: false,
        reason: 's',
      },
    ],
  });

  it('joins rules through any chain of shared targets, not only direct ones', () => {
    const k = chain.component('typescript:J');
    expect(k).toBe('eslint:t');
    for (const r of ['typescript:U', 'typescript:O', 'typescript:K', 'typescript:L']) {
      expect(chain.component(r), r).toBe(k);
    }
    // competingRules stops after one hop; the component does not.
    expect(chain.competingRules(['typescript:L'])).not.toContain('typescript:U');
    expect(chain.componentRules(k!)).toEqual([
      'eslint_mirror:t',
      'eslint_mirror:t2',
      'eslint_mirror:t3',
      'external_eslint_repo:t',
      'external_eslint_repo:t2',
      'external_eslint_repo:t3',
      'tslegacy:J',
      'tslegacy:K',
      'tslegacy:L',
      'tslegacy:O',
      'tslegacy:U',
      'typescript:J',
      'typescript:K',
      'typescript:L',
      'typescript:O',
      'typescript:U',
    ]);
    expect(chain.component('typescript:S')).toBe('eslint:s');
    expect(chain.component('tslegacy:S')).toBe('eslint:s');
  });

  it('keys a component of repository-mapped rules by its target, shared by every repository of the engine', () => {
    const k = chain.component('external_eslint_repo:plugin/rule');
    expect(k).toBe('eslint:plugin/rule');
    expect(chain.component('eslint_mirror:plugin/rule')).toBe(k);
    expect(chain.componentRules(k!)).toEqual([
      'eslint_mirror:plugin/rule',
      'external_eslint_repo:plugin/rule',
    ]);
    // A repository key of a table target joins the table's component.
    expect(chain.component('eslint_mirror:t3')).toBe('eslint:t');
    expect(chain.component('typescript:nothing')).toBeNull();
    expect(chain.component('nokey')).toBeNull();
    expect(chain.componentsOf(['typescript:U', 'typescript:L', 'nokey', 'typescript:S'])).toEqual([
      'eslint:s',
      'eslint:t',
    ]);
  });

  it('spans the shipped table: every key sharing a target is in its component, and every rule listed is', () => {
    expect(SONAR_MAPPING.componentRules(SONAR_MAPPING.component('typescript:S1440')!)).toEqual([
      'external_eslint_repo:eqeqeq',
      'javascript:S1440',
      'typescript:S1440',
    ]);
    expect(SONAR_MAPPING.component('squid:S108')).toBe(
      SONAR_MAPPING.component('pmd:EmptyCatchBlock'),
    );
    const keys = raw.rules.flatMap((e) => e.sonar);
    for (const k of keys) {
      const c = SONAR_MAPPING.component(k);
      expect(c, k).not.toBeNull();
      const listed = SONAR_MAPPING.componentRules(c!);
      expect(listed, k).toContain(k);
      for (const other of listed) expect(SONAR_MAPPING.component(other), other).toBe(c);
      for (const other of SONAR_MAPPING.competingRules([k])) expect(listed, k).toContain(other);
    }
  });
});

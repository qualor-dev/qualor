import { describe, expect, it } from 'vitest';
import { loadSonarMapping } from './rules';
import raw from '../../../rules/sonarqube.json' with { type: 'json' };
import {
  isReservedName,
  mappedConditions,
  planGate,
  planProfile,
  severityOverride,
  type SonarActiveRule,
  type SonarGateData,
  type SonarProfileData,
} from './plan';
import type { SonarCondition } from './metrics';

const rule = (key: string, over: Partial<SonarActiveRule> = {}): SonarActiveRule => ({
  key,
  name: `Rule ${key}`,
  language: 'ts',
  defaultSeverity: 'MAJOR',
  severity: 'MAJOR',
  defaultImpacts: [],
  impacts: [],
  paramsCustomised: false,
  ...over,
});
const profile = (over: Partial<SonarProfileData> = {}): SonarProfileData => ({
  key: 'p1',
  name: 'Team TS',
  language: 'ts',
  isDefault: false,
  isBuiltIn: false,
  active: [],
  inactive: [],
  complete: true,
  ...over,
});
/** The shipped table with every curated entry reviewed, as after the user's review. */
const reviewed = loadSonarMapping({
  ...structuredClone(raw),
  rules: raw.rules.map((r) => ({ ...r, reviewed: true })),
});

describe('planProfile (import-sonarqube.md §7)', () => {
  it('turns on reviewed equivalents of active rules and off those the profile leaves off', () => {
    // S3504 and S3776 are also real sonarjs 2.0.4 keys (Phase 8), so each gets a repository row
    // (always reviewed) alongside, or instead of, its curated table target (§6.2).
    const plan = planProfile(
      profile({
        active: [rule('typescript:S3504')],
        inactive: ['typescript:S1143', 'typescript:S3776'],
      }),
      reviewed,
    );
    expect(plan.skip).toBeNull();
    expect(plan.language).toBe('typescript');
    expect(plan.rows).toEqual([
      { ruleKey: 'eslint:no-unsafe-finally', active: false, severityOverride: null },
      { ruleKey: 'eslint:no-var', active: true, severityOverride: null },
      { ruleKey: 'sonarjs:S3504', active: true, severityOverride: null },
      { ruleKey: 'sonarjs:S3776', active: false, severityOverride: null },
    ]);
    expect(plan.stats).toMatchObject({
      active: 1,
      mapped: 1,
      deactivated: 2,
      severityOverrides: 0,
    });
  });

  it('never uses unreviewed entries for profiles, and lists them as pending review', () => {
    // S1143 is curated-table only (not a real sonarjs key), so it stays pending review here.
    const plan = planProfile(profile({ active: [rule('typescript:S1143')] }));
    expect(plan.rows).toEqual([]);
    expect(plan.skip).toBe('no_mapped_rules');
    expect(plan.stats.pendingReview).toEqual(['typescript:S1143']);
  });

  it('keeps overlap targets out of profiles and lists unmapped rules with their names', () => {
    // S108 and S1440 are curated-table only and stay overlap-only (neither is a real sonarjs
    // key); S9999 is in neither source at all.
    const plan = planProfile(
      profile({
        active: [rule('typescript:S108'), rule('typescript:S1440'), rule('typescript:S9999')],
      }),
      reviewed,
    );
    expect(plan.rows).toEqual([]);
    expect(plan.stats.statusOnly).toEqual(['typescript:S108', 'typescript:S1440']);
    expect(plan.stats.unmapped).toEqual([
      { key: 'typescript:S9999', name: 'Rule typescript:S9999' },
    ]);
  });

  it('activates only the equivalent sonarjs target when a curated overlap shares the rule (mixed case)', () => {
    // S1481 is curated as overlap (eslint:no-unused-vars, @typescript-eslint/no-unused-vars) and,
    // since Phase 8, also a real sonarjs key (equivalent, repository). usable() (plan.ts) filters
    // to relation === 'equivalent', so only sonarjs:S1481 becomes a row; the curated overlap
    // targets never do, whatever their review state.
    const js = planProfile(profile({ active: [rule('javascript:S1481')] }), reviewed);
    expect(js.rows).toEqual([{ ruleKey: 'sonarjs:S1481', active: true, severityOverride: null }]);
    expect(js.stats).toMatchObject({ mapped: 1, statusOnly: [], pendingReview: [] });

    const ts = planProfile(profile({ active: [rule('typescript:S1481')] }), reviewed);
    expect(ts.rows).toEqual([{ ruleKey: 'sonarjs:S1481', active: true, severityOverride: null }]);
  });

  it('gives a TypeScript profile the typescript-eslint rule of S1186, plus the shared sonarjs rule', () => {
    // S1186 is also a real sonarjs key (Phase 8), shared by both languages' repository rows.
    const ts = planProfile(profile({ active: [rule('typescript:S1186')] }), reviewed);
    expect(ts.rows.map((r) => r.ruleKey)).toEqual([
      'eslint:@typescript-eslint/no-empty-function',
      'sonarjs:S1186',
    ]);
    const js = planProfile(
      profile({ language: 'js', active: [rule('javascript:S1186', { language: 'js' })] }),
      reviewed,
    );
    expect(js.rows.map((r) => r.ruleKey)).toEqual(['eslint:no-empty-function', 'sonarjs:S1186']);
  });

  it('lets an active rule win over one left off with the same target', () => {
    const mapping = loadSonarMapping({
      ...structuredClone(raw),
      rules: [
        {
          sonar: ['typescript:S1'],
          qualor: ['eslint:x'],
          relation: 'equivalent',
          reviewed: true,
          reason: 'r',
        },
        {
          sonar: ['typescript:S2'],
          qualor: ['eslint:x'],
          relation: 'equivalent',
          reviewed: true,
          reason: 'r',
        },
      ],
    });
    const plan = planProfile(
      profile({ active: [rule('typescript:S2')], inactive: ['typescript:S1'] }),
      mapping,
    );
    expect(plan.rows).toEqual([{ ruleKey: 'eslint:x', active: true, severityOverride: null }]);
    expect(plan.stats.deactivated).toBe(0);
  });

  it('keeps the more severe override when two active rules share a target', () => {
    const mapping = loadSonarMapping({
      ...structuredClone(raw),
      rules: [
        {
          sonar: ['typescript:S1', 'typescript:S2'],
          qualor: ['eslint:x'],
          relation: 'equivalent',
          reviewed: true,
          reason: 'r',
        },
      ],
    });
    const active = [
      rule('typescript:S1', { severity: 'MINOR' }),
      rule('typescript:S2', { severity: 'BLOCKER' }),
    ];
    for (const order of [active, [...active].reverse()]) {
      const plan = planProfile(profile({ active: order }), mapping);
      expect(plan.rows).toEqual([
        { ruleKey: 'eslint:x', active: true, severityOverride: 'blocker' },
      ]);
      expect(plan.stats.severityOverrides).toBe(1);
    }
  });

  it('only overrides a severity the profile changed, and prefers impacts', () => {
    expect(severityOverride(rule('k'))).toBeNull();
    expect(severityOverride(rule('k', { severity: 'CRITICAL' }))).toBe('high');
    expect(
      severityOverride(
        rule('k', {
          defaultImpacts: [{ softwareQuality: 'MAINTAINABILITY', severity: 'MEDIUM' }],
          impacts: [{ softwareQuality: 'MAINTAINABILITY', severity: 'BLOCKER' }],
        }),
      ),
    ).toBe('blocker');
    expect(
      severityOverride(
        rule('k', {
          defaultImpacts: [{ softwareQuality: 'MAINTAINABILITY', severity: 'MEDIUM' }],
          impacts: [{ softwareQuality: 'MAINTAINABILITY', severity: 'MEDIUM' }],
        }),
      ),
    ).toBeNull();
  });

  it('skips unsupported languages, reserved or invalid names, and incompletely read profiles', () => {
    expect(planProfile(profile({ language: 'go' })).skip).toBe('language_unsupported');
    expect(planProfile(profile({ name: 'qualor  WAY' })).skip).toBe('name_reserved');
    expect(planProfile(profile({ name: 'x'.repeat(101) })).skip).toBe('name_invalid');
    expect(planProfile(profile({ name: '   ' })).skip).toBe('name_invalid');
    expect(planProfile(profile({ complete: false }), reviewed).skip).toBe('rules_not_all_read');
  });

  it('gives a C# profile the roslyn row, one to one (§6.1, Phase 8)', () => {
    const plan = planProfile(
      profile({
        language: 'cs',
        active: [rule('csharpsquid:S1481', { language: 'cs' })],
      }),
    );
    expect(plan.language).toBe('csharp');
    expect(plan.skip).toBeNull();
    expect(plan.rows).toEqual([{ ruleKey: 'roslyn:S1481', active: true, severityOverride: null }]);
  });

  it('classifies a Swift profile, all unmapped, and skips it for no mapped rules (plan 8F)', () => {
    const plan = planProfile(
      profile({ language: 'swift', active: [rule('swift:S1481', { language: 'swift' })] }),
    );
    expect(plan.language).toBe('swift');
    expect(plan.skip).toBe('no_mapped_rules');
    expect(plan.rows).toEqual([]);
    expect(plan.stats.unmapped.map((u) => u.key)).toEqual(['swift:S1481']);
  });

  it('never turns off a target whose left-off rule is an unreviewed equivalent', () => {
    const mapping = loadSonarMapping({
      ...structuredClone(raw),
      rules: [
        {
          sonar: ['typescript:S1'],
          qualor: ['eslint:x'],
          relation: 'equivalent',
          reviewed: true,
          reason: 'r',
        },
        {
          sonar: ['typescript:S2'],
          qualor: ['eslint:y'],
          relation: 'equivalent',
          reviewed: false,
          reason: 'r',
        },
      ],
    });
    const plan = planProfile(
      profile({ active: [rule('typescript:S1')], inactive: ['typescript:S2'] }),
      mapping,
    );
    expect(plan.rows).toEqual([{ ruleKey: 'eslint:x', active: true, severityOverride: null }]);
    expect(plan.stats.deactivated).toBe(0);
  });

  it('classifies the active rules of a skipped profile too, so its counts add up', () => {
    // S1143 (curated only, unreviewed) -> pending review; S1440 (curated only, overlap) ->
    // status only; S9999 (neither source) -> unmapped; external_eslint_repo:no-var (repository,
    // always reviewed) -> mapped.
    const active = [
      rule('typescript:S1143'),
      rule('typescript:S1440'),
      rule('typescript:S9999'),
      rule('external_eslint_repo:no-var'),
    ];
    const add = (p: ReturnType<typeof planProfile>) =>
      p.stats.mapped +
      p.stats.pendingReview.length +
      p.stats.statusOnly.length +
      p.stats.unmapped.length;
    for (const over of [
      { name: 'Qualor way' },
      { name: 'x'.repeat(101) },
      { complete: false },
      {},
    ] satisfies Partial<SonarProfileData>[]) {
      const p = planProfile(profile({ active, ...over }));
      expect(p.stats.active, JSON.stringify(over)).toBe(4);
      expect(add(p), JSON.stringify(over)).toBe(4);
      expect(p.stats).toMatchObject({
        mapped: 1,
        pendingReview: ['typescript:S1143'],
        statusOnly: ['typescript:S1440'],
        unmapped: [{ key: 'typescript:S9999', name: 'Rule typescript:S9999' }],
      });
      if (p.skip !== null) expect(p.rows).toEqual([]);
    }
    // A language Qualor does not analyse is not classified: nothing of it is counted.
    const go = planProfile(profile({ language: 'go', active }));
    expect(go.skip).toBe('language_unsupported');
    expect(add(go)).toBe(0);
    expect(go.stats.active).toBe(0);
  });

  it('lists customised parameters as not imported', () => {
    const plan = planProfile(
      profile({ active: [rule('typescript:S3504', { paramsCustomised: true })] }),
      reviewed,
    );
    expect(plan.stats.parametersNotImported).toEqual(['typescript:S3504']);
  });

  it('counts a mapped rule the bundled configuration does not run as mapped, not run', () => {
    // S1192 is off in eslint-plugin-sonarjs's recommended config; S1871 is on. csharpsquid:S107
    // is disabled by default in SonarAnalyzer.CSharp; S1481 is enabled.
    const ts = planProfile(
      profile({ active: [rule('typescript:S1192'), rule('typescript:S1871')] }),
      reviewed,
    );
    expect(ts.stats.mapped).toBe(2);
    expect(ts.stats.mappedNotRun).toEqual(['typescript:S1192']);
    expect(ts.rows.map((r) => r.ruleKey).sort()).toEqual(['sonarjs:S1192', 'sonarjs:S1871']);
    const cs = planProfile(
      profile({
        language: 'cs',
        active: [
          rule('csharpsquid:S107', { language: 'cs' }),
          rule('csharpsquid:S1481', { language: 'cs' }),
        ],
      }),
    );
    expect(cs.stats.mappedNotRun).toEqual(['csharpsquid:S107']);
    // A rule mapped to the project's own ESLint is assumed to run.
    const eslint = planProfile(
      profile({ active: [rule('external_eslint_repo:no-console')] }),
      reviewed,
    );
    expect(eslint.stats.mapped).toBe(1);
    expect(eslint.stats.mappedNotRun).toEqual([]);
  });

  it('keeps java rows to PMD and SpotBugs targets, and other engines to statuses', () => {
    const java = (key: string) => rule(key, { language: 'java' });
    const plan = planProfile(
      profile({
        language: 'java',
        active: [
          java('java:S106'),
          java('pmd:UnusedLocalVariable'),
          java('findbugs:NP_NULL_ON_SOME_PATH'),
          java('java:S1481'),
        ],
      }),
      reviewed,
    );
    expect(plan.rows.map((r) => r.ruleKey)).toEqual([
      'pmd:SystemPrintln',
      'pmd:UnusedLocalVariable',
      'spotbugs:NP_NULL_ON_SOME_PATH',
    ]);
    expect(plan.stats.statusOnly).toEqual(['java:S1481']);
    const ts = planProfile(profile({ active: [rule('findbugs:NP_NULL_ON_SOME_PATH')] }), reviewed);
    expect(ts.stats.statusOnly).toEqual(['findbugs:NP_NULL_ON_SOME_PATH']);
    expect(ts.skip).toBe('no_mapped_rules');
  });

  it('plans a py profile: external_ruff rows and reviewed equivalent python rows activate Ruff rules; overlap rows are status only', () => {
    // The curated python: rows are reviewed (plan 8C follow-up, 2026-10-01). python:S1716
    // (equivalent to ruff:F701 and ruff:F702) activates both; python:S1128 (overlap with
    // ruff:F401) stays status only, and external_ruff:F401 still activates ruff:F401.
    // external_ruff:ERA001 is outside qualor-default, so it lands in mappedNotRun.
    const plan = planProfile(
      profile({
        language: 'py',
        active: [
          rule('external_ruff:F401', { language: 'py' }),
          rule('external_ruff:ERA001', { language: 'py' }),
          rule('python:S1716', { language: 'py' }),
          rule('python:S1128', { language: 'py' }),
          rule('python:S9999', { language: 'py' }),
        ],
      }),
    );
    expect(plan.skip).toBeNull();
    expect(plan.rows).toEqual([
      { ruleKey: 'ruff:ERA001', active: true, severityOverride: null },
      { ruleKey: 'ruff:F401', active: true, severityOverride: null },
      { ruleKey: 'ruff:F701', active: true, severityOverride: null },
      { ruleKey: 'ruff:F702', active: true, severityOverride: null },
    ]);
    expect(plan.stats.mappedNotRun).toEqual(['external_ruff:ERA001']);
    expect(plan.stats.statusOnly).toEqual(['python:S1128']);
    expect(plan.stats.pendingReview).toEqual([]);
    expect(plan.stats.unmapped).toEqual([expect.objectContaining({ key: 'python:S9999' })]);
  });

  it('plans a ruby profile: reviewed equivalent ruby rows and external_rubocop rows activate cops; overlap rows are status only (plan 9B)', () => {
    // Rulings B9-11/B9-12: external_rubocop:Lint/UselessAssignment activates a cop qualor-default
    // runs; ruby:S1066 → Style/SoleNestedConditional is equivalent but outside qualor-default
    // (mapped, not run); ruby:S8423 and ruby:S7916 are overlaps, so status only.
    const ruby = (key: string) => rule(key, { language: 'ruby' });
    const plan = planProfile(
      profile({
        language: 'ruby',
        active: [
          ruby('ruby:S1066'),
          ruby('ruby:S8423'),
          ruby('ruby:S7916'),
          ruby('external_rubocop:Lint/UselessAssignment'),
          ruby('ruby:S9999'),
        ],
      }),
    );
    expect(plan.skip).toBeNull();
    expect(plan.language).toBe('ruby');
    expect(plan.rows).toEqual([
      { ruleKey: 'rubocop:Lint/UselessAssignment', active: true, severityOverride: null },
      { ruleKey: 'rubocop:Style/SoleNestedConditional', active: true, severityOverride: null },
    ]);
    expect(plan.stats.mappedNotRun).toEqual(['ruby:S1066']);
    expect(plan.stats.pendingReview).toEqual([]);
    expect(plan.stats.statusOnly).toEqual(['ruby:S8423', 'ruby:S7916']);
    expect(plan.stats.unmapped).toEqual([expect.objectContaining({ key: 'ruby:S9999' })]);
  });

  it('keeps an unreviewed python row out of the profile and lists it as pending review', () => {
    const mapping = loadSonarMapping({
      ...structuredClone(raw),
      rules: [
        ...raw.rules,
        {
          sonar: ['python:S0001'],
          qualor: ['ruff:F841'],
          relation: 'equivalent',
          reviewed: false,
          reason: 'Synthetic row for the unreviewed path.',
        },
      ],
    });
    const plan = planProfile(
      profile({ language: 'py', active: [rule('python:S0001', { language: 'py' })] }),
      mapping,
    );
    expect(plan.rows).toEqual([]);
    expect(plan.skip).toBe('no_mapped_rules');
    expect(plan.stats.pendingReview).toEqual(['python:S0001']);
  });
});

const gate = (conditions: SonarCondition[]): SonarGateData => ({
  name: 'Mixed',
  isDefault: false,
  isBuiltIn: false,
  conditions,
});

describe('planGate (import-sonarqube.md §8)', () => {
  it('maps what it can and keeps the rest as unmapped', () => {
    const plan = planGate({
      name: 'Sonar way',
      isDefault: true,
      isBuiltIn: true,
      conditions: [
        { metric: 'new_violations', op: 'GT', error: '0' },
        { metric: 'new_security_hotspots_reviewed', op: 'LT', error: '100' },
      ],
    });
    expect(plan.skip).toBeNull();
    expect(mappedConditions(plan)).toEqual([
      { metric: 'new_issues', operator: 'gt', threshold: 0 },
    ]);
    expect(plan.conditions[1]?.mapping).toEqual({ ok: false, reason: 'metric' });
  });

  it('skips a gate with nothing mapped, and reserved names', () => {
    expect(planGate(gate([])).skip).toBe('no_mapped_conditions');
    expect(planGate(gate([{ metric: 'coverage', op: 'EQ', error: '1' }])).skip).toBe(
      'no_mapped_conditions',
    );
    expect(isReservedName(' Qualor Way ')).toBe(true);
    expect(
      planGate({
        name: 'Qualor way',
        isDefault: false,
        isBuiltIn: false,
        conditions: [{ metric: 'coverage', op: 'LT', error: '1' }],
      }).skip,
    ).toBe('name_reserved');
  });

  it('reports a condition with an unknown operator as unmapped, keeping the others', () => {
    const plan = planGate(
      gate([
        { metric: 'new_violations', op: 'NE', error: '0' },
        { metric: 'new_coverage', op: 'LT', error: '80' },
      ]),
    );
    expect(plan.conditions[0]?.mapping).toEqual({ ok: false, reason: 'operator' });
    expect(mappedConditions(plan)).toEqual([
      { metric: 'new_coverage', operator: 'lt', threshold: 80 },
    ]);
  });

  /** A gate built across SonarQube's legacy and MQR modes: pairs that meet on one Qualor metric. */
  const mixed: SonarCondition[] = [
    { metric: 'violations', op: 'GT', error: '10' },
    { metric: 'open_issues', op: 'GT', error: '5' },
    { metric: 'bugs', op: 'GT', error: '0' },
    { metric: 'software_quality_reliability_issues', op: 'GT', error: '0' },
    { metric: 'reliability_rating', op: 'GT', error: '1' },
    { metric: 'software_quality_reliability_rating', op: 'GT', error: '2' },
    { metric: 'security_rating', op: 'LT', error: '3' },
    { metric: 'software_quality_security_rating', op: 'LT', error: '4' },
    { metric: 'new_violations', op: 'GT', error: '0' },
    { metric: 'new_coverage', op: 'LT', error: '80' },
    { metric: 'coverage', op: 'LT', error: '70' },
  ];
  const expected = [
    { metric: 'coverage', operator: 'lt', threshold: 70 },
    { metric: 'issues', operator: 'gt', threshold: 5 },
    { metric: 'new_coverage', operator: 'lt', threshold: 80 },
    { metric: 'new_issues', operator: 'gt', threshold: 0 },
    { metric: 'reliability_issues', operator: 'gt', threshold: 0 },
    { metric: 'reliability_rating', operator: 'gt', threshold: 1 },
    { metric: 'security_rating', operator: 'lt', threshold: 4 },
  ];
  const duplicates = [
    'bugs',
    'software_quality_reliability_rating',
    'security_rating',
    'violations',
  ].sort();

  it.each([
    ['as listed', mixed],
    ['reversed', [...mixed].reverse()],
  ])(
    'keeps the stricter of two conditions on one metric and reports the other (%s)',
    (_, conditions) => {
      const plan = planGate(gate(conditions));
      expect(plan.skip).toBeNull();
      const got = mappedConditions(plan).sort((a, b) => (a.metric < b.metric ? -1 : 1));
      expect(got).toEqual(expected);
      const dropped = plan.conditions
        .filter((c) => !c.mapping.ok && c.mapping.reason === 'duplicate_metric')
        .map((c) => c.sonar.metric)
        .sort();
      expect(dropped).toEqual(duplicates);
      expect(plan.conditions).toHaveLength(mixed.length);
      const kept = plan.conditions.find(
        (c) => c.sonar.metric === 'software_quality_reliability_issues',
      );
      expect(kept?.mapping).toMatchObject({ ok: true, approximate: false });
    },
  );

  it('keeps the first of two conditions on one metric with different operators', () => {
    const plan = planGate(
      gate([
        { metric: 'coverage', op: 'LT', error: '80' },
        { metric: 'line_coverage', op: 'LT', error: '80' },
        { metric: 'coverage', op: 'GT', error: '99' },
      ]),
    );
    expect(mappedConditions(plan)).toEqual([
      { metric: 'coverage', operator: 'lt', threshold: 80 },
      { metric: 'line_coverage', operator: 'lt', threshold: 80 },
    ]);
    expect(plan.conditions[2]?.mapping).toEqual({
      ok: false,
      reason: 'operator_conflict',
      qualorMetric: 'coverage',
    });
  });

  it('names the Qualor metric a duplicate condition collided on', () => {
    const plan = planGate(gate(mixed));
    const byMetric = new Map(plan.conditions.map((c) => [c.sonar.metric, c.mapping]));
    expect(byMetric.get('violations')).toEqual({
      ok: false,
      reason: 'duplicate_metric',
      qualorMetric: 'issues',
    });
    expect(byMetric.get('bugs')).toEqual({
      ok: false,
      reason: 'duplicate_metric',
      qualorMetric: 'reliability_issues',
    });
  });

  it('breaks a tie of two exact conditions by the smaller SonarQube metric key', () => {
    const tie: SonarCondition[] = [
      { metric: 'software_quality_blocker_issues', op: 'GT', error: '0' },
      { metric: 'blocker_violations', op: 'GT', error: '0' },
    ];
    for (const order of [tie, [...tie].reverse()]) {
      const plan = planGate(gate(order));
      const kept = plan.conditions.filter((c) => c.mapping.ok).map((c) => c.sonar.metric);
      expect(kept).toEqual(['blocker_violations']);
      expect(
        plan.conditions.find((c) => c.sonar.metric === 'software_quality_blocker_issues')?.mapping,
      ).toEqual({ ok: false, reason: 'duplicate_metric', qualorMetric: 'blocker_issues' });
    }
  });

  it('never sends one metric twice, whatever the gate holds', () => {
    const plan = planGate(gate([...mixed, ...mixed]));
    const metrics = mappedConditions(plan).map((c) => c.metric);
    expect(new Set(metrics).size).toBe(metrics.length);
    expect(metrics).toHaveLength(expected.length);
  });
});

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
    ]);
    expect(plan.stats).toMatchObject({
      active: 1,
      mapped: 1,
      deactivated: 1,
      severityOverrides: 0,
    });
  });

  it('never uses unreviewed entries for profiles, and lists them as pending review', () => {
    const plan = planProfile(profile({ active: [rule('typescript:S3504')] }));
    expect(plan.rows).toEqual([]);
    expect(plan.skip).toBe('no_mapped_rules');
    expect(plan.stats.pendingReview).toEqual(['typescript:S3504']);
  });

  it('keeps overlap targets out of profiles and lists unmapped rules with their names', () => {
    const plan = planProfile(
      profile({
        active: [rule('typescript:S1481'), rule('typescript:S1440'), rule('typescript:S3776')],
      }),
      reviewed,
    );
    expect(plan.rows).toEqual([]);
    expect(plan.stats.statusOnly).toEqual(['typescript:S1481', 'typescript:S1440']);
    expect(plan.stats.unmapped).toEqual([
      { key: 'typescript:S3776', name: 'Rule typescript:S3776' },
    ]);
  });

  it('gives a TypeScript profile the typescript-eslint rule of S1186 only', () => {
    const ts = planProfile(profile({ active: [rule('typescript:S1186')] }), reviewed);
    expect(ts.rows.map((r) => r.ruleKey)).toEqual(['eslint:@typescript-eslint/no-empty-function']);
    const js = planProfile(
      profile({ language: 'js', active: [rule('javascript:S1186', { language: 'js' })] }),
      reviewed,
    );
    expect(js.rows.map((r) => r.ruleKey)).toEqual(['eslint:no-empty-function']);
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
    expect(planProfile(profile({ language: 'py' })).skip).toBe('language_unsupported');
    expect(planProfile(profile({ language: 'cs' })).skip).toBe('language_unsupported');
    expect(planProfile(profile({ name: 'qualor  WAY' })).skip).toBe('name_reserved');
    expect(planProfile(profile({ name: 'x'.repeat(101) })).skip).toBe('name_invalid');
    expect(planProfile(profile({ name: '   ' })).skip).toBe('name_invalid');
    expect(planProfile(profile({ complete: false }), reviewed).skip).toBe('rules_not_all_read');
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
    const active = [
      rule('typescript:S3504'),
      rule('typescript:S1440'),
      rule('typescript:S3776'),
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
        pendingReview: ['typescript:S3504'],
        statusOnly: ['typescript:S1440'],
        unmapped: [{ key: 'typescript:S3776', name: 'Rule typescript:S3776' }],
      });
      if (p.skip !== null) expect(p.rows).toEqual([]);
    }
    // A language Qualor does not analyse is not classified: nothing of it is counted.
    const py = planProfile(profile({ language: 'py', active }));
    expect(py.skip).toBe('language_unsupported');
    expect(add(py)).toBe(0);
    expect(py.stats.active).toBe(0);
  });

  it('lists customised parameters as not imported', () => {
    const plan = planProfile(
      profile({ active: [rule('typescript:S3504', { paramsCustomised: true })] }),
      reviewed,
    );
    expect(plan.stats.parametersNotImported).toEqual(['typescript:S3504']);
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

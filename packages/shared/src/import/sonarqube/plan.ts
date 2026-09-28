import type { Severity } from '../../report/taxonomy';
import type { ImpactSeverity, LegacySeverity, SonarImpact } from './api';
import { mapGateCondition, type ConditionMapping, type SonarCondition } from './metrics';
import { engineOf, SONAR_MAPPING, type ProfileLanguage, type SonarMapping } from './rules';

export interface SonarActiveRule {
  key: string;
  name: string;
  language: string;
  defaultSeverity: LegacySeverity | null;
  severity: LegacySeverity | null;
  defaultImpacts: readonly SonarImpact[];
  impacts: readonly SonarImpact[];
  paramsCustomised: boolean;
}

export interface SonarProfileData {
  key: string;
  name: string;
  language: string;
  isDefault: boolean;
  isBuiltIn: boolean;
  active: SonarActiveRule[];
  inactive: string[];
  /** False when not every active rule could be read (the 10 000 window, spec §5.2). */
  complete: boolean;
}

export interface SonarGateData {
  name: string;
  isDefault: boolean;
  isBuiltIn: boolean;
  conditions: SonarCondition[];
}

export interface SonarProjectData {
  key: string;
  name: string;
  mainBranch: string;
  profiles: { language: string; profileKey: string; isDefault: boolean }[];
  gate: { name: string; isDefault: boolean } | null;
}

export interface PlannedRow {
  ruleKey: string;
  active: boolean;
  severityOverride: Severity | null;
}

export type ProfileSkip =
  | 'language_unsupported'
  | 'name_invalid'
  | 'name_reserved'
  | 'no_mapped_rules'
  | 'rules_not_all_read';

export interface ProfileStats {
  active: number;
  mapped: number;
  deactivated: number;
  severityOverrides: number;
  pendingReview: string[];
  statusOnly: string[];
  unmapped: { key: string; name: string }[];
  parametersNotImported: string[];
}

export interface PlannedProfile {
  sonarKey: string;
  name: string;
  sonarLanguage: string;
  language: ProfileLanguage | null;
  isDefault: boolean;
  skip: ProfileSkip | null;
  rows: PlannedRow[];
  stats: ProfileStats;
}

export type GateSkip = 'name_invalid' | 'name_reserved' | 'no_mapped_conditions';

/**
 * A condition's mapping in a plan: `mapGateCondition`'s, or one that lost to another condition of
 * the gate mapped to the same Qualor metric and scope (spec §8.2), `qualorMetric` naming it:
 * `duplicate_metric` when the other is stricter, `operator_conflict` when the two point in
 * opposite directions (neither is stricter; the first one stays).
 */
export type PlannedConditionMapping =
  | ConditionMapping
  | { ok: false; reason: 'duplicate_metric' | 'operator_conflict'; qualorMetric: string };

export interface PlannedGate {
  name: string;
  isDefault: boolean;
  skip: GateSkip | null;
  conditions: { sonar: SonarCondition; mapping: PlannedConditionMapping }[];
}

type Mapped = Extract<ConditionMapping, { ok: true }>;

const LEGACY: Record<LegacySeverity, Severity> = {
  BLOCKER: 'blocker',
  CRITICAL: 'high',
  MAJOR: 'medium',
  MINOR: 'low',
  INFO: 'info',
};
const IMPACT: Record<ImpactSeverity, Severity> = {
  BLOCKER: 'blocker',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
};
const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, blocker: 4 };

function worst(a: Severity | null, b: Severity | null): Severity | null {
  if (a === null) return b;
  if (b === null) return a;
  return RANK[a] >= RANK[b] ? a : b;
}

function maxImpact(impacts: readonly SonarImpact[]): Severity | null {
  return impacts.reduce<Severity | null>((acc, i) => worst(acc, IMPACT[i.severity]), null);
}

/** Spec §7.3: an override only where the profile changed the rule's severity. */
export function severityOverride(r: SonarActiveRule): Severity | null {
  const legacyChanged =
    r.severity !== null && r.defaultSeverity !== null && r.severity !== r.defaultSeverity;
  const active = maxImpact(r.impacts);
  const byDefault = maxImpact(r.defaultImpacts);
  const impactChanged = active !== null && byDefault !== null && active !== byDefault;
  if (!legacyChanged && !impactChanged) return null;
  if (active !== null) return active;
  return r.severity === null ? null : LEGACY[r.severity];
}

/** api.md §3: "Qualor way" is reserved in any case or spacing. */
export function isReservedName(name: string): boolean {
  return name.toLowerCase().replace(/\s+/g, '') === 'qualorway';
}

function nameProblem(name: string): 'name_invalid' | 'name_reserved' | null {
  const trimmed = name.trim();
  if (trimmed === '' || trimmed.length > 100 || trimmed.includes('\u0000')) return 'name_invalid';
  return isReservedName(trimmed) ? 'name_reserved' : null;
}

export function planProfile(
  p: SonarProfileData,
  mapping: SonarMapping = SONAR_MAPPING,
): PlannedProfile {
  const lang = mapping.language(p.language);
  const stats: ProfileStats = {
    // Rules of a language Qualor does not analyse are not read, nor counted (spec §7.1).
    active: lang === null ? 0 : p.active.length,
    mapped: 0,
    deactivated: 0,
    severityOverrides: 0,
    pendingReview: [],
    statusOnly: [],
    unmapped: [],
    parametersNotImported: [],
  };
  const planned = (skip: ProfileSkip | null, rows: PlannedRow[]): PlannedProfile => ({
    sonarKey: p.key,
    name: p.name.trim(),
    sonarLanguage: p.language,
    language: lang?.language ?? null,
    isDefault: p.isDefault,
    skip,
    rows,
    stats,
  });
  // A language Qualor does not analyse is not classified: none of its rules is counted.
  if (lang === null) return planned('language_unsupported', []);

  // Every other profile is classified first, skipped or not, so that its counts add up
  // (active = mapped + pending review + status only + unmapped).
  const usable = (key: string) =>
    mapping
      .targets(key)
      .filter(
        (t) =>
          t.relation === 'equivalent' &&
          (lang.engines as readonly string[]).includes(engineOf(t.key)),
      );
  const rows = new Map<string, PlannedRow>();
  for (const r of p.active) {
    const targets = mapping.targets(r.key);
    if (targets.length === 0) {
      stats.unmapped.push({ key: r.key, name: r.name });
      continue;
    }
    const candidates = usable(r.key);
    const reviewed = candidates.filter((t) => t.reviewed);
    if (reviewed.length === 0) {
      (candidates.length > 0 ? stats.pendingReview : stats.statusOnly).push(r.key);
      continue;
    }
    stats.mapped += 1;
    if (r.paramsCustomised) stats.parametersNotImported.push(r.key);
    const override = severityOverride(r);
    for (const t of reviewed) {
      const prev = rows.get(t.key);
      rows.set(t.key, {
        ruleKey: t.key,
        active: true,
        severityOverride: prev?.active === true ? worst(prev.severityOverride, override) : override,
      });
    }
  }
  for (const key of p.inactive) {
    for (const t of usable(key).filter((x) => x.reviewed)) {
      if (!rows.has(t.key))
        rows.set(t.key, { ruleKey: t.key, active: false, severityOverride: null });
    }
  }
  const sorted = [...rows.values()].sort((a, b) => (a.ruleKey < b.ruleKey ? -1 : 1));
  stats.deactivated = sorted.filter((r) => !r.active).length;
  stats.severityOverrides = sorted.filter((r) => r.active && r.severityOverride !== null).length;
  const nameSkip = nameProblem(p.name);
  if (nameSkip !== null) return planned(nameSkip, []);
  if (!p.complete) return planned('rules_not_all_read', []);
  return planned(sorted.length === 0 ? 'no_mapped_rules' : null, sorted);
}

/**
 * Whether `b` should replace `a`, two conditions with one operator on one Qualor metric: the
 * stricter threshold (the lower for `gt`, the higher for `lt`); on a tie the exact one over an
 * approximate one, then the smaller SonarQube metric key, so the result does not depend on the
 * gate's order. (With different operators neither is stricter: `operator_conflict`.)
 */
function replaces(a: { sonar: SonarCondition; m: Mapped }, b: typeof a): boolean {
  if (a.m.threshold !== b.m.threshold) {
    return a.m.operator === 'gt' ? b.m.threshold < a.m.threshold : b.m.threshold > a.m.threshold;
  }
  if (a.m.approximate !== b.m.approximate) return a.m.approximate;
  return b.sonar.metric < a.sonar.metric;
}

const lost = (reason: 'duplicate_metric' | 'operator_conflict', qualorMetric: string) =>
  ({ ok: false, reason, qualorMetric }) as const;

export function planGate(g: SonarGateData): PlannedGate {
  const conditions: PlannedGate['conditions'] = g.conditions.map((sonar) => ({
    sonar,
    mapping: mapGateCondition(sonar),
  }));
  // One condition per metric and scope (409 CONDITION_EXISTS): keep the stricter, report the other.
  const kept = new Map<string, { index: number; sonar: SonarCondition; m: Mapped }>();
  conditions.forEach(({ sonar, mapping }, index) => {
    if (!mapping.ok) return;
    const next = { index, sonar, m: mapping };
    const prev = kept.get(mapping.metric);
    if (prev === undefined) {
      kept.set(mapping.metric, next);
    } else if (prev.m.operator !== next.m.operator) {
      conditions[index] = { sonar, mapping: lost('operator_conflict', mapping.metric) };
    } else if (replaces(prev, next)) {
      conditions[prev.index] = {
        sonar: prev.sonar,
        mapping: lost('duplicate_metric', mapping.metric),
      };
      kept.set(mapping.metric, next);
    } else {
      conditions[index] = { sonar, mapping: lost('duplicate_metric', mapping.metric) };
    }
  });
  const nameSkip = nameProblem(g.name);
  const anyMapped = conditions.some((c) => c.mapping.ok);
  return {
    name: g.name.trim(),
    isDefault: g.isDefault,
    skip: nameSkip ?? (anyMapped ? null : 'no_mapped_conditions'),
    conditions,
  };
}

/**
 * The conditions a gate gets, in the gate's order. `planGate` leaves at most one mapped condition
 * per metric (the others are `duplicate_metric`); the map only guards a plan built elsewhere.
 */
export function mappedConditions(
  g: PlannedGate,
): { metric: string; operator: 'gt' | 'lt'; threshold: number }[] {
  const out = new Map<string, { metric: string; operator: 'gt' | 'lt'; threshold: number }>();
  for (const c of g.conditions) {
    if (c.mapping.ok && !out.has(c.mapping.metric)) {
      const { metric, operator, threshold } = c.mapping;
      out.set(metric, { metric, operator, threshold });
    }
  }
  return [...out.values()];
}

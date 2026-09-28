import {
  mappedConditions,
  type PlannedGate,
  type PlannedProfile,
  type PlannedRow,
  type SonarProjectData,
} from '@qualor/shared';
import { CliError, EXIT } from '../errors';
import { UnreachableError } from '../server/http';
import {
  QualorApiError,
  type QualorApi,
  type QualorProject,
  type UnknownRules,
} from './qualor-api';

export type ObjectOutcome =
  | 'created'
  | 'would_create'
  | 'updated'
  | 'would_update'
  | 'unchanged'
  | 'conflict'
  | 'skipped'
  | 'failed';

export interface ApplyOptions {
  dryRun: boolean;
  overwrite: boolean;
  setDefaults: boolean;
  createProjects: boolean;
}
/**
 * `--set-defaults` (spec §9): `set` when the import made the object the organisation's default,
 * `would_set` when a dry run would have, `null` otherwise (not asked, not SonarQube's default,
 * already the default, or the object was not imported).
 */
export type DefaultChange = 'set' | 'would_set' | null;
export interface ProfileResult {
  planned: PlannedProfile;
  outcome: ObjectOutcome;
  reason: string | null;
  qualorProfileId: string | null;
  defaultChange: DefaultChange;
}
export interface GateResult {
  planned: PlannedGate;
  outcome: ObjectOutcome;
  reason: string | null;
  qualorGateId: string | null;
  defaultChange: DefaultChange;
}
export interface AssignmentResult {
  outcome: 'assigned' | 'would_assign' | 'unchanged' | 'conflict' | 'skipped' | 'failed';
  reason: string | null;
}
export interface ProjectResult {
  sonar: SonarProjectData;
  outcome: 'found' | 'created' | 'would_create' | 'missing' | 'key_invalid' | 'failed';
  reason: string | null;
  qualorProjectId: string | null;
  profiles: (AssignmentResult & { language: string; profile: string })[];
  gate: (AssignmentResult & { gate: string }) | null;
}

/** data-model.md §4.2. */
const QUALOR_PROJECT_KEY = /^[A-Za-z0-9._\-/:]{1,255}$/;
/** Outcomes whose Qualor object stands for the SonarQube one (it can be assigned). */
const USED = new Set<ObjectOutcome>([
  'created',
  'would_create',
  'updated',
  'would_update',
  'unchanged',
]);
/** every imported profile activates the rules it has no row for. */
const UNKNOWN_RULES: UnknownRules = 'activate';

/**
 * Failures no later request can escape stop the whole import (spec §13): authentication (401,
 * any 403 including PASSWORD_CHANGE_REQUIRED) and an unreachable Qualor (after the client's
 * retries). The object they interrupted is recorded `failed` first (ruling S13: the partial
 * report names it).
 */
function fatal(err: unknown): boolean {
  return (err instanceof CliError && err.exitCode === EXIT.AUTH) || err instanceof UnreachableError;
}

/** A failure as a bounded reason. */
function failure(err: unknown): string {
  return (err instanceof Error ? err.message : 'unknown error').slice(0, 500);
}

/**
 * Spec §13: a created object whose later steps failed, or an object whose `--overwrite` update
 * failed part way, is completed by a rerun with --overwrite.
 */
const HALF_DONE = '; it was created in part: run the import again with --overwrite to complete it';
const HALF_UPDATED =
  '; it was updated in part: run the import again with --overwrite to complete it';
const partly = (created: boolean, updating: boolean) =>
  created ? HALF_DONE : updating ? HALF_UPDATED : '';

/** Why an assignment failed with the object it assigns. */
const dependency = (reason: string | null) =>
  `the object to assign failed in Qualor: ${reason ?? 'unknown error'}`.slice(0, 500);

/** `text` cut to `max` UTF-16 units without splitting a surrogate pair. */
export function cutName(text: string, max: number): string {
  if (text.length <= max) return text;
  const code = text.charCodeAt(max - 1);
  return text.slice(0, code >= 0xd800 && code <= 0xdbff ? max - 1 : max);
}

const rowKey = (r: PlannedRow) =>
  `${r.ruleKey}\u0000${String(r.active)}\u0000${r.severityOverride ?? ''}`;
function sameRows(a: readonly PlannedRow[], b: readonly PlannedRow[]): boolean {
  const x = a.map(rowKey).sort();
  const y = b.map(rowKey).sort();
  return x.length === y.length && x.every((k, n) => k === y[n]);
}

/**
 * Spec §7, §13: each planned profile by `(organisation, language, name)`. Created with
 * `unknownRules: activate` and its rows; an existing one whose own rows and `unknownRules` are
 * the plan's is `unchanged`, any other is a `conflict`, or with `--overwrite` made equal.
 */
export async function applyProfiles(
  api: QualorApi,
  orgId: string,
  planned: readonly PlannedProfile[],
  o: ApplyOptions,
  out: ProfileResult[] = [],
): Promise<ProfileResult[]> {
  // Listed only when a profile needs it; a list that fails fails those profiles, not the run.
  let existing: Awaited<ReturnType<QualorApi['profiles']>> = [];
  let listFailed: string | null = null;
  if (planned.some((p) => p.skip === null && p.language !== null)) {
    try {
      existing = await api.profiles(orgId);
    } catch (err) {
      if (fatal(err)) throw err;
      listFailed = `cannot list the organisation's profiles: ${failure(err)}`;
    }
  }
  for (const p of planned) {
    let defaultChange: DefaultChange = null;
    const done = (outcome: ObjectOutcome, reason: string | null, id: string | null) =>
      out.push({ planned: p, outcome, reason, qualorProfileId: id, defaultChange });
    const wantsDefault = o.setDefaults && p.isDefault;
    if (p.skip !== null || p.language === null) {
      done('skipped', p.skip ?? 'language_unsupported', null);
      continue;
    }
    if (listFailed !== null) {
      done('failed', listFailed, null);
      continue;
    }
    const language = p.language;
    const same = existing.filter((x) => x.language === language && x.name === p.name);
    if (same.some((x) => x.isBuiltin)) {
      done('skipped', 'name_reserved', null);
      continue;
    }
    // Spec §13: a profile that inherits shows rows it does not own; making its own rows the plan
    // would still leave the parent's rows in force, so it can never equal the plan.
    const inheriting = same.find((x) => x.parentId !== null);
    if (inheriting !== undefined) {
      done(
        'conflict',
        'a Qualor profile of this name inherits from another profile; rename or detach it',
        inheriting.id,
      );
      continue;
    }
    let id: string | null = null;
    let created = false;
    let updating = false;
    try {
      const found = same[0];
      if (found === undefined) {
        if (o.dryRun) {
          if (wantsDefault) defaultChange = 'would_set';
          done('would_create', null, null);
          continue;
        }
        const made = await api.createProfile(orgId, p.name, language);
        id = made.id;
        created = true;
        // Explicit, never the database default.
        await api.setProfileUnknownRules(made.id, UNKNOWN_RULES);
        for (const row of p.rows) await api.setProfileRule(made.id, row);
        if (wantsDefault) {
          await api.setDefaultProfile(made.id);
          defaultChange = 'set';
        }
        done('created', null, made.id);
        continue;
      }
      id = found.id;
      const rows = await api.profileRows(found.id);
      const rowsEqual = sameRows(rows, p.rows);
      const unknownEqual = found.unknownRules === UNKNOWN_RULES;
      let outcome: ObjectOutcome = 'unchanged';
      if (!rowsEqual || !unknownEqual) {
        if (!o.overwrite) {
          done(
            'conflict',
            rowsEqual
              ? 'a Qualor profile of this name ignores unknown rules; --overwrite makes it activate them'
              : 'a Qualor profile of this name has other rules; --overwrite replaces them',
            found.id,
          );
          continue;
        }
        outcome = o.dryRun ? 'would_update' : 'updated';
        if (!o.dryRun) {
          updating = true;
          if (!unknownEqual) await api.setProfileUnknownRules(found.id, UNKNOWN_RULES);
          const wanted = new Set(p.rows.map((r) => r.ruleKey));
          const current = new Map(rows.map((r) => [r.ruleKey, r]));
          for (const r of rows) {
            if (!wanted.has(r.ruleKey)) await api.deleteProfileRule(found.id, r.ruleKey);
          }
          for (const r of p.rows) {
            const c = current.get(r.ruleKey);
            if (c === undefined || rowKey(c) !== rowKey(r)) await api.setProfileRule(found.id, r);
          }
        }
      }
      if (wantsDefault && !found.isDefault) {
        if (o.dryRun) defaultChange = 'would_set';
        else {
          await api.setDefaultProfile(found.id);
          defaultChange = 'set';
        }
      }
      done(outcome, null, found.id);
    } catch (err) {
      done('failed', `${failure(err)}${partly(created, updating)}`, id);
      if (fatal(err)) throw err;
    }
  }
  return out;
}

const condKey = (c: { metric: string; operator: string; threshold: number }) =>
  `${c.metric}\u0000${c.operator}\u0000${String(c.threshold)}`;

/**
 * Spec §8, §13: each planned gate by `(organisation, name)`. Created with its mapped conditions;
 * an existing one with the same conditions is `unchanged`, any other a `conflict`, or with
 * `--overwrite` made equal; two gates of that name are `name_ambiguous`.
 */
export async function applyGates(
  api: QualorApi,
  orgId: string,
  planned: readonly PlannedGate[],
  o: ApplyOptions,
  out: GateResult[] = [],
): Promise<GateResult[]> {
  // Listed only when a gate needs it; a list that fails fails those gates, not the run.
  let existing: Awaited<ReturnType<QualorApi['gates']>> = [];
  let listFailed: string | null = null;
  if (planned.some((g) => g.skip === null)) {
    try {
      existing = await api.gates(orgId);
    } catch (err) {
      if (fatal(err)) throw err;
      listFailed = `cannot list the organisation's gates: ${failure(err)}`;
    }
  }
  for (const g of planned) {
    let defaultChange: DefaultChange = null;
    const done = (outcome: ObjectOutcome, reason: string | null, id: string | null) =>
      out.push({ planned: g, outcome, reason, qualorGateId: id, defaultChange });
    const wantsDefault = o.setDefaults && g.isDefault;
    if (g.skip !== null) {
      done('skipped', g.skip, null);
      continue;
    }
    if (listFailed !== null) {
      done('failed', listFailed, null);
      continue;
    }
    const wanted = mappedConditions(g);
    const same = existing.filter((x) => x.name === g.name);
    if (same.some((x) => x.isBuiltin)) {
      done('skipped', 'name_reserved', null);
      continue;
    }
    if (same.length > 1) {
      done('conflict', 'name_ambiguous', null);
      continue;
    }
    let id: string | null = null;
    let created = false;
    let updating = false;
    try {
      const found = same[0];
      if (found === undefined) {
        if (o.dryRun) {
          if (wantsDefault) defaultChange = 'would_set';
          done('would_create', null, null);
          continue;
        }
        const made = await api.createGate(orgId, g.name);
        id = made.id;
        created = true;
        for (const c of wanted) await api.addCondition(made.id, c);
        if (wantsDefault) {
          await api.setDefaultGate(made.id);
          defaultChange = 'set';
        }
        done('created', null, made.id);
        continue;
      }
      id = found.id;
      const have = new Set(found.conditions.map(condKey));
      const equal =
        found.conditions.length === wanted.length && wanted.every((c) => have.has(condKey(c)));
      let outcome: ObjectOutcome = 'unchanged';
      if (!equal) {
        if (!o.overwrite) {
          done(
            'conflict',
            'a Qualor gate of this name has other conditions; --overwrite replaces them',
            found.id,
          );
          continue;
        }
        outcome = o.dryRun ? 'would_update' : 'updated';
        if (!o.dryRun) {
          updating = true;
          const byMetric = new Map(found.conditions.map((c) => [c.metric, c]));
          const wantedMetrics = new Set(wanted.map((c) => c.metric));
          // Deletions first: a metric is unique per gate (409 CONDITION_EXISTS).
          for (const c of found.conditions) {
            if (!wantedMetrics.has(c.metric)) await api.deleteCondition(found.id, c.id);
          }
          for (const c of wanted) {
            const cur = byMetric.get(c.metric);
            if (cur === undefined) await api.addCondition(found.id, c);
            else if (condKey(cur) !== condKey(c)) await api.updateCondition(found.id, cur.id, c);
          }
        }
      }
      if (wantsDefault && !found.isDefault) {
        if (o.dryRun) defaultChange = 'would_set';
        else {
          await api.setDefaultGate(found.id);
          defaultChange = 'set';
        }
      }
      done(outcome, null, found.id);
    } catch (err) {
      done('failed', `${failure(err)}${partly(created, updating)}`, id);
      if (fatal(err)) throw err;
    }
  }
  return out;
}

/**
 * Spec §9: each SonarQube project to the Qualor project of the same key in `orgId` (created only
 * with `--create-projects`), with SonarQube's explicit profile and gate assignments.
 */
export async function applyProjects(
  api: QualorApi,
  orgId: string,
  projects: readonly SonarProjectData[],
  profiles: readonly ProfileResult[],
  gates: readonly GateResult[],
  o: ApplyOptions,
  out: ProjectResult[] = [],
): Promise<ProjectResult[]> {
  for (const sp of projects) {
    const result: ProjectResult = {
      sonar: sp,
      outcome: 'found',
      reason: null,
      qualorProjectId: null,
      profiles: [],
      gate: null,
    };
    out.push(result);
    // A key Qualor refuses can name no Qualor project: nothing to look up.
    if (!QUALOR_PROJECT_KEY.test(sp.key)) {
      result.outcome = 'key_invalid';
      continue;
    }
    let q: QualorProject | null;
    try {
      q = await api.projectByKey(sp.key);
      if (q !== null && q.organizationId !== orgId) {
        result.outcome = 'failed';
        result.reason = 'a Qualor project of this key belongs to another organisation';
        continue;
      }
      if (q === null) {
        if (!o.createProjects) {
          result.outcome = 'missing';
          continue;
        }
        if (o.dryRun) {
          result.outcome = 'would_create';
        } else {
          q = await api.createProject(orgId, sp.key, cutName(sp.name, 255), sp.mainBranch);
          result.outcome = 'created';
        }
      }
    } catch (err) {
      result.outcome = 'failed';
      result.reason =
        err instanceof QualorApiError && err.status === 409
          ? 'a Qualor project of this key exists in another organisation or is not visible to this user'
          : failure(err);
      if (fatal(err)) throw err;
      continue;
    }
    const project = q;
    result.qualorProjectId = project?.id ?? null;
    // Each assignment on its own: one that fails is recorded and the others are still tried.
    let current: Awaited<ReturnType<QualorApi['projectProfiles']>> | null = null;
    for (const a of sp.profiles.filter((x) => !x.isDefault)) {
      const pr = profiles.find((r) => r.planned.sonarKey === a.profileKey);
      if (pr === undefined || pr.planned.language === null) continue;
      const language = pr.planned.language;
      const entry = { language, profile: pr.planned.name };
      // A profile Qualor failed to import or look up: its assignment fails with it (exit 4).
      if (pr.outcome === 'failed') {
        result.profiles.push({ ...entry, outcome: 'failed', reason: dependency(pr.reason) });
        continue;
      }
      if (!USED.has(pr.outcome)) {
        result.profiles.push({
          ...entry,
          outcome: 'skipped',
          reason: `the profile was not imported (${pr.outcome})`,
        });
        continue;
      }
      try {
        current ??= project === null ? [] : await api.projectProfiles(project.id);
        const now = current.find((c) => c.language === language);
        if (now?.source === 'project' && now.profileId === pr.qualorProfileId) {
          result.profiles.push({ ...entry, outcome: 'unchanged', reason: null });
        } else if (now?.source === 'project' && !o.overwrite) {
          result.profiles.push({
            ...entry,
            outcome: 'conflict',
            reason: 'the project uses another profile; --overwrite replaces it',
          });
        } else if (o.dryRun || project === null || pr.qualorProfileId === null) {
          result.profiles.push({ ...entry, outcome: 'would_assign', reason: null });
        } else {
          await api.setProjectProfile(project.id, language, pr.qualorProfileId);
          result.profiles.push({ ...entry, outcome: 'assigned', reason: null });
        }
      } catch (err) {
        result.profiles.push({ ...entry, outcome: 'failed', reason: failure(err) });
        if (fatal(err)) throw err;
      }
    }
    const sonarGate = sp.gate;
    if (sonarGate !== null && !sonarGate.isDefault) {
      const gr = gates.find((r) => r.planned.name === sonarGate.name.trim());
      const entry = { gate: sonarGate.name };
      try {
        if (gr?.outcome === 'failed') {
          result.gate = { ...entry, outcome: 'failed', reason: dependency(gr.reason) };
        } else if (gr === undefined || !USED.has(gr.outcome)) {
          result.gate = {
            ...entry,
            outcome: 'skipped',
            reason: `the gate was not imported (${gr?.outcome ?? 'not read'})`,
          };
        } else if (
          project !== null &&
          project.qualityGateId !== null &&
          project.qualityGateId === gr.qualorGateId
        ) {
          result.gate = { ...entry, outcome: 'unchanged', reason: null };
        } else if (project !== null && project.qualityGateId !== null && !o.overwrite) {
          result.gate = {
            ...entry,
            outcome: 'conflict',
            reason: 'the project uses another gate; --overwrite replaces it',
          };
        } else if (o.dryRun || project === null || gr.qualorGateId === null) {
          result.gate = { ...entry, outcome: 'would_assign', reason: null };
        } else {
          await api.setProjectGate(project.id, gr.qualorGateId);
          result.gate = { ...entry, outcome: 'assigned', reason: null };
        }
      } catch (err) {
        result.gate = { ...entry, outcome: 'failed', reason: failure(err) };
        if (fatal(err)) throw err;
      }
    }
  }
  return out;
}

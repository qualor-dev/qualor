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
  type NewCondition,
  type QualorApi,
  type QualorGate,
  type QualorProfile,
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
 * What was done to an object before a failure, which the failed row says (partly created, partly
 * updated).
 */
interface Progress {
  id: string | null;
  created: boolean;
  updating: boolean;
}

/**
 * Spec §13: a created object whose later steps failed, or an object whose `--overwrite` update
 * failed part way, is completed by a rerun with --overwrite.
 */
const HALF_DONE = '; it was created in part: run the import again with --overwrite to complete it';
const HALF_UPDATED =
  '; it was updated in part: run the import again with --overwrite to complete it';
function partly(progress: Progress): string {
  if (progress.created) return HALF_DONE;
  return progress.updating ? HALF_UPDATED : '';
}

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

/** One object's outcome, reason, Qualor id and `--set-defaults` change, before it is a result. */
interface Applied {
  outcome: ObjectOutcome;
  reason: string | null;
  id: string | null;
  defaultChange: DefaultChange;
}
const applied = (
  outcome: ObjectOutcome,
  reason: string | null,
  id: string | null,
  defaultChange: DefaultChange = null,
): Applied => ({ outcome, reason, id, defaultChange });

/**
 * The organisation's objects, listed only when `needed`; a list that fails yields its reason
 * (`listFailed`), which fails the objects that needed it, not the run.
 */
async function listExisting<T>(
  needed: boolean,
  list: () => Promise<T[]>,
  what: string,
): Promise<{ existing: T[]; listFailed: string | null }> {
  if (!needed) return { existing: [], listFailed: null };
  try {
    return { existing: await list(), listFailed: null };
  } catch (err) {
    if (fatal(err)) throw err;
    return { existing: [], listFailed: `cannot list the organisation's ${what}: ${failure(err)}` };
  }
}

/**
 * `--set-defaults` on an existing object that is not the default yet (`wanted`): `would_set` in a
 * dry run, else `set` once `set` made it the default; `null` when not wanted.
 */
async function makeDefault(
  wanted: boolean,
  dryRun: boolean,
  set: () => Promise<void>,
): Promise<DefaultChange> {
  if (!wanted) return null;
  if (dryRun) return 'would_set';
  await set();
  return 'set';
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
  const listed = await listExisting(
    planned.some((p) => p.skip === null && p.language !== null),
    () => api.profiles(orgId),
    'profiles',
  );
  for (const p of planned) await applyProfile(api, orgId, p, o, listed, out);
  return out;
}

/** One planned profile of `applyProfiles`: its result goes to `out`, before a fatal error too. */
async function applyProfile(
  api: QualorApi,
  orgId: string,
  p: PlannedProfile,
  o: ApplyOptions,
  listed: { existing: QualorProfile[]; listFailed: string | null },
  out: ProfileResult[],
): Promise<void> {
  const done = (a: Applied) =>
    out.push({
      planned: p,
      outcome: a.outcome,
      reason: a.reason,
      qualorProfileId: a.id,
      defaultChange: a.defaultChange,
    });
  const language = p.language;
  if (p.skip !== null || language === null) {
    done(applied('skipped', p.skip ?? 'language_unsupported', null));
    return;
  }
  if (listed.listFailed !== null) {
    done(applied('failed', listed.listFailed, null));
    return;
  }
  const same = listed.existing.filter((x) => x.language === language && x.name === p.name);
  if (same.some((x) => x.isBuiltin)) {
    done(applied('skipped', 'name_reserved', null));
    return;
  }
  // Spec §13: a profile that inherits shows rows it does not own; making its own rows the plan
  // would still leave the parent's rows in force, so it can never equal the plan.
  const inheriting = same.find((x) => x.parentId !== null);
  if (inheriting !== undefined) {
    done(
      applied(
        'conflict',
        'a Qualor profile of this name inherits from another profile; rename or detach it',
        inheriting.id,
      ),
    );
    return;
  }
  // What was done before a failure, which the failed row says (partly created, partly updated).
  const progress: Progress = { id: null, created: false, updating: false };
  try {
    const found = same[0];
    done(
      found === undefined
        ? await createPlannedProfile(api, orgId, p, language, o, progress)
        : await reconcileProfile(api, p, found, o, progress),
    );
  } catch (err) {
    done(applied('failed', `${failure(err)}${partly(progress)}`, progress.id));
    if (fatal(err)) throw err;
  }
}

/** A planned profile Qualor does not have: created with its rows (or `would_create`). */
async function createPlannedProfile(
  api: QualorApi,
  orgId: string,
  p: PlannedProfile,
  language: string,
  o: ApplyOptions,
  progress: Progress,
): Promise<Applied> {
  const wantsDefault = o.setDefaults && p.isDefault;
  if (o.dryRun) return applied('would_create', null, null, wantsDefault ? 'would_set' : null);
  const made = await api.createProfile(orgId, p.name, language);
  progress.id = made.id;
  progress.created = true;
  // Explicit, never the database default.
  await api.setProfileUnknownRules(made.id, UNKNOWN_RULES);
  for (const row of p.rows) await api.setProfileRule(made.id, row);
  if (wantsDefault) await api.setDefaultProfile(made.id);
  return applied('created', null, made.id, wantsDefault ? 'set' : null);
}

/**
 * A planned profile Qualor has (`found`): `unchanged` when its own rows and `unknownRules` are
 * the plan's, else a `conflict`, or with `--overwrite` made equal.
 */
async function reconcileProfile(
  api: QualorApi,
  p: PlannedProfile,
  found: QualorProfile,
  o: ApplyOptions,
  progress: Progress,
): Promise<Applied> {
  progress.id = found.id;
  const rows = await api.profileRows(found.id);
  const rowsEqual = sameRows(rows, p.rows);
  const unknownEqual = found.unknownRules === UNKNOWN_RULES;
  let outcome: ObjectOutcome = 'unchanged';
  if (!rowsEqual || !unknownEqual) {
    if (!o.overwrite) {
      return applied(
        'conflict',
        rowsEqual
          ? 'a Qualor profile of this name ignores unknown rules; --overwrite makes it activate them'
          : 'a Qualor profile of this name has other rules; --overwrite replaces them',
        found.id,
      );
    }
    outcome = o.dryRun ? 'would_update' : 'updated';
    if (!o.dryRun) {
      progress.updating = true;
      await overwriteProfile(api, found.id, unknownEqual, rows, p.rows);
    }
  }
  const defaultChange = await makeDefault(
    o.setDefaults && p.isDefault && !found.isDefault,
    o.dryRun,
    () => api.setDefaultProfile(found.id),
  );
  return applied(outcome, null, found.id, defaultChange);
}

/** `--overwrite`: makes profile `id`'s own rows (`rows`) and `unknownRules` the plan's. */
async function overwriteProfile(
  api: QualorApi,
  id: string,
  unknownEqual: boolean,
  rows: readonly PlannedRow[],
  plannedRows: readonly PlannedRow[],
): Promise<void> {
  if (!unknownEqual) await api.setProfileUnknownRules(id, UNKNOWN_RULES);
  const wanted = new Set(plannedRows.map((r) => r.ruleKey));
  const current = new Map(rows.map((r) => [r.ruleKey, r]));
  for (const r of rows) {
    if (!wanted.has(r.ruleKey)) await api.deleteProfileRule(id, r.ruleKey);
  }
  for (const r of plannedRows) {
    const c = current.get(r.ruleKey);
    if (c === undefined || rowKey(c) !== rowKey(r)) await api.setProfileRule(id, r);
  }
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
  const listed = await listExisting(
    planned.some((g) => g.skip === null),
    () => api.gates(orgId),
    'gates',
  );
  for (const g of planned) await applyGate(api, orgId, g, o, listed, out);
  return out;
}

/** One planned gate of `applyGates`: its result goes to `out`, before a fatal error too. */
async function applyGate(
  api: QualorApi,
  orgId: string,
  g: PlannedGate,
  o: ApplyOptions,
  listed: { existing: QualorGate[]; listFailed: string | null },
  out: GateResult[],
): Promise<void> {
  const done = (a: Applied) =>
    out.push({
      planned: g,
      outcome: a.outcome,
      reason: a.reason,
      qualorGateId: a.id,
      defaultChange: a.defaultChange,
    });
  if (g.skip !== null) {
    done(applied('skipped', g.skip, null));
    return;
  }
  if (listed.listFailed !== null) {
    done(applied('failed', listed.listFailed, null));
    return;
  }
  const wanted = mappedConditions(g);
  const same = listed.existing.filter((x) => x.name === g.name);
  if (same.some((x) => x.isBuiltin)) {
    done(applied('skipped', 'name_reserved', null));
    return;
  }
  if (same.length > 1) {
    done(applied('conflict', 'name_ambiguous', null));
    return;
  }
  // What was done before a failure, which the failed row says (partly created, partly updated).
  const progress: Progress = { id: null, created: false, updating: false };
  try {
    const found = same[0];
    done(
      found === undefined
        ? await createPlannedGate(api, orgId, g, wanted, o, progress)
        : await reconcileGate(api, g, found, wanted, o, progress),
    );
  } catch (err) {
    done(applied('failed', `${failure(err)}${partly(progress)}`, progress.id));
    if (fatal(err)) throw err;
  }
}

/** A planned gate Qualor does not have: created with its mapped conditions (or `would_create`). */
async function createPlannedGate(
  api: QualorApi,
  orgId: string,
  g: PlannedGate,
  wanted: readonly NewCondition[],
  o: ApplyOptions,
  progress: Progress,
): Promise<Applied> {
  const wantsDefault = o.setDefaults && g.isDefault;
  if (o.dryRun) return applied('would_create', null, null, wantsDefault ? 'would_set' : null);
  const made = await api.createGate(orgId, g.name);
  progress.id = made.id;
  progress.created = true;
  for (const c of wanted) await api.addCondition(made.id, c);
  if (wantsDefault) await api.setDefaultGate(made.id);
  return applied('created', null, made.id, wantsDefault ? 'set' : null);
}

/**
 * A planned gate Qualor has (`found`): `unchanged` with the same conditions, else a `conflict`,
 * or with `--overwrite` made equal.
 */
async function reconcileGate(
  api: QualorApi,
  g: PlannedGate,
  found: QualorGate,
  wanted: readonly NewCondition[],
  o: ApplyOptions,
  progress: Progress,
): Promise<Applied> {
  progress.id = found.id;
  const have = new Set(found.conditions.map(condKey));
  const equal =
    found.conditions.length === wanted.length && wanted.every((c) => have.has(condKey(c)));
  let outcome: ObjectOutcome = 'unchanged';
  if (!equal) {
    if (!o.overwrite) {
      return applied(
        'conflict',
        'a Qualor gate of this name has other conditions; --overwrite replaces them',
        found.id,
      );
    }
    outcome = o.dryRun ? 'would_update' : 'updated';
    if (!o.dryRun) {
      progress.updating = true;
      await overwriteConditions(api, found, wanted);
    }
  }
  const defaultChange = await makeDefault(
    o.setDefaults && g.isDefault && !found.isDefault,
    o.dryRun,
    () => api.setDefaultGate(found.id),
  );
  return applied(outcome, null, found.id, defaultChange);
}

/** `--overwrite`: makes gate `found`'s conditions the `wanted` ones. */
async function overwriteConditions(
  api: QualorApi,
  found: QualorGate,
  wanted: readonly NewCondition[],
): Promise<void> {
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
    const resolved = await resolveProject(api, orgId, sp, o, result);
    if (resolved === null) continue;
    const project = resolved.project;
    result.qualorProjectId = project?.id ?? null;
    await assignProfiles(api, sp, project, profiles, o, result);
    await assignGate(api, sp, project, gates, o, result);
  }
  return out;
}

/**
 * The Qualor project of `sp`, created with `--create-projects` (`project: null` in a dry run
 * that would create it); `null` when `result` is settled without one (key invalid, missing,
 * failed).
 */
async function resolveProject(
  api: QualorApi,
  orgId: string,
  sp: SonarProjectData,
  o: ApplyOptions,
  result: ProjectResult,
): Promise<{ project: QualorProject | null } | null> {
  // A key Qualor refuses can name no Qualor project: nothing to look up.
  if (!QUALOR_PROJECT_KEY.test(sp.key)) {
    result.outcome = 'key_invalid';
    return null;
  }
  try {
    const q = await api.projectByKey(sp.key);
    if (q !== null && q.organizationId !== orgId) {
      result.outcome = 'failed';
      result.reason = 'a Qualor project of this key belongs to another organisation';
      return null;
    }
    if (q !== null) return { project: q };
    if (!o.createProjects) {
      result.outcome = 'missing';
      return null;
    }
    if (o.dryRun) {
      result.outcome = 'would_create';
      return { project: null };
    }
    const made = await api.createProject(orgId, sp.key, cutName(sp.name, 255), sp.mainBranch);
    result.outcome = 'created';
    return { project: made };
  } catch (err) {
    result.outcome = 'failed';
    result.reason =
      err instanceof QualorApiError && err.status === 409
        ? 'a Qualor project of this key exists in another organisation or is not visible to this user'
        : failure(err);
    if (fatal(err)) throw err;
    return null;
  }
}

/**
 * The assignment of a profile or gate (`what`) whose import `r` cannot be assigned: `failed` with
 * it when Qualor failed to import or look it up (exit 4), `skipped` when it was not imported;
 * `null` when it can be assigned.
 */
function unassignable(
  what: 'profile' | 'gate',
  r: { outcome: ObjectOutcome; reason: string | null },
): AssignmentResult | null {
  if (r.outcome === 'failed') return { outcome: 'failed', reason: dependency(r.reason) };
  if (!USED.has(r.outcome)) {
    return { outcome: 'skipped', reason: `the ${what} was not imported (${r.outcome})` };
  }
  return null;
}

type ProjectProfiles = Awaited<ReturnType<QualorApi['projectProfiles']>>;

/**
 * SonarQube's explicit profile assignments of `sp`, each on its own: one that fails is recorded
 * and the others are still tried.
 */
async function assignProfiles(
  api: QualorApi,
  sp: SonarProjectData,
  project: QualorProject | null,
  profiles: readonly ProfileResult[],
  o: ApplyOptions,
  result: ProjectResult,
): Promise<void> {
  let current: ProjectProfiles | null = null;
  for (const a of sp.profiles.filter((x) => !x.isDefault)) {
    const pr = profiles.find((r) => r.planned.sonarKey === a.profileKey);
    if (pr === undefined || pr.planned.language === null) continue;
    const language = pr.planned.language;
    const entry = { language, profile: pr.planned.name };
    const blocked = unassignable('profile', pr);
    if (blocked !== null) {
      result.profiles.push({ ...entry, ...blocked });
      continue;
    }
    try {
      current ??= project === null ? [] : await api.projectProfiles(project.id);
      const now = current.find((c) => c.language === language);
      result.profiles.push({
        ...entry,
        ...(await assignProfile(api, project, now, language, pr.qualorProfileId, o)),
      });
    } catch (err) {
      result.profiles.push({ ...entry, outcome: 'failed', reason: failure(err) });
      if (fatal(err)) throw err;
    }
  }
}

/** One profile assignment, against the project's current one for its language (`now`). */
async function assignProfile(
  api: QualorApi,
  project: QualorProject | null,
  now: ProjectProfiles[number] | undefined,
  language: string,
  profileId: string | null,
  o: ApplyOptions,
): Promise<AssignmentResult> {
  if (now?.source === 'project' && now.profileId === profileId) {
    return { outcome: 'unchanged', reason: null };
  }
  if (now?.source === 'project' && !o.overwrite) {
    return {
      outcome: 'conflict',
      reason: 'the project uses another profile; --overwrite replaces it',
    };
  }
  if (o.dryRun || project === null || profileId === null) {
    return { outcome: 'would_assign', reason: null };
  }
  await api.setProjectProfile(project.id, language, profileId);
  return { outcome: 'assigned', reason: null };
}

/** SonarQube's explicit gate assignment of `sp`, if it has one. */
async function assignGate(
  api: QualorApi,
  sp: SonarProjectData,
  project: QualorProject | null,
  gates: readonly GateResult[],
  o: ApplyOptions,
  result: ProjectResult,
): Promise<void> {
  const sonarGate = sp.gate;
  if (sonarGate === null || sonarGate.isDefault) return;
  const gr = gates.find((r) => r.planned.name === sonarGate.name.trim());
  const entry = { gate: sonarGate.name };
  try {
    result.gate = { ...entry, ...(await gateAssignment(api, project, gr, o)) };
  } catch (err) {
    result.gate = { ...entry, outcome: 'failed', reason: failure(err) };
    if (fatal(err)) throw err;
  }
}

/** The gate assignment, against the project's current gate. */
async function gateAssignment(
  api: QualorApi,
  project: QualorProject | null,
  gr: GateResult | undefined,
  o: ApplyOptions,
): Promise<AssignmentResult> {
  if (gr === undefined) {
    return { outcome: 'skipped', reason: 'the gate was not imported (not read)' };
  }
  const blocked = unassignable('gate', gr);
  if (blocked !== null) return blocked;
  const currentGate = project?.qualityGateId ?? null;
  if (currentGate !== null && currentGate === gr.qualorGateId) {
    return { outcome: 'unchanged', reason: null };
  }
  if (currentGate !== null && !o.overwrite) {
    return {
      outcome: 'conflict',
      reason: 'the project uses another gate; --overwrite replaces it',
    };
  }
  if (o.dryRun || project === null || gr.qualorGateId === null) {
    return { outcome: 'would_assign', reason: null };
  }
  await api.setProjectGate(project.id, gr.qualorGateId);
  return { outcome: 'assigned', reason: null };
}

import { ecosystemsOf, FIX_ECOSYSTEM_FAMILY, type FixFamily } from '@qualor/shared/fix';
import { and, asc, eq, isNotNull, or, sql, type SQL } from 'drizzle-orm';
import { textList } from '../db/bulk';
import type { Db, Executor } from '../db/client';
import { projectFixSettings, projects } from '../db/schema';
import { onTargets, qualifyingRow } from '../jira/auto-rule';
import type { ProjectRow } from '../projects/access';
import { compare } from '../vulnerabilities/order';
import { scopedRows } from '../vulnerabilities/summary';
import { GO_STDLIB, mainBranchId, pep503Name } from './eligibility';
import { activeFixCount, lockProject, requestFix } from './requests';
import type { FixJobDeps } from './run';
import { fixPreconditions, fixSettingsOf, type FixSettingsRow } from './settings';

/**
 * The automatic fix mode (0.16 fix MRs §6.3, §6.7 step 4, B4, R9, R18): step 4 of the fix sync
 * pass requests the packages that the project's rule qualifies on main, oldest first, never beyond
 * the project's cap. The qualifying rows are the Jira rule's own (ruling F23: `qualifyingRow`).
 */

/** A package the automatic mode would request, with its qualifying vulnerability ids. */
export interface AutoCandidate {
  family: FixFamily;
  /** As the fix stores it: a Python package by its PEP 503 name (ruling T8b). */
  packageName: string;
  vulnerabilityIds: string[];
}

const familyWhen = ([type, family]: [string, FixFamily]): SQL => sql`WHEN ${type} THEN ${family}`;
const WHENS = sql.join(Object.entries(FIX_ECOSYSTEM_FAMILY).map(familyWhen), sql.raw(' '));

/** B7: the family of a row's Trivy type, over a {@link scopedRows} row `r`. */
const FAMILY = sql`CASE r.ecosystem ${WHENS} END`;

/** The name a fix of the row's package is stored under (ruling T8b). */
const FIX_NAME = sql`CASE WHEN r.ecosystem IN ${textList(ecosystemsOf('python'))}
  THEN ${pep503Name(sql.raw('r.package_name'))} ELSE r.package_name END`;

/**
 * R3, R12: a row a fix can be made for: a supported Trivy type, a fixed version (one that
 * `parseFixedVersions` keeps), and not Go's standard library.
 */
const FIXABLE = sql`r.ecosystem IN ${textList(Object.keys(FIX_ECOSYSTEM_FAMILY))}
  AND r.fixed_version ~ '[^[:space:],]'
  AND NOT (r.ecosystem IN ${textList(ecosystemsOf('go'))} AND r.package_name = ${GO_STDLIB})`;

interface CandidateRow extends Record<string, unknown> {
  family: FixFamily;
  name: string;
  ids: string[];
}

/**
 * spec §6.3, B4, R9: the project's packages the rule qualifies now, at most `limit`, the one with
 * the oldest qualifying row first. A package qualifies with a row on the main-branch target that
 * is effective-open, not ignored, fixable ({@link FIXABLE}) and new and severe or exploited (the
 * Jira rule's `qualifyingRow`), and no fix row, or a `merged` or `fixed` one whose
 * `vulnerability_ids` lack one of the qualifying ids (B4: the automatic mode never re-requests a
 * `failed`, `no_fix`, `cancelled`, `declined` or `taken_over` fix). `exploited` is the rule's own
 * as it applies now: stored and `vuln.priority` active.
 */
export async function autoCandidates(
  db: Executor,
  project: ProjectRow,
  settings: FixSettingsRow,
  options: { exploited: boolean; limit: number },
): Promise<AutoCandidate[]> {
  const { autoMinSeverity: min, autoSince: since } = settings;
  if (since === null || options.limit <= 0 || (min === null && !options.exploited)) return [];
  const main = await mainBranchId(db, project.id);
  if (main === null) return [];
  const onMain = onTargets([{ kind: 'branch', branchId: main }]);
  const found = await db.execute<CandidateRow>(sql`
    SELECT q.family, q.name, array_agg(DISTINCT q.vulnerability_id) AS ids
      FROM (
        SELECT ${FAMILY} AS family, ${FIX_NAME} AS name, r.vulnerability_id, r.first_seen_at
          FROM (${scopedRows(sql`tv.project_id = ${project.id} AND ${onMain}`)}) r
         WHERE r.eff_status = 'open' AND NOT r.ignored AND ${FIXABLE}
           AND ${qualifyingRow(min, options.exploited, since)}
      ) q
      LEFT JOIN dependency_fixes f
        ON f.project_id = ${project.id} AND f.family = q.family AND f.package_name = q.name
     WHERE f.id IS NULL
        OR (f.state IN ('merged', 'fixed') AND q.vulnerability_id <> ALL (f.vulnerability_ids))
     GROUP BY q.family, q.name
     ORDER BY min(q.first_seen_at), q.name COLLATE "C", q.family COLLATE "C"
     LIMIT ${options.limit}`);
  return found.rows.map((r) => ({
    family: r.family,
    packageName: r.name,
    vulnerabilityIds: r.ids.toSorted(compare),
  }));
}

/**
 * The organisation's projects whose rule is on as it applies now (an exploited-only rule needs
 * `vuln.priority`) and whose fixes are switched on (R18: a project switched off requests nothing),
 * the rule switched on longest ago first.
 */
async function ruleProjects(
  db: Executor,
  organizationId: string,
  priority: boolean,
): Promise<string[]> {
  const s = projectFixSettings;
  const rows = await db
    .select({ projectId: s.projectId })
    .from(s)
    .innerJoin(projects, eq(projects.id, s.projectId))
    .where(
      and(
        eq(projects.organizationId, organizationId),
        eq(s.enabled, true),
        isNotNull(s.autoSince),
        priority
          ? or(isNotNull(s.autoMinSeverity), eq(s.autoExploited, true))
          : isNotNull(s.autoMinSeverity),
      ),
    )
    .orderBy(asc(s.autoSince), asc(s.projectId));
  return rows.map((r) => r.projectId);
}

/**
 * Whether a fix of the project could be served now: switched on, bound to a repository whose
 * connection allows fix MRs (B2), with vulnerability monitoring on (B5, spec §6.7: monitoring off
 * skips the automatic step).
 */
async function usable(
  tx: Executor,
  project: ProjectRow,
  settings: FixSettingsRow,
): Promise<boolean> {
  if (!settings.enabled) return false;
  const pre = await fixPreconditions(tx, project);
  return pre.scmBound && pre.fixMrsAllowed && pre.monitoringOn;
}

/**
 * One project's candidates requested in one transaction under the project row lock (ruling T2a:
 * the requests' lock order), so the settings and the cap are read as they stand and a member's
 * request waits: `requestFix` with origin `auto`, no user and no audit. Returns how many fixes it
 * made or re-armed.
 */
function requestProject(db: Db, projectId: string, priority: boolean): Promise<number> {
  return db.transaction(async (tx) => {
    const project = await lockProject(tx, projectId);
    const settings = project === null ? null : await fixSettingsOf(tx, projectId);
    if (project === null || settings === null || !(await usable(tx, project, settings))) return 0;
    const limit = settings.maxOpen - (await activeFixCount(tx, projectId));
    const exploited = priority && settings.autoExploited;
    let made = 0;
    for (const c of await autoCandidates(tx, project, settings, { exploited, limit })) {
      const { family, packageName } = c;
      const request = { project, family, packageName, userId: null, origin: 'auto' as const };
      if ((await requestFix(tx, request)).outcome !== 'active') made += 1;
    }
    return made;
  });
}

/**
 * spec §6.3, §6.7 step 4: the automatic mode of the organisation's projects, each under its own
 * cap (R9: manual and automatic fixes share it). A stored `exploited` applies only while
 * `vuln.priority` is active. `skip` names projects whose part of the pass has ended. Returns how
 * many fixes it requested.
 */
export async function runFixAuto(
  deps: FixJobDeps,
  organizationId: string,
  options: { skip?: ReadonlySet<string> } = {},
): Promise<number> {
  const { priority } = deps.limits().vulnerabilities;
  let requested = 0;
  for (const projectId of await ruleProjects(deps.db, organizationId, priority)) {
    if (options.skip?.has(projectId) !== true) {
      requested += await requestProject(deps.db, projectId, priority);
    }
  }
  return requested;
}

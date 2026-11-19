import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  compareVersions,
  FIX_LIMITS,
  schemeOf,
  type FixClaimAnswer,
  type FixClaimBody,
  type FixClaimItem,
  type FixClaimReason,
  type FixFamily,
} from '@qualor/shared/fix';
import { and, eq, inArray, notInArray, or, sql } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import { dependencyFixes, projectFixSettings } from '../db/schema';
import { conflict, notFound } from '../http/problem';
import type { ProjectRow } from '../projects/access';
import { fixProblem, isGoStdlib, mainVulnerabilities, type MainVulnerability } from './eligibility';
import { lockProject } from './requests';
import { fixColumns, type DependencyFixRow } from './rows';
import { fixPreconditions, fixSettingsOf, type FixSettingsRow } from './settings';

/**
 * The fix job's claim (0.16 fix MRs §6.5, R4, R5, R31): up to `max` fixes of the job's families,
 * `requested` or `open` with `refresh`, oldest first, each moved to `preparing` with a 30-minute
 * lease whose token is shown once and stored only as its hash.
 */

/** The SHA-256 of a lease token, hex: the only form of it the database holds. */
export function leaseHash(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** Whether `token` is the lease whose hash is stored, compared in constant time. */
export function leaseMatches(storedHash: string | null, token: string): boolean {
  if (storedHash === null) return false;
  const stored = Buffer.from(storedHash, 'hex');
  const given = Buffer.from(leaseHash(token), 'hex');
  return stored.length === given.length && timingSafeEqual(stored, given);
}

/** Whether the fix has an MR Qualor keeps current (R8: its outcomes keep it `open`). */
export const hasOpenMr = (row: Pick<DependencyFixRow, 'mrNumber' | 'headSha'>): boolean =>
  row.mrNumber !== null && row.headSha !== null;

/**
 * R4: why the project's fixes cannot be claimed now, in the order of `requireFixesUsable`
 * (switch, binding, the connection's allowance, monitoring); null when they can.
 */
async function claimReason(
  tx: Executor,
  project: ProjectRow,
  settings: FixSettingsRow | null,
): Promise<FixClaimReason | null> {
  if (settings === null || !settings.enabled) return 'disabled';
  const pre = await fixPreconditions(tx, project);
  if (!pre.scmBound) return 'not_bound';
  if (!pre.fixMrsAllowed) return 'not_allowed';
  return pre.monitoringOn ? null : 'monitoring_off';
}

/**
 * Up to `n` claimable fixes of the families, oldest first, locked for the transaction; `passed`
 * are those this claim looked at and did not hand out (R31). Ruling T8a: a SELECT with its own
 * `LIMIT … FOR UPDATE SKIP LOCKED`, then an UPDATE per id, so no plan can take more than `n`.
 */
function pickClaimable(
  tx: Executor,
  projectId: string,
  families: readonly FixFamily[],
  n: number,
  passed: readonly string[],
): Promise<DependencyFixRow[]> {
  const f = dependencyFixes;
  return tx
    .select(fixColumns)
    .from(f)
    .where(
      and(
        eq(f.projectId, projectId),
        inArray(f.family, [...families]),
        or(eq(f.state, 'requested'), and(eq(f.state, 'open'), eq(f.refresh, true))),
        passed.length === 0 ? undefined : notInArray(f.id, [...passed]),
      ),
    )
    .orderBy(f.updatedAt, f.id)
    .limit(n)
    .for('update', { skipLocked: true });
}

const NO_FIXED_VERSION = 'No vulnerability of the package on the main branch has a fixed version';
const GO_STDLIB_TEXT = "Go's standard library is fixed by the Go version, not by a module update";

/**
 * R31: a claimable fix with nothing left to fix is not handed out. Its main rows gone: `fixed`
 * without an MR, left for the pass with one. No fixed version: `no_fix` `no_fixed_version`, or
 * (R8, with an MR) `open` with that failure shown and `refresh` off.
 */
async function nothingLeft(tx: Executor, row: DependencyFixRow, gone: boolean): Promise<void> {
  const withMr = hasOpenMr(row);
  if (gone && withMr) return;
  const message = isGoStdlib(row.family, row.packageName) ? GO_STDLIB_TEXT : NO_FIXED_VERSION;
  const failure = gone ? null : { code: 'no_fixed_version', message };
  let state: DependencyFixRow['state'] = 'no_fix';
  if (gone) state = 'fixed';
  else if (withMr) state = 'open';
  await tx
    .update(dependencyFixes)
    .set({
      state,
      refresh: false,
      failure,
      leaseTokenHash: null,
      leaseUntil: null,
      updatedAt: sql`now()`,
    })
    .where(eq(dependencyFixes.id, row.id));
}

const unique = <T>(values: readonly T[]): T[] => [...new Set(values)];

/** The installed versions in the family's order (unparsable ones last, by text). */
function sortedVersions(family: FixFamily, versions: readonly string[]): string[] {
  const scheme = schemeOf(family);
  return unique(versions).toSorted((a, b) => {
    const c = compareVersions(scheme, a, b);
    if (c !== null) return c;
    return a < b ? -1 : Number(a > b);
  });
}

/** R5: the package's main rows by vulnerability, each with the installed versions it affects. */
export function claimVulnerabilities(
  family: FixFamily,
  rows: readonly MainVulnerability[],
): FixClaimItem['vulnerabilities'] {
  const byId = new Map<string, [MainVulnerability, ...MainVulnerability[]]>();
  for (const r of rows) {
    const of = byId.get(r.vulnerabilityId);
    if (of === undefined) byId.set(r.vulnerabilityId, [r]);
    else of.push(r);
  }
  return [...byId].map(([id, of]) => ({
    id,
    severity: of[0].severity,
    title: of.find((r) => r.title !== null)?.title ?? null,
    url: of.find((r) => r.primaryUrl !== null)?.primaryUrl ?? null,
    installedVersions: sortedVersions(
      family,
      of.map((r) => r.packageVersion),
    ),
    fixedVersions: unique(of.flatMap((r) => r.fixedVersions)),
  }));
}

/**
 * One claimable fix: handed out (`preparing`, a new lease of 30 minutes, `vulnerability_ids` the
 * handled set, B4) with what the job needs (R5), or null when nothing is left to fix (R31).
 */
async function claimOne(
  tx: Executor,
  project: ProjectRow,
  row: DependencyFixRow,
): Promise<FixClaimItem | null> {
  const rows = await mainVulnerabilities(tx, project.id, row.family, row.packageName);
  if (fixProblem(row.family, row.packageName, rows) !== null) {
    await nothingLeft(tx, row, rows.length === 0);
    return null;
  }
  const leaseToken = randomBytes(32).toString('base64url');
  const vulnerabilityIds = unique(rows.map((r) => r.vulnerabilityId));
  const [claimed] = await tx
    .update(dependencyFixes)
    .set({
      state: 'preparing',
      leaseTokenHash: leaseHash(leaseToken),
      leaseUntil: sql`now() + make_interval(mins => ${FIX_LIMITS.leaseMinutes})`,
      vulnerabilityIds,
      updatedAt: sql`now()`,
    })
    .where(eq(dependencyFixes.id, row.id))
    .returning();
  if (!claimed) throw new Error(`fix ${row.id} vanished while it was locked`);
  return {
    id: claimed.id,
    generation: claimed.generation,
    leaseToken,
    family: claimed.family,
    packageName: claimed.packageName,
    installedVersions: sortedVersions(
      claimed.family,
      rows.map((r) => r.packageVersion),
    ),
    vulnerabilities: claimVulnerabilities(claimed.family, rows),
    mainBranch: project.mainBranchName,
    declinedTarget: claimed.declinedTarget,
  };
}

/** Claimable fixes, oldest first, until `max` are handed out or none is left. */
async function claimItems(
  tx: Executor,
  project: ProjectRow,
  families: readonly FixFamily[],
  max: number,
): Promise<FixClaimItem[]> {
  const items: FixClaimItem[] = [];
  const passed: string[] = [];
  while (items.length < max) {
    const rows = await pickClaimable(tx, project.id, families, max - items.length, passed);
    if (rows.length === 0) break;
    for (const row of rows) {
      const item = await claimOne(tx, project, row);
      if (item === null) passed.push(row.id);
      else items.push(item);
    }
  }
  return items;
}

/**
 * spec §6.5, R4, R5, R31: the claim of a fix job of the project. A `branch` other than the
 * project's main branch is 409 `NOT_MAIN_BRANCH`. In one transaction under the project row lock
 * (requests of a project run one at a time, ruling T2a): an enabled project's `last_claim_at` is
 * set; a project whose fixes cannot be claimed answers its reason and nothing; else up to `max`
 * fixes of `families` are handed out ({@link claimItems}). `revision` is not read (ruling F12).
 */
export async function claimFixes(
  db: Db,
  project: ProjectRow,
  body: FixClaimBody,
): Promise<FixClaimAnswer> {
  return db.transaction(async (tx) => {
    const locked = await lockProject(tx, project.id);
    if (!locked) throw notFound('Project');
    if (body.branch !== locked.mainBranchName) {
      throw conflict(
        'NOT_MAIN_BRANCH',
        `Fixes are claimed from the main branch (${locked.mainBranchName}) only`,
      );
    }
    const settings = await fixSettingsOf(tx, locked.id);
    if (settings?.enabled === true) {
      // A claim is no change of the settings: their `updated_at` stays.
      await tx
        .update(projectFixSettings)
        .set({ lastClaimAt: sql`now()`, updatedAt: sql`${projectFixSettings.updatedAt}` })
        .where(eq(projectFixSettings.projectId, locked.id));
    }
    const reason = await claimReason(tx, locked, settings);
    if (reason !== null) return { items: [], reason };
    const items = await claimItems(tx, locked, unique(body.families), body.max);
    return { items, reason: null };
  });
}

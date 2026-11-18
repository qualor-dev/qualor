import { and, count, eq, inArray } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { dependencyFixes, projectFixSettings, scmConnections, type FixState } from '../db/schema';
import { conflict } from '../http/problem';
import type { ProjectRow } from '../projects/access';
import { monitoringOn } from '../vulnerabilities/targets';

export type FixSettingsRow = typeof projectFixSettings.$inferSelect;

/** The states that count against `maxOpen` (R9). */
const CAPPED_STATES = [
  'requested',
  'preparing',
  'committing',
  'open',
] as const satisfies readonly FixState[];

/** The project's fix settings, or null (the defaults: off, five open at most). */
export async function fixSettingsOf(
  db: Executor,
  projectId: string,
): Promise<FixSettingsRow | null> {
  const [row] = await db
    .select()
    .from(projectFixSettings)
    .where(eq(projectFixSettings.projectId, projectId));
  return row ?? null;
}

/** What a request, a claim and an automatic pass need besides the project's own switch (spec §6.2). */
export interface FixPreconditions {
  scmBound: boolean;
  provider: 'gitlab' | 'github' | null;
  fixMrsAllowed: boolean;
  monitoringOn: boolean;
  /** When a CLI job last claimed on this project; null before the first claim. */
  lastClaimAt: string | null;
}

/** The project's SCM binding, the connection's switch (B2) and monitoring (B5), as they stand now. */
export async function fixPreconditions(
  db: Executor,
  project: ProjectRow,
): Promise<FixPreconditions> {
  const [connection] =
    project.scmConnectionId === null
      ? []
      : await db
          .select({ provider: scmConnections.provider, allowed: scmConnections.fixMrsAllowed })
          .from(scmConnections)
          .where(eq(scmConnections.id, project.scmConnectionId));
  const [monitoring, settings] = await Promise.all([
    monitoringOn(db, project.id),
    fixSettingsOf(db, project.id),
  ]);
  return {
    scmBound: connection !== undefined && project.scmProjectRef !== null,
    provider: connection?.provider ?? null,
    fixMrsAllowed: connection?.allowed ?? false,
    monitoringOn: monitoring,
    lastClaimAt: settings?.lastClaimAt?.toISOString() ?? null,
  };
}

/** The project's fixes by state, for the "3 of 5 open" line and the cap (R9, R34). */
export async function fixCounts(
  db: Executor,
  projectId: string,
): Promise<Record<(typeof CAPPED_STATES)[number], number>> {
  const rows = await db
    .select({ state: dependencyFixes.state, n: count() })
    .from(dependencyFixes)
    .where(
      and(
        eq(dependencyFixes.projectId, projectId),
        inArray(dependencyFixes.state, [...CAPPED_STATES]),
      ),
    )
    .groupBy(dependencyFixes.state);
  const counts = { requested: 0, preparing: 0, committing: 0, open: 0 };
  for (const row of rows) {
    if (row.state in counts) counts[row.state as keyof typeof counts] = row.n;
  }
  return counts;
}

/**
 * The project's settings when fixes may be requested, claimed or run automatically, else a 409 for
 * the first precondition that fails: `FIXES_DISABLED`, `SCM_NOT_BOUND`, `FIX_MRS_NOT_ALLOWED`,
 * `MONITORING_OFF`.
 */
export async function requireFixesUsable(
  db: Executor,
  project: ProjectRow,
): Promise<FixSettingsRow> {
  const settings = await fixSettingsOf(db, project.id);
  if (settings === null || !settings.enabled) {
    throw conflict('FIXES_DISABLED', 'Fix merge requests are switched off for this project');
  }
  const pre = await fixPreconditions(db, project);
  if (!pre.scmBound) {
    throw conflict('SCM_NOT_BOUND', 'The project is not mapped to a repository');
  }
  if (!pre.fixMrsAllowed) {
    throw conflict(
      'FIX_MRS_NOT_ALLOWED',
      "An organisation admin has not allowed fix merge requests on the project's SCM connection",
    );
  }
  if (!pre.monitoringOn) {
    throw conflict('MONITORING_OFF', 'Vulnerability monitoring is off for this project');
  }
  return settings;
}

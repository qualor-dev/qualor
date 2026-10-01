import {
  DEFAULT_SMALL_CHANGESET_LINES,
  type GateResult,
  type Quality,
  type Severity,
} from '@qualor/shared';
import { z } from 'zod';
import { and, asc, count, eq, inArray, isNotNull, isNull, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import {
  analyses,
  branches,
  issues,
  measures,
  projects,
  rules,
  scmConnections,
} from '../db/schema';
import { SMALL_CHANGESET_SETTING } from '../gates/stage';
import { instanceSetting } from '../settings';
import { readScmContext } from './context';
import { mergeRequestTitle, SUMMARY_TOP_ISSUES, type IssueLine, type SummaryInput } from './render';

/**
 * What a decoration reads from the database, for either provider (scm.md §4–§5, github.md §5–§6):
 * the analysis and its branch, project, connection and gate, the issue lists and counts of the
 * summary, the links, and the merge request (pull request) record on the branch.
 */

const SEVERITIES: readonly Severity[] = ['blocker', 'high', 'medium', 'low', 'info'];

/** Everything a decoration reads from the database. */
export interface Loaded {
  analysis: typeof analyses.$inferSelect;
  branch: typeof branches.$inferSelect;
  project: typeof projects.$inferSelect;
  connection: typeof scmConnections.$inferSelect;
  gate: GateResult;
  /** The analysed commit (a succeeded analysis always has one). */
  revision: string;
}

/** The analysis to decorate with what goes with it, or why there is nothing to decorate. */
export async function loadDecoration(db: Db, analysisId: string): Promise<Loaded | string> {
  const [row] = await db
    .select({ analysis: analyses, branch: branches, project: projects, connection: scmConnections })
    .from(analyses)
    .innerJoin(branches, eq(branches.id, analyses.branchId))
    .innerJoin(projects, eq(projects.id, analyses.projectId))
    .leftJoin(scmConnections, eq(scmConnections.id, projects.scmConnectionId))
    .where(eq(analyses.id, analysisId));
  if (!row) return 'the analysis is gone';
  if (row.analysis.status !== 'succeeded' || row.analysis.revision === null) {
    return 'the analysis did not succeed';
  }
  if (!row.connection || row.project.scmProjectRef === null) return 'the project is not mapped';
  if (row.connection.provider !== 'gitlab' && row.connection.provider !== 'github') {
    return 'the connection is not supported';
  }
  // §4.1: a local scan never decorates (checked when enqueued; again here, from what was stored),
  // and a report decorates only through a connection of its own provider (github.md §5.1).
  const stored = readScmContext(row.analysis.scmContext);
  if (stored.kind === 'ok' && stored.context.provider !== row.connection.provider) {
    return row.connection.provider === 'gitlab'
      ? 'the analysis is not from GitLab CI'
      : 'the analysis is not from GitHub Actions';
  }
  const gate = row.analysis.gateResult as GateResult | null;
  if (!gate || typeof gate !== 'object' || !Array.isArray(gate.conditions)) {
    return 'the analysis has no gate result';
  }
  return {
    analysis: row.analysis,
    branch: row.branch,
    project: row.project,
    connection: row.connection,
    gate,
    revision: row.analysis.revision,
  };
}

export function branchUrl(publicUrl: string | null, loaded: Loaded): string | null {
  return publicUrl === null
    ? null
    : `${publicUrl}/projects/${loaded.project.id}/branches/${loaded.branch.id}`;
}

export function issueUrl(
  publicUrl: string | null,
  projectId: string,
  issueId: string,
): string | null {
  return publicUrl === null ? null : `${publicUrl}/projects/${projectId}/issues/${issueId}`;
}

/** A provider's link when it is on the given web base, else null (scm.md §8, github.md GH13). */
export function linkOn(link: string, webBase: string): string | null {
  try {
    const url = new URL(link);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.href.startsWith(`${webBase}/`) && url.href.length <= 2_048 ? url.href : null;
  } catch {
    return null;
  }
}

/** Open, visible, new issues of the branch: most severe first, then by place (scm.md §5.2). */
function openNewIssues(branchId: string) {
  return and(
    eq(issues.branchId, branchId),
    eq(issues.status, 'open'),
    isNull(issues.duplicateOfIssueId),
    eq(issues.kind, 'issue'),
    eq(issues.inNewCode, true),
  );
}

async function summaryIssues(
  db: Db,
  loaded: Loaded,
  publicUrl: string | null,
): Promise<{ top: IssueLine[]; total: number }> {
  const where = openNewIssues(loaded.branch.id);
  const rows = await db
    .select({
      id: issues.id,
      severity: issues.severity,
      quality: issues.quality,
      ruleKey: rules.key,
      path: issues.path,
      line: issues.startLine,
      message: issues.message,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .where(where)
    .orderBy(
      asc(issues.severityRank),
      sql`${issues.path} NULLS LAST`,
      asc(issues.startLine),
      asc(issues.id),
    )
    .limit(SUMMARY_TOP_ISSUES);
  const [total] = await db.select({ n: count() }).from(issues).where(where);
  return {
    top: rows.map((r) => ({
      id: r.id,
      severity: r.severity as Severity,
      quality: r.quality as Quality,
      ruleKey: r.ruleKey,
      path: r.path,
      line: r.line,
      message: r.message,
      url: issueUrl(publicUrl, loaded.project.id, r.id),
    })),
    total: total?.n ?? 0,
  };
}

async function newIssueCounts(db: Db, analysisId: string): Promise<SummaryInput['newIssues']> {
  const keys = ['issues', ...SEVERITIES.map((s) => `${s}_issues`)];
  const rows = await db
    .select({ key: measures.metricKey, value: measures.value })
    .from(measures)
    .where(
      and(
        eq(measures.analysisId, analysisId),
        eq(measures.scope, 'new'),
        inArray(measures.metricKey, keys),
      ),
    );
  const value = (key: string) => rows.find((r) => r.key === key)?.value ?? null;
  return {
    total: value('issues'),
    bySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, value(`${s}_issues`)])),
  };
}

export interface SummaryData {
  top: IssueLine[];
  total: number;
  newIssues: SummaryInput['newIssues'];
  /** The instance's small-changeset threshold, for the reason of a skipped condition. */
  smallChangesetLines: number;
}

/** The summary's issue list, its total and the new-issue counts (scm.md §5.2). */
export async function summaryData(
  db: Db,
  loaded: Loaded,
  publicUrl: string | null,
): Promise<SummaryData> {
  const { top, total } = await summaryIssues(db, loaded, publicUrl);
  return {
    top,
    total,
    newIssues: await newIssueCounts(db, loaded.analysis.id),
    smallChangesetLines: await instanceSetting(
      db,
      SMALL_CHANGESET_SETTING,
      z.number().int().min(0),
      DEFAULT_SMALL_CHANGESET_LINES,
    ),
  };
}

/**
 * The branch's open new issues with a place, most severe first (scm.md §5.4, github.md §6.4): the
 * ones a decoration comments or annotates inline.
 */
export async function desiredInlineIssues(db: Db, branchId: string, limit: number) {
  return db
    .select({
      id: issues.id,
      severity: issues.severity,
      quality: issues.quality,
      ruleKey: rules.key,
      path: issues.path,
      line: issues.startLine,
      message: issues.message,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .where(
      and(
        eq(issues.branchId, branchId),
        eq(issues.status, 'open'),
        isNull(issues.duplicateOfIssueId),
        eq(issues.kind, 'issue'),
        eq(issues.inNewCode, true),
        isNotNull(issues.path),
        isNotNull(issues.startLine),
      ),
    )
    .orderBy(asc(issues.severityRank), asc(issues.path), asc(issues.startLine), asc(issues.id))
    .limit(limit);
}
export type DesiredInlineIssue = Awaited<ReturnType<typeof desiredInlineIssues>>[number];

/** A note body as compared for "changed": the provider may store line ends or a final newline its way. */
export function comparable(body: string): string {
  return body.replace(/\r\n?/g, '\n').trimEnd();
}

/**
 * scm.md §8, github.md GH13: the merge (pull) request's title and URL on the branch, when they
 * changed; the URL only when it is on `webBase`.
 */
export async function recordMergeRequest(
  db: Db,
  loaded: Loaded,
  mr: { title: string; url: string },
  webBase: string,
): Promise<void> {
  const title = mergeRequestTitle(mr.title) || null;
  const url = linkOn(mr.url, webBase);
  if (loaded.branch.mrTitle === title && loaded.branch.mrUrl === url) return;
  await db.transaction(async (tx) => {
    // Written only while the project still maps to the connection the job loaded, at the address
    // it loaded. FOR SHARE, connection first then project (the order a connection's PATCH and
    // DELETE and a project's PATCH take them): a concurrent change of either waits for this
    // write and then forgets a link no longer on the address, or this waits for it and sees it.
    const [connection] = await tx
      .select({ baseUrl: scmConnections.baseUrl })
      .from(scmConnections)
      .where(eq(scmConnections.id, loaded.connection.id))
      .for('share');
    const [project] = await tx
      .select({ connectionId: projects.scmConnectionId })
      .from(projects)
      .where(eq(projects.id, loaded.project.id))
      .for('share');
    if (
      connection?.baseUrl !== loaded.connection.baseUrl ||
      project?.connectionId !== loaded.connection.id
    ) {
      return;
    }
    await tx
      .update(branches)
      .set({ mrTitle: title, mrUrl: url, updatedAt: sql`now()` })
      .where(eq(branches.id, loaded.branch.id));
  });
}

import {
  assertNever,
  DEFAULT_SMALL_CHANGESET_LINES,
  ruleHelpUri,
  type GateResult,
  type Quality,
  type Severity,
} from '@qualor/shared';
import { z } from 'zod';
import { and, asc, count, desc, eq, inArray, isNotNull, isNull, ne, or, sql } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import {
  analyses,
  branches,
  issueChanges,
  issues,
  measures,
  projects,
  reviewFindings,
  reviewRuns,
  reviewSnapshotFiles,
  reviewSnapshots,
  rules,
  scmConnections,
  type AiCategory,
  type ReviewFailureReason,
  type ReviewRunRow,
  type ReviewSkipReason,
} from '../db/schema';
import { SMALL_CHANGESET_SETTING } from '../gates/stage';
import { PROMPT_FINDINGS, UNPLACED_LISTED, type ReviewSummaryState } from '../review/render';
import { AI_THREAD_SEVERITIES, aiSeverityOf, notAiIssue, type AiSeverity } from '../review/rules';
import { reviewSummarySchema } from '../review/schemas';
import type { ReviewSuggestion } from '../review/suggestion';
import { AI_ENGINE } from '../rules/server-engines';
import { instanceSetting } from '../settings';
import { readScmContext } from './context';
import { isFullSha } from './markdown';
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
  if (
    row.connection.provider !== 'gitlab' /* provider-guard: allowlist of supported connections */ &&
    row.connection.provider !== 'github' /* provider-guard: allowlist of supported connections */
  ) {
    return 'the connection is not supported';
  }
  // §4.1: a local scan never decorates (checked when enqueued; again here, from what was stored),
  // and a report decorates only through a connection of its own provider (github.md §5.1).
  const stored = readScmContext(row.analysis.scmContext);
  if (stored.kind === 'ok' && stored.context.provider !== row.connection.provider) {
    switch (row.connection.provider) {
      case 'gitlab':
        return 'the analysis is not from GitLab CI';
      case 'github':
        return 'the analysis is not from GitHub Actions';
      default:
        return assertNever(row.connection.provider, 'provider');
    }
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

/**
 * Open, visible, new issues of the branch: most severe first, then by place (scm.md §5.2). The AI
 * review's findings are not among them: the summary lists and counts the analyzers' issues.
 */
function openNewIssues(branchId: string) {
  return and(
    eq(issues.branchId, branchId),
    eq(issues.status, 'open'),
    isNull(issues.duplicateOfIssueId),
    eq(issues.kind, 'issue'),
    eq(issues.inNewCode, true),
    notAiIssue(issues.ruleId),
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
      helpUri: rules.helpUri,
      path: issues.path,
      line: issues.startLine,
      message: issues.message,
      confidence: issues.confidence,
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
      helpUri: ruleHelpUri(r.ruleKey, r.helpUri),
      path: r.path,
      line: r.line,
      message: r.message,
      confidence: r.confidence,
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

/** An open AI finding of the branch: not a duplicate, and an issue of its own engine. */
function openAiFindings(branchId: string) {
  return and(
    eq(issues.branchId, branchId),
    eq(issues.status, 'open'),
    isNull(issues.duplicateOfIssueId),
    eq(issues.kind, 'issue'),
    eq(rules.engineId, AI_ENGINE),
  );
}

/** An issue's severity as the AI review's three, as the section counts and lists them. */
const aiSeverity = (severity: string): AiSeverity => aiSeverityOf(severity) ?? 'low';

/** What the section holds of the branch's findings when it shows none. */
const NO_OPEN_FINDINGS = {
  counts: { high: 0, medium: 0, low: 0 },
  unplaced: [],
  moreUnplaced: 0,
  fixPrompt: [],
} as const satisfies Pick<
  Extract<ReviewSummaryState, { kind: 'done' }>,
  'counts' | 'unplaced' | 'moreUnplaced' | 'fixPrompt'
>;

/**
 * The finished review's part of its section that comes from the merge request's findings as they
 * are now (people dismiss them, later reviews close them): the open ones by severity, the ones that
 * sit on no changed line, and the ones the prompt for an agent lists.
 */
async function openAiSummary(
  db: Executor,
  run: Pick<ReviewRunRow, 'branchId' | 'projectId'>,
  publicUrl: string | null,
): Promise<
  Pick<
    Extract<ReviewSummaryState, { kind: 'done' }>,
    'counts' | 'unplaced' | 'moreUnplaced' | 'fixPrompt'
  >
> {
  const where = openAiFindings(run.branchId);
  const withPlace = and(isNotNull(issues.path), isNotNull(issues.startLine));
  const order = [
    asc(issues.severityRank),
    asc(issues.path),
    asc(issues.startLine),
    asc(issues.id),
  ] as const;
  const grouped = await db
    .select({
      severity: issues.severity,
      total: count(),
      // A finding without a row of its own has no anchor either.
      unplaced: sql<number>`count(*) FILTER (WHERE ${reviewFindings.anchorLine} IS NULL)`.mapWith(
        Number,
      ),
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .leftJoin(reviewFindings, eq(reviewFindings.issueId, issues.id))
    .where(where)
    .groupBy(issues.severity);
  const counts = { high: 0, medium: 0, low: 0 };
  let unplacedTotal = 0;
  for (const row of grouped) {
    counts[aiSeverity(row.severity)] += row.total;
    unplacedTotal += row.unplaced;
  }
  const unplaced = await db
    .select({
      id: issues.id,
      severity: issues.severity,
      path: issues.path,
      line: issues.startLine,
      title: issues.message,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .leftJoin(reviewFindings, eq(reviewFindings.issueId, issues.id))
    .where(and(where, withPlace, isNull(reviewFindings.anchorLine)))
    .orderBy(...order)
    .limit(UNPLACED_LISTED);
  const prompt = await db
    .select({
      path: issues.path,
      line: issues.startLine,
      title: issues.message,
      body: reviewFindings.body,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .leftJoin(reviewFindings, eq(reviewFindings.issueId, issues.id))
    .where(and(where, withPlace))
    .orderBy(...order)
    .limit(PROMPT_FINDINGS);
  const listed = unplaced.flatMap((u) =>
    u.path === null || u.line === null
      ? []
      : [
          {
            severity: aiSeverity(u.severity),
            path: u.path,
            line: u.line,
            title: u.title,
            url: issueUrl(publicUrl, run.projectId, u.id),
          },
        ],
  );
  return {
    counts,
    unplaced: listed,
    moreUnplaced: Math.max(0, unplacedTotal - listed.length),
    fixPrompt: prompt.flatMap((p) =>
      p.path === null || p.line === null
        ? []
        : [{ path: p.path, line: p.line, title: p.title, body: p.body ?? '' }],
    ),
  };
}

/**
 * How the AI review of the analysis stands, for the AI section of the summary: a run that
 * waits or runs is in progress; one that was skipped or failed says why; one that is done gives the
 * summary it stored (its verdict and walkthrough, read back by `reviewSummarySchema`: one that
 * cannot be read has no verdict), the commit it covered, what it says of itself, and the merge
 * request's open AI findings as they are now, for the branch's newest analysis; an older one gets
 * `latest: false` and none of them, since they are the branch's now and not that run's. Null when
 * the analysis has no run, and for a run an older analysis was superseded by: a newer analysis' own
 * run is the one the summary shows. `mergeRequestHeadSha` is left for the decoration, which knows
 * the live head.
 */
export async function loadReviewSummary(
  db: Executor,
  analysisId: string,
  publicUrl: string | null,
): Promise<ReviewSummaryState | null> {
  const [found] = await db
    .select({ run: reviewRuns, newest: branches.lastAnalysisId })
    .from(reviewRuns)
    .innerJoin(branches, eq(branches.id, reviewRuns.branchId))
    .where(eq(reviewRuns.analysisId, analysisId));
  if (found === undefined) return null;
  const { run } = found;
  switch (run.status) {
    case 'waiting':
    case 'running':
      return { kind: 'pending' };
    case 'skipped':
      return { kind: 'skipped', reason: run.reason as ReviewSkipReason, detail: run.detail };
    case 'failed':
      return { kind: 'failed', reason: run.reason as ReviewFailureReason, detail: run.detail };
    case 'done': {
      const stored = reviewSummarySchema.safeParse(run.summary);
      const summary = stored.success ? stored.data : { verdict: '', walkthrough: [], notes: [] };
      const latest = found.newest === analysisId;
      return {
        kind: 'done',
        ...(latest ? {} : { latest: false }),
        verdict: summary.verdict,
        walkthrough: summary.walkthrough,
        ...(latest ? await openAiSummary(db, run, publicUrl) : NO_OPEN_FINDINGS),
        reviewedSha: run.headSha ?? '',
        mergeRequestHeadSha: null,
        tokenLimitReached: run.tokenLimitReached,
        snapshotPartial: run.snapshotPartial,
        notes: summary.notes,
      };
    }
    default:
      return null;
  }
}

/**
 * The revision each of the issues was found fixed at: that of the analysis that closed it last
 * (its newest change of status to `closed`, which an analysis records, or the review of one), as a
 * full commit SHA in lower case. An issue never closed, or whose closing analysis is gone, has none.
 */
export async function closingRevisions(
  db: Executor,
  issueIds: readonly string[],
): Promise<Map<string, string>> {
  if (issueIds.length === 0) return new Map();
  const rows = await db
    .selectDistinctOn([issueChanges.issueId], {
      issueId: issueChanges.issueId,
      revision: analyses.revision,
    })
    .from(issueChanges)
    .leftJoin(analyses, eq(analyses.id, issueChanges.analysisId))
    .where(
      and(
        inArray(issueChanges.issueId, [...issueIds]),
        eq(issueChanges.field, 'status'),
        eq(issueChanges.newValue, 'closed'),
      ),
    )
    .orderBy(issueChanges.issueId, desc(issueChanges.createdAt), desc(issueChanges.id));
  const revisions = new Map<string, string>();
  for (const { issueId, revision } of rows) {
    const sha = revision?.toLowerCase();
    if (sha !== undefined && isFullSha(sha)) revisions.set(issueId, sha);
  }
  return revisions;
}

/**
 * The branch's open new issues with a place, most severe first (scm.md §5.4, github.md §6.4): the
 * ones a decoration comments inline, each with its rule's documentation link. The AI review's
 * findings are not among them: these threads are the analyzers'.
 */
export async function desiredInlineIssues(db: Db, branchId: string, limit: number) {
  const rows = await db
    .select({
      id: issues.id,
      severity: issues.severity,
      quality: issues.quality,
      ruleKey: rules.key,
      helpUri: rules.helpUri,
      path: issues.path,
      line: issues.startLine,
      message: issues.message,
      confidence: issues.confidence,
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
        ne(rules.engineId, AI_ENGINE),
        isNotNull(issues.path),
        isNotNull(issues.startLine),
      ),
    )
    .orderBy(asc(issues.severityRank), asc(issues.path), asc(issues.startLine), asc(issues.id))
    .limit(limit);
  // The link to show: a stored dead one becomes the live page, a Qualor rule gets its own page.
  return rows.map((r) => ({ ...r, helpUri: ruleHelpUri(r.ruleKey, r.helpUri) }));
}

/**
 * An AI review finding a decoration may comment inline (R18): an open AI issue with its place and
 * the thread's line, and what its first note says.
 */
export interface DesiredAiIssue {
  id: string;
  severity: string;
  quality: string;
  ruleKey: string;
  helpUri: string | null;
  path: string;
  line: number;
  message: string;
  confidence: 'high' | 'medium';
  /** The added line of the reviewed head the thread sits on. */
  anchorLine: number;
  category: AiCategory;
  /** The issue's message: the finding's title. */
  title: string;
  body: string;
  assumption: string | null;
  verification: 'confirmed' | 'needs_validation' | null;
  /** The replacement of the reviewed head's lines `startLine` to `endLine`, which starts at the anchor. */
  suggestion: ReviewSuggestion | null;
}

/** A suggestion as its row stores it: a replacement of whole lines, or none. */
const storedSuggestion = z.object({
  startLine: z.number().int(),
  endLine: z.number().int(),
  lines: z.array(z.string()),
});

/**
 * The branch's open AI findings that get a thread on the head `reviewedHeadSha` (R18), most severe
 * first, then by place: those the review placed on that head (their row's head and its anchor), of
 * a severity in AI_THREAD_SEVERITIES, or of another one with a suggestion (posted only for it).
 * The caller asks only for the head of the branch's newest finished review, and creates threads only
 * while the merge request is at it: a finding kept from an older head keeps that head's numbers,
 * and is never posted with them.
 */
export async function desiredAiIssues(
  db: Executor,
  branchId: string,
  reviewedHeadSha: string,
  limit: number,
): Promise<DesiredAiIssue[]> {
  const rows = await db
    .select({
      id: issues.id,
      severity: issues.severity,
      quality: issues.quality,
      ruleKey: rules.key,
      helpUri: rules.helpUri,
      path: issues.path,
      line: issues.startLine,
      message: issues.message,
      confidence: issues.confidence,
      anchorLine: reviewFindings.anchorLine,
      category: reviewFindings.category,
      body: reviewFindings.body,
      assumption: reviewFindings.assumption,
      verification: reviewFindings.verification,
      suggestion: reviewFindings.suggestion,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .innerJoin(reviewFindings, eq(reviewFindings.issueId, issues.id))
    .where(
      and(
        openAiFindings(branchId),
        eq(reviewFindings.reviewedHeadSha, reviewedHeadSha.toLowerCase()),
        isNotNull(reviewFindings.anchorLine),
        isNotNull(issues.path),
        isNotNull(issues.startLine),
        or(
          inArray(issues.severity, [...AI_THREAD_SEVERITIES]),
          sql`jsonb_typeof(${reviewFindings.suggestion}) = 'object'`,
        ),
      ),
    )
    .orderBy(asc(issues.severityRank), asc(issues.path), asc(issues.startLine), asc(issues.id))
    .limit(limit);
  return rows.flatMap(({ path, line, anchorLine, confidence, suggestion, message, ...row }) => {
    if (path === null || line === null || anchorLine === null) return [];
    const stored = suggestion === null ? null : storedSuggestion.safeParse(suggestion);
    return [
      {
        ...row,
        helpUri: ruleHelpUri(row.ruleKey, row.helpUri),
        path,
        line,
        message,
        title: message,
        // Every AI issue is stored with one; without it, the finding reads as the less sure.
        confidence: confidence ?? 'medium',
        anchorLine,
        suggestion: stored?.success === true ? stored.data : null,
      },
    ];
  });
}

/** The head commit of the branch's newest finished AI review, or null when none has finished. */
export async function newestReviewedHead(db: Executor, branchId: string): Promise<string | null> {
  const [row] = await db
    .select({ headSha: reviewRuns.headSha })
    .from(reviewRuns)
    .where(and(eq(reviewRuns.branchId, branchId), eq(reviewRuns.status, 'done')))
    .orderBy(desc(reviewRuns.createdAt), desc(reviewRuns.id))
    .limit(1);
  return row?.headSha ?? null;
}

/**
 * Lines `from` to `to` of the head file `path` as the AI review of `headSha` read it, without their
 * line ends: from the snapshot of that head the merge request keeps. Null when it keeps none (it was
 * deleted, or replaced by one of another head), or the file has no text there or fewer lines. Only
 * those lines are read: a file of the snapshot can be a megabyte.
 */
export async function reviewedLines(
  db: Executor,
  branchId: string,
  headSha: string,
  path: string,
  from: number,
  to: number,
): Promise<string[] | null> {
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 1 || to < from) {
    return null;
  }
  const text = reviewSnapshotFiles.text;
  // The lines as git counts them: a final newline ends the last line, it does not start another.
  const ended = sql`CASE WHEN right(${text}, 1) = chr(10) THEN left(${text}, -1) ELSE ${text} END`;
  const range = sql`[(${from})::int:(${to})::int]`;
  const lines = sql<string[] | null>`(string_to_array(${ended}, chr(10)))${range}`;
  const [row] = await db
    .select({ lines })
    .from(reviewSnapshotFiles)
    .innerJoin(reviewSnapshots, eq(reviewSnapshots.id, reviewSnapshotFiles.snapshotId))
    .where(
      and(
        eq(reviewSnapshots.branchId, branchId),
        eq(reviewSnapshots.status, 'ready'),
        eq(reviewSnapshots.headSha, headSha.toLowerCase()),
        eq(reviewSnapshotFiles.path, path),
      ),
    )
    .orderBy(desc(reviewSnapshots.createdAt))
    .limit(1);
  const found = row?.lines ?? null;
  if (found === null || found.length !== to - from + 1) return null;
  return found.map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
}

/** An AI finding the decoration could not post as a thread, as the summary lists it. */
export function unplacedFinding(
  issue: DesiredAiIssue,
  url: string | null,
): Extract<ReviewSummaryState, { kind: 'done' }>['unplaced'][number] {
  return {
    severity: aiSeverity(issue.severity),
    path: issue.path,
    line: issue.line,
    title: issue.title,
    url,
  };
}

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

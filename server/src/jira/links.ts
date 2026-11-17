import { and, eq, getTableColumns, inArray, ne, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { jiraConnections, jiraLinks, type JiraLinkState } from '../db/schema';
import { conflict, ProblemError } from '../http/problem';
import { iso, isoOrNull, timestamp } from '../http/schemas';
import type { ProjectRow } from '../projects/access';
import {
  isTrackedBranch,
  vulnerabilitySettings,
  type VulnerabilitySettings,
} from '../versions/settings';
import { trackedTargets } from '../vulnerabilities/targets';
import { TRIVY_ENGINE, writesDecision } from '../vulnerabilities/trivy-issues';
import { connectionOf, type JiraConnectionRow } from './connection';
import { mappingOf, type JiraMappingRow } from './mapping';
import { isCredentialProblem } from './problems';

export type JiraLinkRow = typeof jiraLinks.$inferSelect;

/** api.md §3: `POST /projects/{id}/jira/links` names at most this many issues, or pairs. */
export const MAX_LINK_ISSUE_IDS = 500;
export const MAX_LINK_VULNERABILITIES = 100;

/** Why an item of a link request made no row (spec §6.4). */
export type LinkSkip = 'NOT_FOUND' | 'NOT_ELIGIBLE' | 'ALREADY_LINKED';

/** spec §6.3: the states a request for a Jira issue re-arms (a pending or created row stays). */
export const REARMABLE_STATES = [
  'dismissed',
  'failed',
  'missing',
] as const satisfies readonly JiraLinkState[];

/** spec §6.8: the states `POST /jira-links/{id}/retry` takes back to pending (R9). */
export const RETRYABLE_STATES = ['failed', 'missing'] as const satisfies readonly JiraLinkState[];

/** spec §6.8: a finding's Jira link, embedded in the issue and vulnerability lists. */
export const jiraLinkSchema = z.object({
  id: z.uuid(),
  state: z.enum(['pending', 'created', 'failed', 'missing', 'dismissed']),
  /** `auto` for a link the automatic rule made (spec §6.6). */
  origin: z.enum(['manual', 'auto']),
  /** The Jira issue's key; null until it is created (and after a re-arm). */
  key: z.string().nullable(),
  /** `<siteUrl>/browse/<key>`; null without a key. */
  url: z.string().nullable(),
  /** The Jira issue's status as last read (spec §6.5 step 4); null until read. */
  status: z
    .object({ name: z.string(), category: z.enum(['new', 'indeterminate', 'done']) })
    .nullable(),
  statusCheckedAt: timestamp.nullable(),
  failure: z
    .object({
      code: z.string().meta({
        description:
          'field_refused, permission_missing, not_found, limit_reached, not_mapped, finding_gone or outcome_unknown',
      }),
      /** A fixed text; for `field_refused`, Jira's own field errors (at most 500 characters). */
      message: z.string(),
    })
    .nullable(),
  /** When the fixed comment was posted; null while the finding is not reported fixed. */
  reportedFixedAt: timestamp.nullable(),
  createdAt: timestamp,
});
export type JiraLink = z.infer<typeof jiraLinkSchema>;

export function jiraLinkDto(row: JiraLinkRow, siteUrl: string): JiraLink {
  return {
    id: row.id,
    state: row.state,
    origin: row.origin,
    key: row.jiraKey,
    url: row.jiraKey === null ? null : `${siteUrl}/browse/${encodeURIComponent(row.jiraKey)}`,
    status:
      row.statusName === null || row.statusCategory === null
        ? null
        : { name: row.statusName, category: row.statusCategory },
    statusCheckedAt: isoOrNull(row.statusCheckedAt),
    failure: row.failure,
    reportedFixedAt: isoOrNull(row.reportedFixedAt),
    createdAt: iso(row.createdAt),
  };
}

/** The map key of a vulnerability: its package and id. */
export const pairKey = (packageName: string, vulnerabilityId: string): string =>
  JSON.stringify([packageName, vulnerabilityId]);

/**
 * R6, spec §6.3: whether a Jira issue may be requested for the issue. A code issue (no package)
 * on the main branch, or a Trivy issue whose triage writes the project's decision (main or a
 * tracked branch, never a merge request); a closed issue never (R7).
 */
export function issueLinkable(
  issue: { status: string; packageName: string | null; engineId: string },
  branch: { name: string; isMain: boolean; kind: string },
  settings: VulnerabilitySettings,
): boolean {
  if (issue.status === 'closed') return false;
  if (issue.packageName === null) return branch.isMain;
  return writesDecision(settings, {
    engineId: issue.engineId,
    packageName: issue.packageName,
    branch,
  });
}

/** What a link is about: a code issue, or a vulnerability of the project. */
export type LinkTarget =
  | { kind: 'issue'; issueId: string }
  | { kind: 'vulnerability'; packageName: string; vulnerabilityId: string };

/** One key per finding: the issue's id, or the pair's {@link pairKey}. */
export function targetKey(target: LinkTarget): string {
  return target.kind === 'issue'
    ? target.issueId
    : pairKey(target.packageName, target.vulnerabilityId);
}

/** The target a stored row is about. */
export function rowTarget(row: JiraLinkRow): LinkTarget {
  return row.kind === 'issue'
    ? { kind: 'issue', issueId: row.issueId ?? '' }
    : {
        kind: 'vulnerability',
        packageName: row.packageName ?? '',
        vulnerabilityId: row.vulnerabilityId ?? '',
      };
}

/** A link row and the site URL of its connection. */
export type JiraLinkWithSite = JiraLinkRow & { siteUrl: string };

const withSite = { ...getTableColumns(jiraLinks), siteUrl: jiraConnections.siteUrl };

/**
 * The project's link rows of these targets by {@link targetKey}, dismissed ones too unless
 * `live`. One statement, each half on its unique index (`jira_links_issue_uq`,
 * `jira_links_vulnerability_uq`), never a query per target.
 */
export async function linkRowsOf(
  db: Executor,
  projectId: string,
  targets: readonly LinkTarget[],
  options: { live?: boolean } = {},
): Promise<Map<string, JiraLinkWithSite>> {
  const issueIds: string[] = [];
  const pairs: { package_name: string; vulnerability_id: string }[] = [];
  for (const t of targets) {
    if (t.kind === 'issue') issueIds.push(t.issueId);
    else pairs.push({ package_name: t.packageName, vulnerability_id: t.vulnerabilityId });
  }
  const select = (where: SQL | undefined) =>
    db
      .select(withSite)
      .from(jiraLinks)
      .innerJoin(jiraConnections, eq(jiraConnections.id, jiraLinks.connectionId))
      .where(
        and(
          eq(jiraLinks.projectId, projectId),
          options.live ? ne(jiraLinks.state, 'dismissed') : undefined,
          where,
        ),
      );
  const byIssue =
    issueIds.length === 0
      ? null
      : select(and(eq(jiraLinks.kind, 'issue'), inArray(jiraLinks.issueId, uuidList(issueIds))));
  const byPair =
    pairs.length === 0
      ? null
      : select(
          and(
            eq(jiraLinks.kind, 'vulnerability'),
            sql`(${jiraLinks.packageName}, ${jiraLinks.vulnerabilityId}) IN (
              SELECT p.package_name, p.vulnerability_id
                FROM jsonb_to_recordset(${JSON.stringify(pairs)}::jsonb)
                     AS p(package_name text, vulnerability_id text))`,
          ),
        );
  const rows =
    byIssue && byPair ? await byIssue.unionAll(byPair) : ((await (byIssue ?? byPair)) ?? []);
  return new Map(rows.map((row) => [targetKey(rowTarget(row)), row]));
}

/** An issue as {@link linksForIssues} looks up its link. */
export interface IssueLinkLookup {
  id: string;
  packageName: string | null;
  /** The Trivy rule's `engine_rule_id`; null for a code issue. */
  vulnerabilityId: string | null;
}

/**
 * The links of issues of the project, by issue id, without the dismissed ones (spec §6.8). An
 * issue with a `vulnerabilityId` (the Trivy rule's `engine_rule_id`) and a package is looked up by
 * its pair, any other by its id. Callers pass a Trivy issue's pair only when its branch is main or
 * tracked, so a merge request's Trivy issue embeds nothing; a closed issue still shows its link.
 */
export async function linksForIssues(
  db: Executor,
  projectId: string,
  issues: readonly IssueLinkLookup[],
): Promise<Map<string, JiraLink>> {
  const targetOf = (i: IssueLinkLookup): LinkTarget =>
    i.packageName !== null && i.vulnerabilityId !== null
      ? { kind: 'vulnerability', packageName: i.packageName, vulnerabilityId: i.vulnerabilityId }
      : { kind: 'issue', issueId: i.id };
  const found = new Map<string, JiraLink>();
  if (issues.length === 0) return found;
  const rows = await linkRowsOf(db, projectId, issues.map(targetOf), { live: true });
  for (const issue of issues) {
    const row = rows.get(targetKey(targetOf(issue)));
    if (row) found.set(issue.id, jiraLinkDto(row, row.siteUrl));
  }
  return found;
}

/** The links of vulnerabilities of the project, by {@link pairKey}, without the dismissed ones. */
export async function linksForPairs(
  db: Executor,
  projectId: string,
  pairs: readonly { packageName: string; vulnerabilityId: string }[],
): Promise<Map<string, JiraLink>> {
  const found = new Map<string, JiraLink>();
  if (pairs.length === 0) return found;
  const rows = await linkRowsOf(
    db,
    projectId,
    pairs.map((p) => ({ kind: 'vulnerability', ...p })),
    { live: true },
  );
  for (const [key, row] of rows) found.set(key, jiraLinkDto(row, row.siteUrl));
  return found;
}

/** How the project holds each pair, by {@link pairKey}. */
export interface PairPresence {
  /** A `target_vulnerabilities` row of the project on any target, or a Trivy issue of it. */
  known: Set<string>;
  /**
   * Ruling T6d: present as the sync pass judges presence (spec §6.5, "gone"): a
   * `target_vulnerabilities` row on a target `trackedTargets` returns, or a non-closed Trivy issue
   * of the main branch or a tracked branch. Only such a pair may be linked; one seen only on an
   * untracked target or a merge request would read as gone at the first pass.
   */
  linkable: Set<string>;
}

/**
 * {@link PairPresence} of the pairs: the tracked targets, then one query over the project's
 * vulnerability rows and one over its Trivy issues (and the settings when there are some), the
 * same few queries for any number of pairs.
 */
export async function pairPresence(
  db: Executor,
  projectId: string,
  pairs: readonly { packageName: string; vulnerabilityId: string }[],
): Promise<PairPresence> {
  const presence: PairPresence = { known: new Set(), linkable: new Set() };
  if (pairs.length === 0) return presence;
  const json = JSON.stringify(
    pairs.map((p) => ({ package_name: p.packageName, vulnerability_id: p.vulnerabilityId })),
  );
  const tracked = await trackedTargets(db, projectId);
  const trackedBranches = tracked.flatMap((t) => (t.kind === 'branch' ? [t.branchId] : []));
  const trackedVersions = tracked.flatMap((t) => (t.kind === 'version' ? [t.versionId] : []));
  const rows = await db.execute<{
    package_name: string;
    vulnerability_id: string;
    tracked: boolean;
  }>(sql`
    SELECT tv.package_name, tv.vulnerability_id,
           bool_or(tv.branch_id = ANY(${uuidArray(trackedBranches)})
                   OR tv.version_id = ANY(${uuidArray(trackedVersions)})) AS tracked
      FROM (SELECT DISTINCT * FROM jsonb_to_recordset(${json}::jsonb)
                   AS p(package_name text, vulnerability_id text)) p
      JOIN target_vulnerabilities tv
        ON tv.project_id = ${projectId} AND tv.package_name = p.package_name
       AND tv.vulnerability_id = p.vulnerability_id
     GROUP BY tv.package_name, tv.vulnerability_id`);
  for (const r of rows.rows) {
    const key = pairKey(r.package_name, r.vulnerability_id);
    presence.known.add(key);
    if (r.tracked) presence.linkable.add(key);
  }
  const reported = await db.execute<{
    package_name: string;
    vulnerability_id: string;
    closed: boolean;
    name: string;
    is_main: boolean;
    kind: string;
  }>(sql`
    SELECT DISTINCT p.package_name, p.vulnerability_id, i.status = 'closed' AS closed,
           b.name, b.is_main, b.kind
      FROM jsonb_to_recordset(${json}::jsonb) AS p(package_name text, vulnerability_id text)
      JOIN issues i ON i.project_id = ${projectId} AND i.package_name = p.package_name
      JOIN rules r ON r.id = i.rule_id AND r.engine_id = ${TRIVY_ENGINE}
                  AND r.engine_rule_id = p.vulnerability_id
      JOIN branches b ON b.id = i.branch_id`);
  if (reported.rows.length > 0) {
    const settings = await vulnerabilitySettings(db, projectId);
    for (const r of reported.rows) {
      const key = pairKey(r.package_name, r.vulnerability_id);
      presence.known.add(key);
      if (
        !r.closed &&
        isTrackedBranch(settings, { name: r.name, isMain: r.is_main, kind: r.kind })
      ) {
        presence.linkable.add(key);
      }
    }
  }
  return presence;
}

/** `ARRAY(...)` of uuids, bound as one parameter (an empty list matches nothing). */
function uuidArray(ids: readonly string[]): SQL {
  return sql`ARRAY(SELECT jsonb_array_elements_text(${JSON.stringify(ids)}::jsonb)::uuid)`;
}

/**
 * spec §6.4: the organisation's connection, unless it has none (409 JIRA_NOT_CONNECTED) or a
 * credential problem (409 JIRA_CONNECTION_BROKEN, with the problem's code as `problemCode`); a
 * transient problem refuses nothing.
 */
export async function usableConnection(
  db: Executor,
  project: ProjectRow,
): Promise<JiraConnectionRow> {
  const connection = await connectionOf(db, project.organizationId);
  if (!connection) throw conflict('JIRA_NOT_CONNECTED', 'The organisation has no Jira connection');
  if (connection.problem !== null && isCredentialProblem(connection.problem)) {
    throw new ProblemError(
      409,
      'JIRA_CONNECTION_BROKEN',
      'The Jira connection needs an organisation admin',
      {
        detail: connection.problem.message,
        extensions: { problemCode: connection.problem.code },
      },
    );
  }
  return connection;
}

/** spec §6.4: the three preconditions of a link request, in order (the mapping last). */
export async function linkPreconditions(
  db: Executor,
  project: ProjectRow,
): Promise<{ connection: JiraConnectionRow; mapping: JiraMappingRow }> {
  const connection = await usableConnection(db, project);
  const mapping = await mappingOf(db, project.id);
  if (!mapping) {
    throw conflict('JIRA_PROJECT_NOT_MAPPED', 'The project is not mapped to a Jira project');
  }
  return { connection, mapping };
}

/**
 * A pending row, `origin` manual and made by `userId`, for each target that has none (one
 * statement per kind, `ON CONFLICT DO NOTHING` on its unique index). Returns the rows made: a
 * target another request linked meanwhile makes none.
 */
export async function insertPendingLinks(
  tx: Executor,
  at: { projectId: string; connectionId: string; userId: string },
  targets: readonly LinkTarget[],
): Promise<JiraLinkRow[]> {
  const base = {
    projectId: at.projectId,
    connectionId: at.connectionId,
    state: 'pending' as const,
    origin: 'manual' as const,
    createdBy: at.userId,
  };
  const issueRows = targets.flatMap((t) =>
    t.kind === 'issue' ? [{ ...base, kind: 'issue' as const, issueId: t.issueId }] : [],
  );
  const pairRows = targets.flatMap((t) =>
    t.kind === 'vulnerability'
      ? [
          {
            ...base,
            kind: 'vulnerability' as const,
            packageName: t.packageName,
            vulnerabilityId: t.vulnerabilityId,
          },
        ]
      : [],
  );
  const made: JiraLinkRow[] = [];
  if (issueRows.length > 0) {
    made.push(
      ...(await tx
        .insert(jiraLinks)
        .values(issueRows)
        .onConflictDoNothing({ target: jiraLinks.issueId })
        .returning()),
    );
  }
  if (pairRows.length > 0) {
    made.push(
      ...(await tx
        .insert(jiraLinks)
        .values(pairRows)
        .onConflictDoNothing({
          target: [jiraLinks.projectId, jiraLinks.packageName, jiraLinks.vulnerabilityId],
          where: sql`kind = 'vulnerability'`,
        })
        .returning()),
    );
  }
  return made;
}

/**
 * spec §6.3, ruling P2: the row back to `pending` for a new create, if its state is one of
 * `from`: `generation` + 1 (the old Jira issue's label no longer matches), and everything of the
 * old Jira issue and its creation cleared (key, id, status, failure, `attempted_at`, so the create
 * claims it; `missed_passes`, `reported_fixed_at`). Null when the row is in another state, as when
 * a concurrent request re-armed it first.
 */
export async function rearmLink(
  tx: Executor,
  linkId: string,
  from: readonly JiraLinkState[],
  userId: string | null,
): Promise<JiraLinkRow | null> {
  const [row] = await tx
    .update(jiraLinks)
    .set({
      state: 'pending',
      origin: 'manual',
      createdBy: userId,
      generation: sql`${jiraLinks.generation} + 1`,
      jiraKey: null,
      jiraIssueId: null,
      statusName: null,
      statusCategory: null,
      statusCheckedAt: null,
      failure: null,
      attemptedAt: null,
      missedPasses: 0,
      reportedFixedAt: null,
      updatedAt: sql`now()`,
    })
    .where(and(eq(jiraLinks.id, linkId), inArray(jiraLinks.state, [...from])))
    .returning();
  return row ?? null;
}

/** Whether `engineId` and the package make the issue a Trivy issue of a pair. */
export function isPairIssue(issue: { engineId: string; packageName: string | null }): boolean {
  return issue.engineId === TRIVY_ENGINE && issue.packageName !== null;
}

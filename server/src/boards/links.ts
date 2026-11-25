import { and, eq, getTableColumns, inArray, ne, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import {
  BOARDS_STATE_CATEGORIES,
  boardsLinks,
  scmConnections,
  type JiraLinkState,
  type ScmProblemValue,
} from '../db/schema';
import { conflict, ProblemError } from '../http/problem';
import { iso, isoOrNull, timestamp } from '../http/schemas';
import { rowTarget, targetKey, type IssueLinkLookup, type LinkTarget } from '../jira/links';
import type { ProjectRow } from '../projects/access';
import { azureWebBase } from '../scm/azure/url';
import type { ScmConnectionRow } from '../scm/connections';
import type { ScmBackgroundProblemCode } from '../scm/problems';
import { boardsMappingOf, type BoardsMappingRow } from './mapping';

/*
 * Azure DevOps design §7.8, plan Ruling 2: the Jira link rules (jira/links.ts) for Azure Boards.
 * What carries no Jira (the targets, `issueLinkable`, presence, the request's limits and the states
 * a request or a retry re-arms) is imported from there, not copied.
 */

export type BoardsLinkRow = typeof boardsLinks.$inferSelect;

/** A finding's Azure Boards link, embedded in the issue and vulnerability lists (design §7.8). */
export const boardsLinkSchema = z.object({
  id: z.uuid(),
  state: z.enum(['pending', 'created', 'failed', 'missing', 'dismissed']),
  /** `auto` for a link the automatic rule made. */
  origin: z.enum(['manual', 'auto']),
  /** The work item's id; null until it is created (and after a re-arm). */
  workItemId: z.number().int().nullable(),
  /**
   * `<connection base URL>/<Azure DevOps project id>/_workitems/edit/<id>`, from the link's own
   * connection and Azure DevOps project (kept when the mapping is removed); null without a work
   * item id.
   */
  url: z.string().nullable(),
  /**
   * The work item's state as last read, with its category (null for a state the work item type no
   * longer lists); null until read.
   */
  workItemState: z
    .object({ name: z.string(), category: z.enum(BOARDS_STATE_CATEGORIES).nullable() })
    .nullable(),
  /** When `workItemState` was last read. */
  stateCheckedAt: timestamp.nullable(),
  failure: z
    .object({
      code: z.string().meta({
        description:
          'field_refused, permission_missing, not_found, limit_reached, not_mapped, finding_gone, outcome_unknown or type_unsupported; note_refused on a created link whose note Azure DevOps refused (it is not sent again)',
      }),
      /**
       * A fixed text; for `field_refused`, Azure DevOps' own words (at most 500 characters), empty
       * when it gave none.
       */
      message: z.string(),
    })
    .nullable(),
  /** When the fixed note was posted; null while the finding is not reported fixed. */
  reportedFixedAt: timestamp.nullable(),
  createdAt: timestamp,
});
export type BoardsLink = z.infer<typeof boardsLinkSchema>;

/**
 * The link as the API shows it: the work item page's URL (Part B a/d) from the link's connection's
 * base URL and its own Azure DevOps project.
 */
export function boardsLinkDto(row: BoardsLinkRow, connectionBaseUrl: string): BoardsLink {
  return {
    id: row.id,
    state: row.state,
    origin: row.origin,
    workItemId: row.workItemId,
    url:
      row.workItemId === null
        ? null
        : `${azureWebBase(connectionBaseUrl)}/${row.azureProjectId}/_workitems/edit/${row.workItemId}`,
    workItemState:
      row.stateName === null ? null : { name: row.stateName, category: row.stateCategory },
    stateCheckedAt: isoOrNull(row.stateCheckedAt),
    failure: row.failure,
    reportedFixedAt: isoOrNull(row.reportedFixedAt),
    createdAt: iso(row.createdAt),
  };
}

/** A link row with what its URL needs besides its own columns: its connection's base URL. */
export type BoardsLinkWithUrl = BoardsLinkRow & { baseUrl: string };

const withUrl = { ...getTableColumns(boardsLinks), baseUrl: scmConnections.baseUrl };

/** The DTO of a row {@link boardsLinkRowsOf} read. */
export const boardsLinkDtoOf = (row: BoardsLinkWithUrl): BoardsLink =>
  boardsLinkDto(row, row.baseUrl);

/**
 * The project's Boards link rows of these targets by {@link targetKey}, dismissed ones too unless
 * `live`. One statement, each half on its unique index (`boards_links_issue_uq`,
 * `boards_links_vulnerability_uq`), never a query per target.
 */
export async function boardsLinkRowsOf(
  db: Executor,
  projectId: string,
  targets: readonly LinkTarget[],
  options: { live?: boolean } = {},
): Promise<Map<string, BoardsLinkWithUrl>> {
  const issueIds: string[] = [];
  const pairs: { package_name: string; vulnerability_id: string }[] = [];
  for (const t of targets) {
    if (t.kind === 'issue') issueIds.push(t.issueId);
    else pairs.push({ package_name: t.packageName, vulnerability_id: t.vulnerabilityId });
  }
  const select = (where: SQL | undefined) =>
    db
      .select(withUrl)
      .from(boardsLinks)
      .innerJoin(scmConnections, eq(scmConnections.id, boardsLinks.connectionId))
      .where(
        and(
          eq(boardsLinks.projectId, projectId),
          options.live ? ne(boardsLinks.state, 'dismissed') : undefined,
          where,
        ),
      );
  const byIssue =
    issueIds.length === 0
      ? null
      : select(
          and(eq(boardsLinks.kind, 'issue'), inArray(boardsLinks.issueId, uuidList(issueIds))),
        );
  const byPair =
    pairs.length === 0
      ? null
      : select(
          and(
            eq(boardsLinks.kind, 'vulnerability'),
            sql`(${boardsLinks.packageName}, ${boardsLinks.vulnerabilityId}) IN (
              SELECT p.package_name, p.vulnerability_id
                FROM jsonb_to_recordset(${JSON.stringify(pairs)}::jsonb)
                     AS p(package_name text, vulnerability_id text))`,
          ),
        );
  const rows =
    byIssue && byPair ? await byIssue.unionAll(byPair) : ((await (byIssue ?? byPair)) ?? []);
  return new Map(rows.map((row) => [targetKey(rowTarget(row)), row]));
}

/**
 * The Boards links of issues of the project, by issue id, as Jira's `linksForIssues` (the same
 * lookups: a Trivy issue by its pair), without the dismissed ones unless `dismissed`.
 */
export async function boardsLinksForIssues(
  db: Executor,
  projectId: string,
  issues: readonly IssueLinkLookup[],
  options: { dismissed?: boolean } = {},
): Promise<Map<string, BoardsLink>> {
  const targetOf = (i: IssueLinkLookup): LinkTarget =>
    i.packageName !== null && i.vulnerabilityId !== null
      ? { kind: 'vulnerability', packageName: i.packageName, vulnerabilityId: i.vulnerabilityId }
      : { kind: 'issue', issueId: i.id };
  const found = new Map<string, BoardsLink>();
  if (issues.length === 0) return found;
  const rows = await boardsLinkRowsOf(db, projectId, issues.map(targetOf), {
    live: options.dismissed !== true,
  });
  for (const issue of issues) {
    const row = rows.get(targetKey(targetOf(issue)));
    if (row) found.set(issue.id, boardsLinkDtoOf(row));
  }
  return found;
}

/**
 * The Boards links of vulnerabilities of the project, by `pairKey`, without the dismissed ones
 * unless `dismissed`.
 */
export async function boardsLinksForPairs(
  db: Executor,
  projectId: string,
  pairs: readonly { packageName: string; vulnerabilityId: string }[],
  options: { dismissed?: boolean } = {},
): Promise<Map<string, BoardsLink>> {
  const found = new Map<string, BoardsLink>();
  if (pairs.length === 0) return found;
  const rows = await boardsLinkRowsOf(
    db,
    projectId,
    pairs.map((p) => ({ kind: 'vulnerability', ...p })),
    { live: options.dismissed !== true },
  );
  for (const [key, row] of rows) found.set(key, boardsLinkDtoOf(row));
  return found;
}

/** A link the lists embed: none for a dismissed one (it reads as no link). */
export function liveLink<T extends { state: string }>(link: T | undefined): T | null {
  return link === undefined || link.state === 'dismissed' ? null : link;
}

const notConnected = (title: string) => conflict('BOARDS_NOT_CONNECTED', title);

/**
 * The connection problems that stop Azure Boards: the credential itself is refused or cannot be
 * used. A `permission_missing` decoration recorded for one right of its own, a service hook code
 * or a transient failure stops nothing; a Boards 403 is the link's `permission_missing` failure
 * and is never written to the connection. The pass's probe clears only these codes.
 */
export const BOARDS_BLOCKING_CODES = [
  'token_refused',
  'sign_in_required',
  'html_answer',
  'token_endpoint',
  'undecryptable',
  'url_not_allowed',
] as const satisfies readonly ScmBackgroundProblemCode[];

const BLOCKING: ReadonlySet<string> = new Set(BOARDS_BLOCKING_CODES);

/** Whether the stored problem stops Azure Boards: nothing is requested or sent while it is set. */
export function isBoardsBlockingProblem(problem: ScmProblemValue | null): boolean {
  return problem !== null && BLOCKING.has(problem.code);
}

/**
 * The organisation's Azure DevOps connection `connectionId` (a mapping's or a link's), unless it is
 * gone (409 BOARDS_NOT_CONNECTED) or has a blocking problem ({@link BOARDS_BLOCKING_CODES}: 409
 * BOARDS_CONNECTION_BROKEN, with the problem's code as `problemCode`); any other problem refuses
 * nothing.
 */
export async function usableBoardsConnection(
  db: Executor,
  project: ProjectRow,
  connectionId: string,
): Promise<ScmConnectionRow> {
  const [connection] = await db
    .select()
    .from(scmConnections)
    .where(
      and(
        eq(scmConnections.id, connectionId),
        eq(scmConnections.organizationId, project.organizationId),
        eq(scmConnections.provider, 'azure'),
      ),
    );
  if (!connection) throw notConnected('The Azure DevOps connection of the project is gone');
  const problem = connection.problem;
  if (problem !== null && BLOCKING.has(problem.code)) {
    throw new ProblemError(
      409,
      'BOARDS_CONNECTION_BROKEN',
      'The Azure DevOps connection needs an organisation admin',
      { extensions: { problemCode: problem.code } },
    );
  }
  return connection;
}

/**
 * Design §7.8: the preconditions of a link request, in order: the organisation has an Azure
 * DevOps connection (409 BOARDS_NOT_CONNECTED), the mapping's connection has no credential problem
 * (409 BOARDS_CONNECTION_BROKEN), and the project is mapped (409 BOARDS_PROJECT_NOT_MAPPED). A
 * project's connection is its mapping's, so without a mapping there is no credential to judge.
 */
export async function boardsLinkPreconditions(
  db: Executor,
  project: ProjectRow,
): Promise<{ connection: ScmConnectionRow; mapping: BoardsMappingRow }> {
  const mapping = await boardsMappingOf(db, project.id);
  if (!mapping) {
    const [any] = await db
      .select({ id: scmConnections.id })
      .from(scmConnections)
      .where(
        and(
          eq(scmConnections.organizationId, project.organizationId),
          eq(scmConnections.provider, 'azure'),
        ),
      )
      .limit(1);
    if (!any) throw notConnected('The organisation has no Azure DevOps connection');
    throw conflict('BOARDS_PROJECT_NOT_MAPPED', 'The project is not mapped to Azure Boards');
  }
  const connection = await usableBoardsConnection(db, project, mapping.connectionId);
  return { connection, mapping };
}

/**
 * A pending row for each target that has none (one statement per kind, `ON CONFLICT DO NOTHING`
 * on its unique index), on the mapping's connection and Azure DevOps project: `origin` manual and
 * made by `userId`, or, with `userId` null, the automatic rule's (`origin` auto, no
 * `created_by`). Returns the rows made: a target another request linked meanwhile makes none.
 */
export async function insertPendingBoardsLinks(
  tx: Executor,
  at: { projectId: string; connectionId: string; azureProjectId: string; userId: string | null },
  targets: readonly LinkTarget[],
): Promise<BoardsLinkRow[]> {
  const base = {
    projectId: at.projectId,
    connectionId: at.connectionId,
    azureProjectId: at.azureProjectId,
    state: 'pending' as const,
    origin: at.userId === null ? ('auto' as const) : ('manual' as const),
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
  const made: BoardsLinkRow[] = [];
  if (issueRows.length > 0) {
    made.push(
      ...(await tx
        .insert(boardsLinks)
        .values(issueRows)
        .onConflictDoNothing({ target: boardsLinks.issueId })
        .returning()),
    );
  }
  if (pairRows.length > 0) {
    made.push(
      ...(await tx
        .insert(boardsLinks)
        .values(pairRows)
        .onConflictDoNothing({
          target: [boardsLinks.projectId, boardsLinks.packageName, boardsLinks.vulnerabilityId],
          where: sql`kind = 'vulnerability'`,
        })
        .returning()),
    );
  }
  return made;
}

/**
 * The row back to `pending` for a new create, if its state is one of `from`: `generation` + 1 (the
 * old work item's reconciliation key no longer matches), and everything of the old work item and
 * its creation cleared (id, state, failure, `attempted_at`, so the create claims it;
 * `missed_passes`, `reported_fixed_at`). With `onto` the row moves to that connection and Azure
 * DevOps project (a request, and a retry of a mapped project, re-arm onto the mapping's current
 * ones; a retry without a mapping keeps the link's).
 * Null when the row is in another state, as when a concurrent request re-armed it first.
 */
export async function rearmBoardsLink(
  tx: Executor,
  linkId: string,
  from: readonly JiraLinkState[],
  userId: string | null,
  onto?: { connectionId: string; azureProjectId: string },
): Promise<BoardsLinkRow | null> {
  const [row] = await tx
    .update(boardsLinks)
    .set({
      state: 'pending',
      origin: 'manual',
      createdBy: userId,
      ...(onto === undefined
        ? {}
        : { connectionId: onto.connectionId, azureProjectId: onto.azureProjectId }),
      generation: sql`${boardsLinks.generation} + 1`,
      workItemId: null,
      stateName: null,
      stateCategory: null,
      stateCheckedAt: null,
      failure: null,
      attemptedAt: null,
      missedPasses: 0,
      reportedFixedAt: null,
      updatedAt: sql`now()`,
    })
    .where(and(eq(boardsLinks.id, linkId), inArray(boardsLinks.state, [...from])))
    .returning();
  return row ?? null;
}

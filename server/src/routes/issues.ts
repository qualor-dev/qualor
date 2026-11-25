import {
  CONFIDENCES,
  ISSUE_KINDS,
  QUALITIES,
  ruleHelpUri,
  SEVERITIES,
  secondaryLocation,
} from '@qualor/shared';
import { and, asc, eq, gt } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { accessOf, requireUser } from '../auth/access';
import { first } from '../db/rows';
import { AI_CATEGORIES, branches, issueChanges, reviewFindings, rules, users } from '../db/schema';
import { fixFacets, type FixFacet } from '../fixes/eligibility';
import { dependencyFixSchema } from '../fixes/rows';
import { decodeCursor, pageQuery, pageSchema, toPage } from '../http/pagination';
import { conflict, forbidden, notFound, ProblemError, validationFailed } from '../http/problem';
import { idParams, iso, isoOrNull, noNul, text, timestamp } from '../http/schemas';
import {
  ISSUE_FACETS,
  ISSUE_SORTS,
  ISSUE_STATUSES,
  issueFacets,
  issueSortPlan,
  listIssues,
  type IssueFacet,
  type IssueFilters,
  type IssueListRow,
} from '../issues/query';
import { transitionComment } from '../issues/comment';
import { issueChangeCharge, type ChargeIssueChanges } from '../issues/rate-limit';
import { overrideSeverity } from '../issues/severity';
import {
  ownCommentMax,
  provenanceLine,
  triageSuggestionFor,
  withProvenance,
} from '../llm/provenance';
import { transitionIssues, USER_STATUSES } from '../issues/transitions';
import { boardsLinkSchema, boardsLinksForIssues, liveLink, type BoardsLink } from '../boards/links';
import { boardsMappingOf } from '../boards/mapping';
import {
  isPairIssue,
  issueLinkable,
  jiraLinkSchema,
  linksForIssues,
  pairKey,
  type IssueLinkLookup,
  type JiraLink,
} from '../jira/links';
import { branchForUser, issueForUser, type IssueRow } from '../projects/access';
import type { IssueStatus } from '../tracking/plan';
import {
  isTrackedBranch,
  vulnerabilitySettings,
  type VulnerabilitySettings,
} from '../versions/settings';
import {
  DECISION_STATUSES,
  effectiveDecision,
  VEX_JUSTIFICATIONS,
  type VexJustification,
} from '../vulnerabilities/decisions';
import { TRIVY_ENGINE, writesDecision } from '../vulnerabilities/trivy-issues';

export const issueStatusSchema = z.enum(ISSUE_STATUSES);

/** What R6 and the triage of a Trivy issue read of its branch. */
type Branch = { name: string; isMain: boolean; kind: string };

export const issueSchema = z.object({
  id: z.uuid(),
  projectId: z.uuid(),
  branchId: z.uuid(),
  rule: z.object({ key: z.string(), name: z.string(), engine: z.string() }),
  severity: z.enum(SEVERITIES),
  severityOverridden: z.boolean(),
  quality: z.enum(QUALITIES),
  kind: z.enum(ISSUE_KINDS),
  status: issueStatusSchema,
  message: z.string(),
  path: z.string().nullable(),
  startLine: z.number().int().nullable(),
  startColumn: z.number().int().nullable(),
  endLine: z.number().int().nullable(),
  endColumn: z.number().int().nullable(),
  inNewCode: z.boolean(),
  duplicateOfIssueId: z.uuid().nullable(),
  /**
   * Qualor's C# taint engine's confidence (R-9): `medium` when the reported path goes through the
   * heap, a lookup by a request key or a fallback edge (shown as "possible"); null when the
   * analyzer sets none (every other one).
   */
  confidence: z.enum(CONFIDENCES).nullable(),
  firstSeenAt: timestamp,
  resolvedAt: timestamp.nullable(),
  closedAt: timestamp.nullable(),
  createdAt: timestamp,
  updatedAt: timestamp,
  /**
   * 0.16 Jira §6.8: the finding's Jira link while one exists that is not dismissed: a Trivy issue
   * of main or a tracked branch shows its vulnerability's link; null otherwise.
   */
  jira: jiraLinkSchema.nullable(),
  /**
   * R6: whether a Jira issue may be requested for it: a code issue of the main branch, or a Trivy
   * issue of main or a tracked branch, that is not closed, and that has no Azure Boards link in
   * any state (Azure DevOps plan Ruling 9: one tracker per finding).
   */
  jiraLinkable: z.boolean(),
  /**
   * Azure DevOps design §7.8: the finding's Azure Boards link while one exists that is not
   * dismissed, looked up as `jira`; null otherwise.
   */
  boards: boardsLinkSchema.nullable(),
  /**
   * Whether a work item may be requested for it: as R6, while the project has an Azure Boards
   * mapping and the finding has no Jira link in any state (Ruling 9).
   */
  boardsLinkable: z.boolean(),
  /**
   * 0.16 fix MRs R12: a Trivy issue of main shows the fix of its package while main has a row of
   * its vulnerability; null otherwise (a code issue, another branch, a merge request).
   */
  fix: dependencyFixSchema.nullable(),
  /**
   * R12: whether a fix MR may be requested for a Trivy issue of main: its pair has an
   * effective-open, not ignored row on the main branch with a fixed version (B5), in a supported
   * ecosystem, and is not Go's standard library.
   */
  fixable: z.boolean(),
  /**
   * T18b: the Trivy package type of the pair's main row (npm, pnpm, yarn, gomod, pom, uv, poetry),
   * the `ecosystem` a fix request names; null for a code issue or an issue off main.
   */
  fixEcosystem: z.string().nullable(),
});
export type IssueDto = z.infer<typeof issueSchema>;

/** An issue's tracker links and whether each may be requested (R6, Azure DevOps plan Ruling 9). */
export interface IssueTrackers {
  jira: JiraLink | null;
  jiraLinkable: boolean;
  boards: BoardsLink | null;
  boardsLinkable: boolean;
}

/** Off the lists' pages: no link, none to request. */
const NO_TRACKERS: IssueTrackers = Object.freeze({
  jira: null,
  jiraLinkable: false,
  boards: null,
  boardsLinkable: false,
});

/**
 * What an AI review kept beside the issue it raised: the finding's own text, what it takes
 * for granted, the second check of a security finding and its one-click suggestion. All of it
 * was bounded and scrubbed when stored, and goes out as stored.
 */
const aiReviewSchema = z.object({
  category: z.enum(AI_CATEGORIES),
  body: z.string(),
  /** What the finding takes for granted; null when it says nothing. */
  assumption: z.string().nullable(),
  /** The independent check of a security finding; null when it was not checked. */
  verification: z.enum(['confirmed', 'needs_validation']).nullable(),
  /** The head lines `startLine` to `endLine` become `lines`; null without a suggestion. */
  suggestion: z
    .object({
      startLine: z.number().int(),
      endLine: z.number().int(),
      lines: z.array(z.string()),
    })
    .nullable(),
  /** The head commit the review read when it made the suggestion and placed the finding. */
  reviewedCommit: z.string(),
});

/**
 * A Trivy issue's pair and the project's decision on it (vuln plan 2b, D4): the one in force on
 * the issue's branch, its own row else the project's, null while there is none.
 */
const vulnerabilitySchema = z.object({
  packageName: z.string(),
  vulnerabilityId: z.string(),
  /** Whether triage of this issue writes the project-wide decision (main or a tracked branch). */
  writesDecision: z.boolean(),
  decision: z
    .object({
      status: z.enum(DECISION_STATUSES),
      reason: z.enum(VEX_JUSTIFICATIONS).nullable(),
      comment: z.string().nullable(),
      decidedAt: timestamp,
      decidedBy: z.object({ id: z.uuid(), name: z.string() }).nullable(),
      scope: z.enum(['project', 'branch']),
    })
    .nullable(),
});

export const issueDetailSchema = issueSchema.extend({
  rule: z.object({
    key: z.string(),
    name: z.string(),
    engine: z.string(),
    descriptionMd: z.string().nullable(),
    helpUri: z.string().nullable(),
    defaultSeverity: z.enum(SEVERITIES),
    quality: z.enum(QUALITIES),
    kind: z.enum(ISSUE_KINDS),
    tags: z.array(z.string()),
    cwe: z.array(z.number().int()),
  }),
  fingerprint: z.string(),
  snippet: z.unknown(),
  secondaryLocations: z.array(secondaryLocation),
  firstSeenAnalysisId: z.uuid().nullable(),
  lastSeenAnalysisId: z.uuid().nullable(),
  resolvedBy: z.object({ id: z.uuid(), username: z.string() }).nullable(),
  /** The finding of an AI review; null for every issue the analyzers report. */
  aiReview: aiReviewSchema.nullable(),
  /** The vulnerability of a Trivy issue with a package name (vuln plan 2b); null for others. */
  vulnerability: vulnerabilitySchema.nullable(),
});

const changeSchema = z.object({
  id: z.uuid(),
  user: z.object({ id: z.uuid(), username: z.string() }).nullable(),
  analysisId: z.uuid().nullable(),
  field: z.enum(['status', 'severity', 'comment']),
  oldValue: z.string().nullable(),
  newValue: z.string().nullable(),
  comment: z.string().nullable(),
  createdAt: timestamp,
});

/** data-model.md §6: at most 2 000 characters (issue_changes_comment_length), no U+0000. */
const commentField = noNul(z.string().max(2_000)).optional();
const transitionBody = {
  to: z.enum(USER_STATUSES),
  comment: commentField,
  /** Required for a false positive that writes the project's vulnerability decision (D9). */
  reason: z.enum(VEX_JUSTIFICATIONS).optional(),
};
/** api.md §3: a bulk transition names at most this many issues. */
const BULK_TRANSITION_MAX_IDS = 500;

/** 422 REASON_REQUIRED: the transition of a false positive that writes a decision named none. */
function reasonRequired(): ProblemError {
  return new ProblemError(
    422,
    'REASON_REQUIRED',
    'A reason is required to set false_positive on a Trivy issue of main or a tracked branch',
    { errors: [{ path: 'body.reason', message: 'Required for false_positive' }] },
  );
}

const facetValues = z.array(z.object({ value: z.string(), count: z.number().int() }));

/** A repeatable query parameter: `?status=open&status=resolved` or a single `?status=open`. */
function many<T extends z.ZodType>(item: T, max: number) {
  return z.union([item, z.array(item).min(1).max(max)]).optional();
}

function list<T>(value: T | T[] | undefined): T[] | undefined {
  if (value === undefined) return undefined;
  return [...new Set(Array.isArray(value) ? value : [value])];
}

const booleanParam = z.enum(['true', 'false']).optional();

export const issueListQuery = z.strictObject({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  cursor: z.string().max(8_192).optional(),
  branchId: z.uuid(),
  status: many(issueStatusSchema, ISSUE_STATUSES.length),
  severity: many(z.enum(SEVERITIES), SEVERITIES.length),
  quality: many(z.enum(QUALITIES), QUALITIES.length),
  kind: many(z.enum(ISSUE_KINDS), ISSUE_KINDS.length),
  rule: many(text(512), 50),
  engine: many(text(64), 20),
  path: many(text(1_024), 20),
  inNewCode: booleanParam,
  q: noNul(z.string().trim().min(1).max(200)).optional(),
  includeDuplicates: booleanParam,
  sort: z.enum(ISSUE_SORTS).default('severity'),
  facets: z.string().max(200).optional(),
});
type IssueListQuery = z.infer<typeof issueListQuery>;

export function filtersFrom(query: IssueListQuery): IssueFilters {
  return {
    branchId: query.branchId,
    statuses: list(query.status) ?? ['open'],
    severities: list(query.severity),
    qualities: list(query.quality),
    kinds: list(query.kind),
    ruleKeys: list(query.rule),
    engines: list(query.engine),
    pathPrefixes: list(query.path),
    inNewCode: query.inNewCode === undefined ? undefined : query.inNewCode === 'true',
    q: query.q,
    includeDuplicates: query.includeDuplicates === 'true',
  };
}

/** `?facets=severity,rule` → the distinct facet names; anything else is a 422. */
export function facetList(raw: string | undefined): IssueFacet[] {
  if (raw === undefined) return [];
  const names = [...new Set(raw.split(',').map((s) => s.trim()))];
  const unknown = names.filter((n) => !(ISSUE_FACETS as readonly string[]).includes(n));
  if (unknown.length > 0) {
    throw validationFailed([
      { path: 'query.facets', message: `Unknown facet: ${unknown.join(', ')}` },
    ]);
  }
  return names as IssueFacet[];
}

/** A code issue's, or an issue off main's: no fix, none to request. */
const NO_FIX: FixFacet = Object.freeze({
  fix: null,
  fixable: false,
  ecosystem: null,
});

export function issueDto(row: IssueListRow, trackers: IssueTrackers, fix: FixFacet): IssueDto {
  return {
    id: row.id,
    projectId: row.projectId,
    branchId: row.branchId,
    rule: { key: row.ruleKey, name: row.ruleName, engine: row.engineId },
    severity: row.severity as IssueDto['severity'],
    severityOverridden: row.severityOverridden,
    quality: row.quality as IssueDto['quality'],
    kind: row.kind as IssueDto['kind'],
    status: row.status as IssueStatus,
    message: row.message,
    path: row.path,
    startLine: row.startLine,
    startColumn: row.startColumn,
    endLine: row.endLine,
    endColumn: row.endColumn,
    inNewCode: row.inNewCode,
    duplicateOfIssueId: row.duplicateOfIssueId,
    confidence: (row.confidence as IssueDto['confidence']) ?? null,
    firstSeenAt: iso(row.firstSeenAt),
    resolvedAt: isoOrNull(row.resolvedAt),
    closedAt: isoOrNull(row.closedAt),
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
    jira: trackers.jira,
    jiraLinkable: trackers.jiraLinkable,
    boards: trackers.boards,
    boardsLinkable: trackers.boardsLinkable,
    fix: fix.fix,
    fixable: fix.fixable,
    fixEcosystem: fix.ecosystem,
  };
}

export const issueRoutes: FastifyPluginAsyncZod<{
  deps: RouteDeps;
  /** The app's G7 bound, shared with the AI routes (routes/index.ts). */
  chargeIssueChanges?: ChargeIssueChanges;
}> = async (app, { deps, chargeIssueChanges }) => {
  // scm.md §7, ruling G7: each issue a transition or severity override names costs its user one
  // change; checked before anything is read or written.
  const chargeChanges = chargeIssueChanges ?? issueChangeCharge();

  /**
   * The Jira and Azure Boards links of issues of one branch, in one batched lookup per tracker
   * (spec §6.8), and R6. A Trivy issue is looked up by its pair only on main or a tracked branch,
   * so a merge request's embeds nothing. Dismissed rows are read too: a row of either tracker, in
   * any state, keeps the other one's create away (Azure DevOps plan Ruling 9).
   */
  const trackersOf = async (
    projectId: string,
    branch: Branch,
    settings: VulnerabilitySettings,
    rows: readonly IssueListRow[],
  ): Promise<(row: IssueListRow) => IssueTrackers> => {
    const tracked = isTrackedBranch(settings, branch);
    const lookups = rows.flatMap((row): IssueLinkLookup[] => {
      if (!isPairIssue(row)) return [{ id: row.id, packageName: null, vulnerabilityId: null }];
      if (!tracked) return [];
      return [{ id: row.id, packageName: row.packageName, vulnerabilityId: row.engineRuleId }];
    });
    const jira = await linksForIssues(deps.db, projectId, lookups, { dismissed: true });
    const boards = await boardsLinksForIssues(deps.db, projectId, lookups, { dismissed: true });
    const linkable = new Set(
      rows.filter((row) => issueLinkable(row, branch, settings)).map((row) => row.id),
    );
    const mapped = linkable.size > 0 && (await boardsMappingOf(deps.db, projectId)) !== null;
    return (row) => ({
      jira: liveLink(jira.get(row.id)),
      jiraLinkable: linkable.has(row.id) && !boards.has(row.id),
      boards: liveLink(boards.get(row.id)),
      boardsLinkable: mapped && linkable.has(row.id) && !jira.has(row.id),
    });
  };

  /**
   * R12: the fix of each Trivy issue of main, in one batched lookup (`fixFacets`, two queries);
   * every other issue (a code issue, another branch, a merge request) has none.
   */
  const fixOf = async (
    projectId: string,
    branch: Branch,
    rows: readonly IssueListRow[],
  ): Promise<(row: IssueListRow) => FixFacet> => {
    const pairOf = (row: IssueListRow) =>
      branch.isMain && isPairIssue(row) && row.packageName !== null
        ? { packageName: row.packageName, vulnerabilityId: row.engineRuleId }
        : null;
    const pairs = rows.flatMap((row) => pairOf(row) ?? []);
    if (pairs.length === 0) return () => NO_FIX;
    const facets = await fixFacets(deps.db, projectId, pairs);
    return (row) => {
      const pair = pairOf(row);
      return pair
        ? (facets.get(pairKey(pair.packageName, pair.vulnerabilityId)) ?? NO_FIX)
        : NO_FIX;
    };
  };

  /** The pair of a Trivy issue and the decision in force on its branch; null for other issues. */
  const vulnerabilityOf = async (
    issue: IssueRow,
    rule: typeof rules.$inferSelect,
    branch: Branch,
    settings: VulnerabilitySettings,
  ): Promise<z.infer<typeof vulnerabilitySchema> | null> => {
    if (rule.engineId !== TRIVY_ENGINE || issue.packageName === null) return null;
    const decision = await effectiveDecision(deps.db, {
      projectId: issue.projectId,
      branchId: issue.branchId,
      versionId: null,
      packageName: issue.packageName,
      vulnerabilityId: rule.engineRuleId,
    });
    const [decider] = decision?.decidedBy
      ? await deps.db
          .select({ id: users.id, username: users.username, displayName: users.displayName })
          .from(users)
          .where(eq(users.id, decision.decidedBy))
      : [];
    return {
      packageName: issue.packageName,
      vulnerabilityId: rule.engineRuleId,
      writesDecision: writesDecision(settings, {
        engineId: rule.engineId,
        packageName: issue.packageName,
        branch,
      }),
      decision: decision && {
        status: decision.status,
        reason: decision.reason as VexJustification | null,
        comment: decision.comment,
        decidedAt: iso(decision.decidedAt),
        decidedBy: decider
          ? { id: decider.id, name: decider.displayName ?? decider.username }
          : null,
        scope: decision.branchId === null ? 'project' : 'branch',
      },
    };
  };

  /** The full issue (snippet, secondary locations, rule summary), after the access check. */
  const detail = async (issue: IssueRow): Promise<z.infer<typeof issueDetailSchema>> => {
    const rule = first(await deps.db.select().from(rules).where(eq(rules.id, issue.ruleId)));
    const [resolver] = issue.resolvedBy
      ? await deps.db
          .select({ id: users.id, username: users.username })
          .from(users)
          .where(eq(users.id, issue.resolvedBy))
      : [];
    const [finding] = await deps.db
      .select()
      .from(reviewFindings)
      .where(eq(reviewFindings.issueId, issue.id));
    const branch = first(
      await deps.db
        .select({ name: branches.name, isMain: branches.isMain, kind: branches.kind })
        .from(branches)
        .where(eq(branches.id, issue.branchId)),
    );
    const settings = await vulnerabilitySettings(deps.db, issue.projectId);
    const row: IssueListRow = {
      ...issue,
      ruleKey: rule.key,
      ruleName: rule.name,
      engineId: rule.engineId,
      engineRuleId: rule.engineRuleId,
    };
    const trackers = await trackersOf(issue.projectId, branch, settings, [row]);
    const fix = await fixOf(issue.projectId, branch, [row]);
    return {
      ...issueDto(row, trackers(row), fix(row)),
      rule: {
        key: rule.key,
        name: rule.name,
        engine: rule.engineId,
        descriptionMd: rule.descriptionMd,
        helpUri: ruleHelpUri(rule.key, rule.helpUri),
        defaultSeverity: rule.defaultSeverity as IssueDto['severity'],
        quality: rule.quality as IssueDto['quality'],
        kind: rule.kind,
        tags: rule.tags,
        cwe: rule.cwe,
      },
      fingerprint: issue.fingerprint,
      snippet: issue.snippet ?? null,
      secondaryLocations: issue.secondaryLocations as z.infer<typeof secondaryLocation>[],
      firstSeenAnalysisId: issue.firstSeenAnalysisId,
      lastSeenAnalysisId: issue.lastSeenAnalysisId,
      resolvedBy: resolver ?? null,
      aiReview: finding
        ? {
            category: finding.category,
            body: finding.body,
            assumption: finding.assumption,
            verification: finding.verification,
            suggestion: finding.suggestion,
            reviewedCommit: finding.reviewedHeadSha,
          }
        : null,
      vulnerability: await vulnerabilityOf(issue, rule, branch, settings),
    };
  };

  app.get(
    '/issues',
    {
      config: { openapi: { problems: [404] } },
      schema: {
        tags: ['issues'],
        summary: 'Issues of a branch: repeatable filters, keyset pages, optional facets',
        querystring: issueListQuery,
        response: {
          200: z.object({
            items: z.array(issueSchema),
            nextCursor: z.string().nullable(),
            facets: z.partialRecord(z.enum(ISSUE_FACETS), facetValues).optional(),
          }),
        },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const facets = facetList(request.query.facets);
      // The cursor is checked before any query runs: a bad one is a 422 that costs no facets.
      const plan = issueSortPlan(request.query.sort, request.query.cursor);
      const branch = await branchForUser(
        accessOf(deps),
        principal,
        request.query.branchId,
        'project.read',
      );
      const filters = filtersFrom(request.query);
      const [page, counts] = await Promise.all([
        listIssues(deps.db, filters, { plan, limit: request.query.limit }),
        facets.length > 0 ? issueFacets(deps.db, filters, facets) : undefined,
      ]);
      // After the page, so the request still holds at most three pool connections (api.md §4).
      const trackers =
        page.items.length === 0
          ? () => NO_TRACKERS
          : await trackersOf(
              branch.projectId,
              branch,
              await vulnerabilitySettings(deps.db, branch.projectId),
              page.items,
            );
      const fix = await fixOf(branch.projectId, branch, page.items);
      return {
        items: page.items.map((row) => issueDto(row, trackers(row), fix(row))),
        nextCursor: page.nextCursor,
        ...(counts === undefined ? {} : { facets: counts }),
      };
    },
  );

  app.get(
    '/issues/:id',
    {
      schema: {
        tags: ['issues'],
        summary: 'One issue with its snippet, secondary locations and rule summary',
        params: idParams,
        response: { 200: issueDetailSchema },
      },
    },
    async (request) =>
      detail(
        await issueForUser(accessOf(deps), requireUser(request), request.params.id, 'project.read'),
      ),
  );
  app.post(
    '/issues/:id/transition',
    {
      config: {
        openapi: {
          problems: [409, 429, 503],
          problemDescriptions: {
            409: 'The transition is not allowed from the current status (INVALID_TRANSITION)',
            429: 'Too many issue changes by this user (RATE_LIMITED); see Retry-After',
            422: 'Validation failed (VALIDATION_FAILED; also a suggestionId that is not a succeeded AI triage suggestion of this issue), a required comment is missing (COMMENT_REQUIRED), or a false positive that writes the vulnerability decision has no reason (REASON_REQUIRED)',
            503: 'The issue stayed locked by an ingestion (CONCURRENCY_CONFLICT); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['issues'],
        summary:
          'Change the status (open, resolved, wont_fix, false_positive); mirrored onto duplicates, and onto the vulnerability decision of a Trivy issue on main or a tracked branch',
        params: idParams,
        body: z.strictObject({ ...transitionBody, suggestionId: z.uuid().optional() }),
        response: { 200: issueDetailSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      let comment = transitionComment(request.body.to, request.body.comment);
      if (request.body.suggestionId !== undefined) {
        // llm.md §7, a person accepts (or not) an AI triage suggestion; the model never
        // changes the issue. The issue is looked up as this person first (404 as without it), so
        // a suggestion id never tells anything about an issue they cannot see.
        await issueForUser(accessOf(deps), principal, request.params.id, 'issue.triage');
        const suggestion = await triageSuggestionFor(
          deps.db,
          request.params.id,
          request.body.suggestionId,
        );
        if (!suggestion) {
          throw validationFailed([
            {
              path: 'body.suggestionId',
              message: 'Not a succeeded AI triage suggestion of this issue',
            },
          ]);
        }
        const line = provenanceLine(suggestion.row, suggestion.result, principal.user.username);
        const max = ownCommentMax(line);
        if ((comment ?? '').length > max) {
          throw validationFailed([
            { path: 'body.comment', message: `At most ${max} characters with a suggestion` },
          ]);
        }
        comment = withProvenance(comment, line);
      }
      chargeChanges(principal.user.id, 1);
      const result = await transitionIssues(
        accessOf(deps),
        principal,
        [request.params.id],
        request.body.to,
        comment,
        {
          audit: {
            recorder: deps.audit,
            context: actorOf(request),
            bulk: false,
            suggestionId: request.body.suggestionId ?? null,
            mcpClientId: principal.kind === 'oauth' ? principal.clientId : null,
          },
          reason: request.body.reason ?? null,
          chargeMirrored: (count) => chargeChanges(principal.user.id, count),
          logger: request.log,
        },
      );
      const [failure] = result.failed;
      if (failure?.code === 'NOT_FOUND') throw notFound('Issue');
      if (failure?.code === 'FORBIDDEN')
        throw forbidden('FORBIDDEN', 'Your role does not allow this');
      if (failure?.code === 'REASON_REQUIRED') throw reasonRequired();
      if (failure) {
        throw conflict(
          'INVALID_TRANSITION',
          `An issue cannot go from ${failure.from ?? 'its status'} to ${request.body.to}`,
        );
      }
      return detail(
        await issueForUser(accessOf(deps), principal, request.params.id, 'issue.triage'),
      );
    },
  );

  app.post(
    '/issues/bulk-transition',
    {
      config: {
        openapi: {
          problems: [429, 503],
          problemDescriptions: {
            422: 'Validation failed (VALIDATION_FAILED), or a required comment is missing (COMMENT_REQUIRED)',
            429: 'Too many issue changes by this user, one per id (RATE_LIMITED); see Retry-After',
            503: 'An issue stayed locked by an ingestion (CONCURRENCY_CONFLICT); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['issues'],
        summary: 'Change the status of up to 500 issues; each one succeeds or fails on its own',
        body: z.strictObject({
          ids: z.array(z.uuid()).min(1).max(BULK_TRANSITION_MAX_IDS),
          ...transitionBody,
        }),
        response: {
          200: z.object({
            succeeded: z.array(z.uuid()),
            failed: z.array(
              z.object({
                id: z.uuid(),
                code: z.enum(['NOT_FOUND', 'FORBIDDEN', 'INVALID_TRANSITION', 'REASON_REQUIRED']),
              }),
            ),
          }),
        },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      const comment = transitionComment(request.body.to, request.body.comment);
      // One change per distinct issue: naming an id twice changes it once.
      chargeChanges(principal.user.id, new Set(request.body.ids).size);
      const result = await transitionIssues(
        accessOf(deps),
        principal,
        request.body.ids,
        request.body.to,
        comment,
        {
          audit: {
            recorder: deps.audit,
            context: actorOf(request),
            bulk: true,
            suggestionId: null,
          },
          reason: request.body.reason ?? null,
          chargeMirrored: (count) => chargeChanges(principal.user.id, count),
          logger: request.log,
        },
      );
      return {
        succeeded: result.succeeded,
        failed: result.failed.map((f) => ({ id: f.id, code: f.code })),
      };
    },
  );

  app.patch(
    '/issues/:id',
    {
      config: {
        openapi: {
          problems: [429, 503],
          problemDescriptions: {
            429: 'Too many issue changes by this user (RATE_LIMITED); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['issues'],
        summary: 'Override the severity (recorded in the changelog)',
        params: idParams,
        body: z.strictObject({ severity: z.enum(SEVERITIES) }),
        response: { 200: issueDetailSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request, 'write');
      chargeChanges(principal.user.id, 1);
      await issueForUser(accessOf(deps), principal, request.params.id, 'issue.triage');
      const updated = await overrideSeverity(
        deps.db,
        principal.user,
        request.params.id,
        request.body.severity,
        { recorder: deps.audit, context: actorOf(request) },
      );
      if (!updated) throw notFound('Issue');
      return detail(updated);
    },
  );

  app.get(
    '/issues/:id/changelog',
    {
      schema: {
        tags: ['issues'],
        summary: 'Status and severity changes, oldest first',
        params: idParams,
        querystring: z.strictObject(pageQuery),
        response: { 200: pageSchema(changeSchema) },
      },
    },
    async (request) => {
      const issue = await issueForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const after = decodeCursor(request.query.cursor);
      const rows = await deps.db
        .select({ change: issueChanges, username: users.username })
        .from(issueChanges)
        .leftJoin(users, eq(users.id, issueChanges.userId))
        .where(
          and(eq(issueChanges.issueId, issue.id), after ? gt(issueChanges.id, after) : undefined),
        )
        .orderBy(asc(issueChanges.id))
        .limit(request.query.limit + 1);
      const page = toPage(
        rows.map((r) => ({ ...r, id: r.change.id })),
        request.query.limit,
      );
      return {
        items: page.items.map(({ change, username }) => ({
          id: change.id,
          user:
            change.userId !== null && username !== null ? { id: change.userId, username } : null,
          analysisId: change.analysisId,
          field: change.field,
          oldValue: change.oldValue,
          newValue: change.newValue,
          comment: change.comment,
          createdAt: iso(change.createdAt),
        })),
        nextCursor: page.nextCursor,
      };
    },
  );
};
